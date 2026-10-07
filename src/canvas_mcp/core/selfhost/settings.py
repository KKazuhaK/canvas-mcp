"""Environment contract of the self-hosted Entra OAuth mode.

Every variable is parsed here and every problem is collected, so one failed
start shows the operator everything that needs fixing. Messages name the
variable and never include its value: several of them are secrets.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import ClassVar, Literal
from urllib.parse import urlsplit

AUTH_MODE_ENV = "MCP_AUTH_MODE"
AUTH_MODE_ENTRA = "entra-oauth"
AUTH_MODE_LEGACY = "legacy"

DEFAULT_API_SCOPE = "Canvas.Access"
DEFAULT_REQUIRED_ROLE = "Canvas.User"
DEFAULT_OWNER_ROLE = "Canvas.Owner"
DEFAULT_REDIRECT_URIS: tuple[str, ...] = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "http://localhost/callback",
    "http://127.0.0.1/callback",
)
DEFAULT_SESSION_TTL_SECONDS = 900
DEFAULT_DATA_DIR = "/data"

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SCOPE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_ROLE_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
_RESERVED_TENANTS = frozenset({"common", "organizations", "consumers"})
_OIDC_SCOPES = frozenset({"openid", "profile", "email", "offline_access"})
_LOOPBACK_HTTP_HOSTS = frozenset({"localhost", "127.0.0.1"})
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

MIN_CLIENT_SECRET_CHARS = 16
MIN_SIGNING_KEY_CHARS = 32
MIN_SESSION_SECRET_BYTES = 32
MIN_SESSION_TTL_SECONDS = 60
MAX_SESSION_TTL_SECONDS = 3600


class SelfhostConfigError(Exception):
    """The self-hosted configuration is unusable; ``problems`` lists every cause."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


@dataclass(frozen=True)
class SelfhostSettings:
    """Validated configuration of the ``entra-oauth`` mode."""

    public_base_url: str
    public_host: str
    tenant_id: str
    client_id: str
    client_secret: str = field(repr=False)
    api_scope: str
    required_role: str
    owner_role: str
    oauth_jwt_signing_key: str = field(repr=False)
    allowed_client_redirect_uris: tuple[str, ...]
    account_session_secret: bytes = field(repr=False)
    account_session_ttl_seconds: int
    canvas_token_keys_raw: str = field(repr=False)
    data_dir: Path
    fastmcp_home: Path

    mcp_path: ClassVar[str] = "/mcp"

    @property
    def mcp_url(self) -> str:
        return self.public_base_url + self.mcp_path

    @property
    def account_url(self) -> str:
        return self.public_base_url + "/account"

    @property
    def token_db_path(self) -> Path:
        return self.data_dir / "canvas-mcp" / "tokens.sqlite3"


def auth_mode(env: Mapping[str, str] | None = None) -> Literal["legacy", "entra-oauth"]:
    """The selected mode: unset, empty or ``legacy`` keep today's behaviour.

    Anything but the exact opt-in value ``entra-oauth`` is refused rather than
    guessed at, so a typo can never silently select the wrong authentication.
    """
    source = os.environ if env is None else env
    value = (source.get(AUTH_MODE_ENV) or "").strip()
    if value in ("", AUTH_MODE_LEGACY):
        return "legacy"
    if value == AUTH_MODE_ENTRA:
        return "entra-oauth"
    raise SelfhostConfigError(
        [f"{AUTH_MODE_ENV} must be unset, 'legacy' or '{AUTH_MODE_ENTRA}'"]
    )


def _is_absolute(value: str) -> bool:
    # A POSIX-style path such as /data counts as absolute on every platform:
    # the container image is Linux, and tests run on Windows too.
    return PurePosixPath(value).is_absolute() or Path(value).is_absolute()


def _parse_public_base_url(raw: str, problems: list[str]) -> tuple[str, str] | None:
    name = "PUBLIC_BASE_URL"
    if not raw:
        problems.append(f"{name} is required (the public https origin, e.g. https://canvas.example.com)")
        return None
    if any(ch.isspace() for ch in raw) or "?" in raw or "#" in raw:
        problems.append(f"{name} must not contain whitespace, a query or a fragment")
        return None
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        problems.append(f"{name} is not a valid URL")
        return None
    if parts.scheme != "https":
        problems.append(f"{name} must use https")
        return None
    host = parts.hostname
    if not host:
        problems.append(f"{name} must include a host name")
        return None
    if "@" in parts.netloc:
        problems.append(f"{name} must not contain user information")
        return None
    if parts.path not in ("", "/"):
        problems.append(f"{name} must be an origin only, with no path")
        return None
    host_part = f"[{host}]" if ":" in host else host
    netloc = host_part if port is None else f"{host_part}:{port}"
    return f"https://{netloc}", host


def _guid(name: str, raw: str, problems: list[str]) -> str:
    if not raw:
        problems.append(f"{name} is required (a GUID)")
        return ""
    if not _GUID_RE.match(raw):
        problems.append(f"{name} must be a GUID such as 00000000-0000-0000-0000-000000000000")
        return ""
    return raw.lower()


def _parse_redirect_uris(raw: str, problems: list[str]) -> tuple[str, ...]:
    name = "OAUTH_ALLOWED_REDIRECT_URIS"
    if not raw:
        return DEFAULT_REDIRECT_URIS
    entries: list[str] = []
    bad = False
    for item in raw.split(","):
        entry = item.strip()
        if not entry:
            continue
        if not _redirect_entry_ok(entry):
            bad = True
            continue
        if entry not in entries:
            entries.append(entry)
    if bad:
        problems.append(
            f"{name} entries must be https on a non-loopback host, or http on "
            "localhost or 127.0.0.1 without a port; no wildcards, user "
            "information, query or fragment"
        )
    elif not entries:
        problems.append(f"{name} is set but lists no redirect URI")
    return tuple(entries)


def _redirect_entry_ok(entry: str) -> bool:
    if "*" in entry or any(ch.isspace() for ch in entry) or "?" in entry or "#" in entry:
        return False
    try:
        parts = urlsplit(entry)
        port = parts.port
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    if not host or "@" in parts.netloc or not parts.path.startswith("/"):
        return False
    if parts.scheme == "https":
        return host not in _LOOPBACK_HOSTS and not host.endswith(".localhost")
    if parts.scheme == "http":
        return host in _LOOPBACK_HTTP_HOSTS and port is None
    return False


def _decode_session_secret(raw: str) -> bytes | None:
    if not raw or not _BASE64_RE.match(raw):
        return None
    text = raw.rstrip("=").replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def _parse_int(name: str, raw: str, default: int, low: int, high: int, problems: list[str]) -> int:
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        problems.append(f"{name} must be an integer from {low} to {high}")
        return default
    if not low <= value <= high:
        problems.append(f"{name} must be an integer from {low} to {high}")
        return default
    return value


def load_selfhost_settings(env: Mapping[str, str] | None = None) -> SelfhostSettings:
    """Parse and validate every variable of the mode, reporting all problems at once."""
    source = os.environ if env is None else env

    def get(name: str) -> str:
        return (source.get(name) or "").strip()

    problems: list[str] = []

    base = _parse_public_base_url(get("PUBLIC_BASE_URL"), problems)

    tenant_raw = get("ENTRA_TENANT_ID")
    if tenant_raw.lower() in _RESERVED_TENANTS:
        problems.append(
            "ENTRA_TENANT_ID must be the directory (tenant) GUID, not "
            "common, organizations or consumers"
        )
        tenant_id = ""
    else:
        tenant_id = _guid("ENTRA_TENANT_ID", tenant_raw, problems)
    client_id = _guid("ENTRA_CLIENT_ID", get("ENTRA_CLIENT_ID"), problems)

    client_secret = get("ENTRA_CLIENT_SECRET")
    if not client_secret:
        problems.append("ENTRA_CLIENT_SECRET is required")
    elif len(client_secret) < MIN_CLIENT_SECRET_CHARS:
        problems.append(f"ENTRA_CLIENT_SECRET must be at least {MIN_CLIENT_SECRET_CHARS} characters")

    api_scope = get("ENTRA_API_SCOPE") or DEFAULT_API_SCOPE
    if not _SCOPE_RE.match(api_scope):
        problems.append("ENTRA_API_SCOPE must match [A-Za-z0-9._-] and be 1 to 64 characters")
    elif api_scope.lower() in _OIDC_SCOPES:
        problems.append(
            "ENTRA_API_SCOPE must be the custom scope exposed by the app, "
            "not an OpenID Connect scope"
        )

    required_role = get("ENTRA_REQUIRED_ROLE") or DEFAULT_REQUIRED_ROLE
    owner_role = get("ENTRA_OWNER_ROLE") or DEFAULT_OWNER_ROLE
    if not _ROLE_RE.match(required_role):
        problems.append("ENTRA_REQUIRED_ROLE must match [A-Za-z0-9._-] and be 1 to 120 characters")
    if not _ROLE_RE.match(owner_role):
        problems.append("ENTRA_OWNER_ROLE must match [A-Za-z0-9._-] and be 1 to 120 characters")
    if required_role == owner_role:
        problems.append("ENTRA_REQUIRED_ROLE and ENTRA_OWNER_ROLE must be different roles")

    signing_key = get("OAUTH_JWT_SIGNING_KEY")
    if not signing_key:
        problems.append("OAUTH_JWT_SIGNING_KEY is required (generate one with: openssl rand -base64 48)")
    elif len(signing_key) < MIN_SIGNING_KEY_CHARS:
        problems.append(f"OAUTH_JWT_SIGNING_KEY must be at least {MIN_SIGNING_KEY_CHARS} characters")

    redirect_uris = _parse_redirect_uris(get("OAUTH_ALLOWED_REDIRECT_URIS"), problems)

    session_raw = get("ACCOUNT_SESSION_SECRET")
    session_secret = b""
    if not session_raw:
        problems.append("ACCOUNT_SESSION_SECRET is required (base64 of at least 32 random bytes)")
    else:
        decoded = _decode_session_secret(session_raw)
        if decoded is None:
            problems.append("ACCOUNT_SESSION_SECRET must be valid base64")
        elif len(decoded) < MIN_SESSION_SECRET_BYTES:
            problems.append(
                f"ACCOUNT_SESSION_SECRET must decode to at least {MIN_SESSION_SECRET_BYTES} bytes"
            )
        else:
            session_secret = decoded

    ttl = _parse_int(
        "ACCOUNT_SESSION_TTL_SECONDS", get("ACCOUNT_SESSION_TTL_SECONDS"),
        DEFAULT_SESSION_TTL_SECONDS, MIN_SESSION_TTL_SECONDS, MAX_SESSION_TTL_SECONDS, problems,
    )

    token_keys = get("CANVAS_TOKEN_KEYS")
    if not token_keys:
        problems.append("CANVAS_TOKEN_KEYS is required (kid:base64key[,kid2:base64key])")

    data_dir_raw = get("SELFHOST_DATA_DIR") or DEFAULT_DATA_DIR
    if not _is_absolute(data_dir_raw):
        problems.append("SELFHOST_DATA_DIR must be an absolute path")

    home_raw = get("FASTMCP_HOME")
    if not home_raw:
        problems.append(
            "FASTMCP_HOME is required and must be set explicitly, so OAuth state "
            "is not silently ephemeral"
        )
    elif not _is_absolute(home_raw):
        problems.append("FASTMCP_HOME must be an absolute path")

    if problems or base is None:
        raise SelfhostConfigError(problems)

    return SelfhostSettings(
        public_base_url=base[0],
        public_host=base[1],
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        api_scope=api_scope,
        required_role=required_role,
        owner_role=owner_role,
        oauth_jwt_signing_key=signing_key,
        allowed_client_redirect_uris=redirect_uris,
        account_session_secret=session_secret,
        account_session_ttl_seconds=ttl,
        canvas_token_keys_raw=token_keys,
        data_dir=Path(data_dir_raw),
        fastmcp_home=Path(home_raw),
    )
