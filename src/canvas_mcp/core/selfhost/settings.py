"""Infrastructure environment contract of the self-hosted server.

Every variable is parsed here and every problem is collected, so one failed
start shows the operator everything that needs fixing. Messages name the
variable and never include its value: several of them are secrets. Login
credentials come from database snapshots; an explicit import adapter supplies
old provider input without making the environment a runtime credential layer.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import ClassVar, Literal
from urllib.parse import urlsplit

from ..tool_policy import TOOL_EFFECTS
from .accounts import AccessPolicy, default_policy, parse_access_settings
from .db.url import (
    ALLOW_OUTSIDE_ENV,
    DATABASE_URL_ENV,
    DatabaseTarget,
    default_sqlite_path,
    parse_database_url,
    sqlite_target,
)
from .login.config import LoginProvidersConfig, ProviderSettingsInput
from .profile import PILOT_DISABLED_TOOLS, read_profile
from .runtime_secrets import RuntimeSecretsError, with_saved_secrets

AUTH_MODE_ENV = "MCP_AUTH_MODE"
AUTH_MODE_SELFHOST = "selfhost"
AUTH_MODE_LEGACY = "legacy"

COURSE_STATE_ENV = "SELFHOST_COURSE_STATE"
COURSE_STATE_REQUEST_LOCAL = "request_local"
COURSE_STATE_PER_PRINCIPAL = "per_principal"
COURSE_STATES = (COURSE_STATE_REQUEST_LOCAL, COURSE_STATE_PER_PRINCIPAL)
DEFAULT_COURSE_STATE = COURSE_STATE_REQUEST_LOCAL

DISABLED_TOOLS_ENV = "SELFHOST_DISABLED_TOOLS"

DEFAULT_MCP_SCOPE = "Canvas.Access"
DEFAULT_REQUIRED_ROLE = "Canvas.User"
DEFAULT_OWNER_ROLE = "Canvas.Owner"
DEFAULT_REDIRECT_URIS: tuple[str, ...] = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "http://localhost/callback",
    "http://127.0.0.1/callback",
)
DEFAULT_SESSION_TTL_SECONDS = 7 * 86400
DEFAULT_DATA_DIR = "/data"

AUTO_MIGRATE_ENV = "DATABASE_AUTO_MIGRATE"
STATE_BACKEND_ENV = "SELFHOST_STATE_BACKEND"
#: Where short-lived state (rate limits, one-time login state) lives. Only the
#: in-process backend exists; ``redis`` is reserved for a later multi-instance mode.
STATE_BACKEND_MEMORY = "memory"
STATE_BACKEND_REDIS = "redis"

# Old settings are refused by presence, including an explicitly empty value.
REMOVED_SETTINGS = {
    "SELFHOST_AUTH_MODE": "removed in v1: the built-in authorization server is always used; delete this variable",
    "OAUTH_JWT_SIGNING_KEY": "removed in v1: JWT keys derive from CANVAS_TOKEN_KEYS; delete this variable",
    "GRANT_STATUS_CACHE_S": "removed in v1: authorization status is read on each request; delete this variable",
    "CANVAS_FEATURED_SCHOOLS": "removed in v1: manage featured schools in account administration",
    "CANVAS_SCHOOL_SEARCH": "removed in v1: manage directory search in account administration",
    "CANVAS_API_URL": "removed in v1: each account selects its own Canvas school; delete this variable",
    "ACCOUNT_UI": "removed in v1: the React UI is the only account UI; delete this variable",
    "ENTRA_API_SCOPE": "renamed in v1: use MCP_SCOPE (same format, default Canvas.Access)",
}

DEFAULT_ACCESS_TOKEN_TTL = 3600
DEFAULT_REFRESH_ABSOLUTE_TTL = 30 * 86400
DEFAULT_REFRESH_REUSE_GRACE_S = 30
DEFAULT_CIMD_FETCH_TIMEOUT_S = 3
DEFAULT_CIMD_STALE_MAX = 7 * 86400
DEFAULT_MAX_UPSTREAM_AUTH_AGE = 14 * 86400

ACCOUNT_WEB_DIST_ENV = "ACCOUNT_WEB_DIST"
#: Where the container image keeps the built account UI.
DEFAULT_ACCOUNT_WEB_DIST = "/app/web-dist"

_SCOPE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
_OIDC_SCOPES = frozenset({"openid", "profile", "email", "offline_access"})
_LOOPBACK_HTTP_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

MIN_SESSION_SECRET_BYTES = 32
MIN_SESSION_TTL_SECONDS = 60
MAX_SESSION_TTL_SECONDS = 30 * 86400


class SelfhostConfigError(Exception):
    """The self-hosted configuration is unusable; ``problems`` lists every cause."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


@dataclass(frozen=True)
class AuthzSettings:
    """Tunables of the built-in authorization server.

    All durations are seconds. Invalid values refuse startup.
    """

    #: Lifetime of an access token (a JWT), 5 minutes to 24 hours.
    access_token_ttl: int = DEFAULT_ACCESS_TOKEN_TTL
    #: Absolute lifetime of a grant (a refresh family): rotation never extends it.
    refresh_absolute_ttl: int = DEFAULT_REFRESH_ABSOLUTE_TTL
    #: A replay of a just-used code or refresh token inside this window is a benign
    #: duplicate, not theft; 0 means strict.
    refresh_reuse_grace_s: int = DEFAULT_REFRESH_REUSE_GRACE_S
    #: Resolve client ids that are URLs (Client ID Metadata Documents).
    cimd_enabled: bool = True
    cimd_fetch_timeout_s: int = DEFAULT_CIMD_FETCH_TIMEOUT_S
    #: How old a stored client metadata document may be and still serve /token.
    cimd_stale_max: int = DEFAULT_CIMD_STALE_MAX
    #: How long ago the user must have signed in at /account for a grant to continue.
    max_upstream_auth_age: int = DEFAULT_MAX_UPSTREAM_AUTH_AGE


@dataclass(frozen=True)
class SelfhostSettings:
    """Validated configuration of the ``selfhost`` mode."""

    public_base_url: str
    public_host: str
    tenant_id: str
    client_id: str
    client_secret: str = field(repr=False)
    api_scope: str
    required_role: str
    owner_role: str
    allowed_client_redirect_uris: tuple[str, ...]
    account_session_secret: bytes = field(repr=False)
    account_session_ttl_seconds: int
    canvas_token_keys_raw: str = field(repr=False)
    data_dir: Path
    # Whether course metadata, policy decisions, pseudonyms and discussion hints
    # live only inside one request (the default; stricter than upstream, which keeps
    # policies, pseudonyms and hints in process-wide maps shared by all callers)
    # or are cached per principal across requests (explicit opt-in).
    course_state: Literal["request_local", "per_principal"] = "request_local"
    # Where tokens and access state live: SQLite in the data directory unless
    # DATABASE_URL names PostgreSQL. ``None`` means the SQLite default.
    # (DatabaseTarget keeps the URL, which may hold a password, out of its repr.)
    database: DatabaseTarget | None = None
    auto_migrate: bool = True
    state_backend: Literal["memory"] = "memory"
    # Tools (read or write) the operator removes at startup, sorted and de-duplicated.
    # It can only remove tools: it never registers one and never widens what
    # ``ALLOWED_WRITE_TOOLS`` or a user's own switches allow.
    disabled_tools: tuple[str, ...] = ()
    profile: str = ""
    # Who is admitted and who is an owner (see :mod:`.accounts`). The default is the
    # first release's behaviour: the two Entra app roles, nothing else.
    # ``None`` (a settings object built by hand) means that default.
    access_policy: AccessPolicy = field(default=None)  # type: ignore[assignment]
    account_web_dist: Path = Path(DEFAULT_ACCOUNT_WEB_DIST)
    authz: AuthzSettings = field(default_factory=AuthzSettings)
    # The sign-in providers (``SELFHOST_LOGIN_PROVIDERS``). The default is Entra alone, which
    # is the default. Without
    # Entra, ``tenant_id``, ``client_id`` and ``client_secret`` are empty strings.
    login_providers: LoginProvidersConfig = field(default_factory=LoginProvidersConfig)
    access_source: Mapping[str, str] | None = field(default=None, repr=False)

    mcp_path: ClassVar[str] = "/mcp"

    def __post_init__(self) -> None:
        if self.database is None:
            object.__setattr__(
                self, "database", sqlite_target(default_sqlite_path(self.data_dir))
            )
        if getattr(self, "access_policy", None) is None:
            object.__setattr__(
                self,
                "access_policy",
                default_policy(self.required_role, self.owner_role),
            )

    @property
    def mcp_url(self) -> str:
        return self.public_base_url + self.mcp_path

    @property
    def entra_enabled(self) -> bool:
        return self.login_providers.entra_enabled

    @property
    def account_url(self) -> str:
        return self.public_base_url + "/account"

    @property
    def token_db_path(self) -> Path:
        """The SQLite file of the default layout (also the pre-PostgreSQL location)."""
        return default_sqlite_path(self.data_dir)

    @property
    def database_target(self) -> DatabaseTarget:
        assert self.database is not None
        return self.database


def auth_mode(env: Mapping[str, str] | None = None) -> Literal["legacy", "selfhost"]:
    """The selected mode: unset, empty or ``legacy`` keep today's behaviour.

    Anything but the exact opt-in value ``selfhost`` is refused rather than
    guessed at, so a typo can never silently select the wrong authentication.
    """
    source = os.environ if env is None else env
    value = (source.get(AUTH_MODE_ENV) or "").strip()
    if value in ("", AUTH_MODE_LEGACY):
        return "legacy"
    if value == AUTH_MODE_SELFHOST:
        return "selfhost"
    if value == "entra-oauth":
        raise SelfhostConfigError(
            ["MCP_AUTH_MODE renamed in v1: use MCP_AUTH_MODE=selfhost"]
        )
    raise SelfhostConfigError(
        [f"{AUTH_MODE_ENV} must be unset, 'legacy' or '{AUTH_MODE_SELFHOST}'"]
    )


def _is_absolute(value: str) -> bool:
    # A POSIX-style path such as /data counts as absolute on every platform:
    # the container image is Linux, and tests run on Windows too.
    return PurePosixPath(value).is_absolute() or Path(value).is_absolute()


def _parse_public_base_url(raw: str, problems: list[str]) -> tuple[str, str] | None:
    name = "PUBLIC_BASE_URL"
    if not raw:
        problems.append(
            f"{name} is required (the public https origin, e.g. https://canvas.example.com)"
        )
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
            "localhost, 127.0.0.1 or [::1] without a port; no wildcards, user "
            "information, query or fragment"
        )
    elif not entries:
        problems.append(f"{name} is set but lists no redirect URI")
    return tuple(entries)


def _redirect_entry_ok(entry: str) -> bool:
    if (
        "*" in entry
        or any(ch.isspace() for ch in entry)
        or "?" in entry
        or "#" in entry
    ):
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


def _parse_int(
    name: str, raw: str, default: int, low: int, high: int, problems: list[str]
) -> int:
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


_DURATION_RE = re.compile(r"^([0-9]{1,9})([smhd]?)$")
_DURATION_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def format_duration(seconds: int) -> str:
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size and seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def _parse_duration(
    name: str, raw: str, default: int, low: int, high: int, problems: list[str]
) -> int | None:
    """A duration such as ``3600``, ``30m``, ``12h`` or ``30d``, in seconds.

    Returns ``None`` (after recording a problem) for anything malformed or out of
    range; the value is never echoed. An unset variable gives ``default``.
    """
    if not raw:
        return default
    match = _DURATION_RE.fullmatch(raw)
    seconds = int(match.group(1)) * _DURATION_UNITS[match.group(2)] if match else -1
    if not low <= seconds <= high:
        problems.append(
            f"{name} must be a duration such as 3600, 30m, 12h or 30d, from "
            f"{format_duration(low)} to {format_duration(high)}"
        )
        return None
    return seconds


def _parse_bool_default(
    name: str, raw: str, default: bool, problems: list[str]
) -> bool:
    """A true/false switch whose unset value is ``default`` (``_parse_bool`` is False when unset)."""
    word = raw.strip().lower()
    if not word:
        return default
    if word in _TRUE_WORDS:
        return True
    if word in _FALSE_WORDS:
        return False
    problems.append(f"{name} must be true or false")
    return default


def _parse_authz_settings(
    get: Callable[[str], str], problems: list[str]
) -> AuthzSettings:
    """The tunables of the built-in authorization server."""
    defaults = AuthzSettings()
    access_ttl = _parse_duration(
        "ACCESS_TOKEN_TTL",
        get("ACCESS_TOKEN_TTL"),
        defaults.access_token_ttl,
        300,
        24 * 3600,
        problems,
    )
    refresh_ttl = _parse_duration(
        "REFRESH_ABSOLUTE_TTL",
        get("REFRESH_ABSOLUTE_TTL"),
        defaults.refresh_absolute_ttl,
        3600,
        90 * 86400,
        problems,
    )
    if access_ttl is not None and refresh_ttl is not None and refresh_ttl <= access_ttl:
        problems.append("REFRESH_ABSOLUTE_TTL must be longer than ACCESS_TOKEN_TTL")
    stale_max = _parse_duration(
        "CIMD_STALE_MAX",
        get("CIMD_STALE_MAX"),
        defaults.cimd_stale_max,
        0,
        30 * 86400,
        problems,
    )
    upstream_age = _parse_duration(
        "MAX_UPSTREAM_AUTH_AGE",
        get("MAX_UPSTREAM_AUTH_AGE"),
        defaults.max_upstream_auth_age,
        3600,
        90 * 86400,
        problems,
    )
    return AuthzSettings(
        access_token_ttl=access_ttl
        if access_ttl is not None
        else defaults.access_token_ttl,
        refresh_absolute_ttl=(
            refresh_ttl if refresh_ttl is not None else defaults.refresh_absolute_ttl
        ),
        refresh_reuse_grace_s=_parse_int(
            "REFRESH_REUSE_GRACE_S",
            get("REFRESH_REUSE_GRACE_S"),
            defaults.refresh_reuse_grace_s,
            0,
            120,
            problems,
        ),
        cimd_enabled=_parse_bool_default(
            "CIMD_ENABLED", get("CIMD_ENABLED"), True, problems
        ),
        cimd_fetch_timeout_s=_parse_int(
            "CIMD_FETCH_TIMEOUT_S",
            get("CIMD_FETCH_TIMEOUT_S"),
            defaults.cimd_fetch_timeout_s,
            1,
            5,
            problems,
        ),
        cimd_stale_max=stale_max if stale_max is not None else defaults.cimd_stale_max,
        max_upstream_auth_age=(
            upstream_age if upstream_age is not None else defaults.max_upstream_auth_age
        ),
    )


_TRUE_WORDS = frozenset({"true", "1", "yes"})
_FALSE_WORDS = frozenset({"", "false", "0", "no"})


def _parse_bool(name: str, raw: str, problems: list[str]) -> bool:
    word = raw.strip().lower()
    if word in _TRUE_WORDS:
        return True
    if word not in _FALSE_WORDS:
        problems.append(f"{name} must be true or false")
    return False


def _parse_course_state(
    raw: str, problems: list[str]
) -> Literal["request_local", "per_principal"]:
    """``request_local`` (the default) or ``per_principal``; anything else is refused."""
    value = raw.strip().lower()
    if not value or value == COURSE_STATE_REQUEST_LOCAL:
        return "request_local"
    if value == COURSE_STATE_PER_PRINCIPAL:
        return "per_principal"
    problems.append(
        f"{COURSE_STATE_ENV} must be '{COURSE_STATE_REQUEST_LOCAL}' (the default) "
        f"or '{COURSE_STATE_PER_PRINCIPAL}'"
    )
    return "request_local"


def _parse_auto_migrate(raw: str, problems: list[str]) -> bool:
    """``DATABASE_AUTO_MIGRATE``: true unless explicitly switched off."""
    word = raw.strip().lower()
    if word == "" or word in _TRUE_WORDS:
        return True
    if word in _FALSE_WORDS:
        return False
    problems.append(f"{AUTO_MIGRATE_ENV} must be true or false")
    return True


def _parse_state_backend(raw: str, problems: list[str]) -> Literal["memory"]:
    word = raw.strip().lower()
    if word in ("", STATE_BACKEND_MEMORY):
        return "memory"
    if word == STATE_BACKEND_REDIS:
        problems.append(
            f"{STATE_BACKEND_ENV}=redis is reserved and not implemented yet; leave it unset "
            "(this server is a single instance)"
        )
    else:
        problems.append(
            f"{STATE_BACKEND_ENV} must be unset or '{STATE_BACKEND_MEMORY}'"
        )
    return "memory"


def _parse_disabled_tools(raw: str, problems: list[str]) -> tuple[str, ...]:
    """Comma-separated tool names to remove; an unknown name is refused.

    Only names are echoed, and only names that look like tool names and are not
    known tools. An entry that is not shaped like a tool name is counted, never
    quoted, so a value pasted into the wrong variable cannot reach the log.
    """
    entries = [part.strip().lower() for part in raw.split(",")]
    entries = [part for part in entries if part]
    unknown: set[str] = set()
    malformed = 0
    for entry in entries:
        if not _TOOL_NAME_RE.match(entry):
            malformed += 1
        elif entry not in TOOL_EFFECTS:
            unknown.add(entry)
    if unknown:
        problems.append(
            f"{DISABLED_TOOLS_ENV} names unknown tools: {', '.join(sorted(unknown))}"
        )
    if malformed:
        problems.append(
            f"{DISABLED_TOOLS_ENV} has {malformed} entries that are not tool names "
            "(use a comma-separated list such as read_course_file_text,list_users)"
        )
    return tuple(sorted(set(entries)))


def load_selfhost_settings(
    env: Mapping[str, str] | None = None,
    *,
    _provider_input: ProviderSettingsInput | None = None,
) -> SelfhostSettings:
    """Parse and validate every variable of the mode, reporting all problems at once."""
    source = os.environ if env is None else env
    problems: list[str] = []
    try:
        source = with_saved_secrets(source)
    except RuntimeSecretsError as exc:
        problems.append(str(exc))

    def get(name: str) -> str:
        return (source.get(name) or "").strip()

    removed = set(REMOVED_SETTINGS) & source.keys()
    removed.update(
        name for name in source if re.fullmatch(r"OIDC_[A-Z0-9_]+_DISPLAY_NAME", name)
    )
    for name in sorted(removed):
        hint = REMOVED_SETTINGS.get(
            name,
            "removed in v1: manage provider display names in account administration",
        )
        problems.append(f"{name}: {hint}")
    # Removed variables must produce one clear problem, rather than being parsed again.
    source = {name: value for name, value in source.items() if name not in removed}

    authz = _parse_authz_settings(get, problems)

    supplied = _provider_input or ProviderSettingsInput(LoginProvidersConfig(order=()))
    problems.extend(supplied.problems)
    login = supplied.login
    tenant_id = supplied.tenant_id
    client_id = supplied.client_id
    client_secret = supplied.client_secret

    # This scope belongs to this authorization server, independently of sign-in providers.
    api_scope = get("MCP_SCOPE") or DEFAULT_MCP_SCOPE
    if not _SCOPE_RE.match(api_scope):
        problems.append("MCP_SCOPE must match [A-Za-z0-9._-] and be 1 to 64 characters")
    elif api_scope.lower() in _OIDC_SCOPES:
        problems.append(
            "MCP_SCOPE must be a custom MCP scope, not an OpenID Connect scope"
        )

    required_role = supplied.required_role
    owner_role = supplied.owner_role

    redirect_uris = _parse_redirect_uris(get("OAUTH_ALLOWED_REDIRECT_URIS"), problems)

    session_raw = get("ACCOUNT_SESSION_SECRET")
    session_secret = b""
    if not session_raw:
        problems.append(
            "ACCOUNT_SESSION_SECRET is required (base64 of at least 32 random bytes)"
        )
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
        "ACCOUNT_SESSION_TTL_SECONDS",
        get("ACCOUNT_SESSION_TTL_SECONDS"),
        DEFAULT_SESSION_TTL_SECONDS,
        MIN_SESSION_TTL_SECONDS,
        MAX_SESSION_TTL_SECONDS,
        problems,
    )

    token_keys = get("CANVAS_TOKEN_KEYS")
    if not token_keys:
        problems.append(
            "CANVAS_TOKEN_KEYS is required (kid:base64key[,kid2:base64key])"
        )

    data_dir_raw = get("SELFHOST_DATA_DIR") or DEFAULT_DATA_DIR
    if not _is_absolute(data_dir_raw):
        problems.append("SELFHOST_DATA_DIR must be an absolute path")

    allow_outside = _parse_bool(ALLOW_OUTSIDE_ENV, get(ALLOW_OUTSIDE_ENV), problems)
    database = parse_database_url(
        get(DATABASE_URL_ENV),
        Path(data_dir_raw),
        allow_external_sqlite=allow_outside,
        problems=problems,
    )
    from .db.errors import StoreUnavailable
    from .site_url import saved_site_url

    base: tuple[str, str] | None = None
    try:
        stored_base = saved_site_url(database) if database is not None else None
        base = _parse_public_base_url(stored_base or get("PUBLIC_BASE_URL"), problems)
    except StoreUnavailable:
        problems.append(
            "the token database cannot be opened or is not a valid database; database-managed site address cannot be loaded"
        )
    except (ValueError, OSError):
        problems.append(
            "database-managed site address cannot be loaded from the token database"
        )
    if base is not None and base[0].endswith(":443"):
        problems.append("PUBLIC_BASE_URL must not include the default port")
    auto_migrate = _parse_auto_migrate(get(AUTO_MIGRATE_ENV), problems)
    state_backend = _parse_state_backend(get(STATE_BACKEND_ENV), problems)
    web_dist_raw = get(ACCOUNT_WEB_DIST_ENV) or DEFAULT_ACCOUNT_WEB_DIST
    if not _is_absolute(web_dist_raw):
        problems.append(f"{ACCOUNT_WEB_DIST_ENV} must be an absolute path")

    course_state = _parse_course_state(get(COURSE_STATE_ENV), problems)
    disabled_tools = _parse_disabled_tools(get(DISABLED_TOOLS_ENV), problems)
    try:
        profile = read_profile(source)
    except ValueError as exc:
        problems.append(str(exc))
        profile = ""
    if profile == "pilot":
        disabled_tools = tuple(sorted(set(disabled_tools) | PILOT_DISABLED_TOOLS))
    access_source = {
        name: value
        for name, value in source.items()
        if name
        in {
            "ACCESS_POLICY",
            "ACCESS_RULES",
            "ACCESS_FALLBACK",
            "OWNER_RULES",
            "ACCESS_OPEN_ACKNOWLEDGE_PUBLIC",
            "SELFHOST_BOOTSTRAP_OWNER",
            "TRUSTED_PROXY_CIDRS",
            "ACCOUNT_LINK_BY_VERIFIED_EMAIL",
        }
    }
    access_policy = (
        parse_access_settings(
            source,
            tenant_id=tenant_id,
            required_role=required_role,
            owner_role=owner_role,
            problems=problems,
            providers=login.ids,
            issuers=login.issuers(),
        )
        if _provider_input is not None
        else default_policy(required_role, owner_role)
    )

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
        allowed_client_redirect_uris=redirect_uris,
        account_session_secret=session_secret,
        account_session_ttl_seconds=ttl,
        canvas_token_keys_raw=token_keys,
        data_dir=Path(data_dir_raw),
        course_state=course_state,
        database=database,
        auto_migrate=auto_migrate,
        state_backend=state_backend,
        disabled_tools=disabled_tools,
        profile=profile,
        access_policy=access_policy,
        account_web_dist=Path(web_dist_raw),
        authz=authz,
        login_providers=login,
        access_source=None if _provider_input is not None else access_source,
    )
