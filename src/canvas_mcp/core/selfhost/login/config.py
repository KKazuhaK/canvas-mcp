"""Which sign-in providers the server offers, parsed from the environment.

Standard library only: ``settings`` imports this module in every mode, so it must not need
joserfc, httpx or the data layer. Every problem is collected (never raised one at a time),
messages name variables and never echo values, and client secrets are ``repr=False``.

``SELFHOST_LOGIN_PROVIDERS`` is a comma-separated list in button order::

    entra                    Microsoft Entra ID (the first release; the default)
    google                   Google (OpenID Connect)             GOOGLE_CLIENT_ID / _SECRET
    github                   GitHub (OAuth 2.0)                  GITHUB_CLIENT_ID / _SECRET
    oidc:<slug>              any OpenID Connect provider         OIDC_<SLUG>_ISSUER / ...

The built-in authorization server supports each configured sign-in provider.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..accounts import OIDC_SLUG_RE, PROVIDER_ENTRA, PROVIDER_GITHUB, PROVIDER_GOOGLE

LOGIN_PROVIDERS_ENV = "SELFHOST_LOGIN_PROVIDERS"
GOOGLE_CLIENT_ID_ENV = "GOOGLE_CLIENT_ID"
GOOGLE_CLIENT_SECRET_ENV = "GOOGLE_CLIENT_SECRET"
GITHUB_CLIENT_ID_ENV = "GITHUB_CLIENT_ID"
GITHUB_CLIENT_SECRET_ENV = "GITHUB_CLIENT_SECRET"

#: Variables that belong to Entra and are refused when ``entra`` is not listed.
ENTRA_ONLY_ENV = (
    "ENTRA_TENANT_ID",
    "ENTRA_CLIENT_ID",
    "ENTRA_CLIENT_SECRET",
    "ENTRA_REQUIRED_ROLE",
    "ENTRA_OWNER_ROLE",
)

MAX_PROVIDERS = 8
MIN_CLIENT_SECRET_CHARS = 16
MAX_ISSUER_CHARS = 255
MAX_SCOPES = 10
DEFAULT_OIDC_SCOPES = ("openid", "email", "profile")
TOKEN_AUTH_METHODS = ("client_secret_basic", "client_secret_post")

_GOOGLE_CLIENT_ID_RE = re.compile(
    r"^[0-9A-Za-z-]{1,200}\.apps\.googleusercontent\.com$"
)
_GITHUB_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_OIDC_VAR_RE = re.compile(
    r"^OIDC_[A-Z0-9_]+_(ISSUER|CLIENT_ID|CLIENT_SECRET|SCOPES|TOKEN_AUTH_METHOD|USERINFO)$"
)
_OIDC_SUFFIXES = (
    "ISSUER",
    "CLIENT_ID",
    "CLIENT_SECRET",
    "SCOPES",
    "TOKEN_AUTH_METHOD",
    "USERINFO",
)
# RFC 6749 section 3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
_SCOPE_TOKEN_RE = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]{1,128}$")
_VISIBLE_ASCII_RE = re.compile(r"^[\x21-\x7e]+$")

logger = logging.getLogger("canvas_mcp.selfhost.account")

_TRUE_WORDS = frozenset({"true", "1", "yes"})
_FALSE_WORDS = frozenset({"", "false", "0", "no"})


@dataclass(frozen=True)
class GoogleConfig:
    client_id: str
    client_secret: str = field(repr=False)


@dataclass(frozen=True)
class GitHubConfig:
    client_id: str
    client_secret: str = field(repr=False)


@dataclass(frozen=True)
class OidcConfig:
    """One generic OpenID Connect provider (``oidc:<slug>``)."""

    slug: str
    #: The exact https issuer the provider publishes (kept verbatim, trailing slash included).
    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    scopes: tuple[str, ...] = DEFAULT_OIDC_SCOPES
    #: ``client_secret_basic`` or ``client_secret_post``; ``None`` follows the discovery document.
    token_auth_method: str | None = None
    #: Call the userinfo endpoint after the token exchange (its ``sub`` must match).
    userinfo: bool = False

    @property
    def provider_id(self) -> str:
        return f"oidc:{self.slug}"

    @property
    def label(self) -> str:
        return self.slug


@dataclass(frozen=True)
class LoginProvidersConfig:
    """The configured providers, in button order. The default is Entra alone (today's behaviour)."""

    order: tuple[str, ...] = (PROVIDER_ENTRA,)
    google: GoogleConfig | None = None
    github: GitHubConfig | None = None
    oidc: tuple[OidcConfig, ...] = ()

    @property
    def entra_enabled(self) -> bool:
        return PROVIDER_ENTRA in self.order

    @property
    def ids(self) -> frozenset[str]:
        return frozenset(self.order)

    @property
    def non_entra(self) -> tuple[str, ...]:
        return tuple(p for p in self.order if p != PROVIDER_ENTRA)

    @property
    def public(self) -> bool:
        """True when anyone with an account at an outside provider can reach the sign-in."""
        return bool(self.non_entra)

    @property
    def linking_enabled(self) -> bool:
        """Accounts can link identities only when there is more than one way to sign in."""
        return len(self.order) >= 2

    @property
    def single(self) -> bool:
        return len(self.order) == 1

    def oidc_by_id(self) -> dict[str, OidcConfig]:
        return {cfg.provider_id: cfg for cfg in self.oidc}

    def issuers(self) -> dict[str, str]:
        """``oidc:<slug>`` -> the configured issuer (what the bootstrap owner needs)."""
        return {cfg.provider_id: cfg.issuer for cfg in self.oidc}


@dataclass(frozen=True)
class ProviderSettingsInput:
    """Explicit protocol input for the removable environment import adapter."""

    login: LoginProvidersConfig
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = field(default="", repr=False)
    required_role: str = "Canvas.User"
    owner_role: str = "Canvas.Owner"
    problems: tuple[str, ...] = ()


def env_prefix(slug: str) -> str:
    """``OIDC_<SLUG>_``: the variable prefix of a generic provider (``-`` becomes ``_``)."""
    return "OIDC_" + slug.upper().replace("-", "_") + "_"


# -- hosts an outbound provider URL may never name -----------------------------------------


_LEGACY_IPV4_RE = re.compile(r"(?:0x[0-9a-f]*|[0-9]+)(?:\.(?:0x[0-9a-f]*|[0-9]+)){0,3}")


def blocked_host(host: str) -> bool:
    """True for a host the server must not call: ``localhost``, ``*.localhost`` and IP literals
    that are loopback, link-local, unspecified or multicast (IPv4-mapped IPv6 included), and every
    host spelled as a non-canonical IPv4 number (``127.1``, ``2130706433``, ``0x7f000001``)."""
    name = host.strip().strip("[]").lower().rstrip(".")
    if not name or name == "localhost" or name.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        # Not a canonical address. The C resolver of the production image still reads the old
        # spellings (127.1, 2130706433, 0x7f000001, 0177.0.0.1) as IPv4 addresses, so a host made
        # only of such numbers is refused whatever it points at; a real name is never one.
        return _LEGACY_IPV4_RE.fullmatch(name) is not None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return (
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
    )


def _issuer_problem(raw: str) -> bool:
    """True when ``raw`` is not an acceptable issuer URL."""
    if (
        not raw
        or len(raw) > MAX_ISSUER_CHARS
        or any(ch.isspace() for ch in raw)
        or not raw.isascii()
        or "?" in raw
        or "#" in raw
    ):
        return True
    try:
        parts = urlsplit(raw)
        parts.port  # noqa: B018 - raises ValueError for a bad port
    except ValueError:
        return True
    host = parts.hostname
    return (
        parts.scheme != "https"
        or not host
        or "@" in parts.netloc
        or blocked_host(host)
        or parts.query != ""
        or parts.fragment != ""
    )


# -- parsing -------------------------------------------------------------------------------


def parse_login_providers(
    env: Mapping[str, str],
    problems: list[str],
) -> LoginProvidersConfig:
    """Parse ``SELFHOST_LOGIN_PROVIDERS`` and the per-provider variables.

    Unset or empty gives Entra alone. Problems are appended to ``problems``; the result is
    still a usable object (it holds what parsed), because the caller raises once at the end.
    """

    def get(name: str) -> str:
        return (env.get(name) or "").strip()

    raw = get(LOGIN_PROVIDERS_ENV)
    order: list[str] = []
    if not raw:
        order = [PROVIDER_ENTRA]
    else:
        entries = [part.strip().lower() for part in raw.split(",")]
        entries = [part for part in entries if part]
        if not entries:
            problems.append(f"{LOGIN_PROVIDERS_ENV} is set but lists no provider")
        if len(entries) > MAX_PROVIDERS:
            problems.append(
                f"{LOGIN_PROVIDERS_ENV} lists more than {MAX_PROVIDERS} providers"
            )
        for index, entry in enumerate(entries[: MAX_PROVIDERS + 1], start=1):
            if entry in (PROVIDER_ENTRA, PROVIDER_GOOGLE, PROVIDER_GITHUB):
                provider_id = entry
            elif entry.startswith("oidc:"):
                if not OIDC_SLUG_RE.match(entry[5:]):
                    problems.append(
                        f"{LOGIN_PROVIDERS_ENV} entry {index} has an oidc slug outside a-z, 0-9 "
                        "and '-' (1 to 32 characters, starting with a letter)"
                    )
                    continue
                provider_id = entry
            else:
                problems.append(
                    f"{LOGIN_PROVIDERS_ENV} entry {index} is not entra, google, github or "
                    "oidc:<slug>"
                )
                continue
            if provider_id in order:
                problems.append(f"{LOGIN_PROVIDERS_ENV} lists a provider twice")
                continue
            order.append(provider_id)

    if PROVIDER_ENTRA not in order:
        for name in ENTRA_ONLY_ENV:
            if get(name):
                problems.append(
                    f"{name} is set but {LOGIN_PROVIDERS_ENV} does not list entra"
                )

    # A deployment that never set SELFHOST_LOGIN_PROVIDERS (every one from before the variable
    # existed) keeps starting whatever else its environment holds, such as a shared env file with
    # provider variables for another service: those are ignored (and named in the log). Once the
    # operator lists providers, a variable for one that is not listed is a mistake and is refused.
    strict = bool(raw)
    google = _parse_google(get, PROVIDER_GOOGLE in order, problems, strict)
    github = _parse_github(get, PROVIDER_GITHUB in order, problems, strict)
    oidc = _parse_oidc(
        env, get, [p[5:] for p in order if p.startswith("oidc:")], problems, strict
    )
    return LoginProvidersConfig(
        order=tuple(order), google=google, github=github, oidc=oidc
    )


def _secret(name: str, value: str, problems: list[str]) -> str:
    if not value:
        problems.append(f"{name} is required")
        return ""
    if len(value) < MIN_CLIENT_SECRET_CHARS:
        problems.append(f"{name} must be at least {MIN_CLIENT_SECRET_CHARS} characters")
        return ""
    return value


def _unlisted(name: str, provider: str, problems: list[str], strict: bool) -> None:
    if strict:
        problems.append(
            f"{name} is set but {LOGIN_PROVIDERS_ENV} does not list {provider}"
        )
    else:
        logger.warning(
            "%s is set but %s is unset: it is ignored", name, LOGIN_PROVIDERS_ENV
        )


def _parse_google(
    get: Callable[[str], str], listed: bool, problems: list[str], strict: bool = True
) -> GoogleConfig | None:
    client_id = get(GOOGLE_CLIENT_ID_ENV)
    client_secret = get(GOOGLE_CLIENT_SECRET_ENV)
    if not listed:
        for name, value in (
            (GOOGLE_CLIENT_ID_ENV, client_id),
            (GOOGLE_CLIENT_SECRET_ENV, client_secret),
        ):
            if value:
                _unlisted(name, "google", problems, strict)
        return None
    ok_id = ""
    if not client_id:
        problems.append(f"{GOOGLE_CLIENT_ID_ENV} is required")
    elif not _GOOGLE_CLIENT_ID_RE.match(client_id):
        problems.append(
            f"{GOOGLE_CLIENT_ID_ENV} must be the client id of a Google Cloud web OAuth client "
            "(it ends with .apps.googleusercontent.com)"
        )
    else:
        ok_id = client_id
    secret = _secret(GOOGLE_CLIENT_SECRET_ENV, client_secret, problems)
    if not ok_id or not secret:
        return None
    return GoogleConfig(client_id=ok_id, client_secret=secret)


def _parse_github(
    get: Callable[[str], str], listed: bool, problems: list[str], strict: bool = True
) -> GitHubConfig | None:
    client_id = get(GITHUB_CLIENT_ID_ENV)
    client_secret = get(GITHUB_CLIENT_SECRET_ENV)
    if not listed:
        # Only these two exact names: other GITHUB_* variables (CI sets several) are ignored.
        for name, value in (
            (GITHUB_CLIENT_ID_ENV, client_id),
            (GITHUB_CLIENT_SECRET_ENV, client_secret),
        ):
            if value:
                _unlisted(name, "github", problems, strict)
        return None
    ok_id = ""
    if not client_id:
        problems.append(f"{GITHUB_CLIENT_ID_ENV} is required")
    elif not _GITHUB_CLIENT_ID_RE.match(client_id):
        problems.append(
            f"{GITHUB_CLIENT_ID_ENV} must be the client id of a GitHub OAuth App "
            "(8 to 64 letters, digits, '.', '_' or '-')"
        )
    else:
        ok_id = client_id
    secret = _secret(GITHUB_CLIENT_SECRET_ENV, client_secret, problems)
    if not ok_id or not secret:
        return None
    return GitHubConfig(client_id=ok_id, client_secret=secret)


def _parse_oidc(
    env: Mapping[str, str],
    get: Callable[[str], str],
    slugs: list[str],
    problems: list[str],
    strict: bool = True,
) -> tuple[OidcConfig, ...]:
    # A variable of the OIDC_*_ISSUER family that belongs to no listed slug is refused, by name.
    known = {env_prefix(slug) + suffix for slug in slugs for suffix in _OIDC_SUFFIXES}
    for name in sorted(env):
        if (
            _OIDC_VAR_RE.match(name)
            and name not in known
            and (env.get(name) or "").strip()
        ):
            if strict:
                problems.append(
                    f"{name} is set but {LOGIN_PROVIDERS_ENV} does not list its provider"
                )
            else:
                logger.warning(
                    "%s is set but %s is unset: it is ignored",
                    name,
                    LOGIN_PROVIDERS_ENV,
                )

    parsed: list[OidcConfig] = []
    for slug in slugs:
        prefix = env_prefix(slug)
        count = len(problems)

        def var(suffix: str, _prefix: str = prefix) -> str:
            return get(_prefix + suffix)

        issuer = var("ISSUER")
        if not issuer:
            problems.append(f"{prefix}ISSUER is required")
        elif _issuer_problem(issuer):
            problems.append(
                f"{prefix}ISSUER must be the exact https issuer the provider publishes "
                "(no query, fragment or user information)"
            )
        client_id = var("CLIENT_ID")
        if not client_id:
            problems.append(f"{prefix}CLIENT_ID is required")
        elif len(client_id) > 255 or not _VISIBLE_ASCII_RE.match(client_id):
            problems.append(
                f"{prefix}CLIENT_ID must be 1 to 255 visible ASCII characters"
            )
        secret = _secret(f"{prefix}CLIENT_SECRET", var("CLIENT_SECRET"), problems)

        scopes: tuple[str, ...] = DEFAULT_OIDC_SCOPES
        scopes_raw = var("SCOPES")
        if scopes_raw:
            tokens = scopes_raw.split()
            if (
                "openid" not in tokens
                or len(tokens) > MAX_SCOPES
                or len(set(tokens)) != len(tokens)
                or not all(_SCOPE_TOKEN_RE.match(t) for t in tokens)
            ):
                problems.append(
                    f"{prefix}SCOPES must be space-separated scopes that include openid "
                    f"(at most {MAX_SCOPES})"
                )
            else:
                scopes = tuple(tokens)

        method: str | None = None
        method_raw = var("TOKEN_AUTH_METHOD").lower()
        if method_raw:
            if method_raw in TOKEN_AUTH_METHODS:
                method = method_raw
            else:
                problems.append(
                    f"{prefix}TOKEN_AUTH_METHOD must be client_secret_basic or client_secret_post"
                )

        userinfo = False
        userinfo_raw = var("USERINFO").lower()
        if userinfo_raw in _TRUE_WORDS:
            userinfo = True
        elif userinfo_raw not in _FALSE_WORDS:
            problems.append(f"{prefix}USERINFO must be true or false")

        if len(problems) == count:
            parsed.append(
                OidcConfig(
                    slug=slug,
                    issuer=issuer,
                    client_id=client_id,
                    client_secret=secret,
                    scopes=scopes,
                    token_auth_method=method,
                    userinfo=userinfo,
                )
            )
    return tuple(parsed)
