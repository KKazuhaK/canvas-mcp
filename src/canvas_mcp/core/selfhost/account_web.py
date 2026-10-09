"""/account browser pages for the self-hosted multi-user mode.

Each user signs in with Microsoft Entra ID (authorization code + PKCE + nonce)
and enrolls their own Canvas personal access token here. Canvas tokens never go
through chat: they are accepted only from the form on this page, verified
against Canvas, and handed to the encrypted :class:`TokenStore`.

This module does not import any auth-branch module. Who may sign in (tenant,
rules, owner, approval) is decided by the injected identity service
(:class:`~.identity.IdentityService`); a successful sign-in names the user's account
``acct:<uuid>``, which keys the session and everything stored for the user.

Security notes:

* The session and the login transaction live in AES-GCM sealed cookies
  (``__Host-`` prefix, Secure, HttpOnly, SameSite=Lax). Expiry is enforced from
  the sealed payload, not from the browser's Max-Age.
* Every POST needs the session CSRF token and an ``Origin`` equal to the public
  base URL. Bodies are capped at 8 KiB.
* Every response is ``no-store`` with a strict CSP; there is no JavaScript and
  every interpolation goes through ``html.escape``.
* Neither the Canvas token, the Entra ``error_description`` nor any upstream
  response body is ever logged or rendered.
* Each user picks their own Canvas school (see :mod:`.schools`). The school
  host submitted with the token is accepted only if the operator features it
  or, with the opt-in search, Instructure's directory confirms that exact
  domain; its DNS answer must be public; only then is the token sent to it.
  The school search is a plain GET form, needs a session and is rate limited.
* A token that Canvas rejected (or that cannot be decrypted, or that an owner
  marked invalid) is shown with a banner and a "Check again" button (POST, CSRF,
  once a minute per user) that probes Canvas once and can restore it. Replacing a
  token with one that belongs to a different Canvas user at the same school needs
  an explicit confirmation on the page and is logged.
* Write tools are off for everyone until the user ticks them in the "Write tools"
  section (POST, CSRF, Origin). Turning anything on needs a session issued within
  the last ten minutes; turning off never does. Only this page can change the
  switches (see :mod:`.tool_prefs`).
* Access is an authorization decision, not an enrollment row. An owner can
  *disable* a user (and enable them again); that is stored apart from the token row
  (``accounts.status``), so removing the row never lets a disabled user back in.
  Deleting your own token is only a self-disconnect: you may enroll again. The
  session cookie carries the user's ``session_epoch``; every request re-reads the
  stored status, so a session is rejected the moment the user is disabled or the
  epoch changes (no cache here: the delay is zero for this page). The owner role in
  the cookie is a snapshot and is not trusted by itself: owner pages and actions need
  a sign-in from the last ten minutes *and* the stored owner role, and the store
  re-checks that the acting owner is still an active owner inside the transaction
  that disables, enables, approves or denies someone. An owner cannot disable
  themselves or the last active owner.
* With ``ACCESS_POLICY=approval`` (or the ``approval`` fallback) a new user lands in
  a ``pending`` state: they can sign in and see that they are waiting, but the token
  form and the write-tool switches are hidden and refused, and the store refuses a
  token for a pending account in the same transaction as the write. An owner approves
  or denies at ``/account/admin``.
* Every sign-in is written to ``auth_events`` (the page shows the last twenty); the
  client address is ``unknown`` (no proxy is trusted) and the user agent is only a
  keyed hash. Owners can read the audit log at ``/account/admin/audit``.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import html
import json
import logging
import re
import secrets
import time
import urllib.parse
from collections.abc import Awaitable, Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta, tzinfo
from typing import TYPE_CHECKING, Any, Literal

import anyio.to_thread
import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from canvas_mcp.core import audit
from canvas_mcp.core.dates import output_timezone
from canvas_mcp.core.selfhost.accounts import (
    DENY_ACCESS_DISABLED,
    DENY_SIGNUPS_PAUSED,
    PROVIDER_ENTRA,
    Denied,
    valid_account_key,
)
from canvas_mcp.core.selfhost.identity import IdentityService, SignIn
from canvas_mcp.core.selfhost.limits import (
    InMemorySlidingWindowLimiter,
    RateLimiters,
    build_rate_limiters,
)
from canvas_mcp.core.selfhost.principal_access import PrincipalAccessCache
from canvas_mcp.core.selfhost.schools import (
    MAX_QUERY_CHARS,
    MIN_QUERY_CHARS,
    DirectoryError,
    HostResolver,
    School,
    SchoolDirectory,
    SchoolDirectoryLike,
    SchoolPolicy,
    check_public_host,
    is_blocked_hostname,
    parse_hostname,
    system_resolve,
)
from canvas_mcp.core.selfhost.token_health import TokenHealth
from canvas_mcp.core.selfhost.token_store import (
    DISABLE_REASON_ADMIN,
    DISABLE_REASON_DENIED,
    DISABLE_REASON_OPERATOR,
    REASON_CANVAS_TOKEN_REJECTED,
    REASON_DECRYPT_FAILED,
    REASON_REVOKED_BY_ADMIN,
    STATUS_INVALID,
    AccessActionRefused,
    AccountInfo,
    AuditEntry,
    AuthEvent,
    EnrollmentInfo,
    PrincipalDisabledError,
    PrincipalMissingError,
    PrincipalPendingError,
    PrincipalStatus,
    TokenDecryptionError,
    TokenStore,
    ToolPrefs,
    valid_principal_key,
)
from canvas_mcp.core.selfhost.tool_prefs import (
    OTHER_GROUP,
    WRITE_TOOL_GROUPS,
    ToolPrefsCache,
    WriteToolCatalog,
    user_can_enable,
)
from canvas_mcp.core.tool_policy import TOOL_EFFECTS, Effect

if TYPE_CHECKING:
    from fastmcp import FastMCP

logger = logging.getLogger("canvas_mcp.selfhost.account")

ACCOUNT_PATH = "/account"
ACCOUNT_CALLBACK_PATH = "/account/callback"
_LOGIN_PATH = "/account/login"
_TOKEN_PATH = "/account/token"
_TOKEN_DELETE_PATH = "/account/token/delete"
_TOKEN_RECHECK_PATH = "/account/token/recheck"
_LOGOUT_PATH = "/account/logout"
_ADMIN_PATH = "/account/admin"
_ADMIN_REMOVE_PATH = "/account/admin/remove"
_ADMIN_DISABLE_PATH = "/account/admin/disable"
_ADMIN_ENABLE_PATH = "/account/admin/enable"
_ADMIN_INVALIDATE_PATH = "/account/admin/invalidate"
_ADMIN_APPROVE_PATH = "/account/admin/approve"
_ADMIN_DENY_PATH = "/account/admin/deny"
_ADMIN_AUDIT_PATH = "/account/admin/audit"
_SCHOOLS_PATH = "/account/schools"
_WRITE_TOOLS_PATH = "/account/write-tools"

LOGIN_COOKIE = "__Host-cmcp_login"
SESSION_COOKIE = "__Host-cmcp_session"
# Display-language preference only: no authentication meaning. Scoped to
# /account (so it cannot be a ``__Host-`` cookie) and limited to "zh" / "en".
LANG_COOKIE = "canvas_mcp_lang"
_LANG_COOKIE_PATH = ACCOUNT_PATH
_LANG_COOKIE_MAX_AGE = 365 * 24 * 3600
_LANGS = ("zh", "en")
_DEFAULT_LANG = "en"
_LOGIN_TTL_SECONDS = 600
_IAT_SKEW_SECONDS = 600
_MAX_BODY_BYTES = 8192
_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
_RATE_LIMIT_ATTEMPTS = 10
_RATE_LIMIT_WINDOW_SECONDS = 600
_RATE_LIMIT_MAX_KEYS = 1024
_RECHECK_LIMIT_ATTEMPTS = 1
_RECHECK_LIMIT_WINDOW_SECONDS = 60
# Turning a write tool ON needs a session issued this recently (OFF never does).
_FRESH_SIGN_IN_SECONDS = 600
# The admin pages and actions need a sign-in this recent, so an owner whose Entra
# role was removed loses them within this time even if the stored flag is stale.
_OWNER_FRESH_SECONDS = _FRESH_SIGN_IN_SECONDS
# Session cookie format. Version 3 names the account (``acct``) and the login provider
# (``pid``) instead of the Entra tenant and object id; older cookies are refused, so
# everyone signs in once after the account-model upgrade.
_SESSION_VERSION = 3
# How many sign-ins the account page lists, and how many audit rows a page of the
# audit log shows.
_SIGN_IN_HISTORY = 20
_AUDIT_PAGE = 100
# Where the verified session of a request is kept (in the ASGI scope).
_SESSION_SCOPE_KEY = "canvas_mcp.session"
# One checkbox per offered write tool plus the CSRF token and a button.
_WRITE_FORM_MAX_FIELDS = 120
_EXPIRY_REMINDER_DAYS = 7
_EXPIRY_MAX_YEARS = 10
_FILTER_NEEDS_REENROLL = "needs_reenroll"
_SEARCH_LIMIT_ATTEMPTS = 30
_SEARCH_LIMIT_WINDOW_SECONDS = 600
_SCOPE = "openid profile"
_ALL_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

_TOKEN_RE = re.compile(r"^[A-Za-z0-9~._-]{20,512}$")
_ERROR_CODE_RE = re.compile(r"^[a-z_]{1,64}$")
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)
_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Content-Security-Policy": _CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Type": "text/html; charset=utf-8",
}


# -- public types ------------------------------------------------------------


IdTokenVerifier = Callable[[str], Awaitable[Mapping[str, Any] | None]]


@dataclass(frozen=True)
class CanvasIdentity:
    user_id: str
    name: str


class CanvasCheckError(Exception):
    """Canvas token verification failed: ``invalid`` or ``unavailable``."""

    def __init__(self, kind: Literal["invalid", "unavailable"]) -> None:
        super().__init__(kind)
        self.kind: Literal["invalid", "unavailable"] = kind


# Called as (token, api_url): the API URL of the school the user chose.
CanvasWhoAmI = Callable[[str, str], Awaitable[CanvasIdentity]]


@dataclass(frozen=True)
class AccountConfig:
    public_base_url: str
    tenant_id: str
    client_id: str
    client_secret: str = field(repr=False)
    session_secret: bytes = field(repr=False)
    schools: SchoolPolicy
    session_ttl_seconds: int = 900
    authority_host: str = "login.microsoftonline.com"


# -- sealed cookies ----------------------------------------------------------


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class _CookieCodec:
    """AES-256-GCM sealed JSON cookies; the cookie name is the associated data."""

    _PREFIX = "v1."

    def __init__(self, secret: bytes) -> None:
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"canvas-mcp-account",
            info=b"cookie-aead-v1",
        ).derive(secret)
        self._aead = AESGCM(key)

    def seal(self, name: str, payload: Mapping[str, Any]) -> str:
        nonce = secrets.token_bytes(12)
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        sealed = self._aead.encrypt(nonce, data, name.encode("ascii"))
        return self._PREFIX + _b64url(nonce + sealed)

    def unseal(self, name: str, value: str | None) -> dict[str, Any] | None:
        """Return the payload, or None for anything missing or invalid."""
        if not value or not value.startswith(self._PREFIX):
            return None
        try:
            raw = _b64url_decode(value[len(self._PREFIX) :])
            if len(raw) < 12 + 16:
                return None
            data = self._aead.decrypt(raw[:12], raw[12:], name.encode("ascii"))
            payload = json.loads(data.decode("utf-8"))
        except Exception:  # noqa: BLE001 - any decode failure means "absent"
            return None
        return payload if isinstance(payload, dict) else None


@dataclass(frozen=True)
class _Session:
    #: The account key ``acct:<uuid>``: the principal of everything stored for the user.
    acct: str
    name: str
    upn: str
    owner: bool
    csrf: str
    exp: int
    # When the sign-in happened (epoch seconds); 0 for a cookie that carries none,
    # which counts as "not recent".
    iat: int = 0
    # The user's session epoch at sign-in; valid only while the stored epoch equals it.
    ep: int = 0
    # The login provider that issued this session.
    pid: str = PROVIDER_ENTRA
    # Set from the stored status on every request: the account waits for approval.
    pending: bool = False


class _StoreUnavailable(Exception):
    """The access status could not be read, so no session can be trusted (fail closed)."""


_UNAVAILABLE = object()


#: The in-process sliding-window limiter (moved to :mod:`.limits`; the name is kept).
_RateLimiter = InMemorySlidingWindowLimiter


# -- language ----------------------------------------------------------------


@dataclass
class _RenderContext:
    """Per-request rendering state (language, toggle target, signed-in user)."""

    lang: str = _DEFAULT_LANG
    path: str = ACCOUNT_PATH
    session: _Session | None = None


# A ContextVar (not a module global): each request runs in its own task, so
# concurrent requests can never see each other's language.
_RENDER: ContextVar[_RenderContext | None] = ContextVar(
    "canvas_mcp_account_render", default=None
)


def _render_context() -> _RenderContext:
    return _RENDER.get() or _RenderContext()


def _current_lang() -> str:
    return _render_context().lang


def _query_lang(request: Request) -> str | None:
    """A valid ``?lang=`` value on a GET request, else None (anything else is ignored)."""
    if request.method != "GET":
        return None
    value = request.query_params.get("lang")
    return value if value in _LANGS else None


def _choose_lang(request: Request) -> str:
    """?lang= (GET only), then the preference cookie, then English.

    English is the default on purpose; the browser's Accept-Language is not
    consulted, so Chinese appears only after the user picks it with the toggle.
    """
    chosen = _query_lang(request)
    if chosen is not None:
        return chosen
    cookie = request.cookies.get(LANG_COOKIE)
    if cookie in _LANGS:
        return cookie
    return _DEFAULT_LANG


# -- HTML --------------------------------------------------------------------

_CSS = """
:root{--bg:#f6f7f9;--fg:#1c2024;--muted:#5f6b76;--card:#fff;--line:#d9dee3;
--accent:#0b57d0;--accent-fg:#fff;--bad:#b3261e;--bad-bg:#fdecea;--ok:#146c2e;
--ok-bg:#e8f5ec;--warn-bg:#fff4d6}
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--fg:#e6e9ec;--muted:#9aa5b0;
--card:#1d2125;--line:#333a41;--accent:#8ab4f8;--accent-fg:#10141a;--bad:#f2b8b5;
--bad-bg:#3a1f1d;--ok:#8fd5a6;--ok-bg:#1c3324;--warn-bg:#3a3118}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:16px/1.5 system-ui,-apple-system,"Segoe UI","Noto Sans SC","PingFang SC",sans-serif}
main{max-width:40rem;margin:0 auto;padding:.9rem 16px 3rem}
main.wide{max-width:56rem}
a{color:var(--accent)}
h1{font-size:1.3rem;line-height:1.3;margin:1.4rem 0 1rem}
h2{font-size:1.05rem;line-height:1.35;margin:0 0 .8rem}
.top{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;
gap:.5rem 1rem;padding-bottom:.8rem;border-bottom:1px solid var(--line)}
.brand{font-weight:700;color:var(--fg);text-decoration:none}
.tools{display:flex;flex-wrap:wrap;align-items:center;justify-content:flex-end;
gap:.4rem .9rem;font-size:.9rem;min-width:0}
.who{color:var(--muted);max-width:11rem;overflow:hidden;text-overflow:ellipsis;
white-space:nowrap}
.acct{margin:-.6rem 0 1rem;overflow-wrap:anywhere}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:1.1rem 1.2rem;margin:0 0 1rem}
.card>:last-child{margin-bottom:0}
p{margin:0 0 .8rem}
.muted{color:var(--muted)}.small{font-size:.9rem}
code{background:var(--bg);border:1px solid var(--line);border-radius:4px;
padding:.05rem .3rem;word-break:break-all}
.btn{display:inline-block;background:var(--accent);color:var(--accent-fg);
border:1px solid var(--accent);border-radius:8px;padding:.6rem 1.1rem;font:inherit;
line-height:1.3;cursor:pointer;text-decoration:none;white-space:nowrap}
.btn.secondary{background:transparent;color:var(--accent);border-color:var(--line)}
.btn.danger{background:transparent;color:var(--bad);border-color:var(--bad)}
.btn.sm{padding:.3rem .75rem;font-size:.9rem}
label{display:block;font-weight:600;font-size:.92rem}
input[type=password],input[type=search],input[type=date]{width:100%;padding:.6rem;border:1px solid var(--line);
border-radius:8px;background:var(--bg);color:var(--fg);font:inherit;margin:.4rem 0 .9rem}
fieldset{border:0;padding:0;margin:0 0 .9rem;min-width:0}
legend{font-weight:600;font-size:.92rem;padding:0;margin:0 0 .3rem}
.choice{display:flex;gap:.5rem;align-items:baseline;font-weight:400;margin:.3rem 0}
.choice input{flex:none}
ul.results{margin:0 0 1rem;padding-left:1.3rem}
.notice{border-radius:8px;padding:.6rem .8rem;margin:1rem 0 0}
.notice.error{background:var(--bad-bg);color:var(--bad)}
.notice.ok{background:var(--ok-bg);color:var(--ok)}
.warn{background:var(--warn-bg);border-radius:8px;padding:.5rem .8rem}
.banner{border-left:4px solid var(--bad)}
.banner.soon{border-left-color:var(--accent)}
.act form+form{margin-top:.4rem}
ol{margin:0 0 1rem;padding-left:1.3rem}li{margin:0 0 .3rem}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.25rem 1rem;margin:0 0 1rem}
dt{color:var(--muted)}dd{margin:0;word-break:break-word}
form{margin:0}.inline{display:inline}
details>summary{cursor:pointer;color:var(--accent);font-weight:600}
details[open]>summary{margin-bottom:.9rem}
details.card{padding:.8rem 1.2rem}
details.tech{margin-top:.4rem;font-size:.9rem}
details.tech>summary{font-weight:400}
details.tech[open]>summary{margin-bottom:.4rem}
details.tech dl{margin:0}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:.65rem .5rem;border-bottom:1px solid var(--line);
vertical-align:top;word-break:break-word}
th{color:var(--muted);font-size:.85rem;font-weight:600}
.act{text-align:right}
.tablecard{padding:.4rem .7rem}
@media (max-width:40rem){
.who{max-width:7rem}
.tools{flex:1 1 auto}
.tablecard{background:none;border:0;padding:0}
table,tbody,tr,td{display:block}
thead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
tr{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:.7rem .9rem;margin:0 0 .8rem}
td{border:0;padding:.25rem 0}
td[data-label]::before{content:attr(data-label);display:block;color:var(--muted);
font-size:.8rem}
.act{text-align:left;padding-top:.6rem}
}
""".strip()


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _has_control(text: str) -> bool:
    return any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in text)


def _bi(zh: str, en: str) -> str:
    """The Chinese or the English text, per the current request. Inputs are trusted.

    Both strings stay in the source so each language is complete; only the one
    chosen for this request is rendered.
    """
    return zh if _current_lang() == "zh" else en


# Chinese renderings of the identity layer's fixed refusal messages, keyed by the
# exact English text. Anything not listed (a future message) falls back to a generic
# line, so an unknown refusal is never shown untranslated to a Chinese reader.
_DENIAL_ZH: dict[str, str] = {
    "Your Microsoft account belongs to a different directory than this server accepts.": (
        "你的 Microsoft 账号属于另一个目录，此服务器不接受。"
    ),
    "This sign-in was issued to a different application than this server accepts.": (
        "此次登录签发给了另一个应用，此服务器不接受。"
    ),
    "Your sign-in does not carry a valid account identifier.": (
        "你的登录信息中没有有效的账号标识。"
    ),
    (
        "Your Microsoft account is not allowed to use this server. "
        "Ask the server owner to add you to the access group."
    ): "你的 Microsoft 账号没有使用此服务器的权限，请联系服务器所有者把你加入访问组。",
    "Your sign-in carries malformed role information. Sign in again.": (
        "你的登录信息中的角色数据格式有误，请重新登录。"
    ),
    "Your sign-in carries malformed group information. Sign in again.": (
        "你的登录信息中的组数据格式有误，请重新登录。"
    ),
    "New sign-ups are paused on this server. Contact the server owner.": (
        "此服务器暂时不接受新的注册，请联系服务器所有者。"
    ),
}

# Chinese line shown for a refusal message that has no entry in _DENIAL_ZH.
_DENIAL_ZH_FALLBACK = "此账号没有使用权限，请联系服务器所有者。"

# The language switcher shows each language's own name (its endonym).
_ZH_ENDONYM = "中文"


def _denial_html(message: str) -> str:
    """The identity layer's refusal text; Chinese gets a translation or a generic line."""
    if _current_lang() == "zh":
        return _e(_DENIAL_ZH.get(message, _DENIAL_ZH_FALLBACK))
    return _e(message)


def _display_tz() -> tzinfo:
    try:
        return output_timezone()
    except Exception:  # noqa: BLE001 - never fail a page over a timezone
        return UTC


def _fmt_ts(value: int | None) -> str:
    """e.g. ``2026-09-01 14:12 PDT`` in the configured TIMEZONE (UTC fallback)."""
    if value is None:
        return "-"
    try:
        moment = datetime.fromtimestamp(value, tz=UTC).astimezone(_display_tz())
        return moment.strftime("%Y-%m-%d %H:%M %Z").strip()
    except (OverflowError, OSError, ValueError):
        return "-"


def _fmt_date(value: int | None) -> str:
    """e.g. ``2026-09-01`` in the configured TIMEZONE (UTC fallback)."""
    if value is None:
        return "-"
    try:
        moment = datetime.fromtimestamp(value, tz=UTC).astimezone(_display_tz())
        return moment.strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return "-"


def _fmt_utc_date(value: int) -> str:
    """The calendar date a user typed for a token expiry (stored as midnight UTC)."""
    try:
        return datetime.fromtimestamp(value, tz=UTC).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return "-"


def _parse_expiry(raw: str, now: float) -> int | None | Literal["invalid"]:
    """The expiry date from the optional form field as epoch seconds (midnight UTC).

    ``None`` for an empty field; ``"invalid"`` for anything that is not a real
    calendar date between today and ``_EXPIRY_MAX_YEARS`` years ahead.
    """
    text = raw.strip()
    if not text:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return "invalid"
    try:
        day = date.fromisoformat(text)
    except ValueError:
        return "invalid"
    today = datetime.fromtimestamp(now, tz=UTC).date()
    if day < today or day > today + timedelta(days=365 * _EXPIRY_MAX_YEARS):
        return "invalid"
    return int(datetime(day.year, day.month, day.day, tzinfo=UTC).timestamp())


def _document(title: str, body: str, *, wide: bool = False) -> str:
    lang = "zh-CN" if _current_lang() == "zh" else "en"
    main_class = ' class="wide"' if wide else ""
    return (
        f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="robots" content="noindex, nofollow">'
        f"<title>{_e(title)}</title><style>{_CSS}</style></head>"
        f"<body><main{main_class}>{body}</main></body></html>"
    )


def _csrf_field(csrf: str) -> str:
    return f'<input type="hidden" name="csrf" value="{_e(csrf)}">'


def _identity_line(session: _Session) -> str:
    """The signed-in Microsoft account as visible muted text (no hover needed)."""
    if not session.upn:
        return ""
    return f'<p class="muted small acct">{_bi("Microsoft 账号", "Microsoft account")}: {_e(session.upn)}</p>'


def _header(session: _Session | None = None) -> str:
    """Slim header row: product title left; name, Admin, language toggle, Sign out right."""
    ctx = _render_context()
    session = session or ctx.session
    tools: list[str] = []
    if session is not None:
        full = f"{session.name} ({session.upn})" if session.upn else session.name
        tools.append(f'<span class="who" title="{_e(full)}">{_e(session.name)}</span>')
        if session.owner:
            tools.append(f'<a href="{_ADMIN_PATH}">{_bi("管理", "Admin")}</a>')
    # Same-path link with a fixed value: nothing from the request is reflected.
    if ctx.lang == "zh":
        tools.append(f'<a href="{_e(ctx.path)}?lang=en" hreflang="en" lang="en">English</a>')
    else:
        tools.append(f'<a href="{_e(ctx.path)}?lang=zh" hreflang="zh" lang="zh">{_ZH_ENDONYM}</a>')
    if session is not None:
        tools.append(
            f'<form method="post" action="{_LOGOUT_PATH}" class="inline">'
            f"{_csrf_field(session.csrf)}"
            f'<button class="btn secondary sm" type="submit">{_bi("退出登录", "Sign out")}</button>'
            "</form>"
        )
    return (
        f'<header class="top"><a class="brand" href="{ACCOUNT_PATH}">Canvas MCP</a>'
        f'<nav class="tools">{"".join(tools)}</nav></header>'
    )


# -- the app -----------------------------------------------------------------

Handler = Callable[[Request], Awaitable[Response]]


class _AccountApp:
    def __init__(
        self,
        cfg: AccountConfig,
        store: TokenStore,
        identity: IdentityService,
        id_token_verifier: IdTokenVerifier | None,
        canvas_whoami: CanvasWhoAmI | None,
        http_client_factory: Callable[[], httpx.AsyncClient] | None,
        clock: Callable[[], float],
        directory: SchoolDirectoryLike | None = None,
        resolve_host: HostResolver | None = None,
        health: TokenHealth | None = None,
        write_tools: WriteToolCatalog | None = None,
        tool_prefs: ToolPrefsCache | None = None,
        access: PrincipalAccessCache | None = None,
        rate_limiters: RateLimiters | None = None,
    ) -> None:
        window = (rate_limiters or build_rate_limiters("memory")).sliding_window
        self.cfg = cfg
        self.write_tools = write_tools
        self.tool_prefs = tool_prefs
        self.access = access
        self.schools = cfg.schools
        self.base = cfg.public_base_url.rstrip("/")
        self.tenant = cfg.tenant_id.lower()
        self.store = store
        self.identity = identity
        self.clock = clock
        self.codec = _CookieCodec(cfg.session_secret)
        # Keyed hash of the user agent for the sign-in history: the secret is never
        # used directly, and the user agent itself is never stored.
        self._ua_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"canvas-mcp-account",
            info=b"auth-event-ua-v1",
        ).derive(cfg.session_secret)
        self.limiter = window(
            _RATE_LIMIT_ATTEMPTS,
            _RATE_LIMIT_WINDOW_SECONDS,
            _RATE_LIMIT_MAX_KEYS,
            clock,
        )
        self.recheck_limiter = window(
            _RECHECK_LIMIT_ATTEMPTS,
            _RECHECK_LIMIT_WINDOW_SECONDS,
            _RATE_LIMIT_MAX_KEYS,
            clock,
        )
        self.health = health or TokenHealth(store, account_url=self.base + ACCOUNT_PATH)
        self.search_limiter = window(
            _SEARCH_LIMIT_ATTEMPTS,
            _SEARCH_LIMIT_WINDOW_SECONDS,
            _RATE_LIMIT_MAX_KEYS,
            clock,
        )
        self._client_factory = http_client_factory or (
            lambda: httpx.AsyncClient(timeout=10, follow_redirects=False)
        )
        self._directory: SchoolDirectoryLike = directory or SchoolDirectory(
            client_factory=self._client_factory
        )
        self._resolve_host: HostResolver = resolve_host or system_resolve
        self._id_token_verifier = id_token_verifier
        self._canvas_whoami = canvas_whoami or self._default_whoami

    # -- routing -------------------------------------------------------------

    def routes(self) -> list[Route]:
        table: list[tuple[str, dict[str, Handler]]] = [
            (ACCOUNT_PATH, {"GET": self.page}),
            (_LOGIN_PATH, {"GET": self.login}),
            (ACCOUNT_CALLBACK_PATH, {"GET": self.callback}),
            (_TOKEN_PATH, {"POST": self.save_token}),
            (_TOKEN_DELETE_PATH, {"POST": self.delete_token}),
            (_TOKEN_RECHECK_PATH, {"POST": self.recheck_token}),
            (_LOGOUT_PATH, {"POST": self.logout}),
            (_ADMIN_PATH, {"GET": self.admin}),
            (_ADMIN_REMOVE_PATH, {"POST": self.admin_remove}),
            (_ADMIN_DISABLE_PATH, {"POST": self.admin_disable}),
            (_ADMIN_ENABLE_PATH, {"POST": self.admin_enable}),
            (_ADMIN_INVALIDATE_PATH, {"POST": self.admin_invalidate}),
            (_ADMIN_APPROVE_PATH, {"POST": self.admin_approve}),
            (_ADMIN_DENY_PATH, {"POST": self.admin_deny}),
            (_ADMIN_AUDIT_PATH, {"GET": self.admin_audit}),
            (_SCHOOLS_PATH, {"GET": self.schools_page}),
            (_WRITE_TOOLS_PATH, {"POST": self.save_write_tools}),
        ]
        return [
            Route(path, self._endpoint(handlers), methods=_ALL_METHODS)
            for path, handlers in table
        ]

    def _endpoint(self, handlers: dict[str, Handler]) -> Handler:
        async def endpoint(request: Request) -> Response:
            session: _Session | None = None
            try:
                session = await self._resolve_session(request)
                request.scope[_SESSION_SCOPE_KEY] = session
            except Exception as exc:  # noqa: BLE001 - fail closed, never leak details
                logger.error("account session check failed: %s", type(exc).__name__)
                request.scope[_SESSION_SCOPE_KEY] = _UNAVAILABLE
            ctx = _RenderContext(
                lang=_choose_lang(request),
                path=self._toggle_path(request),
                session=session,
            )
            token = _RENDER.set(ctx)
            try:
                response = await self._dispatch(handlers, request)
            finally:
                _RENDER.reset(token)
            chosen = _query_lang(request)
            if chosen is not None:
                self._remember_lang(response, chosen)
            return response

        return endpoint

    async def _dispatch(self, handlers: dict[str, Handler], request: Request) -> Response:
        handler = handlers.get(request.method)
        if handler is None:
            response = self.message_page(
                405,
                _bi("不支持该请求方法。", "Method not allowed."),
            )
            response.headers["Allow"] = ", ".join(sorted(handlers))
            return response
        try:
            return await handler(request)
        except _StoreUnavailable:
            return self.message_page(
                503, _bi("暂时无法读取令牌库。", "The token store is unavailable.")
            )
        except Exception as exc:  # noqa: BLE001 - never leak details
            logger.error("account request failed: %s", type(exc).__name__)
            return self.message_page(
                500, _bi("服务器出错了，请稍后再试。", "Something went wrong.")
            )

    @staticmethod
    def _toggle_path(request: Request) -> str:
        """Target of the language toggle: this page if it is a GET page, else /account.

        Always one of the fixed route constants, never request input.
        """
        path = request.url.path
        return (
            path
            if path in (ACCOUNT_PATH, _ADMIN_PATH, _SCHOOLS_PATH, _ADMIN_AUDIT_PATH)
            else ACCOUNT_PATH
        )

    @staticmethod
    def _remember_lang(response: Response, lang: str) -> None:
        """Store the display-language preference (not an authentication cookie)."""
        response.set_cookie(
            LANG_COOKIE,
            lang,
            max_age=_LANG_COOKIE_MAX_AGE,
            path=_LANG_COOKIE_PATH,
            secure=True,
            httponly=True,
            samesite="lax",
        )

    # -- response helpers ----------------------------------------------------

    def finish(self, response: Response) -> Response:
        for name, value in _SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    def html_page(self, status: int, title: str, body: str, *, wide: bool = False) -> Response:
        return self.finish(Response(_document(title, body, wide=wide), status_code=status))

    def message_page(self, status: int, message_html: str) -> Response:
        body = (
            _header()
            + f'<section class="card"><p>{message_html}</p>'
            f'<p><a class="btn secondary" href="{ACCOUNT_PATH}">'
            f'{_bi("返回账户页", "Back to account")}</a></p></section>'
        )
        return self.html_page(status, "Canvas MCP", body)

    def redirect(self, location: str, status: int = 303) -> Response:
        return self.finish(Response(b"", status_code=status, headers={"Location": location}))

    def _cookie_kwargs(self) -> dict[str, Any]:
        return {"path": "/", "secure": True, "httponly": True, "samesite": "lax"}

    def clear_cookie(self, response: Response, name: str) -> None:
        response.delete_cookie(name, **self._cookie_kwargs())

    # -- session -------------------------------------------------------------

    def session_from(self, request: Request) -> _Session | None:
        payload = self.codec.unseal(SESSION_COOKIE, request.cookies.get(SESSION_COOKIE))
        if payload is None or payload.get("v") != _SESSION_VERSION:
            return None
        try:
            acct, pid = payload["acct"], payload["pid"]
            name, upn, csrf = payload["name"], payload["upn"], payload["csrf"]
            owner, exp, epoch = payload["owner"], payload["exp"], payload["ep"]
        except KeyError:
            return None
        if not (
            isinstance(acct, str)
            and isinstance(pid, str)
            and isinstance(name, str)
            and isinstance(upn, str)
            and isinstance(csrf, str)
            and isinstance(owner, bool)
            and isinstance(exp, int)
            and not isinstance(exp, bool)
            and isinstance(epoch, int)
            and not isinstance(epoch, bool)
            and epoch >= 0
        ):
            return None
        if exp <= self.clock() or not valid_account_key(acct) or pid != PROVIDER_ENTRA or not csrf:
            return None
        raw_iat = payload.get("iat")
        iat = raw_iat if isinstance(raw_iat, int) and not isinstance(raw_iat, bool) else 0
        return _Session(acct, name, upn, owner, csrf, exp, iat, epoch, pid)

    async def _resolve_session(self, request: Request) -> _Session | None:
        """The session in the cookie, accepted only if the stored decision still allows it.

        Read from the database on every request (no cache): the session must be
        refused as soon as the account is disabled, denied or gone, or the epoch moved
        on. A pending account keeps its session (the page tells it to wait) but is
        marked ``pending``. The owner role in the cookie is a snapshot, so it is kept
        only while the stored role agrees and the account is active. A database error
        raises, and the caller fails closed.
        """
        cookie = self.session_from(request)
        if cookie is None:
            return None
        stored = await anyio.to_thread.run_sync(self.store.get_principal_status, cookie.acct)
        if not (stored.active or stored.pending) or stored.session_epoch != cookie.ep:
            return None
        return replace(
            cookie,
            owner=cookie.owner and stored.is_owner and stored.active,
            pending=stored.pending,
        )

    @staticmethod
    def _session_of(request: Request) -> _Session | None:
        """The verified session of this request (see :meth:`_resolve_session`)."""
        value = request.scope.get(_SESSION_SCOPE_KEY)
        if value is _UNAVAILABLE:
            raise _StoreUnavailable
        return value if isinstance(value, _Session) else None

    def _signed_in_recently(self, session: _Session) -> bool:
        """True when this session was issued within the last ``_FRESH_SIGN_IN_SECONDS``."""
        age = self.clock() - session.iat
        return session.iat > 0 and -_IAT_SKEW_SECONDS <= age <= _FRESH_SIGN_IN_SECONDS

    def _csrf_ok(self, session: _Session, supplied: str | None) -> bool:
        if not supplied:
            return False
        return hmac.compare_digest(supplied.encode("utf-8"), session.csrf.encode("utf-8"))

    # -- GET /account --------------------------------------------------------

    async def page(self, request: Request) -> Response:
        session = self._session_of(request)
        if session is None:
            return self.signed_out_page()
        try:
            info = await anyio.to_thread.run_sync(self.store.info, session.acct)
        except Exception as exc:  # noqa: BLE001
            logger.error("account page store read failed: %s", type(exc).__name__)
            return self.message_page(
                503, _bi("暂时无法读取令牌库。", "The token store is unavailable.")
            )
        selected = self._selection(
            request.query_params.get("school"), session, request.query_params.get("sig")
        )
        return await self.account_page(session, info, selected=selected)

    def _pick_signature(self, session: _Session, host: str) -> str:
        """Proof that ``host`` came from this session's own school search results."""
        message = b"school-pick|" + session.csrf.encode("utf-8") + b"|" + host.encode("ascii")
        return _b64url(hmac.new(self.cfg.session_secret, message, hashlib.sha256).digest())

    def _identity_confirmation(
        self, session: _Session, host: str, enrolled_user_id: str, new_user_id: str
    ) -> str:
        """Proof that this session was warned about switching to exactly this Canvas user.

        Bound to the session, the school, the user enrolled now and the user the
        pasted token belongs to, so a confirmation cannot be sent ahead of the
        warning and does not carry over to a token for a third user.
        """
        message = "|".join(
            ("identity-change", session.csrf, host, enrolled_user_id, new_user_id)
        ).encode("utf-8")
        return _b64url(hmac.new(self.cfg.session_secret, message, hashlib.sha256).digest())

    def _selection(
        self,
        raw: str | None,
        session: _Session,
        sig: str | None = None,
        *,
        posted: bool = False,
    ) -> str | None:
        """A school host from ``?school=`` / a failed form that may be pre-selected.

        A featured school is always accepted. A directory host (search on, valid
        and not local) is accepted only when it carries this session's signature
        from the search results page, or when it comes back from our own CSRF
        protected form (``posted``). An unsigned ``?school=`` link is ignored, so
        a crafted link cannot change where the next pasted token is sent.
        """
        if not raw:
            return None
        candidate = raw.strip().lower()
        if self.schools.featured_school(candidate) is not None:
            return candidate
        if not self.schools.search_enabled:
            return None
        host = parse_hostname(candidate)
        if host is None or is_blocked_hostname(host):
            return None
        if posted:
            return host
        if not sig or not hmac.compare_digest(
            sig.encode("utf-8"), self._pick_signature(session, host).encode("utf-8")
        ):
            return None
        return host

    def _mcp_url_section(self) -> str:
        return (
            f'<section class="card"><h2>{_bi("MCP 连接地址", "MCP connector URL")}</h2>'
            f"<p><code>{_e(self.base)}/mcp</code></p>"
            f'<p class="muted small">{_bi("在 Claude 中添加自定义连接器时填写此地址。", "Use this URL when adding a custom connector in Claude.")}</p>'
            "</section>"
        )

    def signed_out_page(self) -> Response:
        body = (
            _header()
            + f"<h1>{_bi('Canvas 账户', 'Canvas account')}</h1>"
            '<section class="card">'
            f"<p>{_bi('先用 Microsoft 账号登录，再绑定你自己的 Canvas 令牌。', 'Sign in with Microsoft, then add your own Canvas access token.')}</p>"
            f'<p><a class="btn" href="{_LOGIN_PATH}">'
            f"{_bi('使用 Microsoft 登录', 'Sign in with Microsoft')}</a></p>"
            "</section>" + self._mcp_url_section()
        )
        return self.html_page(200, _bi("Canvas 账户", "Canvas account"), body)

    def _school_choices(self, info: EnrollmentInfo | None, selected: str | None) -> str | None:
        """The school radios, or None when there is no school to choose from."""
        choices: list[tuple[str, str, str]] = []  # (host, name, note html)
        for school in self.schools.featured:
            choices.append((school.host, school.name, ""))
        listed = {host for host, _name, _note in choices}
        if selected is not None and selected not in listed:
            note = _bi("（来自你的学校搜索，保存时验证）", "(from your school search, verified when you save)")
            choices.append((selected, selected, note))
            listed.add(selected)
        enrolled = info.canvas_host if info is not None else None
        if (
            enrolled is not None
            and enrolled not in listed
            and self.schools.resolve_stored(enrolled) is not None
        ):
            choices.append((enrolled, enrolled, _bi("（你当前的学校）", "(your current school)")))
            listed.add(enrolled)
        if not choices:
            return None

        checked = selected
        if checked is None and enrolled is not None and enrolled in listed:
            checked = enrolled
        if checked is None and self.schools.default is not None:
            checked = self.schools.default.host
        if checked is None or checked not in listed:
            checked = choices[0][0]

        radios = []
        for host, name, note in choices:
            mark = " checked" if host == checked else ""
            host_part = "" if name == host else f' <span class="muted">{_e(host)}</span>'
            note_part = f' <span class="muted">{note}</span>' if note else ""
            radios.append(
                f'<label class="choice"><input type="radio" name="school" value="{_e(host)}"{mark}>'
                f"<span>{_e(name)}{host_part}{note_part}</span></label>"
            )
        return (
            f"<fieldset><legend>{_bi('你的学校', 'Your school')}</legend>"
            + "".join(radios)
            + "</fieldset>"
        )

    def _token_form(
        self,
        session: _Session,
        info: EnrollmentInfo | None = None,
        selected: str | None = None,
        identity_change: tuple[str, str, str] | None = None,
    ) -> str:
        school_part = ""
        if self.schools.picker_enabled:
            choices = self._school_choices(info, selected)
            if choices is None:
                return (
                    f'<p class="warn">{_bi("请先搜索你的学校。", "Search for your school first.")}</p>'
                )
            school_part = choices
        else:
            sole = self.schools.sole_school
            if sole is not None and self.schools.default is None:
                school_part = (
                    f'<p class="muted small">{_bi("学校", "School")}: {_e(sole.name)}'
                    f' <span class="muted">({_e(sole.host)})</span></p>'
                )
        identity_part = ""
        if identity_change is not None:
            old_name, new_name, confirmation = identity_change
            identity_part = (
                '<p class="warn">'
                + _bi(
                    "这个令牌属于另一个 Canvas 用户（{new}），而当前绑定的是 {old}。如果确实要换成这个用户，请勾选下方确认框后再保存。",
                    "This token belongs to a different Canvas user ({new}) than the one enrolled now ({old}). If you really mean to switch, tick the box below and save again.",
                ).format(new=_e(new_name), old=_e(old_name))
                + "</p>"
                '<label class="choice"><input type="checkbox" name="confirm_identity_change" '
                f'value="{_e(confirmation)}" required>'
                f"<span>{_bi('我确认要换成另一个 Canvas 用户的令牌', 'I confirm this is a different Canvas user')}</span></label>"
            )
        return (
            f'<p class="warn"><strong>{_bi("绝不要把令牌粘贴到 Claude 对话里。", "Never paste the token into Claude.")}</strong></p>'
            f'<p class="muted small">{_bi("服务器会加密保存你的令牌，但运营这台服务器的人仍然可以使用它，所以只有信任运营者时才绑定。你可以随时在这里删除它，同时也请在 Canvas 的 Approved Integrations 里撤销它。", "The server stores your token encrypted, but whoever operates this server can still use it, so enroll only if you trust them. You can delete it here at any time; also revoke it in Canvas under Approved Integrations.")}</p>'
            f'<form method="post" action="{_TOKEN_PATH}">'
            f"{_csrf_field(session.csrf)}"
            f"{school_part}"
            f'<label for="canvas_token">{_bi("Canvas 访问令牌", "Canvas access token")}</label>'
            '<input id="canvas_token" name="canvas_token" type="password" '
            'autocomplete="off" spellcheck="false" autocapitalize="off" '
            'required minlength="20" maxlength="512">'
            f'<label for="expires_on">{_bi("令牌到期日（可选）", "Token expires on (optional)")}</label>'
            '<input id="expires_on" name="expires_on" type="date" autocomplete="off">'
            f'<p class="muted small">{_bi("填写 Canvas 显示的到期日，到期前 7 天这里会提醒你。", "Enter the expiry date Canvas shows. This page reminds you 7 days before.")}</p>'
            f"{identity_part}"
            f'<button class="btn" type="submit">{_bi("验证并保存", "Verify and save")}</button>'
            "</form>"
        )

    def _search_section(self) -> str:
        """The school search form (plain GET, no JavaScript); empty when search is off."""
        if not self.schools.search_enabled:
            return ""
        return (
            f'<section class="card"><h2>{_bi("搜索其他学校", "Search other schools")}</h2>'
            f'<form method="get" action="{_SCHOOLS_PATH}">'
            f'<label for="school_q">{_bi("学校名称或 Canvas 域名", "School name or Canvas domain")}</label>'
            f'<input id="school_q" name="q" type="search" required '
            f'minlength="{MIN_QUERY_CHARS}" maxlength="{MAX_QUERY_CHARS}" '
            'autocomplete="off" spellcheck="false">'
            f'<button class="btn secondary" type="submit">{_bi("搜索", "Search")}</button>'
            "</form>"
            f'<p class="muted small">{_bi("搜索词会发送给 Instructure 的公共学校目录。", "Search terms are sent to the public school directory run by Instructure.")}</p>'
            "</section>"
        )

    def _school_status(self, info: EnrollmentInfo) -> str:
        """The School row of the status card, plus a notice when it is no longer offered."""
        school = self.schools.resolve_stored(info.canvas_host)
        if school is not None:
            host_part = "" if school.name == school.host else f' <span class="muted">({_e(school.host)})</span>'
            value = f"{_e(school.name)}{host_part}"
        elif info.canvas_host:
            value = _e(info.canvas_host)
        else:
            value = _bi("未记录学校", "No school recorded")
        return f"<dt>{_bi('学校', 'School')}</dt><dd>{value}</dd>"

    def _school_notice(self, info: EnrollmentInfo) -> str:
        if self.schools.resolve_stored(info.canvas_host) is not None:
            return ""
        return (
            '<p class="warn">'
            f"{_bi('服务器已不再支持你登记的学校，请重新登记。', 'This server no longer offers your school. Enroll again.')}"
            "</p>"
        )

    @staticmethod
    def _status_text(info: EnrollmentInfo) -> str:
        if info.status == STATUS_INVALID:
            return f"<strong>{_bi('需要新的令牌', 'Needs a new token')}</strong>"
        return _bi("正常", "Active")

    @staticmethod
    def _expiry_row(info: EnrollmentInfo) -> str:
        if info.expires_hint_at is None:
            return ""
        return (
            f"<dt>{_bi('令牌到期日', 'Token expires')}</dt>"
            f"<dd>{_e(_fmt_utc_date(info.expires_hint_at))}</dd>"
        )

    def _settings_link(self, info: EnrollmentInfo) -> str:
        """A link to the school's own Canvas settings page, where tokens are made."""
        school = self.schools.resolve_stored(info.canvas_host)
        if school is None or not school.api_url.startswith("https://"):
            return ""
        base = re.sub(r"/api/v\d+/?$", "", school.api_url.rstrip("/"))
        url = f"{base}/profile/settings"
        return (
            f'<p><a href="{_e(url)}" rel="noopener noreferrer" target="_blank">'
            f"{_bi('打开学校的 Canvas 设置页', 'Open your school’s Canvas settings')}</a></p>"
        )

    def _health_banner(self, session: _Session, info: EnrollmentInfo) -> str:
        """The banner for an invalid token, or the reminder shortly before an expiry date."""
        if info.status == STATUS_INVALID:
            return self._invalid_banner(session, info)
        hint = info.expires_hint_at
        now = self.clock()
        if hint is None or hint - now > _EXPIRY_REMINDER_DAYS * 86400:
            return ""
        day = _e(_fmt_utc_date(hint))
        if now < hint + 86400:
            text = _bi(
                "你的 Canvas 令牌将于 {date} 到期。请提前在 Canvas → 账户 → 设置 → 新建访问令牌 中生成新的令牌，并在下方替换。",
                "Your Canvas token expires on {date}. Generate a new one before then in Canvas → Account → Settings → New Access Token and replace it below.",
            )
        else:
            text = _bi(
                "你的 Canvas 令牌已过了 {date} 的到期日。如果它已停止工作，请在 Canvas 中生成新的令牌，并在下方替换。",
                "Your Canvas token passed its expiry date of {date}. If it has stopped working, generate a new one in Canvas and replace it below.",
            )
        return (
            '<section class="card banner soon" role="status">'
            f"<p>{text.format(date=day)}</p>{self._settings_link(info)}</section>"
        )

    def _invalid_banner(self, session: _Session, info: EnrollmentInfo) -> str:
        since = _e(_fmt_date(info.invalid_since))
        if info.invalid_reason == REASON_REVOKED_BY_ADMIN:
            text = _bi(
                "管理员已于 {date} 将你的 Canvas 令牌标记为失效。请在 Canvas → 账户 → 设置 → 新建访问令牌 中生成新的令牌，然后粘贴到下方。",
                "An administrator marked your Canvas token as invalid on {date}. Generate a new one in Canvas → Account → Settings → New Access Token, then paste it below.",
            )
        elif info.invalid_reason == REASON_DECRYPT_FAILED:
            text = _bi(
                "服务器自 {date} 起无法读取你保存的 Canvas 令牌。请在 Canvas → 账户 → 设置 → 新建访问令牌 中生成新的令牌，然后粘贴到下方。",
                "Since {date} the server cannot read your saved Canvas token. Generate a new one in Canvas → Account → Settings → New Access Token, then paste it below.",
            )
        else:
            text = _bi(
                "你的 Canvas 令牌已于 {date} 失效。请在 Canvas → 账户 → 设置 → 新建访问令牌 中生成新的令牌，然后粘贴到下方。",
                "Your Canvas token stopped working on {date}. Generate a new one in Canvas → Account → Settings → New Access Token, then paste it below.",
            )
        recheck = ""
        if info.invalid_reason != REASON_REVOKED_BY_ADMIN:
            recheck = (
                f'<form method="post" action="{_TOKEN_RECHECK_PATH}">'
                f"{_csrf_field(session.csrf)}"
                f'<button class="btn secondary sm" type="submit">{_bi("重新检测", "Check again")}</button>'
                f' <span class="muted small">{_bi("如果这是误判（例如 Canvas 暂时出错），可以重新检测，每分钟一次。", "If this is a mistake (for example Canvas had a hiccup), check again. Once a minute.")}</span>'
                "</form>"
            )
        return (
            '<section class="card banner" role="alert">'
            f"<p><strong>{text.format(date=since)}</strong></p>"
            f"{self._settings_link(info)}{recheck}</section>"
        )

    async def account_page(
        self,
        session: _Session,
        info: EnrollmentInfo | None,
        notice: tuple[Literal["error", "ok"], str] | None = None,
        status: int = 200,
        selected: str | None = None,
        identity_change: tuple[str, str, str] | None = None,
        write_notice: tuple[Literal["error", "ok"], str] | None = None,
    ) -> Response:
        parts: list[str] = [
            _header(session),
            f"<h1>{_bi('Canvas 账户', 'Canvas account')}</h1>",
            _identity_line(session),
        ]
        if notice is not None:
            parts.append(f'<div class="notice {notice[0]}" role="alert">{notice[1]}</div>')
        if session.pending:
            # Waiting for an owner's approval: no token form, no write tools, no MCP.
            parts.append(
                '<section class="card banner" role="status">'
                f"<h2>{_bi('等待管理员批准', 'Waiting for approval')}</h2>"
                f"<p>{_bi('你的账户已创建，但需要服务器所有者批准后才能使用。批准之前不能绑定 Canvas 令牌，AI 应用也无法连接。批准后请刷新此页。', 'Your account was created, but the server owner has to approve it before you can use it. Until then you cannot add a Canvas token and your AI app cannot connect. Reload this page once you are approved.')}</p>"
                "</section>"
            )
            parts.append(await self._sign_in_history(session))
            return self.html_page(status, _bi("Canvas 账户", "Canvas account"), "".join(parts))
        if info is not None:
            parts.append(self._health_banner(session, info))

        if info is None:
            parts.append(
                '<section class="card">'
                f"<h2>{_bi('绑定你的 Canvas 令牌', 'Add your Canvas token')}</h2>"
                "<ol>"
                f"<li>{_bi('在 Canvas 中打开 <strong>Account → Settings → + New Access Token</strong>。', 'In Canvas, open <strong>Account → Settings → + New Access Token</strong>.')}</li>"
                f"<li>{_bi('用途填 <code>Claude MCP</code>，并设置到期时间。', 'Purpose: <code>Claude MCP</code>. Set an expiry date.')}</li>"
                f"<li>{_bi('复制令牌，粘贴到下方。', 'Copy the token and paste it below.')}</li>"
                "</ol>" + self._token_form(session, info, selected) + "</section>"
            )
        else:
            parts.append(
                '<section class="card">'
                f"<h2>{_bi('Canvas 令牌已绑定', 'Canvas token enrolled')}</h2><dl>"
                f"<dt>{_bi('Canvas 用户', 'Canvas user')}</dt>"
                f"<dd>{_e(info.canvas_user_name)} "
                f'<span class="muted">(id {_e(info.canvas_user_id)})</span></dd>'
                f"{self._school_status(info)}"
                f"<dt>{_bi('状态', 'Status')}</dt><dd>{self._status_text(info)}</dd>"
                f"<dt>{_bi('最近使用', 'Last used')}</dt><dd>{_e(_fmt_ts(info.last_used_at))}</dd>"
                f"<dt>{_bi('最近验证', 'Last verified')}</dt><dd>{_e(_fmt_ts(info.last_verified_at))}</dd>"
                f"{self._expiry_row(info)}"
                f"<dt>{_bi('绑定时间', 'Enrolled')}</dt><dd>{_e(_fmt_ts(info.created_at))}</dd>"
                f"<dt>{_bi('更新时间', 'Updated')}</dt><dd>{_e(_fmt_ts(info.updated_at))}</dd>"
                "</dl>"
                f"{self._school_notice(info)}"
                f'<form method="post" action="{_TOKEN_DELETE_PATH}">'
                f"{_csrf_field(session.csrf)}"
                f'<button class="btn danger sm" type="submit">{_bi("删除我的令牌", "Delete my token")}</button> '
                f'<span class="muted small">{_bi("这只会断开你的 Canvas 令牌，你随时可以重新绑定。", "This only disconnects your own Canvas token. You can enroll again at any time.")}</span>'
                "</form></section>"
            )
            # Collapsed unless the last attempt failed (so the error and the form
            # meet) or a school was just chosen from the search results.
            is_open = (
                " open"
                if (notice is not None and notice[0] == "error")
                or selected is not None
                or info.status == STATUS_INVALID
                or identity_change is not None
                else ""
            )
            parts.append(
                f'<details class="card"{is_open}>'
                f"<summary>{_bi('替换令牌', 'Replace token')}</summary>"
                + self._token_form(session, info, selected, identity_change)
                + "</details>"
            )
        parts.append(self._search_section())
        parts.append(self._mcp_url_section())
        parts.append(await self._write_tools_section(session, write_notice))
        parts.append(await self._sign_in_history(session))
        return self.html_page(status, _bi("Canvas 账户", "Canvas account"), "".join(parts))

    @staticmethod
    def _auth_result(event: AuthEvent) -> str:
        """A sign-in event's result as plain text (closed codes only)."""
        if event.outcome == "success":
            if event.reason == "account_created":
                return _bi("登录成功（账户已创建）", "Signed in (account created)")
            if event.reason == "activated":
                return _bi("登录成功（已自动批准）", "Signed in (approved automatically)")
            return _bi("登录成功", "Signed in")
        if event.outcome == "pending":
            return _bi("等待批准", "Waiting for approval")
        if event.reason == "access_disabled":
            return _bi("被拒绝：账户已停用", "Refused: account disabled")
        if event.reason == "signups_paused":
            return _bi("被拒绝：暂停注册", "Refused: sign-ups paused")
        if event.reason == "pending_approval":
            return _bi("等待批准", "Waiting for approval")
        return _bi("被拒绝", "Refused")

    @staticmethod
    def _auth_provider(provider_id: str) -> str:
        return "Microsoft" if provider_id == PROVIDER_ENTRA else provider_id

    async def _sign_in_history(self, session: _Session) -> str:
        """The "Recent sign-ins" card: the last twenty sign-ins of this account."""
        try:
            events = await anyio.to_thread.run_sync(
                self.store.list_auth_events, session.acct, _SIGN_IN_HISTORY
            )
        except Exception as exc:  # noqa: BLE001 - a missing history must not break the page
            logger.error("account sign-in history read failed: %s", type(exc).__name__)
            return ""
        if not events:
            return ""
        rows = "".join(
            "<tr>"
            f'<td data-label="{_e(_bi("时间", "Time"))}">{_e(_fmt_ts(event.at))}</td>'
            f'<td data-label="{_e(_bi("结果", "Result"))}">{_e(self._auth_result(event))}</td>'
            f'<td data-label="{_e(_bi("登录方式", "Method"))}">{_e(self._auth_provider(event.provider_id))}</td>'
            "</tr>"
            for event in events
        )
        return (
            f'<section class="card tablecard" id="sign-ins"><h2>{_bi("最近的登录", "Recent sign-ins")}</h2>'
            "<table><thead><tr>"
            f"<th>{_bi('时间', 'Time')}</th><th>{_bi('结果', 'Result')}</th>"
            f"<th>{_bi('登录方式', 'Method')}</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>"
            f'<p class="muted small">{_bi("如果这里有你不认识的登录，请联系服务器所有者。", "If you see a sign-in here that you do not recognise, tell the server owner.")}</p>'
            "</section>"
        )

    def _ua_hash(self, request: Request) -> str | None:
        """16 hex characters of a keyed hash of the user agent (never the user agent itself)."""
        agent = request.headers.get("user-agent", "")[:512]
        if not agent:
            return None
        return hmac.new(self._ua_key, agent.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:16]

    # -- school search ---------------------------------------------------------

    def _schools_document(
        self,
        session: _Session,
        query: str,
        *,
        notice: tuple[Literal["error", "ok"], str] | None = None,
        results: list[tuple[str, str]] | None = None,
        status: int = 200,
    ) -> Response:
        parts: list[str] = [
            _header(session),
            f"<h1>{_bi('搜索学校', 'Find your school')}</h1>",
            '<section class="card">'
            f'<form method="get" action="{_SCHOOLS_PATH}">'
            f'<label for="school_q">{_bi("学校名称或 Canvas 域名", "School name or Canvas domain")}</label>'
            f'<input id="school_q" name="q" type="search" value="{_e(query)}" required '
            f'minlength="{MIN_QUERY_CHARS}" maxlength="{MAX_QUERY_CHARS}" '
            'autocomplete="off" spellcheck="false">'
            f'<button class="btn" type="submit">{_bi("搜索", "Search")}</button>'
            "</form>"
            f'<p class="muted small">{_bi("搜索词会发送给 Instructure 的公共学校目录。", "Search terms are sent to the public school directory run by Instructure.")}</p>'
            "</section>",
        ]
        if notice is not None:
            parts.append(f'<div class="notice {notice[0]}" role="alert">{notice[1]}</div>')
        if results is not None:
            if results:
                items = "".join(
                    f'<li><a href="{_e(ACCOUNT_PATH + "?" + urllib.parse.urlencode({"school": domain, "sig": self._pick_signature(session, domain)}))}">'
                    f'{_e(name)}</a> <span class="muted">{_e(domain)}</span></li>'
                    for domain, name in results
                )
                parts.append(f'<section class="card"><ul class="results">{items}</ul></section>')
            else:
                parts.append(
                    f'<section class="card"><p>{_bi("没有找到学校。", "No schools found.")}</p></section>'
                )
        parts.append(f'<p><a href="{ACCOUNT_PATH}">{_bi("返回账户页", "Back to account")}</a></p>')
        return self.html_page(
            status, _bi("搜索学校", "Find your school"), "".join(parts)
        )

    async def schools_page(self, request: Request) -> Response:
        session = self._session_of(request)
        if session is None:
            return self.redirect(ACCOUNT_PATH, 303)
        if not self.schools.search_enabled:
            return self.message_page(404, _bi("未启用学校搜索。", "School search is not enabled."))
        query = request.query_params.get("q", "").strip()
        if not query:
            return self._schools_document(session, "")
        if (
            len(query) < MIN_QUERY_CHARS
            or len(query) > MAX_QUERY_CHARS
            or _has_control(query)
        ):
            return self._schools_document(
                session,
                "" if _has_control(query) else query[:MAX_QUERY_CHARS],
                notice=(
                    "error",
                    _bi(
                        "请输入 2 到 64 个字符，不含控制字符。",
                        "Enter 2 to 64 characters, without control characters.",
                    ),
                ),
                status=400,
            )
        if not self.search_limiter.allow((session.acct,)):
            return self._schools_document(
                session,
                query,
                notice=(
                    "error",
                    _bi(
                        "搜索次数过多，请 10 分钟后再试。",
                        "Too many searches. Try again in 10 minutes.",
                    ),
                ),
                status=429,
            )
        try:
            entries = await self._directory.search(query)
        except DirectoryError:
            logger.warning("account school search failed")
            return self._schools_document(
                session,
                query,
                notice=(
                    "error",
                    _bi(
                        "暂时无法连接学校目录。",
                        "The school directory is unavailable right now.",
                    ),
                ),
                status=503,
            )
        results = [
            (entry.domain, entry.name)
            for entry in entries
            if not is_blocked_hostname(entry.domain)
        ]
        logger.info("account school search account=%s results=%d", session.acct, len(results))
        return self._schools_document(session, query, results=results)

    # -- sign-in -------------------------------------------------------------

    def _authority_url(self, path: str) -> str:
        return f"https://{self.cfg.authority_host}/{self.cfg.tenant_id}/{path}"

    async def login(self, request: Request) -> Response:
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
        query = urllib.parse.urlencode(
            {
                "client_id": self.cfg.client_id,
                "response_type": "code",
                "redirect_uri": self.base + ACCOUNT_CALLBACK_PATH,
                "response_mode": "query",
                "scope": _SCOPE,
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "prompt": "select_account",
            }
        )
        response = self.redirect(
            self._authority_url("oauth2/v2.0/authorize") + "?" + query, status=302
        )
        sealed = self.codec.seal(
            LOGIN_COOKIE,
            {
                "state": state,
                "nonce": nonce,
                "verifier": verifier,
                "iat": int(self.clock()),
            },
        )
        response.set_cookie(
            LOGIN_COOKIE, sealed, max_age=_LOGIN_TTL_SECONDS, **self._cookie_kwargs()
        )
        return response

    async def callback(self, request: Request) -> Response:
        response = await self._callback(request)
        self.clear_cookie(response, LOGIN_COOKIE)
        return response

    def _login_transaction(self, request: Request) -> dict[str, Any] | None:
        payload = self.codec.unseal(LOGIN_COOKIE, request.cookies.get(LOGIN_COOKIE))
        if payload is None:
            return None
        iat = payload.get("iat")
        if not isinstance(iat, int) or isinstance(iat, bool):
            return None
        now = self.clock()
        if iat > now + 60 or now - iat > _LOGIN_TTL_SECONDS:
            return None
        for key in ("state", "nonce", "verifier"):
            if not isinstance(payload.get(key), str) or not payload[key]:
                return None
        return payload

    async def _callback(self, request: Request) -> Response:
        txn = self._login_transaction(request)
        state = request.query_params.get("state", "")
        if txn is None or not hmac.compare_digest(
            state.encode("utf-8"), txn["state"].encode("utf-8")
        ):
            return self.message_page(
                400,
                _bi(
                    "登录请求已失效，请重新登录。",
                    "The sign-in request is invalid or expired. Please sign in again.",
                ),
            )

        error = request.query_params.get("error")
        if error is not None:
            code = error if _ERROR_CODE_RE.fullmatch(error) else None
            logger.info("account sign-in refused by Entra: %s", code or "unknown")
            detail = f" (<code>{_e(code)}</code>)" if code else ""
            return self.message_page(
                403,
                _bi(
                    "Microsoft 登录没有完成。",
                    "Microsoft sign-in was not completed.",
                )
                + detail,
            )

        code_param = request.query_params.get("code", "")
        if not code_param or len(code_param) > 4096:
            return self.message_page(
                400, _bi("登录响应不完整。", "The sign-in response is incomplete.")
            )

        id_token = await self._exchange_code(code_param, txn["verifier"])
        if id_token is None:
            return self.message_page(
                502,
                _bi(
                    "无法与 Microsoft 完成登录，请稍后再试。",
                    "Could not complete sign-in with Microsoft. Try again later.",
                ),
            )

        claims = await self._verify_id_token(id_token)
        bad = self.message_page(
            400,
            _bi(
                "无法验证 Microsoft 返回的登录凭证。",
                "The sign-in credential could not be verified.",
            ),
        )
        if claims is None:
            return bad
        nonce = claims.get("nonce")
        if not isinstance(nonce, str) or not hmac.compare_digest(
            nonce.encode("utf-8"), txn["nonce"].encode("utf-8")
        ):
            return bad
        iat = claims.get("iat")
        exp = claims.get("exp")
        now = self.clock()
        if (
            not isinstance(iat, int | float)
            or isinstance(iat, bool)
            or abs(now - iat) > _IAT_SKEW_SECONDS
            or not isinstance(exp, int | float)
            or isinstance(exp, bool)
            or exp <= now
        ):
            return bad
        tid = claims.get("tid")
        if not isinstance(tid, str) or tid.lower() != self.tenant:
            return self.message_page(
                403,
                _bi(
                    "此账号不属于允许的目录。",
                    "This account is not in the allowed directory.",
                ),
            )

        try:
            outcome = await anyio.to_thread.run_sync(
                functools.partial(
                    self.identity.sign_in,
                    claims,
                    ip="unknown",
                    ua_hash=self._ua_hash(request),
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("account sign-in status check failed: %s", type(exc).__name__)
            return self.message_page(
                503, _bi("暂时无法读取令牌库。", "The token store is unavailable.")
            )
        if isinstance(outcome, Denied):
            return self._sign_in_refused(outcome)
        assert isinstance(outcome, SignIn)
        standing = outcome.status
        sign_in_key = standing.principal_key
        if standing.owner_change is not None:
            audit.log_principal_event(standing.owner_change, sign_in_key, reason="sign_in")

        issued = int(now)
        sealed = self.codec.seal(
            SESSION_COOKIE,
            {
                "v": _SESSION_VERSION,
                "acct": sign_in_key,
                "pid": outcome.ext.provider_id,
                "name": outcome.ext.display_name[:200],
                "upn": outcome.ext.username[:254],
                "owner": bool(outcome.owner),
                "iat": issued,
                "exp": issued + self.cfg.session_ttl_seconds,
                "csrf": secrets.token_urlsafe(32),
                "ep": standing.session_epoch,
            },
        )
        logger.info("account sign-in ok account=%s pending=%s", sign_in_key, outcome.pending)
        response = self.redirect(ACCOUNT_PATH, 303)
        response.set_cookie(
            SESSION_COOKIE,
            sealed,
            max_age=self.cfg.session_ttl_seconds,
            **self._cookie_kwargs(),
        )
        return response

    def _sign_in_refused(self, denied: Denied) -> Response:
        """The page for a refused sign-in (closed codes, never an upstream message)."""
        key = getattr(denied, "account_key", None)
        if denied.code == DENY_ACCESS_DISABLED:
            logger.warning("account sign-in refused: account disabled account=%s", key)
            if key:
                audit.log_principal_event("sign_in_refused", key, reason="access_disabled")
            return self.message_page(
                403,
                _bi(
                    "你的访问权限已被管理员停用。请联系服务器所有者恢复。",
                    "Your access to this server was disabled by an administrator. Contact the server owner to have it restored.",
                ),
            )
        if denied.code == DENY_SIGNUPS_PAUSED:
            logger.warning("account sign-in refused: sign-ups paused")
        return self.message_page(403, _denial_html(denied.message))

    async def _exchange_code(self, code: str, verifier: str) -> str | None:
        form = {
            "client_id": self.cfg.client_id,
            "client_secret": self.cfg.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.base + ACCOUNT_CALLBACK_PATH,
            "code_verifier": verifier,
            "scope": _SCOPE,
        }
        try:
            async with self._client_factory() as client:
                resp = await client.post(
                    self._authority_url("oauth2/v2.0/token"),
                    data=form,
                    headers={"Accept": "application/json"},
                    timeout=10.0,
                    follow_redirects=False,
                )
            if resp.status_code != 200:
                logger.warning("account token exchange failed: status %s", resp.status_code)
                return None
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("account token exchange failed: %s", type(exc).__name__)
            return None
        token = data.get("id_token") if isinstance(data, dict) else None
        return token if isinstance(token, str) and token else None

    async def _verify_id_token(self, id_token: str) -> Mapping[str, Any] | None:
        verifier = self._id_token_verifier or self._default_verifier()
        try:
            return await verifier(id_token)
        except Exception as exc:  # noqa: BLE001
            logger.warning("account id_token verification error: %s", type(exc).__name__)
            return None

    def _default_verifier(self) -> IdTokenVerifier:
        from fastmcp.server.auth.providers.jwt import JWTVerifier

        authority = self.cfg.authority_host
        tid = self.cfg.tenant_id
        jwt_verifier = JWTVerifier(
            jwks_uri=f"https://{authority}/{tid}/discovery/v2.0/keys",
            issuer=f"https://{authority}/{tid}/v2.0",
            audience=self.cfg.client_id,
            algorithm="RS256",
        )

        async def verify(token: str) -> Mapping[str, Any] | None:
            access = await jwt_verifier.verify_token(token)
            return access.claims if access is not None and access.claims else None

        # Cache so the JWKS (cached for an hour by the verifier) is reused.
        self._id_token_verifier = verify
        return verify

    # -- Canvas verification -------------------------------------------------

    async def _default_whoami(self, token: str, api_url: str) -> CanvasIdentity:
        url = api_url.rstrip("/") + "/users/self"
        try:
            async with self._client_factory() as client:
                resp = await client.get(
                    url,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                    },
                    timeout=10.0,
                    follow_redirects=False,
                )
            if resp.status_code in (401, 403):
                raise CanvasCheckError("invalid")
            if resp.status_code != 200:
                raise CanvasCheckError("unavailable")
            data = resp.json()
        except CanvasCheckError:
            raise
        except (httpx.HTTPError, ValueError):
            raise CanvasCheckError("unavailable") from None
        if not isinstance(data, dict) or data.get("id") is None:
            raise CanvasCheckError("unavailable")
        name = data.get("name") or data.get("short_name") or ""
        return CanvasIdentity(str(data["id"]), str(name)[:200])

    # -- POST plumbing -------------------------------------------------------

    async def _read_form(
        self, request: Request, max_fields: int = 10
    ) -> dict[str, str] | Response:
        media = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if media != _FORM_CONTENT_TYPE:
            return self.message_page(
                415, _bi("不支持的内容类型。", "Unsupported content type.")
            )
        too_big = self.message_page(
            413, _bi("请求内容过大。", "The request is too large.")
        )
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                return self.message_page(
                    400, _bi("请求格式不正确。", "Malformed request.")
                )
            if length < 0:
                return self.message_page(
                    400, _bi("请求格式不正确。", "Malformed request.")
                )
            if length > _MAX_BODY_BYTES:
                return too_big
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > _MAX_BODY_BYTES:
                return too_big
            chunks.append(chunk)
        try:
            text = b"".join(chunks).decode("utf-8")
            parsed = urllib.parse.parse_qs(
                text, keep_blank_values=True, max_num_fields=max_fields
            )
        except (UnicodeDecodeError, ValueError):
            return self.message_page(400, _bi("请求格式不正确。", "Malformed request."))
        return {key: values[0] for key, values in parsed.items() if values}

    async def _guard_post(
        self,
        request: Request,
        *,
        owner_only: bool = False,
        active_only: bool = False,
        max_fields: int = 10,
    ) -> tuple[_Session, dict[str, str]] | Response:
        """Session, Origin, content type, size and CSRF checks for a POST.

        ``active_only`` refuses an account that waits for approval (it has no token to
        save, check or switch tools for).
        """
        session = self._session_of(request)
        if session is None:
            if owner_only:
                return self.message_page(403, _bi("无权访问。", "Forbidden."))
            return self.redirect(ACCOUNT_PATH, 303)
        if active_only and session.pending:
            return self.message_page(403, self._pending_message())
        if owner_only:
            refusal = self._owner_refusal(session)
            if refusal is not None:
                return refusal
        if request.headers.get("origin") != self.base:
            return self.message_page(
                403, _bi("请求来源不被允许。", "The request origin is not allowed.")
            )
        form = await self._read_form(request, max_fields)
        if isinstance(form, Response):
            return form
        if not self._csrf_ok(session, form.get("csrf")):
            return self.message_page(
                403,
                _bi(
                    "安全校验失败，请刷新页面后重试。",
                    "Security check failed. Reload the page and try again.",
                ),
            )
        return session, form

    @staticmethod
    def _pending_message() -> str:
        return _bi(
            "你的账户正在等待服务器所有者批准，批准之前不能绑定令牌。",
            "Your account is waiting for the server owner's approval, so a token cannot be saved yet.",
        )

    # -- POST handlers -------------------------------------------------------

    async def save_token(self, request: Request) -> Response:
        guarded = await self._guard_post(request, active_only=True)
        if isinstance(guarded, Response):
            return guarded
        session, form = guarded

        if not self.limiter.allow((session.acct,)):
            return await self._token_error(
                session,
                429,
                _bi(
                    "尝试次数过多，请 10 分钟后再试。",
                    "Too many attempts. Try again in 10 minutes.",
                ),
            )
        token = form.get("canvas_token", "").strip()
        if not _TOKEN_RE.fullmatch(token):
            return await self._token_error(
                session,
                400,
                _bi(
                    "令牌格式不正确，请重新复制完整的令牌。",
                    "That does not look like a Canvas token. Copy the whole token.",
                ),
            )
        expiry = _parse_expiry(form.get("expires_on", ""), self.clock())
        if isinstance(expiry, str):
            return await self._token_error(
                session,
                400,
                _bi(
                    "到期日无效，请选择今天或之后的日期。",
                    "That expiry date is not valid. Pick today or a later date.",
                ),
            )
        raw_school = form.get("school", "")
        chosen = await self._choose_school(raw_school)
        selected = self._selection(raw_school, session, posted=True)
        if not isinstance(chosen, School):
            status, message = chosen
            return await self._token_error(session, status, message, selected=selected)
        school = chosen
        try:
            identity = await self._canvas_whoami(token, school.api_url)
        except CanvasCheckError as exc:
            if exc.kind == "invalid":
                return await self._token_error(
                    session,
                    400,
                    _bi("Canvas 拒绝了这个令牌。", "Canvas rejected this token."),
                    selected=selected,
                )
            return await self._token_error(
                session,
                503,
                _bi(
                    "暂时无法连接 Canvas，请稍后再试。",
                    "Canvas is unavailable right now. Try again later.",
                ),
                selected=selected,
            )
        existing = await anyio.to_thread.run_sync(self._safe_info, session)
        if existing is not None and self._identity_changed(existing, school, identity):
            principal_key = self._principal_key(session)
            confirmation = self._identity_confirmation(
                session, school.host, existing.canvas_user_id, identity.user_id
            )
            if not hmac.compare_digest(
                form.get("confirm_identity_change", "").encode("utf-8"),
                confirmation.encode("utf-8"),
            ):
                logger.warning(
                    "account token identity change needs confirmation account=%s", session.acct
                )
                audit.log_token_event(
                    "identity_change_detected", principal_key, outcome="confirmation_required"
                )
                return await self._token_error(
                    session,
                    409,
                    _bi(
                        "这个令牌属于另一个 Canvas 用户。请勾选下方的确认框后再保存。",
                        "This token belongs to a different Canvas user. Tick the confirmation box below and save again.",
                    ),
                    selected=selected,
                    identity_change=(existing.canvas_user_name, identity.name, confirmation),
                )
            logger.warning("account token identity change confirmed account=%s", session.acct)
            audit.log_token_event(
                "identity_change_confirmed", principal_key, outcome="confirmed"
            )
        try:
            await anyio.to_thread.run_sync(
                functools.partial(
                    self.store.put,
                    principal_key=session.acct,
                    api_token=token,
                    canvas_user_id=identity.user_id,
                    canvas_user_name=identity.name,
                    canvas_host=school.host,
                    expires_hint_at=expiry,
                )
            )
        except PrincipalDisabledError:
            # Disabled after the session was checked: the store refused the write.
            audit.log_principal_event("enroll_refused", self._principal_key(session))
            return self.message_page(
                403,
                _bi(
                    "你的访问权限已被管理员停用，无法绑定令牌。",
                    "Your access to this server was disabled by an administrator, so a token cannot be saved.",
                ),
            )
        except PrincipalPendingError:
            # Not approved (or no longer approved) when the write happened.
            audit.log_principal_event("enroll_refused", self._principal_key(session), reason="pending")
            return self.message_page(403, self._pending_message())
        except PrincipalMissingError:
            audit.log_principal_event("enroll_refused", self._principal_key(session), reason="missing")
            return self.message_page(
                403, _bi("此账号不可使用。", "This account cannot be used.")
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("account token save failed: %s", type(exc).__name__)
            return await self._token_error(
                session,
                503,
                _bi("暂时无法保存令牌。", "The token could not be saved right now."),
                selected=selected,
            )
        self.health.forget(self._principal_key(session))
        logger.info("account token enrolled account=%s host=%s", session.acct, school.host)
        return self.redirect(ACCOUNT_PATH, 303)

    @staticmethod
    def _principal_key(session: _Session) -> str:
        return session.acct

    def _identity_changed(
        self, existing: EnrollmentInfo, school: School, identity: CanvasIdentity
    ) -> bool:
        """True when the token is for another Canvas user than the one enrolled, same school.

        Canvas user ids are per school, so a different id at a different school
        means nothing and is not a change.
        """
        default = self.schools.default
        enrolled_host = existing.canvas_host or (default.host if default is not None else None)
        if enrolled_host is None or enrolled_host != school.host:
            return False
        return existing.canvas_user_id != identity.user_id

    async def _choose_school(self, raw: str) -> School | tuple[int, str]:
        """The school to enroll at, or (status, message html) when it is refused.

        Nothing is sent to the school (or anywhere else) before every check has
        passed: syntax, the operator's list or the directory's confirmation, and
        the public-address check on what the name resolves to.
        """
        policy = self.schools
        value = raw.strip().lower()
        default = policy.default
        if not value:
            if default is not None and policy.picker_enabled:
                return default
            sole = policy.sole_school
            if sole is None:
                return 400, _bi("请选择你的学校。", "Choose your school.")
            return await self._public_school_or_refusal(sole)
        if default is not None and value == default.host:
            # The operator's own pin: kept exactly as before, no DNS check.
            return default
        invalid = (400, _bi("学校地址无效。", "That school address is not valid."))
        host = parse_hostname(value)
        if host is None or is_blocked_hostname(host):
            return invalid
        school = policy.featured_school(host)
        if school is None:
            if not policy.search_enabled:
                return 400, _bi("此服务器不提供该学校。", "This server does not offer that school.")
            try:
                entry = await self._directory.confirm(host)
            except DirectoryError:
                return 503, _bi(
                    "暂时无法连接学校目录。", "The school directory is unavailable right now."
                )
            if entry is None:
                return 400, _bi(
                    "学校目录里没有这个地址。", "That address is not in the school directory."
                )
            school = School(host, f"https://{host}/api/v1", entry.name)
        return await self._public_school_or_refusal(school)

    async def _public_school_or_refusal(self, school: School) -> School | tuple[int, str]:
        """Refuse a school whose name does not resolve, or resolves to a non-public address.

        The operator's default school is their own pin and is not checked.
        """
        if school.is_default:
            return school
        verdict = await check_public_host(school.host, self._resolve_host)
        if verdict == "unresolvable":
            return 400, _bi("找不到该学校的服务器。", "Could not find that school's server.")
        if verdict == "blocked":
            return 400, _bi("该学校的地址不被允许。", "That school's address is not allowed.")
        return school

    async def _token_error(
        self,
        session: _Session,
        status: int,
        message_html: str,
        *,
        selected: str | None = None,
        identity_change: tuple[str, str, str] | None = None,
    ) -> Response:
        info = await anyio.to_thread.run_sync(self._safe_info, session)
        return await self.account_page(
            session,
            info,
            ("error", message_html),
            status,
            selected=selected,
            identity_change=identity_change,
        )

    def _safe_info(self, session: _Session) -> EnrollmentInfo | None:
        try:
            return self.store.info(session.acct)
        except Exception:  # noqa: BLE001
            return None

    async def delete_token(self, request: Request) -> Response:
        guarded = await self._guard_post(request)
        if isinstance(guarded, Response):
            return guarded
        session, _form = guarded
        # A self-disconnect: it removes the user's own token and nothing else. It is
        # not an authorization decision, so it does not touch the access status.
        removed = await anyio.to_thread.run_sync(self.store.delete, session.acct)
        logger.info("account token deleted account=%s", session.acct)
        if removed:
            audit.log_principal_event("self_disconnected", self._principal_key(session))
        return self.redirect(ACCOUNT_PATH, 303)

    async def recheck_token(self, request: Request) -> Response:
        """Probe Canvas once with the stored token and restore it if Canvas accepts it."""
        guarded = await self._guard_post(request, active_only=True)
        if isinstance(guarded, Response):
            return guarded
        session, _form = guarded
        if not self.recheck_limiter.allow((session.acct,)):
            return await self._token_error(
                session,
                429,
                _bi(
                    "每分钟只能重新检测一次，请稍后再试。",
                    "You can check once a minute. Try again shortly.",
                ),
            )
        info = await anyio.to_thread.run_sync(self._safe_info, session)
        if (
            info is None
            or info.status != STATUS_INVALID
            or info.invalid_reason == REASON_REVOKED_BY_ADMIN
        ):
            # Nothing to check, or an administrator's decision that only a new
            # token can undo.
            return self.redirect(ACCOUNT_PATH, 303)
        principal_key = self._principal_key(session)
        school = self.schools.resolve_stored(info.canvas_host)
        if school is None:
            return await self._token_error(
                session,
                400,
                _bi(
                    "服务器已不再支持你登记的学校，请重新登记。",
                    "This server no longer offers your school. Enroll again.",
                ),
            )
        try:
            stored = await anyio.to_thread.run_sync(self.store.get, session.acct)
        except TokenDecryptionError:
            audit.log_token_event("recheck", principal_key, outcome="unreadable")
            return await self._token_error(
                session,
                400,
                _bi(
                    "仍然无法读取保存的令牌，请粘贴一个新的令牌。",
                    "The saved token still cannot be read. Paste a new one.",
                ),
            )
        if stored is None:
            return self.redirect(ACCOUNT_PATH, 303)
        try:
            await self._canvas_whoami(stored.api_token, school.api_url)
        except CanvasCheckError as exc:
            if exc.kind == "invalid":
                logger.info("account recheck still rejected account=%s", session.acct)
                audit.log_token_event("recheck", principal_key, outcome="still_rejected")
                return await self._token_error(
                    session,
                    400,
                    _bi(
                        "Canvas 仍然拒绝这个令牌，请生成新的令牌并粘贴到下方。",
                        "Canvas still rejects this token. Generate a new one and paste it below.",
                    ),
                )
            audit.log_token_event("recheck", principal_key, outcome="unavailable")
            return await self._token_error(
                session,
                503,
                _bi(
                    "暂时无法连接 Canvas，请稍后再试。",
                    "Canvas is unavailable right now. Try again later.",
                ),
            )
        restored = await anyio.to_thread.run_sync(
            functools.partial(
                self.store.restore_active,
                principal_key,
                expected_updated_at=info.updated_at,
                # The token that Canvas just accepted is the one that was read
                # above; a replacement saved meanwhile has another generation.
                expected_generation=stored.credential_generation,
            )
        )
        if not restored:
            # The token was replaced or removed while Canvas was being asked.
            return self.redirect(ACCOUNT_PATH, 303)
        self.health.forget(principal_key)
        logger.info("account recheck restored account=%s", session.acct)
        audit.log_token_event("recheck", principal_key, outcome="restored")
        fresh = await anyio.to_thread.run_sync(self._safe_info, session)
        return await self.account_page(
            session,
            fresh,
            ("ok", _bi("Canvas 接受了这个令牌，已恢复使用。", "Canvas accepts this token again. It is active.")),
        )

    # -- write tools ---------------------------------------------------------

    @staticmethod
    def _group_title(group: str) -> str:
        titles = {
            "planner": _bi("计划与日历", "Planner and calendar"),
            "submissions": _bi("作业提交与评论", "Submissions and comments"),
            "modules": _bi("模块完成", "Module completion"),
            "inbox": _bi("站内信", "Inbox"),
            OTHER_GROUP: _bi("其他写工具", "Other write tools"),
        }
        return titles[group]

    @staticmethod
    def _tool_note(name: str) -> str:
        """One line on what the tool changes, with the risk where there is one."""
        notes = {
            "create_planner_note": _bi(
                "在你的 Canvas 计划表里新建一条个人备忘。",
                "Adds a personal note to your Canvas planner.",
            ),
            "update_planner_note": _bi(
                "修改你的一条计划备忘。", "Edits one of your planner notes."
            ),
            "delete_planner_note": _bi(
                "删除你的一条计划备忘。", "Deletes one of your planner notes."
            ),
            "mark_planner_item_complete": _bi(
                "把计划表里的事项标为已完成或未完成。",
                "Marks an item in your planner as done or not done.",
            ),
            "create_personal_calendar_event": _bi(
                "在你的个人 Canvas 日历里新建一个事件。",
                "Adds an event to your personal Canvas calendar.",
            ),
            "delete_personal_calendar_event": _bi(
                "删除你个人日历里的一个事件。",
                "Deletes an event from your personal calendar.",
            ),
            "submit_assignment": _bi(
                "以你的名义提交作业。提交可能计入成绩，而且可能无法撤回。",
                "Submits work for an assignment in your name. A submission can count toward your grade and may not be undoable.",
            ),
            "comment_on_my_submission": _bi(
                "在你自己的提交下发表评论，老师可以看到。",
                "Posts a comment on your own submission, which your instructors can see.",
            ),
            "mark_module_item_done": _bi(
                "替你把模块里的一项标为已完成，这可能解锁后面的内容。",
                "Marks a module item as done for you, which can unlock later items.",
            ),
            "send_message": _bi(
                "以你的名义向你指定的人发送 Canvas 站内信，对方会看到。",
                "Sends a Canvas inbox message in your name to the people you pick. They will see it.",
            ),
            "reply_to_conversation": _bi(
                "以你的名义回复一个已有的 Canvas 会话，对方会看到。",
                "Replies in an existing Canvas conversation in your name. The others will see it.",
            ),
        }
        note = notes.get(name)
        if note is not None:
            return note
        if TOOL_EFFECTS.get(name) is Effect.LOCAL_WRITE:
            return _bi("在服务器上写入文件。", "Writes files on the server.")
        return _bi(
            "以你的名义修改 Canvas 中的内容。",
            "Changes things in Canvas in your name.",
        )

    def _write_group_rows(
        self,
        group: str,
        names: list[str],
        offered: frozenset[str],
        prefs: ToolPrefs | None,
    ) -> str:
        enabled = prefs.enabled_write_tools if prefs is not None else frozenset()
        rows: list[str] = []
        for name in names:
            is_offered = name in offered
            checked = " checked" if is_offered and name in enabled else ""
            disabled = "" if is_offered else " disabled"
            extra = ""
            if not is_offered:
                kept = (
                    _bi("（你之前的选择会保留）", " (your earlier choice is kept)")
                    if name in enabled
                    else ""
                )
                extra = (
                    f' <span class="muted small">'
                    f'{_bi("本服务器未开放", "not offered on this server")}{kept}</span>'
                )
            elif name in enabled and prefs is not None and name in prefs.enabled_at:
                extra = (
                    f' <span class="muted small">'
                    f'{_bi("开启于", "on since")} {_e(_fmt_date(prefs.enabled_at[name]))}</span>'
                )
            rows.append(
                '<label class="choice">'
                f'<input type="checkbox" name="tool.{_e(name)}" value="1"{checked}{disabled}>'
                f"<span><code>{_e(name)}</code>{extra}<br>"
                f'<span class="muted small">{self._tool_note(name)}</span></span></label>'
            )
        return (
            f"<fieldset><legend>{self._group_title(group)}</legend>{''.join(rows)}</fieldset>"
        )

    async def _write_tools_section(
        self,
        session: _Session,
        notice: tuple[Literal["error", "ok"], str] | None = None,
    ) -> str:
        """The "Write tools" card: the three layers, and one checkbox per write tool."""
        if self.write_tools is None:
            return ""
        notice_html = (
            f'<div class="notice {notice[0]}" role="status">{notice[1]}</div>'
            if notice is not None
            else ""
        )
        try:
            offered = await self.write_tools.offered()
            prefs = await anyio.to_thread.run_sync(
                self.store.get_tool_prefs, self._principal_key(session)
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("account write tools read failed: %s", type(exc).__name__)
            return (
                f'<section class="card" id="write-tools"><h2>{_bi("写工具", "Write tools")}</h2>'
                f'<p class="warn">{_bi("暂时无法读取写工具设置。", "Your write-tool settings cannot be read right now.")}</p>'
                f"{notice_html}</section>"
            )
        enabled = prefs.enabled_write_tools if prefs is not None else frozenset()

        grouped: list[tuple[str, list[str]]] = []
        known: set[str] = set()
        for group, names in WRITE_TOOL_GROUPS:
            grouped.append((group, list(names)))
            known.update(names)
        others = sorted(name for name in offered if name not in known)
        if others:
            grouped.append((OTHER_GROUP, others))
        # Names the user had on that this server no longer offers and the page has
        # no row for: kept in the database, listed here so they are not invisible.
        hidden_kept = sorted(
            name for name in enabled if name not in offered and name not in known
        )

        intro = (
            f"<p>{_bi('默认情况下，AI 助手只能读取你的 Canvas 数据。写工具可以以你的名义修改 Canvas 里的内容，所以每一个都保持关闭，直到你在这里打开。只有你本人能在这个页面改这些开关，聊天消息和任何工具都改不了。', 'By default the AI assistant can only read your Canvas data. A write tool lets it change something in Canvas in your name, so each one stays off until you turn it on here. Only you can change these switches, and only from this page: no chat message or tool can.')}</p>"
            "<ol>"
            f"<li><strong>{_bi('服务器允许', 'The server allows it')}</strong>: "
            f"{_bi('服务器管理员决定有哪些写工具可用。服务器没有开放的工具，你无法打开。', 'The server operator decides which write tools exist at all. You cannot turn on a tool the server does not offer.')}</li>"
            f"<li><strong>{_bi('你已开启', 'You turn it on')}</strong>: "
            f"{_bi('在下面勾选你需要的工具。在你勾选之前一个都不会开启，管理员以后新增的工具也默认关闭。', 'Tick the tools you want below. Nothing is on until you do, and tools the operator adds later start off.')}</li>"
            f"<li><strong>{_bi('课程允许', 'Your course allows it')}</strong>: "
            f"{_bi('每门课程仍可以拒绝写入。每次使用工具时都会检查，只会收窄你开启的范围，不会放宽。', 'Each course can still refuse writes. That is checked every time a tool is used, and it can only narrow what you turned on, never widen it.')}</li>"
            "</ol>"
            f'<p class="muted small">{_bi("开启工具不会跳过任何保护：写工具仍然会先预览并要求确认，你的 AI 应用也可能让你逐次批准。开启需要最近 10 分钟内的登录，关闭则不需要。", "Turning a tool on skips no safeguard: write tools still show a preview and ask for confirmation, and your AI app may ask you to approve each call. Turning a tool on needs a sign-in from the last 10 minutes; turning one off never does.")}</p>'
            f'<p class="muted small">{_bi("AI 应用可能会缓存工具列表。修改之后，请开启新的对话或重新连接连接器，让它看到变化。", "AI apps may remember the tool list. After a change, start a new chat or reconnect the connector so the app sees it.")}</p>'
        )
        if not offered:
            intro += (
                f'<p class="warn">{_bi("本服务器没有开放任何写工具，所以下面的开关都不可用。", "This server does not offer any write tools, so the switches below are unavailable.")}</p>'
            )

        fieldsets = "".join(
            self._write_group_rows(group, names, offered, prefs)
            for group, names in grouped
        )
        kept_line = ""
        if hidden_kept:
            kept_line = (
                f'<p class="muted small">{_bi("已保留但本服务器未开放：", "Kept, but not offered on this server:")} '
                f"{', '.join(f'<code>{_e(name)}</code>' for name in hidden_kept)}</p>"
            )
        buttons = ""
        if offered or enabled:
            buttons = (
                f'<button class="btn" type="submit">{_bi("保存", "Save")}</button> '
                '<button class="btn danger" type="submit" name="disable_all" value="1" '
                f'formnovalidate>{_bi("全部关闭", "Turn all off")}</button>'
            )
        return (
            f'<section class="card" id="write-tools"><h2>{_bi("写工具", "Write tools")}</h2>'
            f"{notice_html}{intro}"
            f'<form method="post" action="{_WRITE_TOOLS_PATH}#write-tools">'
            f"{_csrf_field(session.csrf)}{fieldsets}{kept_line}{buttons}</form></section>"
        )

    async def save_write_tools(self, request: Request) -> Response:
        """Save the user's write-tool switches; turning any on needs a recent sign-in."""
        guarded = await self._guard_post(request, active_only=True, max_fields=_WRITE_FORM_MAX_FIELDS)
        if isinstance(guarded, Response):
            return guarded
        session, form = guarded
        if self.write_tools is None:
            return self.message_page(
                404, _bi("此服务器没有写工具设置。", "This server has no write-tool settings.")
            )
        key = self._principal_key(session)

        async def show(
            kind: Literal["error", "ok"], message: str, status: int
        ) -> Response:
            info = await anyio.to_thread.run_sync(self._safe_info, session)
            # The result is shown at the top of the page too, like every other
            # form: the card is the last section and the response starts at the
            # top, so a user on a small screen would otherwise see no feedback.
            return await self.account_page(
                session,
                info,
                (kind, message),
                status=status,
                write_notice=(kind, message),
            )

        try:
            offered = await self.write_tools.offered()
            prefs = await anyio.to_thread.run_sync(self.store.get_tool_prefs, key)
        except Exception as exc:  # noqa: BLE001
            logger.error("account write tools read failed: %s", type(exc).__name__)
            return await show(
                "error",
                _bi("暂时无法读取写工具设置。", "Your write-tool settings cannot be read right now."),
                503,
            )
        current = prefs.enabled_write_tools if prefs is not None else frozenset()

        if form.get("disable_all") == "1":
            desired: frozenset[str] = frozenset()
        else:
            # Only tools the server offers can be ticked; names that are kept but
            # not offered stay as they are. A submitted name outside "offered" is
            # ignored, so this form can never widen the server's ceiling.
            ticked = frozenset(
                name for name in offered if user_can_enable(name) and form.get(f"tool.{name}") == "1"
            )
            desired = ticked | (current - offered)
        turned_on = desired - current
        turned_off = current - desired

        if turned_on and not self._signed_in_recently(session):
            audit.log_write_tools_event(
                "refused", key, enabled=turned_on, disabled=(), outcome="sign_in_too_old"
            )
            return await show(
                "error",
                _bi(
                    "为了安全，开启写工具需要最近 10 分钟内的登录。请退出后重新登录，再试一次。关闭写工具不受此限制。",
                    "For your security, turning on a write tool needs a sign-in from the last 10 minutes. Sign out, sign in again and retry. Turning tools off is always allowed.",
                ),
                403,
            )
        if not turned_on and not turned_off:
            return await show("ok", _bi("没有需要保存的更改。", "Nothing to change."), 200)

        try:
            await anyio.to_thread.run_sync(
                functools.partial(self.store.set_tool_prefs, key, desired)
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("account write tools save failed: %s", type(exc).__name__)
            return await show(
                "error",
                _bi("暂时无法保存写工具设置。", "The write-tool settings could not be saved right now."),
                503,
            )
        if self.tool_prefs is not None:
            self.tool_prefs.invalidate(key)
        audit.log_write_tools_event(
            "cleared" if not desired else "changed",
            key,
            enabled=turned_on,
            disabled=turned_off,
        )
        logger.info(
            "account write tools changed account=%s on=%d off=%d",
            session.acct,
            len(turned_on),
            len(turned_off),
        )
        return await show("ok", _bi("写工具设置已保存。", "Write-tool settings saved."), 200)

    async def logout(self, request: Request) -> Response:
        guarded = await self._guard_post(request)
        if isinstance(guarded, Response):
            return guarded
        response = self.redirect(ACCOUNT_PATH, 303)
        self.clear_cookie(response, SESSION_COOKIE)
        return response

    # -- admin ---------------------------------------------------------------

    @staticmethod
    def _reason_label(reason: str | None) -> str:
        if reason == REASON_CANVAS_TOKEN_REJECTED:
            return _bi("Canvas 拒绝了令牌", "Rejected by Canvas")
        if reason == REASON_DECRYPT_FAILED:
            return _bi("无法解密", "Could not be decrypted")
        if reason == REASON_REVOKED_BY_ADMIN:
            return _bi("管理员标记为失效", "Marked invalid by an administrator")
        return "-"

    def _owner_refusal(self, session: _Session | None) -> Response | None:
        """A refusal page unless this is an owner who signed in recently, else None.

        The cookie's owner flag is only a snapshot (already combined with the stored
        flag by :meth:`_resolve_session`); the Entra role is re-evaluated by requiring
        a sign-in from the last ``_OWNER_FRESH_SECONDS``.
        """
        if session is None or not session.owner:
            return self.message_page(403, _bi("无权访问。", "Forbidden."))
        if not self._signed_in_recently(session):
            return self.message_page(
                403,
                _bi(
                    "为了安全，管理功能需要最近 10 分钟内的登录。请退出后重新登录，再试一次。",
                    "For your security, the admin pages need a sign-in from the last 10 minutes. Sign out, sign in again and retry.",
                ),
            )
        return None

    @staticmethod
    def _disabled_by_label(status: PrincipalStatus) -> str:
        if status.disabled_reason == DISABLE_REASON_OPERATOR:
            return _bi("由服务器运维停用", "Disabled by the server operator")
        if status.disabled_reason == DISABLE_REASON_DENIED:
            return _bi("申请被拒绝", "Request denied")
        return _bi("由管理员停用", "Disabled by an administrator")

    def _admin_status(self, row: EnrollmentInfo | None, access: PrincipalStatus) -> str:
        if access.pending:
            return (
                f"<strong>{_bi('等待批准', 'Waiting for approval')}</strong><br>"
                f'<span class="muted">{_bi("申请时间", "Requested")}: '
                f"{_e(_fmt_ts(access.created_at))}</span>"
            )
        if access.disabled:
            token_line = ""
            if row is not None and row.status == STATUS_INVALID:
                token_line = f'<br><span class="muted">{self._reason_label(row.invalid_reason)}</span>'
            return (
                f"<strong>{_bi('已停用', 'Disabled')}</strong><br>"
                f'<span class="muted">{self._disabled_by_label(access)}</span><br>'
                f'<span class="muted">{_bi("停用时间", "Disabled since")}: '
                f"{_e(_fmt_ts(access.disabled_at))}</span>{token_line}"
            )
        owner = (
            f'<br><span class="muted">{_bi("所有者", "Owner")}</span>' if access.is_owner else ""
        )
        if row is None or row.status != STATUS_INVALID:
            return _bi("正常", "Active") + owner
        return (
            f"<strong>{_bi('需重新绑定', 'Needs re-enroll')}</strong><br>"
            f'<span class="muted">{self._reason_label(row.invalid_reason)}</span><br>'
            f'<span class="muted">{_bi("失效时间", "Invalid since")}: '
            f"{_e(_fmt_ts(row.invalid_since))}</span>{owner}"
        )

    def _admin_actions(
        self,
        session: _Session,
        key: str,
        row: EnrollmentInfo | None,
        access: PrincipalStatus,
    ) -> str:
        forms: list[str] = []
        csrf = _csrf_field(session.csrf)
        target = f'<input type="hidden" name="principal_key" value="{_e(key)}">'
        if access.pending:
            forms.append(
                f'<form method="post" action="{_ADMIN_APPROVE_PATH}">{csrf}{target}'
                f'<button class="btn sm" type="submit">{_bi("批准", "Approve")}</button>'
                "</form>"
            )
            forms.append(
                f'<form method="post" action="{_ADMIN_DENY_PATH}">{csrf}{target}'
                f'<button class="btn danger sm" type="submit">{_bi("拒绝", "Deny")}</button>'
                "</form>"
            )
            return "".join(forms)
        if row is not None and row.status != STATUS_INVALID and access.active:
            forms.append(
                f'<form method="post" action="{_ADMIN_INVALIDATE_PATH}">{csrf}{target}'
                f'<button class="btn secondary sm" type="submit">{_bi("标记为失效", "Mark as invalid")}</button>'
                "</form>"
            )
        if access.disabled:
            forms.append(
                f'<form method="post" action="{_ADMIN_ENABLE_PATH}">{csrf}{target}'
                f'<button class="btn sm" type="submit">{_bi("重新启用用户", "Enable user")}</button>'
                "</form>"
            )
        elif key == self._principal_key(session):
            forms.append(f'<span class="muted small">{_bi("（你自己）", "(you)")}</span>')
        else:
            forms.append(
                f'<form method="post" action="{_ADMIN_DISABLE_PATH}">{csrf}{target}'
                f'<button class="btn danger sm" type="submit">{_bi("停用用户", "Disable user")}</button>'
                "</form>"
            )
        if row is not None:
            forms.append(
                f'<form method="post" action="{_ADMIN_REMOVE_PATH}">{csrf}{target}'
                f'<button class="btn secondary sm" type="submit">{_bi("移除绑定", "Remove enrollment")}</button>'
                "</form>"
            )
        return "".join(forms)

    def _admin_row(
        self,
        session: _Session,
        account: AccountInfo,
        row: EnrollmentInfo | None,
    ) -> str:
        access = account.status
        key = account.principal_key
        who = (
            f"{_e(access.display_name)}<br>"
            f'<span class="muted">{_e(account.username)}</span>'
        )
        identity = account.identities[0] if account.identities else None
        provider = (
            self._auth_provider(identity.provider_id) if identity is not None else "-"
        )
        tenant = identity.tenant_id if identity is not None else ""
        subject = identity.subject if identity is not None else ""
        if row is not None:
            canvas = (
                f'{_e(row.canvas_user_name)}<br><span class="muted">id {_e(row.canvas_user_id)}</span>'
            )
            school = self._admin_school(row)
            enrolled = (
                f"<dt>{_bi('绑定时间', 'Enrolled')}</dt><dd>{_e(_fmt_ts(row.created_at))}</dd>"
                f"<dt>{_bi('更新时间', 'Updated')}</dt><dd>{_e(_fmt_ts(row.updated_at))}</dd>"
            )
            verified = _e(_fmt_ts(row.last_verified_at))
            used = _e(_fmt_ts(row.last_used_at))
        else:
            canvas = '<span class="muted">-</span>'
            school = '<span class="muted">-</span>'
            enrolled = (
                f"<dt>{_bi('绑定', 'Enrollment')}</dt>"
                f"<dd>{_bi('没有保存的令牌', 'no saved token')}</dd>"
            )
            verified = "-"
            used = "-"
        return (
            "<tr>"
            f'<td data-label="{_e(_bi("Entra 用户", "Entra user"))}">{who}'
            '<details class="tech">'
            f"<summary>{_bi('技术信息', 'Technical details')}</summary><dl>"
            f"<dt>{_bi('登录方式', 'Sign-in')}</dt><dd>{_e(provider)}</dd>"
            f"<dt>{_bi('租户', 'Tenant')}</dt><dd><code>{_e(tenant)}</code></dd>"
            f"<dt>{_bi('对象 ID', 'Object')}</dt><dd><code>{_e(subject)}</code></dd>"
            f"<dt>{_bi('账户', 'Account')}</dt><dd><code>{_e(key)}</code></dd>"
            f"{enrolled}"
            "</dl></details></td>"
            f'<td data-label="{_e(_bi("Canvas 用户", "Canvas user"))}">{canvas}</td>'
            f'<td data-label="{_e(_bi("学校", "School"))}">{school}</td>'
            f'<td data-label="{_e(_bi("状态", "Status"))}">{self._admin_status(row, access)}</td>'
            f'<td data-label="{_e(_bi("最近验证", "Last verified"))}">{verified}</td>'
            f'<td data-label="{_e(_bi("最近使用", "Last used"))}">{used}</td>'
            f'<td class="act">{self._admin_actions(session, key, row, access)}</td></tr>'
        )

    async def admin(self, request: Request) -> Response:
        session = self._session_of(request)
        refusal = self._owner_refusal(session)
        if session is None or refusal is not None:
            return refusal or self.message_page(403, _bi("无权访问。", "Forbidden."))
        all_rows = await anyio.to_thread.run_sync(self.store.list_enrollments)
        accounts = await anyio.to_thread.run_sync(self.store.list_accounts)
        by_key = {a.principal_key: a for a in accounts}
        needing = [row for row in all_rows if row.status == STATUS_INVALID]
        only_needing = request.query_params.get("filter") == _FILTER_NEEDS_REENROLL
        entries: list[tuple[AccountInfo, EnrollmentInfo | None]] = []
        seen: set[str] = set()
        for row in needing if only_needing else all_rows:
            key = row.principal_key
            seen.add(key)
            entries.append(
                (by_key.get(key) or AccountInfo(PrincipalStatus(key, status="missing"), ()), row)
            )
        if not only_needing:
            # A pending or disabled user without an enrollment must still be listed, or
            # nobody could approve or enable them.
            entries.extend(
                (a, None)
                for a in accounts
                if (a.status.pending or a.status.disabled) and a.principal_key not in seen
            )
        entries.sort(key=lambda entry: 0 if entry[0].status.pending else 1)
        disabled_total = sum(1 for a in accounts if a.status.disabled)
        pending_total = sum(1 for a in accounts if a.status.pending)
        lines = [self._admin_row(session, account, row) for account, row in entries]
        if lines:
            table = (
                '<section class="card tablecard"><table><thead><tr>'
                f"<th>{_bi('Entra 用户', 'Entra user')}</th>"
                f"<th>{_bi('Canvas 用户', 'Canvas user')}</th>"
                f"<th>{_bi('学校', 'School')}</th>"
                f"<th>{_bi('状态', 'Status')}</th>"
                f"<th>{_bi('最近验证', 'Last verified')}</th>"
                f"<th>{_bi('最近使用', 'Last used')}</th>"
                f'<th class="act"><span class="muted">{_bi("操作", "Actions")}</span></th>'
                "</tr></thead><tbody>" + "".join(lines) + "</tbody></table></section>"
            )
        elif only_needing:
            table = (
                '<section class="card">'
                f"<p>{_bi('没有需要重新绑定的用户。', 'No enrollments need a new token.')}</p></section>"
            )
        else:
            table = (
                '<section class="card">'
                f"<p>{_bi('还没有用户绑定令牌。', 'No enrollments yet.')}</p></section>"
            )
        count_text = _bi(
            "{count} 个绑定需要重新录入令牌（共 {total} 个），{disabled} 个用户已停用。",
            "{count} of {total} enrollments need a new token. {disabled} user(s) disabled.",
        ).format(count=len(needing), total=len(all_rows), disabled=disabled_total)
        if pending_total:
            count_text += " " + _bi(
                "{pending} 个账户等待批准。", "{pending} account(s) waiting for approval."
            ).format(pending=pending_total)
        if only_needing:
            filter_link = (
                f'<a href="{_ADMIN_PATH}">{_bi("显示全部", "Show all")}</a>'
            )
        else:
            filter_link = (
                f'<a href="{_ADMIN_PATH}?filter={_FILTER_NEEDS_REENROLL}">'
                f'{_bi("只看需要重新绑定的", "Show only those that need re-enroll")}</a>'
            )
        explain = (
            '<section class="card"><ul>'
            f"<li><strong>{_bi('批准 / 拒绝', 'Approve / Deny')}</strong>: "
            f"{_bi('等待批准的账户可以登录本页，但在批准之前不能绑定令牌，也不能使用任何 MCP 工具。拒绝会停用该账户，之后仍可重新启用。', 'An account that waits for approval can sign in here, but cannot add a token or use any MCP tool until you approve it. Denying disables the account; you can enable it again later.')}</li>"
            f"<li><strong>{_bi('停用用户', 'Disable user')}</strong>: "
            f"{_bi('禁止此人登录本页、绑定令牌和使用任何 MCP 工具，直到所有者重新启用。已签发的令牌和已登录的会话也会失效。保存的 Canvas 令牌不会被删除。', 'blocks this person from signing in here, enrolling a token and using any MCP tool until an owner enables them again. Tokens already issued and sessions already open stop working. The saved Canvas token is not deleted.')}</li>"
            f"<li><strong>{_bi('移除绑定', 'Remove enrollment')}</strong>: "
            f"{_bi('只删除保存的 Canvas 令牌。对方仍可重新绑定，除非已被停用。', 'deletes the saved Canvas token only. The person can enroll again unless they are disabled.')}</li>"
            "</ul>"
            f'<p class="muted small">{_bi("用户自己删除令牌只是断开自己的连接，与停用无关。你不能停用自己，也不能停用最后一位仍在启用的所有者。", "A user deleting their own token is only a self-disconnect and is not a disablement. You cannot disable yourself or the last active owner.")}</p></section>'
        )
        body = (
            _header(session)
            + f"<h1>{_bi('已绑定的用户', 'Enrollments')}</h1>"
            + f'<p class="muted">{count_text} {filter_link} · '
            + f'<a href="{_ADMIN_AUDIT_PATH}">{_bi("审计日志", "Audit log")}</a></p>'
            + explain
            + table
            + f'<p><a href="{ACCOUNT_PATH}">{_bi("返回账户页", "Back to account")}</a></p>'
        )
        return self.html_page(
            200, _bi("Canvas 绑定管理", "Canvas enrollments"), body, wide=True
        )

    def _admin_school(self, row: EnrollmentInfo) -> str:
        """A row's school for the admin table; flags rows the settings no longer allow."""
        allowed = self.schools.resolve_stored(row.canvas_host) is not None
        if row.canvas_host is None:
            default = self.schools.default
            if default is None:
                text = "-"
            else:
                text = f"{_e(default.host)} <span class=\"muted\">{_bi('（默认）', '(default)')}</span>"
        else:
            text = _e(row.canvas_host)
        if not allowed:
            text += (
                '<br><span class="muted">'
                f"{_bi('当前设置不再允许', 'Not allowed by the current settings')}</span>"
            )
        return text

    def _bad_target_page(self) -> Response:
        return self.message_page(400, _bi("用户标识不正确。", "Invalid user identifier."))

    async def admin_invalidate(self, request: Request) -> Response:
        """Owner action: mark one enrollment invalid so the user must enroll a new token."""
        guarded = await self._guard_post(request, owner_only=True)
        if isinstance(guarded, Response):
            return guarded
        session, form = guarded
        target = valid_principal_key(form.get("principal_key"))
        if target is None:
            return self._bad_target_page()
        changed = await self.health.mark_invalid(
            target, REASON_REVOKED_BY_ADMIN, actor=self._principal_key(session)
        )
        logger.info(
            "account admin mark invalid by account=%s target=%s changed=%s",
            session.acct,
            target,
            changed,
        )
        return self.redirect(_ADMIN_PATH, 303)

    async def admin_remove(self, request: Request) -> Response:
        """Owner action: delete a user's stored token. Not an access decision.

        The user can enroll again unless an owner has disabled them; use
        ``admin_disable`` to cut someone off.
        """
        guarded = await self._guard_post(request, owner_only=True)
        if isinstance(guarded, Response):
            return guarded
        session, form = guarded
        target = valid_principal_key(form.get("principal_key"))
        if target is None:
            return self._bad_target_page()
        removed = await anyio.to_thread.run_sync(
            functools.partial(self.store.delete, target, actor=self._principal_key(session))
        )
        if removed:
            audit.log_principal_event(
                "enrollment_removed", target, actor=self._principal_key(session)
            )
        logger.info(
            "account admin remove enrollment by account=%s target=%s", session.acct, target
        )
        return self.redirect(_ADMIN_PATH, 303)

    def _refused_page(self, code: str) -> Response:
        """The page for an access change the store refused."""
        if code == AccessActionRefused.LAST_OWNER:
            return self.message_page(
                409,
                _bi(
                    "不能停用最后一位仍在启用的所有者。请先添加或启用另一位所有者。",
                    "You cannot disable the last active owner. Add or enable another owner first.",
                ),
            )
        if code == AccessActionRefused.SELF:
            return self.message_page(
                400, _bi("你不能停用自己的账号。", "You cannot disable your own account.")
            )
        return self.message_page(403, _bi("无权访问。", "Forbidden."))

    def _access_changed(self, key: str) -> None:
        """Make this process notice an access change at once (others within the cache TTL)."""
        if self.access is not None:
            self.access.invalidate(key)

    async def admin_disable(self, request: Request) -> Response:
        """Owner action: disable a user. They are refused everywhere until re-enabled."""
        guarded = await self._guard_post(request, owner_only=True)
        if isinstance(guarded, Response):
            return guarded
        session, form = guarded
        target = valid_principal_key(form.get("principal_key"))
        if target is None:
            return self._bad_target_page()
        actor = self._principal_key(session)
        try:
            changed = await anyio.to_thread.run_sync(
                functools.partial(
                    self.store.disable_principal,
                    target,
                    actor=actor,
                    reason=DISABLE_REASON_ADMIN,
                )
            )
        except AccessActionRefused as exc:
            audit.log_principal_event("refused", target, actor=actor, outcome=exc.code)
            return self._refused_page(exc.code)
        except Exception as exc:  # noqa: BLE001
            logger.error("account admin disable failed: %s", type(exc).__name__)
            return self.message_page(
                503, _bi("暂时无法保存这项更改。", "The change could not be saved right now.")
            )
        self._access_changed(target)
        if changed:
            audit.log_principal_event(
                "disabled", target, actor=actor, reason=DISABLE_REASON_ADMIN
            )
        logger.info(
            "account admin disable by account=%s target=%s changed=%s", session.acct, target, changed
        )
        return self.redirect(_ADMIN_PATH, 303)

    async def admin_enable(self, request: Request) -> Response:
        """Owner action: lift a disablement. The user signs in again to get a new session."""
        guarded = await self._guard_post(request, owner_only=True)
        if isinstance(guarded, Response):
            return guarded
        session, form = guarded
        target = valid_principal_key(form.get("principal_key"))
        if target is None:
            return self._bad_target_page()
        actor = self._principal_key(session)
        try:
            changed = await anyio.to_thread.run_sync(
                functools.partial(self.store.enable_principal, target, actor=actor)
            )
        except AccessActionRefused as exc:
            audit.log_principal_event("refused", target, actor=actor, outcome=exc.code)
            return self._refused_page(exc.code)
        except Exception as exc:  # noqa: BLE001
            logger.error("account admin enable failed: %s", type(exc).__name__)
            return self.message_page(
                503, _bi("暂时无法保存这项更改。", "The change could not be saved right now.")
            )
        self._access_changed(target)
        if changed:
            audit.log_principal_event("enabled", target, actor=actor)
        logger.info(
            "account admin enable by account=%s target=%s changed=%s", session.acct, target, changed
        )
        return self.redirect(_ADMIN_PATH, 303)

    async def _decide_pending(self, request: Request, *, approve: bool) -> Response:
        guarded = await self._guard_post(request, owner_only=True)
        if isinstance(guarded, Response):
            return guarded
        session, form = guarded
        target = valid_principal_key(form.get("principal_key"))
        if target is None:
            return self._bad_target_page()
        actor = self._principal_key(session)
        action = self.store.approve_account if approve else self.store.deny_account
        try:
            changed = await anyio.to_thread.run_sync(functools.partial(action, target, actor=actor))
        except AccessActionRefused as exc:
            audit.log_principal_event("refused", target, actor=actor, outcome=exc.code)
            return self._refused_page(exc.code)
        except Exception as exc:  # noqa: BLE001
            logger.error("account admin approval failed: %s", type(exc).__name__)
            return self.message_page(
                503, _bi("暂时无法保存这项更改。", "The change could not be saved right now.")
            )
        self._access_changed(target)
        if changed:
            audit.log_principal_event("approved" if approve else "denied", target, actor=actor)
        logger.info(
            "account admin %s by account=%s target=%s changed=%s",
            "approve" if approve else "deny",
            session.acct,
            target,
            changed,
        )
        return self.redirect(_ADMIN_PATH, 303)

    async def admin_approve(self, request: Request) -> Response:
        """Owner action: approve a pending account so it can enroll a token and use MCP."""
        return await self._decide_pending(request, approve=True)

    async def admin_deny(self, request: Request) -> Response:
        """Owner action: deny a pending account (it becomes disabled and can be enabled again)."""
        return await self._decide_pending(request, approve=False)

    # -- audit log -----------------------------------------------------------

    @staticmethod
    def _audit_action_label(action: str) -> str:
        """The action name as text; an unknown name (a newer release) is shown as it is."""
        if action == "account_created":
            return _bi("账户已创建", "Account created")
        if action == "account_created_by_operator":
            return _bi("运维创建账户", "Account created by the operator")
        if action == "account_activated":
            return _bi("账户已自动启用", "Account activated by the rules")
        if action == "account_approved":
            return _bi("账户已批准", "Account approved")
        if action == "account_denied":
            return _bi("账户申请被拒绝", "Account denied")
        if action == "account_disabled":
            return _bi("账户已停用", "Account disabled")
        if action == "account_enabled":
            return _bi("账户已启用", "Account enabled")
        if action == "role_changed":
            return _bi("角色变更", "Role changed")
        if action == "token_enrolled":
            return _bi("绑定了令牌", "Token enrolled")
        if action == "token_replaced":
            return _bi("替换了令牌", "Token replaced")
        if action == "token_deleted":
            return _bi("删除了令牌", "Token deleted")
        if action == "token_marked_invalid":
            return _bi("令牌被标记失效", "Token marked invalid")
        if action == "write_tools_changed":
            return _bi("写工具开关变更", "Write tools changed")
        if action == "schema_migrated":
            return _bi("数据库已升级", "Database upgraded")
        if action == "pending_purged":
            return _bi("清理了过期的待批准账户", "Stale pending accounts removed")
        return action

    @staticmethod
    def _audit_detail(entry: AuditEntry) -> str:
        parts: list[str] = []
        for name in sorted(entry.detail):
            value = entry.detail[name]
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            if value in ("", None):
                continue
            parts.append(f"{name}={value}")
        return "; ".join(parts)

    @staticmethod
    def _audit_who(value: str | None, names: Mapping[str, str]) -> str:
        if not value:
            return "-"
        name = names.get(value)
        short = value[:13] + "…" if value.startswith("acct:") else value
        return f"{name} ({short})" if name else short

    async def admin_audit(self, request: Request) -> Response:
        """Owner page: the administrative and security actions, newest first, 100 at a time."""
        session = self._session_of(request)
        refusal = self._owner_refusal(session)
        if session is None or refusal is not None:
            return refusal or self.message_page(403, _bi("无权访问。", "Forbidden."))
        raw_before = request.query_params.get("before", "")
        before = int(raw_before) if raw_before.isdigit() and len(raw_before) < 15 else None
        entries = await anyio.to_thread.run_sync(
            functools.partial(self.store.list_audit, _AUDIT_PAGE, before)
        )
        accounts = await anyio.to_thread.run_sync(self.store.list_accounts)
        names = {a.principal_key: a.status.display_name for a in accounts if a.status.display_name}
        rows = []
        for entry in entries:
            reason = _e(entry.reason) if entry.reason else "-"
            rows.append(
                "<tr>"
                f'<td data-label="{_e(_bi("时间", "Time"))}">{_e(_fmt_ts(entry.at))}</td>'
                f'<td data-label="{_e(_bi("操作", "Action"))}">{_e(self._audit_action_label(entry.action))}</td>'
                f'<td data-label="{_e(_bi("执行者", "Actor"))}">{_e(self._audit_who(entry.actor, names))}</td>'
                f'<td data-label="{_e(_bi("对象", "Target"))}">{_e(self._audit_who(entry.target, names))}</td>'
                f'<td data-label="{_e(_bi("原因", "Reason"))}">{reason}</td>'
                f'<td data-label="{_e(_bi("详情", "Details"))}">{_e(self._audit_detail(entry))}</td>'
                "</tr>"
            )
        if rows:
            table = (
                '<section class="card tablecard"><table><thead><tr>'
                f"<th>{_bi('时间', 'Time')}</th><th>{_bi('操作', 'Action')}</th>"
                f"<th>{_bi('执行者', 'Actor')}</th><th>{_bi('对象', 'Target')}</th>"
                f"<th>{_bi('原因', 'Reason')}</th><th>{_bi('详情', 'Details')}</th>"
                "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></section>"
            )
        else:
            table = f'<section class="card"><p>{_bi("没有更多记录。", "No more entries.")}</p></section>'
        older = ""
        if len(entries) >= _AUDIT_PAGE:
            older = (
                f'<p><a href="{_ADMIN_AUDIT_PATH}?before={entries[-1].id}">'
                f'{_bi("更早的记录", "Older entries")}</a></p>'
            )
        body = (
            _header(session)
            + f"<h1>{_bi('审计日志', 'Audit log')}</h1>"
            + f'<p class="muted">{_bi("管理员操作和账户安全变更。这里不会出现令牌、密钥或网络地址。", "Administrator actions and account security changes. No token, key or network address appears here.")}</p>'
            + table
            + older
            + f'<p><a href="{_ADMIN_PATH}">{_bi("返回管理页", "Back to admin")}</a></p>'
        )
        return self.html_page(200, _bi("审计日志", "Audit log"), body, wide=True)


# -- public builders ----------------------------------------------------------


def build_account_routes(
    cfg: AccountConfig,
    store: TokenStore,
    identity: IdentityService,
    *,
    id_token_verifier: IdTokenVerifier | None = None,
    canvas_whoami: CanvasWhoAmI | None = None,
    http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
    clock: Callable[[], float] = time.time,
    directory: SchoolDirectoryLike | None = None,
    resolve_host: HostResolver | None = None,
    health: TokenHealth | None = None,
    write_tools: WriteToolCatalog | None = None,
    tool_prefs: ToolPrefsCache | None = None,
    access: PrincipalAccessCache | None = None,
    rate_limiters: RateLimiters | None = None,
) -> list[Route]:
    """Build the /account Starlette routes.

    ``identity`` decides who may sign in and which account they get. ``directory`` and
    ``resolve_host`` replace the Instructure school directory
    and the system DNS resolver (tests inject fakes; no real network is needed).
    ``health`` is the token-health service shared with the MCP side; the pages
    build their own when none is given. ``write_tools`` lists the write tools the
    server offers (the "Write tools" section is hidden without it) and
    ``tool_prefs`` is the cache the MCP side reads, dropped when a user saves.
    ``access`` is the MCP side's access cache, dropped for a user whenever an owner
    disables, enables, approves or denies them (without it the MCP side notices within
    its TTL).
    """
    app = _AccountApp(
        cfg,
        store,
        identity,
        id_token_verifier,
        canvas_whoami,
        http_client_factory,
        clock,
        directory,
        resolve_host,
        health,
        write_tools,
        tool_prefs,
        access,
        rate_limiters,
    )
    return app.routes()


def register_account_routes(
    mcp: FastMCP,
    cfg: AccountConfig,
    store: TokenStore,
    identity: IdentityService,
    **kwargs: Any,
) -> None:
    """Register the /account routes on a FastMCP server as custom routes."""
    for route in build_account_routes(cfg, store, identity, **kwargs):
        mcp.custom_route(route.path, methods=sorted(route.methods or _ALL_METHODS))(
            route.endpoint
        )
