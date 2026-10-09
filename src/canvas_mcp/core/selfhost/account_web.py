"""/account browser pages for the self-hosted multi-user mode.

Each user signs in with Microsoft Entra ID (authorization code + PKCE + nonce)
and enrolls their own Canvas personal access token here. Canvas tokens never go
through chat: they are accepted only from the form on this page, verified
against Canvas, and handed to the encrypted :class:`TokenStore`.

This module does not import any auth-branch module. Identity rules (tenant,
role, owner) are injected as the ``authorize_claims`` callable.

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
from collections import OrderedDict, deque
from collections.abc import Awaitable, Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, tzinfo
from typing import TYPE_CHECKING, Any, Literal, Protocol

import anyio.to_thread
import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from canvas_mcp.core.dates import output_timezone
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
from canvas_mcp.core.selfhost.token_store import EnrollmentInfo, TokenStore

if TYPE_CHECKING:
    from fastmcp import FastMCP

logger = logging.getLogger("canvas_mcp.selfhost.account")

ACCOUNT_PATH = "/account"
ACCOUNT_CALLBACK_PATH = "/account/callback"
_LOGIN_PATH = "/account/login"
_TOKEN_PATH = "/account/token"
_TOKEN_DELETE_PATH = "/account/token/delete"
_LOGOUT_PATH = "/account/logout"
_ADMIN_PATH = "/account/admin"
_ADMIN_REVOKE_PATH = "/account/admin/revoke"
_SCHOOLS_PATH = "/account/schools"

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


class PrincipalLike(Protocol):
    """What the account pages need to know about a signed-in user."""

    @property
    def tenant_id(self) -> str: ...

    @property
    def object_id(self) -> str: ...

    @property
    def display_name(self) -> str: ...

    @property
    def upn(self) -> str: ...

    @property
    def is_owner(self) -> bool: ...


AuthorizeClaims = Callable[[Mapping[str, Any]], tuple[PrincipalLike | None, str]]
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
    tid: str
    oid: str
    name: str
    upn: str
    owner: bool
    csrf: str
    exp: int


class _RateLimiter:
    """Sliding-window attempt counter in a bounded in-memory table."""

    def __init__(
        self,
        limit: int,
        window: int,
        max_keys: int,
        clock: Callable[[], float],
    ) -> None:
        self._limit = limit
        self._window = window
        self._max_keys = max_keys
        self._clock = clock
        self._hits: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()

    def allow(self, key: tuple[str, str]) -> bool:
        now = self._clock()
        cutoff = now - self._window
        hits = self._hits.get(key)
        if hits is None:
            if len(self._hits) >= self._max_keys:
                self._purge(cutoff)
            while len(self._hits) >= self._max_keys:
                self._hits.popitem(last=False)
            hits = deque()
            self._hits[key] = hits
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if len(hits) >= self._limit:
            return False
        hits.append(now)
        return True

    def _purge(self, cutoff: float) -> None:
        for key in [k for k, h in self._hits.items() if not h or h[-1] <= cutoff]:
            del self._hits[key]


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
input[type=password],input[type=search]{width:100%;padding:.6rem;border:1px solid var(--line);
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
}


def _denial_html(message: str) -> str:
    """The identity layer's refusal text; Chinese gets a translation or a generic line."""
    if _current_lang() == "zh":
        return _e(_DENIAL_ZH.get(message, "此账号没有使用权限，请联系服务器所有者。"))
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
        tools.append(f'<a href="{_e(ctx.path)}?lang=zh" hreflang="zh" lang="zh">中文</a>')
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
        authorize_claims: AuthorizeClaims,
        id_token_verifier: IdTokenVerifier | None,
        canvas_whoami: CanvasWhoAmI | None,
        http_client_factory: Callable[[], httpx.AsyncClient] | None,
        clock: Callable[[], float],
        directory: SchoolDirectoryLike | None = None,
        resolve_host: HostResolver | None = None,
    ) -> None:
        self.cfg = cfg
        self.schools = cfg.schools
        self.base = cfg.public_base_url.rstrip("/")
        self.tenant = cfg.tenant_id.lower()
        self.store = store
        self.authorize_claims = authorize_claims
        self.clock = clock
        self.codec = _CookieCodec(cfg.session_secret)
        self.limiter = _RateLimiter(
            _RATE_LIMIT_ATTEMPTS,
            _RATE_LIMIT_WINDOW_SECONDS,
            _RATE_LIMIT_MAX_KEYS,
            clock,
        )
        self.search_limiter = _RateLimiter(
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
            (_LOGOUT_PATH, {"POST": self.logout}),
            (_ADMIN_PATH, {"GET": self.admin}),
            (_ADMIN_REVOKE_PATH, {"POST": self.admin_revoke}),
            (_SCHOOLS_PATH, {"GET": self.schools_page}),
        ]
        return [
            Route(path, self._endpoint(handlers), methods=_ALL_METHODS)
            for path, handlers in table
        ]

    def _endpoint(self, handlers: dict[str, Handler]) -> Handler:
        async def endpoint(request: Request) -> Response:
            ctx = _RenderContext(
                lang=_choose_lang(request),
                path=self._toggle_path(request),
                session=self.session_from(request),
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
        return path if path in (ACCOUNT_PATH, _ADMIN_PATH, _SCHOOLS_PATH) else ACCOUNT_PATH

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
        if payload is None or payload.get("v") != 1:
            return None
        try:
            tid, oid = payload["tid"], payload["oid"]
            name, upn, csrf = payload["name"], payload["upn"], payload["csrf"]
            owner, exp = payload["owner"], payload["exp"]
        except KeyError:
            return None
        if not (
            isinstance(tid, str)
            and isinstance(oid, str)
            and isinstance(name, str)
            and isinstance(upn, str)
            and isinstance(csrf, str)
            and isinstance(owner, bool)
            and isinstance(exp, int)
            and not isinstance(exp, bool)
        ):
            return None
        if (
            exp <= self.clock()
            or tid != self.tenant
            or not _GUID_RE.fullmatch(oid)
            or not csrf
        ):
            return None
        return _Session(tid, oid.lower(), name, upn, owner, csrf, exp)

    def _csrf_ok(self, session: _Session, supplied: str | None) -> bool:
        if not supplied:
            return False
        return hmac.compare_digest(supplied.encode("utf-8"), session.csrf.encode("utf-8"))

    # -- GET /account --------------------------------------------------------

    async def page(self, request: Request) -> Response:
        session = self.session_from(request)
        if session is None:
            return self.signed_out_page()
        try:
            info = await anyio.to_thread.run_sync(self.store.info, session.tid, session.oid)
        except Exception as exc:  # noqa: BLE001
            logger.error("account page store read failed: %s", type(exc).__name__)
            return self.message_page(
                503, _bi("暂时无法读取令牌库。", "The token store is unavailable.")
            )
        return self.account_page(session, info, selected=self._selection(request.query_params.get("school")))

    def _selection(self, raw: str | None) -> str | None:
        """A school host from ``?school=`` / a failed form that may be pre-selected.

        Only a featured school, or (with search on) a syntactically valid and
        not-local host name, is ever echoed back; anything else is ignored.
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
            note = _bi("（来自学校目录，保存时验证）", "(from the school directory, verified when you save)")
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
        return (
            f'<p class="warn"><strong>{_bi("绝不要把令牌粘贴到 Claude 对话里。", "Never paste the token into Claude.")}</strong></p>'
            f'<form method="post" action="{_TOKEN_PATH}">'
            f"{_csrf_field(session.csrf)}"
            f"{school_part}"
            f'<label for="canvas_token">{_bi("Canvas 访问令牌", "Canvas access token")}</label>'
            '<input id="canvas_token" name="canvas_token" type="password" '
            'autocomplete="off" spellcheck="false" autocapitalize="off" '
            'required minlength="20" maxlength="512">'
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

    def account_page(
        self,
        session: _Session,
        info: EnrollmentInfo | None,
        notice: tuple[Literal["error", "ok"], str] | None = None,
        status: int = 200,
        selected: str | None = None,
    ) -> Response:
        parts: list[str] = [
            _header(session),
            f"<h1>{_bi('Canvas 账户', 'Canvas account')}</h1>",
            _identity_line(session),
        ]
        if notice is not None:
            parts.append(f'<div class="notice {notice[0]}" role="alert">{notice[1]}</div>')

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
                f"<dt>{_bi('最近使用', 'Last used')}</dt><dd>{_e(_fmt_ts(info.last_used_at))}</dd>"
                f"<dt>{_bi('绑定时间', 'Enrolled')}</dt><dd>{_e(_fmt_ts(info.created_at))}</dd>"
                f"<dt>{_bi('更新时间', 'Updated')}</dt><dd>{_e(_fmt_ts(info.updated_at))}</dd>"
                "</dl>"
                f"{self._school_notice(info)}"
                f'<form method="post" action="{_TOKEN_DELETE_PATH}">'
                f"{_csrf_field(session.csrf)}"
                f'<button class="btn danger sm" type="submit">{_bi("删除我的令牌", "Delete my token")}</button>'
                "</form></section>"
            )
            # Collapsed unless the last attempt failed (so the error and the form
            # meet) or a school was just chosen from the search results.
            is_open = (
                " open"
                if (notice is not None and notice[0] == "error") or selected is not None
                else ""
            )
            parts.append(
                f'<details class="card"{is_open}>'
                f"<summary>{_bi('替换令牌', 'Replace token')}</summary>"
                + self._token_form(session, info, selected)
                + "</details>"
            )
        parts.append(self._search_section())
        parts.append(self._mcp_url_section())
        return self.html_page(status, _bi("Canvas 账户", "Canvas account"), "".join(parts))

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
                    f'<li><a href="{_e(ACCOUNT_PATH + "?" + urllib.parse.urlencode({"school": domain}))}">'
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
        session = self.session_from(request)
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
        if not self.search_limiter.allow((session.tid, session.oid)):
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
        logger.info("account school search tid=%s oid=%s results=%d", session.tid, session.oid, len(results))
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

        principal, message = self.authorize_claims(claims)
        if principal is None:
            return self.message_page(403, _denial_html(message))
        if principal.tenant_id.lower() != self.tenant or not _GUID_RE.fullmatch(
            principal.object_id
        ):
            logger.error("account sign-in refused: principal identity mismatch")
            return self.message_page(
                403, _bi("此账号不可使用。", "This account cannot be used.")
            )

        issued = int(now)
        sealed = self.codec.seal(
            SESSION_COOKIE,
            {
                "v": 1,
                "tid": self.tenant,
                "oid": principal.object_id.lower(),
                "name": principal.display_name[:200],
                "upn": principal.upn[:254],
                "owner": bool(principal.is_owner),
                "iat": issued,
                "exp": issued + self.cfg.session_ttl_seconds,
                "csrf": secrets.token_urlsafe(32),
            },
        )
        logger.info(
            "account sign-in ok tid=%s oid=%s", self.tenant, principal.object_id.lower()
        )
        response = self.redirect(ACCOUNT_PATH, 303)
        response.set_cookie(
            SESSION_COOKIE,
            sealed,
            max_age=self.cfg.session_ttl_seconds,
            **self._cookie_kwargs(),
        )
        return response

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

    async def _read_form(self, request: Request) -> dict[str, str] | Response:
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
                text, keep_blank_values=True, max_num_fields=10
            )
        except (UnicodeDecodeError, ValueError):
            return self.message_page(400, _bi("请求格式不正确。", "Malformed request."))
        return {key: values[0] for key, values in parsed.items() if values}

    async def _guard_post(
        self, request: Request, *, owner_only: bool = False
    ) -> tuple[_Session, dict[str, str]] | Response:
        """Session, Origin, content type, size and CSRF checks for a POST."""
        session = self.session_from(request)
        if session is None:
            if owner_only:
                return self.message_page(403, _bi("无权访问。", "Forbidden."))
            return self.redirect(ACCOUNT_PATH, 303)
        if owner_only and not session.owner:
            return self.message_page(403, _bi("无权访问。", "Forbidden."))
        if request.headers.get("origin") != self.base:
            return self.message_page(
                403, _bi("请求来源不被允许。", "The request origin is not allowed.")
            )
        form = await self._read_form(request)
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

    # -- POST handlers -------------------------------------------------------

    async def save_token(self, request: Request) -> Response:
        guarded = await self._guard_post(request)
        if isinstance(guarded, Response):
            return guarded
        session, form = guarded

        if not self.limiter.allow((session.tid, session.oid)):
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
        raw_school = form.get("school", "")
        chosen = await self._choose_school(raw_school)
        selected = self._selection(raw_school)
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
        try:
            await anyio.to_thread.run_sync(
                functools.partial(
                    self.store.put,
                    tenant_id=session.tid,
                    object_id=session.oid,
                    api_token=token,
                    canvas_user_id=identity.user_id,
                    canvas_user_name=identity.name,
                    entra_display_name=session.name,
                    entra_upn=session.upn,
                    canvas_host=school.host,
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("account token save failed: %s", type(exc).__name__)
            return await self._token_error(
                session,
                503,
                _bi("暂时无法保存令牌。", "The token could not be saved right now."),
                selected=selected,
            )
        logger.info(
            "account token enrolled tid=%s oid=%s host=%s", session.tid, session.oid, school.host
        )
        return self.redirect(ACCOUNT_PATH, 303)

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
    ) -> Response:
        info = await anyio.to_thread.run_sync(self._safe_info, session)
        return self.account_page(
            session, info, ("error", message_html), status, selected=selected
        )

    def _safe_info(self, session: _Session) -> EnrollmentInfo | None:
        try:
            return self.store.info(session.tid, session.oid)
        except Exception:  # noqa: BLE001
            return None

    async def delete_token(self, request: Request) -> Response:
        guarded = await self._guard_post(request)
        if isinstance(guarded, Response):
            return guarded
        session, _form = guarded
        await anyio.to_thread.run_sync(self.store.delete, session.tid, session.oid)
        logger.info("account token deleted tid=%s oid=%s", session.tid, session.oid)
        return self.redirect(ACCOUNT_PATH, 303)

    async def logout(self, request: Request) -> Response:
        guarded = await self._guard_post(request)
        if isinstance(guarded, Response):
            return guarded
        response = self.redirect(ACCOUNT_PATH, 303)
        self.clear_cookie(response, SESSION_COOKIE)
        return response

    # -- admin ---------------------------------------------------------------

    async def admin(self, request: Request) -> Response:
        session = self.session_from(request)
        if session is None or not session.owner:
            return self.message_page(403, _bi("无权访问。", "Forbidden."))
        rows = await anyio.to_thread.run_sync(self.store.list_enrollments)
        lines: list[str] = []
        for row in rows:
            lines.append(
                "<tr>"
                f'<td data-label="{_e(_bi("Entra 用户", "Entra user"))}">'
                f"{_e(row.entra_display_name)}<br>"
                f'<span class="muted">{_e(row.entra_upn)}</span>'
                '<details class="tech">'
                f"<summary>{_bi('技术信息', 'Technical details')}</summary><dl>"
                f"<dt>{_bi('租户', 'Tenant')}</dt><dd><code>{_e(row.tenant_id)}</code></dd>"
                f"<dt>{_bi('对象 ID', 'Object')}</dt><dd><code>{_e(row.object_id)}</code></dd>"
                f"<dt>{_bi('绑定时间', 'Enrolled')}</dt><dd>{_e(_fmt_ts(row.created_at))}</dd>"
                f"<dt>{_bi('更新时间', 'Updated')}</dt><dd>{_e(_fmt_ts(row.updated_at))}</dd>"
                "</dl></details></td>"
                f'<td data-label="{_e(_bi("Canvas 用户", "Canvas user"))}">'
                f'{_e(row.canvas_user_name)}<br><span class="muted">id {_e(row.canvas_user_id)}</span></td>'
                f'<td data-label="{_e(_bi("学校", "School"))}">{self._admin_school(row)}</td>'
                f'<td data-label="{_e(_bi("最近使用", "Last used"))}">{_e(_fmt_ts(row.last_used_at))}</td>'
                f'<td class="act"><form method="post" action="{_ADMIN_REVOKE_PATH}">'
                f"{_csrf_field(session.csrf)}"
                f'<input type="hidden" name="tenant_id" value="{_e(row.tenant_id)}">'
                f'<input type="hidden" name="object_id" value="{_e(row.object_id)}">'
                f'<button class="btn danger sm" type="submit">{_bi("撤销", "Revoke")}</button>'
                "</form></td></tr>"
            )
        if lines:
            table = (
                '<section class="card tablecard"><table><thead><tr>'
                f"<th>{_bi('Entra 用户', 'Entra user')}</th>"
                f"<th>{_bi('Canvas 用户', 'Canvas user')}</th>"
                f"<th>{_bi('学校', 'School')}</th>"
                f"<th>{_bi('最近使用', 'Last used')}</th>"
                f'<th class="act"><span class="muted">{_bi("操作", "Actions")}</span></th>'
                "</tr></thead><tbody>" + "".join(lines) + "</tbody></table></section>"
            )
        else:
            table = (
                '<section class="card">'
                f"<p>{_bi('还没有用户绑定令牌。', 'No enrollments yet.')}</p></section>"
            )
        body = (
            _header(session)
            + f"<h1>{_bi('已绑定的用户', 'Enrollments')}</h1>"
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

    async def admin_revoke(self, request: Request) -> Response:
        guarded = await self._guard_post(request, owner_only=True)
        if isinstance(guarded, Response):
            return guarded
        session, form = guarded
        tid = form.get("tenant_id", "")
        oid = form.get("object_id", "")
        if not _GUID_RE.fullmatch(tid) or not _GUID_RE.fullmatch(oid):
            return self.message_page(
                400, _bi("用户标识不正确。", "Invalid user identifier.")
            )
        await anyio.to_thread.run_sync(self.store.delete, tid, oid)
        logger.info(
            "account admin revoke by oid=%s target tid=%s oid=%s",
            session.oid,
            tid.lower(),
            oid.lower(),
        )
        return self.redirect(_ADMIN_PATH, 303)


# -- public builders ----------------------------------------------------------


def build_account_routes(
    cfg: AccountConfig,
    store: TokenStore,
    authorize_claims: AuthorizeClaims,
    *,
    id_token_verifier: IdTokenVerifier | None = None,
    canvas_whoami: CanvasWhoAmI | None = None,
    http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
    clock: Callable[[], float] = time.time,
    directory: SchoolDirectoryLike | None = None,
    resolve_host: HostResolver | None = None,
) -> list[Route]:
    """Build the /account Starlette routes.

    ``directory`` and ``resolve_host`` replace the Instructure school directory
    and the system DNS resolver (tests inject fakes; no real network is needed).
    """
    app = _AccountApp(
        cfg,
        store,
        authorize_claims,
        id_token_verifier,
        canvas_whoami,
        http_client_factory,
        clock,
        directory,
        resolve_host,
    )
    return app.routes()


def register_account_routes(
    mcp: FastMCP,
    cfg: AccountConfig,
    store: TokenStore,
    authorize_claims: AuthorizeClaims,
    **kwargs: Any,
) -> None:
    """Register the /account routes on a FastMCP server as custom routes."""
    for route in build_account_routes(cfg, store, authorize_claims, **kwargs):
        mcp.custom_route(route.path, methods=sorted(route.methods or _ALL_METHODS))(
            route.endpoint
        )
