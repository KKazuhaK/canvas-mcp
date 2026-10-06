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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, Protocol

import anyio.to_thread
import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

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

LOGIN_COOKIE = "__Host-cmcp_login"
SESSION_COOKIE = "__Host-cmcp_session"
_LOGIN_TTL_SECONDS = 600
_IAT_SKEW_SECONDS = 600
_MAX_BODY_BYTES = 8192
_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
_RATE_LIMIT_ATTEMPTS = 10
_RATE_LIMIT_WINDOW_SECONDS = 600
_RATE_LIMIT_MAX_KEYS = 1024
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


CanvasWhoAmI = Callable[[str], Awaitable[CanvasIdentity]]


@dataclass(frozen=True)
class AccountConfig:
    public_base_url: str
    tenant_id: str
    client_id: str
    client_secret: str = field(repr=False)
    session_secret: bytes = field(repr=False)
    canvas_api_url: str
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
font:16px/1.55 system-ui,-apple-system,"Segoe UI","Noto Sans SC","PingFang SC",sans-serif}
main{max-width:46rem;margin:0 auto;padding:1.5rem 16px 3rem}
h1{font-size:1.5rem;margin:.2rem 0 1rem}h2{font-size:1.1rem;margin:0 0 .5rem}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:1rem 1.1rem;margin:0 0 1rem}
.en{color:var(--muted);font-size:.92em}.muted{color:var(--muted)}
code{background:var(--bg);border:1px solid var(--line);border-radius:4px;
padding:.05rem .3rem;word-break:break-all}
.btn{display:inline-block;background:var(--accent);color:var(--accent-fg);
border:0;border-radius:8px;padding:.55rem 1rem;font:inherit;cursor:pointer;
text-decoration:none}
.btn.secondary{background:transparent;color:var(--accent);border:1px solid var(--line)}
.btn.danger{background:transparent;color:var(--bad);border:1px solid var(--bad)}
input[type=password]{width:100%;padding:.55rem;border:1px solid var(--line);
border-radius:8px;background:var(--bg);color:var(--fg);font:inherit;margin:.4rem 0 .7rem}
.notice{border-radius:8px;padding:.6rem .8rem;margin:0 0 1rem}
.notice.error{background:var(--bad-bg);color:var(--bad)}
.notice.ok{background:var(--ok-bg);color:var(--ok)}
.warn{background:var(--warn-bg);border-radius:8px;padding:.6rem .8rem}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem;margin:.3rem 0}
dt{color:var(--muted)}dd{margin:0;word-break:break-word}
.row{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}
form{margin:0}table{width:100%;border-collapse:collapse;font-size:.88rem}
th,td{text-align:left;border-bottom:1px solid var(--line);padding:.35rem .4rem;
vertical-align:top;word-break:break-word}
.scroll{overflow-x:auto}
""".strip()


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _bi(zh: str, en: str) -> str:
    """Short Chinese text with an English line below it. Inputs are trusted."""
    return f'{zh}<br><span class="en">{en}</span>'


def _fmt_ts(value: int | None) -> str:
    if value is None:
        return "-"
    try:
        return datetime.fromtimestamp(value, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return "-"


def _document(title: str, body: str) -> str:
    return (
        '<!doctype html><html lang="zh"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="robots" content="noindex, nofollow">'
        f"<title>{_e(title)}</title><style>{_CSS}</style></head>"
        f"<body><main>{body}</main></body></html>"
    )


def _csrf_field(csrf: str) -> str:
    return f'<input type="hidden" name="csrf" value="{_e(csrf)}">'


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
    ) -> None:
        self.cfg = cfg
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
        self._client_factory = http_client_factory or (
            lambda: httpx.AsyncClient(timeout=10, follow_redirects=False)
        )
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
        ]
        return [
            Route(path, self._endpoint(handlers), methods=_ALL_METHODS)
            for path, handlers in table
        ]

    def _endpoint(self, handlers: dict[str, Handler]) -> Handler:
        async def endpoint(request: Request) -> Response:
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

        return endpoint

    # -- response helpers ----------------------------------------------------

    def finish(self, response: Response) -> Response:
        for name, value in _SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    def html_page(self, status: int, title: str, body: str) -> Response:
        return self.finish(Response(_document(title, body), status_code=status))

    def message_page(self, status: int, message_html: str) -> Response:
        body = (
            "<h1>Canvas MCP</h1>"
            f'<section><p>{message_html}</p><p><a class="btn secondary" '
            f'href="{ACCOUNT_PATH}">{_bi("返回账户页", "Back to account")}</a></p>'
            "</section>"
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
        return self.account_page(session, info)

    def _mcp_url_section(self) -> str:
        return (
            f"<section><h2>{_bi('MCP 连接地址', 'MCP connector URL')}</h2>"
            f"<p><code>{_e(self.base)}/mcp</code></p>"
            f'<p class="muted">{_bi("在 Claude 中添加自定义连接器时填写此地址。", "Use this URL when adding a custom connector in Claude.")}</p>'
            "</section>"
        )

    def signed_out_page(self) -> Response:
        body = (
            f"<h1>{_bi('Canvas 账户', 'Canvas account')}</h1>"
            "<section>"
            f"<p>{_bi('先用 Microsoft 账号登录，再在这里绑定你自己的 Canvas 令牌。', 'Sign in with Microsoft, then enroll your own Canvas access token here.')}</p>"
            f'<p><a class="btn" href="{_LOGIN_PATH}">'
            f"{_bi('使用 Microsoft 登录', 'Sign in with Microsoft')}</a></p>"
            "</section>" + self._mcp_url_section()
        )
        return self.html_page(200, "Canvas account", body)

    def account_page(
        self,
        session: _Session,
        info: EnrollmentInfo | None,
        notice: tuple[Literal["error", "ok"], str] | None = None,
        status: int = 200,
    ) -> Response:
        parts: list[str] = [f"<h1>{_bi('Canvas 账户', 'Canvas account')}</h1>"]
        if notice is not None:
            parts.append(f'<div class="notice {notice[0]}" role="alert">{notice[1]}</div>')

        owner_badge = " (owner)" if session.owner else ""
        parts.append(
            "<section>"
            f"<h2>{_bi('已登录', 'Signed in')}</h2>"
            "<dl>"
            f"<dt>{_bi('姓名', 'Name')}</dt><dd>{_e(session.name)}{_e(owner_badge)}</dd>"
            f"<dt>{_bi('账号', 'Account')}</dt><dd>{_e(session.upn)}</dd>"
            "</dl>"
            f'<form method="post" action="{_LOGOUT_PATH}" class="row">'
            f"{_csrf_field(session.csrf)}"
            f'<button class="btn secondary" type="submit">{_bi("退出登录", "Sign out")}</button>'
            "</form>"
        )
        if session.owner:
            parts.append(
                f'<p><a href="{_ADMIN_PATH}">'
                f"{_bi('管理已绑定的用户', 'Manage enrollments')}</a></p>"
            )
        parts.append("</section>")

        if info is None:
            status_html = f"<p>{_bi('尚未绑定 Canvas 令牌。', 'No Canvas token enrolled yet.')}</p>"
        else:
            status_html = (
                f"<p>{_bi('已绑定 Canvas 令牌。', 'Canvas token enrolled.')}</p><dl>"
                f"<dt>{_bi('Canvas 用户', 'Canvas user')}</dt>"
                f"<dd>{_e(info.canvas_user_name)} (id {_e(info.canvas_user_id)})</dd>"
                f"<dt>{_bi('创建时间', 'Created')}</dt><dd>{_e(_fmt_ts(info.created_at))}</dd>"
                f"<dt>{_bi('更新时间', 'Updated')}</dt><dd>{_e(_fmt_ts(info.updated_at))}</dd>"
                f"<dt>{_bi('最近使用', 'Last used')}</dt><dd>{_e(_fmt_ts(info.last_used_at))}</dd>"
                "</dl>"
                f'<form method="post" action="{_TOKEN_DELETE_PATH}">'
                f"{_csrf_field(session.csrf)}"
                f'<button class="btn danger" type="submit">{_bi("删除我的令牌", "Delete my token")}</button>'
                "</form>"
            )
        parts.append(f"<section><h2>{_bi('绑定状态', 'Enrollment status')}</h2>{status_html}</section>")

        parts.append(
            "<section>"
            f"<h2>{_bi('添加或替换 Canvas 令牌', 'Add or replace your Canvas token')}</h2>"
            "<ol>"
            f"<li>{_bi('在 Canvas 中打开：Account &gt; Settings &gt; + New Access Token。', 'In Canvas open Account &gt; Settings &gt; + New Access Token.')}</li>"
            f"<li>{_bi('用途填 “Claude MCP”，并设置一个到期时间。', 'Set the purpose to &quot;Claude MCP&quot; and choose an expiry date.')}</li>"
            f"<li>{_bi('复制生成的令牌，粘贴到下面的输入框。', 'Copy the generated token and paste it into the box below.')}</li>"
            "</ol>"
            f'<p class="warn"><strong>{_bi("绝不要把令牌粘贴到 Claude 对话里。", "Never paste the token into Claude.")}</strong></p>'
            f'<form method="post" action="{_TOKEN_PATH}">'
            f"{_csrf_field(session.csrf)}"
            '<label for="canvas_token">Canvas access token</label>'
            '<input id="canvas_token" name="canvas_token" type="password" '
            'autocomplete="off" spellcheck="false" autocapitalize="off" '
            'required minlength="20" maxlength="512">'
            f'<button class="btn" type="submit">{_bi("验证并保存", "Verify and save")}</button>'
            "</form></section>"
        )
        parts.append(self._mcp_url_section())
        return self.html_page(status, "Canvas account", "".join(parts))

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
            return self.message_page(403, _e(message))
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

    async def _default_whoami(self, token: str) -> CanvasIdentity:
        url = self.cfg.canvas_api_url.rstrip("/") + "/users/self"
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
        try:
            identity = await self._canvas_whoami(token)
        except CanvasCheckError as exc:
            if exc.kind == "invalid":
                return await self._token_error(
                    session,
                    400,
                    _bi("Canvas 拒绝了这个令牌。", "Canvas rejected this token."),
                )
            return await self._token_error(
                session,
                503,
                _bi(
                    "暂时无法连接 Canvas，请稍后再试。",
                    "Canvas is unavailable right now. Try again later.",
                ),
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
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("account token save failed: %s", type(exc).__name__)
            return await self._token_error(
                session,
                503,
                _bi("暂时无法保存令牌。", "The token could not be saved right now."),
            )
        logger.info("account token enrolled tid=%s oid=%s", session.tid, session.oid)
        return self.redirect(ACCOUNT_PATH, 303)

    async def _token_error(
        self, session: _Session, status: int, message_html: str
    ) -> Response:
        info = await anyio.to_thread.run_sync(self._safe_info, session)
        return self.account_page(session, info, ("error", message_html), status)

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
                f"<td>{_e(row.entra_display_name)}<br>{_e(row.entra_upn)}</td>"
                f"<td>{_e(row.canvas_user_name)}<br>id {_e(row.canvas_user_id)}</td>"
                f"<td>{_e(_fmt_ts(row.created_at))}</td>"
                f"<td>{_e(_fmt_ts(row.updated_at))}</td>"
                f"<td>{_e(_fmt_ts(row.last_used_at))}</td>"
                f"<td><code>{_e(row.tenant_id)}</code><br><code>{_e(row.object_id)}</code></td>"
                f'<td><form method="post" action="{_ADMIN_REVOKE_PATH}">'
                f"{_csrf_field(session.csrf)}"
                f'<input type="hidden" name="tenant_id" value="{_e(row.tenant_id)}">'
                f'<input type="hidden" name="object_id" value="{_e(row.object_id)}">'
                f'<button class="btn danger" type="submit">{_bi("撤销", "Revoke")}</button>'
                "</form></td></tr>"
            )
        if lines:
            table = (
                '<div class="scroll"><table><thead><tr>'
                "<th>Entra</th><th>Canvas</th><th>Created</th><th>Updated</th>"
                "<th>Last used</th><th>IDs</th><th></th></tr></thead><tbody>"
                + "".join(lines)
                + "</tbody></table></div>"
            )
        else:
            table = f"<p>{_bi('还没有用户绑定令牌。', 'No enrollments yet.')}</p>"
        body = (
            f"<h1>{_bi('已绑定的用户', 'Enrollments')}</h1>"
            f"<section>{table}</section>"
            f'<p><a href="{ACCOUNT_PATH}">{_bi("返回账户页", "Back to account")}</a></p>'
        )
        return self.html_page(200, "Canvas enrollments", body)

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
) -> list[Route]:
    """Build the /account Starlette routes."""
    app = _AccountApp(
        cfg,
        store,
        authorize_claims,
        id_token_verifier,
        canvas_whoami,
        http_client_factory,
        clock,
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
