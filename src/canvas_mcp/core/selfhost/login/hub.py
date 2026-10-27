"""Sign in with a verified Hub session through a narrowly proxied, same-origin bridge.

Only /canvas-hub/authorize is served on the Hub origin. The normal account and
OAuth routes remain on PUBLIC_BASE_URL. Hub cookies never cross a browser URL,
enter a stored flow, or reach an arbitrary upstream. Existing account linking
uses the normal Canvas ceremony; this provider never merges accounts by email.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import logging
import re
import secrets
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode

from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from ..accounts import ExternalClaims
from ..login_state import LoginStateStore
from .config import HubConfig
from .http import CAP_USERINFO, SafeHttp, UpstreamError
from .protocol import ProviderDisplay, SignInRejected

if TYPE_CHECKING:
    from ..account_core import AccountCore

logger = logging.getLogger("canvas_mcp.selfhost.account")

BRIDGE_PATH = "/canvas-hub/authorize"
BRIDGE_COOKIE = "__Host-cmcp_hub"
TICKET_KIND = "hub_session_ticket"
CONFIRM_KIND = "hub_session_confirm"
TICKET_TTL_S = 60
CONFIRM_TTL_S = 300
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_COOKIE_NAMES = frozenset(
    {"__Secure-better-auth.session_token", "better-auth.session_token"}
)


def _session_cookie(raw: str) -> str:
    """Forward only the login token, not Hub credentials or cached user identity."""
    if len(raw) > 16384 or any(ord(c) < 32 or ord(c) == 127 for c in raw):
        raise SignInRejected("sign_in_unverified")
    found: dict[str, str] = {}
    for part in raw.split(";"):
        name, sep, value = part.strip().partition("=")
        if name not in _COOKIE_NAMES:
            continue
        if not sep or not value or name in found:
            raise SignInRejected("sign_in_unverified")
        found[name] = value
    if len(found) != 1:
        raise SignInRejected("sign_in_unverified")
    return "; ".join(f"{name}={value}" for name, value in found.items())


def _timestamp(value: object) -> float:
    if not isinstance(value, str) or len(value) > 40:
        raise SignInRejected("sign_in_unverified")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(UTC).timestamp()
    except (ValueError, OverflowError):
        raise SignInRejected("sign_in_unverified") from None


def _identity_text(value: object, limit: int) -> str:
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= limit
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise SignInRejected("sign_in_unverified")
    return value


class HubLoginProvider:
    id = "hub"
    kind = "hub"
    display = ProviderDisplay("MCPHub", "key")
    start_path = "/auth/login/hub"
    callback_path = "/auth/callback/hub"
    response_issuer: str | None = None

    def __init__(
        self,
        config: HubConfig,
        *,
        public_base_url: str,
        http: SafeHttp,
        flow_store: LoginStateStore,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.origin = config.origin
        self.redirect_uri = public_base_url.rstrip("/") + self.callback_path
        self.http = http
        self.flow_store = flow_store
        self.clock = clock

    async def prepare(self) -> None:
        """The operator fixes the Hub origin; there is no runtime discovery."""

    def requires_iss(self) -> bool:
        return False

    def authorize_url(
        self, *, state: str, nonce: str, code_challenge: str, reauth: bool
    ) -> str:
        return (
            self.origin
            + BRIDGE_PATH
            + "?"
            + urlencode(
                {
                    "state": state,
                    "nonce": nonce,
                    "code_challenge": code_challenge,
                }
            )
        )

    async def verify_session(self, raw_cookie: str) -> ExternalClaims:
        cookie = _session_cookie(raw_cookie)
        try:
            session = (
                await self.http.get_json(
                    self.origin + "/api/auth/better/get-session",
                    max_bytes=CAP_USERINFO,
                    headers={"Cookie": cookie, "Cache-Control": "no-cache"},
                )
            ).body
            saved = session.get("session")
            user = session.get("user")
            if not isinstance(saved, dict) or not isinstance(user, dict):
                raise SignInRejected("sign_in_unverified")
            subject = _identity_text(user.get("id"), 255)
            now = self.clock()
            if (
                saved.get("userId") != subject
                or _timestamp(saved.get("expiresAt")) <= now
                or _timestamp(saved.get("createdAt")) > now + 60
            ):
                raise SignInRejected("sign_in_unverified")
            # A session alone is insufficient: the account must still be admitted by Hub.
            access = (
                await self.http.get_json(
                    self.origin + "/api/better-auth/user",
                    max_bytes=CAP_USERINFO,
                    headers={"Cookie": cookie, "Cache-Control": "no-cache"},
                )
            ).body
            admitted = access.get("user")
            if access.get("success") is not True or not isinstance(admitted, dict):
                raise SignInRejected("sign_in_unverified")
            username = _identity_text(admitted.get("username"), 254)
        except UpstreamError as exc:
            raise SignInRejected(
                "sign_in_unverified"
                if exc.status in {401, 403} or exc.code == "not_json"
                else "provider_error"
            ) from None
        # Deliberately omit email and all upstream admin/role fields.
        return ExternalClaims(
            "hub", self.origin, subject, display_name=username, username=username
        )

    async def finish(
        self, *, code: str, code_verifier: str, nonce: str
    ) -> ExternalClaims:
        if not _TOKEN.fullmatch(code):
            raise SignInRejected("sign_in_unverified")
        try:
            raw = await self.flow_store.pop(
                TICKET_KIND,
                code,
                binding_hash=hashlib.sha256(code_verifier.encode("ascii")).hexdigest(),
            )
            data = json.loads(raw) if raw is not None else None
            if not isinstance(data, dict) or not hmac.compare_digest(
                data["nonce"], nonce
            ):
                raise ValueError
            if data["issuer"] != self.origin:
                raise ValueError
            return ExternalClaims(
                "hub",
                self.origin,
                _identity_text(data["subject"], 255),
                username=_identity_text(data["username"], 254),
                display_name=_identity_text(data["username"], 254),
            )
        except (ValueError, KeyError, TypeError, UnicodeError):
            raise SignInRejected("sign_in_unverified") from None


_STYLE = """*{box-sizing:border-box}body{margin:0;background:#f5f7fb;color:#182332;font:16px/1.6 system-ui,-apple-system,'Segoe UI',sans-serif}main{max-width:520px;margin:10vh auto;padding:38px;background:white;border:1px solid #dfe4ed;border-radius:20px;box-shadow:0 12px 48px #10234408}.brand{font-size:13px;font-weight:650;letter-spacing:.08em;color:#5e6a7c;text-transform:uppercase;margin-bottom:28px}h1{font-size:28px;line-height:1.3;letter-spacing:-.03em;margin:0 0 16px}p{color:#556274;margin:0 0 28px;overflow-wrap:anywhere}button,a{display:inline-block;max-width:100%;font:inherit;font-weight:600;border-radius:999px;padding:12px 22px;color:white;background:#0b57d0;border:0;text-decoration:none;cursor:pointer}button{width:100%}button:hover,a:hover{background:#0844a5}button:focus-visible,a:focus-visible{outline:3px solid #80aef1;outline-offset:4px}footer{border-top:1px solid #e7ebf1;margin-top:28px;padding-top:20px;font-size:13px;color:#6c7888}@media(max-width:600px){main{margin:24px 16px;padding:28px 24px}}@media(prefers-color-scheme:dark){body{background:#121316;color:#e8edf6}main{background:#1c1d21;border-color:#353c49}p,footer,.brand{color:#b1bbca}footer{border-color:#353c49}}"""


def _page(title: str, text: str, controls: str) -> HTMLResponse:
    style_hash = base64.b64encode(hashlib.sha256(_STYLE.encode()).digest()).decode()
    return HTMLResponse(
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>Connect Canvas · MCPHub</title><style>" + _STYLE + "</style>"
        '<main><div class="brand">MCPHub / Canvas</div><h1>'
        + html.escape(title)
        + "</h1><p>"
        + html.escape(text)
        + "</p>"
        + controls
        + "<footer>Canvas keeps its existing account and permissions. Hub passwords and cookies are never stored in Canvas.</footer></main></html>",
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; style-src 'sha256-"
            + style_hash
            + "'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        },
    )


def build_hub_bridge_routes(app: AccountCore) -> list[Route]:
    from ..account_core import any_method_route
    from ..config_snapshot import CURRENT_CONFIG
    from .runtime_config import CURRENT_LOGIN

    async def bridge_checked(request: Request) -> Response:
        await app.refresh_login_config()
        provider = app.logins.providers.get("hub")
        if not isinstance(provider, HubLoginProvider):
            return PlainTextResponse("Not found", status_code=404)
        origin = f"{request.url.scheme}://{request.url.netloc}"
        if origin != provider.origin:
            return PlainTextResponse("Not found", status_code=404)
        if request.method not in {"GET", "POST"}:
            return PlainTextResponse(
                "Method not allowed", status_code=405, headers={"Allow": "GET, POST"}
            )
        if app.logins.start_buckets["hub"].take() > 0:
            return PlainTextResponse("Try again later", status_code=429)
        if request.method == "GET":
            params = request.query_params
            if any(
                len(params.getlist(k)) != 1 or not _TOKEN.fullmatch(params[k])
                for k in ("state", "nonce", "code_challenge")
            ) or set(params) != {"state", "nonce", "code_challenge"}:
                return PlainTextResponse("Invalid sign-in request", status_code=400)
            claims = await provider.verify_session(request.headers.get("cookie", ""))
            binding = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(32)
            pending = {k: params[k] for k in ("state", "nonce", "code_challenge")}
            pending.update(subject=claims.subject, csrf=csrf)
            ticket = await provider.flow_store.put(
                CONFIRM_KIND,
                json.dumps(pending).encode(),
                CONFIRM_TTL_S,
                binding_hash=hashlib.sha256(binding.encode()).hexdigest(),
            )
            response: Response = _page(
                "Continue to Canvas",
                f"Use your MCPHub account: {claims.username}. Existing Canvas accounts must be linked from their sign-in settings.",
                '<form method="post" action="'
                + BRIDGE_PATH
                + '"><input type="hidden" name="csrf" value="'
                + csrf
                + '"><button type="submit">Continue with this account</button></form>',
            )
            response.set_cookie(
                BRIDGE_COOKIE,
                app.codec.seal(BRIDGE_COOKIE, {"ticket": ticket, "binding": binding}),
                max_age=CONFIRM_TTL_S,
                secure=True,
                httponly=True,
                samesite="lax",
                path="/",
            )
            return response
        if request.headers.get("origin") != provider.origin or request.headers.get(
            "sec-fetch-site"
        ) not in {None, "same-origin"}:
            return PlainTextResponse("Request refused", status_code=403)
        if (
            request.headers.get("content-type", "").split(";", 1)[0]
            != "application/x-www-form-urlencoded"
        ):
            return PlainTextResponse("Request refused", status_code=415)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 1024:
                return PlainTextResponse("Request too large", status_code=413)
        try:
            form = parse_qs(body.decode("ascii"), strict_parsing=True)
            if (
                set(form) != {"csrf"}
                or len(form["csrf"]) != 1
                or not _TOKEN.fullmatch(form["csrf"][0])
            ):
                raise ValueError
            cookie = app.codec.unseal(BRIDGE_COOKIE, request.cookies.get(BRIDGE_COOKIE))
            if (
                not cookie
                or not _TOKEN.fullmatch(cookie["ticket"])
                or not _TOKEN.fullmatch(cookie["binding"])
            ):
                raise ValueError
            raw = await provider.flow_store.peek(
                CONFIRM_KIND,
                cookie["ticket"],
                binding_hash=hashlib.sha256(cookie["binding"].encode()).hexdigest(),
            )
            saved = json.loads(raw) if raw else None
            if not saved or not hmac.compare_digest(saved["csrf"], form["csrf"][0]):
                raise ValueError
            claims = await provider.verify_session(request.headers.get("cookie", ""))
            if not hmac.compare_digest(claims.subject, saved["subject"]):
                raise ValueError
            consumed = await provider.flow_store.pop(
                CONFIRM_KIND,
                cookie["ticket"],
                binding_hash=hashlib.sha256(cookie["binding"].encode()).hexdigest(),
            )
            if consumed != raw:
                raise ValueError
        except (ValueError, KeyError, TypeError, UnicodeError):
            return PlainTextResponse(
                "Sign-in expired or account changed. Start again from Canvas.",
                status_code=403,
            )
        code = await provider.flow_store.put(
            TICKET_KIND,
            json.dumps(
                {
                    "nonce": saved["nonce"],
                    "issuer": provider.origin,
                    "subject": claims.subject,
                    "username": claims.username,
                }
            ).encode(),
            TICKET_TTL_S,
            binding_hash=base64.urlsafe_b64decode(saved["code_challenge"] + "=").hex(),
        )
        response = Response(
            status_code=303,
            headers={
                "Location": provider.redirect_uri
                + "?"
                + urlencode({"code": code, "state": saved["state"]})
            },
        )
        response.delete_cookie(
            BRIDGE_COOKIE, secure=True, httponly=True, samesite="lax", path="/"
        )
        return response

    async def bridge(request: Request) -> Response:
        marker = CURRENT_CONFIG.set(None)
        login_marker = CURRENT_LOGIN.set(None)
        try:
            try:
                response = await bridge_checked(request)
            except SignInRejected as exc:
                if exc.code == "provider_error":
                    response = _page(
                        "MCPHub is temporarily unavailable",
                        "Your account has not been changed. Wait a moment, then start again from Canvas.",
                        "",
                    )
                    response.status_code = 503
                    return response
                # The fixed operator URL only: no user-controlled return target.
                provider = app.logins.providers.get("hub")
                controls = (
                    '<a href="'
                    + html.escape(provider.origin, quote=True)
                    + '">Sign in to MCPHub</a>'
                    if isinstance(provider, HubLoginProvider)
                    else ""
                )
                response = _page(
                    "MCPHub sign-in required",
                    "Sign in to Hub, then start again from Canvas. No Canvas account has been changed.",
                    controls,
                )
                response.status_code = 401
            except Exception as exc:
                logger.error("Hub bridge failed: %s", type(exc).__name__)
                response = PlainTextResponse(
                    "Sign-in temporarily unavailable", status_code=503
                )
        finally:
            CURRENT_CONFIG.reset(marker)
            CURRENT_LOGIN.reset(login_marker)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            }
        )
        return response

    return [any_method_route(BRIDGE_PATH, bridge)]


class HubBridgeDispatch:
    """Dispatch only the exact bridge path; leave all core host/origin guards intact."""

    def __init__(self, app: ASGIApp, routes: list[Route]) -> None:
        from starlette.routing import Router

        self.app = app
        self.bridge = Router(routes=routes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path") == BRIDGE_PATH:
            await self.bridge(scope, receive, send)
        else:
            await self.app(scope, receive, send)
