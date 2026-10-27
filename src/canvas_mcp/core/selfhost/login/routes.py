"""GET-only browser ceremonies; unknown providers never create state."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route

from ..account_core import _SESSION_SCOPE_KEY, any_method_route
from ..config_snapshot import CURRENT_CONFIG
from ..routes import AUTH_LOGIN, route_provider
from .ceremony import FLOW_COOKIE
from .runtime_config import CURRENT_LOGIN

if TYPE_CHECKING:
    from ..config_snapshot import CURRENT_CONFIG
from ..account_core import AccountCore

logger = logging.getLogger("canvas_mcp.selfhost.account")


def build_login_routes(app: AccountCore) -> list[Route]:
    async def dispatch_checked(request: Request) -> Response:
        if request.method != "GET":
            response: Response = PlainTextResponse(
                "Method not allowed", status_code=405, headers={"Allow": "GET"}
            )
            return app.finish(response)
        try:
            await app.refresh_login_config()
            provider = None
            if request.url.path != AUTH_LOGIN:
                key = request.path_params.get("provider", "")
                if "slug" in request.path_params:
                    key = "oidc/" + request.path_params["slug"]
                provider_id = route_provider(key)
                provider = app.logins.providers.get(provider_id or "")
                if provider is None:
                    return app.finish(PlainTextResponse("Not found", status_code=404))
            # A link callback needs the current session epoch. This check is never cached.
            request.scope[_SESSION_SCOPE_KEY] = await app._resolve_session(request)
            if CURRENT_CONFIG.get() is None:
                await app.refresh_public_config()
            if provider is None:
                return await app._choose_provider(request)
            if request.url.path.startswith("/auth/callback/"):
                return await app.external._callback(request, provider=provider)
            return await app.external._start(request, provider=provider)
        except Exception as exc:  # noqa: BLE001 - only closed codes leave the server
            logger.error("sign-in route failed: %s", type(exc).__name__)
            return app._sign_in_failure("token_store_unavailable")

    async def dispatch(request: Request) -> Response:
        marker = CURRENT_CONFIG.set(None)
        login_marker = CURRENT_LOGIN.set(None)
        try:
            response = await dispatch_checked(request)
        finally:
            CURRENT_CONFIG.reset(marker)
            CURRENT_LOGIN.reset(login_marker)
        if request.url.path.startswith("/auth/callback/"):
            app.clear_cookie(response, FLOW_COOKIE)
        return response

    from .hub import build_hub_bridge_routes

    return build_hub_bridge_routes(app) + [
        any_method_route(path, dispatch)
        for path in (
            AUTH_LOGIN,
            AUTH_LOGIN + "/oidc/{slug}",
            AUTH_LOGIN + "/{provider}",
            "/auth/callback/oidc/{slug}",
            "/auth/callback/{provider}",
        )
    ]
