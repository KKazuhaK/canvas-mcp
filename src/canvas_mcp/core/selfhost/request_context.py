"""Per-request identity and Canvas credentials for the self-hosted mode.

A pure ASGI middleware that runs inside FastMCP's authentication, so
``scope['user']`` already holds the outcome of verifying the bearer token. For
the MCP endpoint it re-checks the verified Entra claims against the operator's
policy, looks up the caller's own Canvas token in the encrypted store, and
publishes both through the request ContextVars that the Canvas client reads.
Nothing here trusts a request header, and nothing outlives the request.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any, Protocol

import anyio.to_thread
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from starlette.types import ASGIApp, Receive, Scope, Send

from ..credentials import (
    RequestCredentials,
    clear_http_request_context,
    set_http_request_active,
    set_missing_credentials_message,
    set_request_credentials,
    set_request_principal,
)
from ..logging import log_error, log_warning
from .identity import ClaimsDenied, ClaimsPolicy, evaluate_entra_claims

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_NO_CLAIMS_MESSAGE = "Your sign-in carries no identity claims. Reconnect the connector."


class StoredTokenLike(Protocol):
    """What the middleware needs from a stored row: the decrypted Canvas token."""

    @property
    def api_token(self) -> str: ...


class CanvasTokenReader(Protocol):
    """The slice of the token store the middleware uses (synchronous methods)."""

    def get(self, tenant_id: str, object_id: str) -> StoredTokenLike | None: ...

    def touch(self, tenant_id: str, object_id: str, *, min_interval_seconds: int = 300) -> None: ...


def not_enrolled_message(account_url: str) -> str:
    return (
        "No Canvas access token is enrolled for your Microsoft account on this server. "
        f"Open {account_url} in a browser, sign in with Microsoft, and add your Canvas "
        "access token there (never paste it into this chat). Then try again."
    )


def unreadable_token_message(account_url: str) -> str:
    return (
        "Your stored Canvas access token could not be read. "
        f"Open {account_url} and enroll it again."
    )


async def _send_json(send: Send, status: int, message: str) -> None:
    body = json.dumps({"error": message}).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ],
    })
    await send({"type": "http.response.body", "body": body})


def _is_mcp_path(path: str, mcp_path: str) -> bool:
    return path == mcp_path or path.startswith(mcp_path + "/")


class SelfhostRequestContextMiddleware:
    """Publish the verified identity and the caller's Canvas token for one request."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        mcp_path: str,
        policy: ClaimsPolicy,
        store: CanvasTokenReader,
        canvas_api_url: str,
        account_url: str,
    ) -> None:
        self.app = app
        self.mcp_path = mcp_path
        self.policy = policy
        self.store = store
        self.canvas_api_url = canvas_api_url
        self.account_url = account_url

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Every HTTP request is an HTTP request: no code path may fall back to
        # a server credential, whichever route it reaches.
        set_http_request_active(True)
        try:
            if not _is_mcp_path(scope.get("path", ""), self.mcp_path):
                await self.app(scope, receive, send)
                return

            user = scope.get("user")
            if not isinstance(user, AuthenticatedUser):
                # Not authenticated: FastMCP's RequireAuthMiddleware answers
                # with the 401 and the resource_metadata challenge.
                await self.app(scope, receive, send)
                return

            claims = getattr(user.access_token, "claims", None)
            if not isinstance(claims, Mapping):
                log_warning("MCP request denied", reason="no_claims")
                await _send_json(send, 403, _NO_CLAIMS_MESSAGE)
                return

            verdict = evaluate_entra_claims(claims, self.policy, token_kind="access")
            if isinstance(verdict, ClaimsDenied):
                oid = claims.get("oid")
                log_warning(
                    "MCP request denied",
                    reason=verdict.reason,
                    entra_oid=oid.lower() if isinstance(oid, str) and _GUID_RE.match(oid) else None,
                )
                await _send_json(send, 403, verdict.message)
                return

            set_request_principal(verdict)
            await self._attach_canvas_credentials(verdict.tenant_id, verdict.object_id)
            await self.app(scope, receive, send)
        finally:
            clear_http_request_context()

    async def _attach_canvas_credentials(self, tenant_id: str, object_id: str) -> None:
        try:
            row: Any = await anyio.to_thread.run_sync(self.store.get, tenant_id, object_id)
        except Exception:
            # The exception text is never logged: it can sit next to key or
            # token material.
            log_error("stored Canvas token unreadable", entra_oid=object_id)
            set_missing_credentials_message(unreadable_token_message(self.account_url))
            return

        if row is None:
            set_missing_credentials_message(not_enrolled_message(self.account_url))
            return

        set_request_credentials(
            RequestCredentials(api_token=row.api_token, api_url=self.canvas_api_url)
        )
        try:
            await anyio.to_thread.run_sync(self.store.touch, tenant_id, object_id)
        except Exception:
            pass  # last-used bookkeeping must never fail a request
