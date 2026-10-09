"""Refuse tool calls and resource reads that have no identity or no Canvas token.

Runs inside the MCP request, after the ASGI middleware has set the request
context. Listing tools, initialising and prompts are not gated, so an
unenrolled user can still connect and read the instructions to enroll.
"""

from __future__ import annotations

from typing import Any

import mcp.types as mt
from fastmcp.exceptions import ResourceError, ToolError
from fastmcp.resources import ResourceResult
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult

from ..credentials import (
    get_request_credentials,
    get_request_principal,
    get_request_token_state,
    missing_credentials_message,
)
from ..logging import log_error

_NOT_SIGNED_IN = "Not signed in."
_IDENTITY_MISMATCH = "Identity check failed; reconnect the connector."


def _check_request_context(error_type: type[Exception]) -> None:
    """Raise ``error_type`` unless this request has a consistent identity and a token."""
    principal = get_request_principal()
    if principal is None:
        raise error_type(_NOT_SIGNED_IN)

    token = get_access_token()
    claims: Any = getattr(token, "claims", None)
    oid = claims.get("oid") if hasattr(claims, "get") else None
    if not isinstance(oid, str) or oid.lower() != principal.object_id:
        # Defence in depth: the verified token and the ContextVar must agree.
        log_error("identity mismatch between access token and request context")
        raise error_type(_IDENTITY_MISMATCH)

    if get_request_credentials() is None:
        # Also the answer for a token marked invalid: the request context mounts
        # no credentials for it and carries the re-enroll message instead, so
        # the call is refused before any Canvas request is made.
        raise error_type(missing_credentials_message())

    state = get_request_token_state()
    if state is not None and state.dead and state.message:
        raise error_type(state.message)


class SelfhostCredentialGate(Middleware):
    """Gate calls and reads behind a verified identity and an enrolled Canvas token."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        _check_request_context(ToolError)
        return await call_next(context)

    async def on_read_resource(
        self,
        context: MiddlewareContext[mt.ReadResourceRequestParams],
        call_next: CallNext[mt.ReadResourceRequestParams, ResourceResult],
    ) -> ResourceResult:
        _check_request_context(ResourceError)
        return await call_next(context)
