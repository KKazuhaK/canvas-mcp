"""Refuse tool calls and resource reads that have no identity or no Canvas token.

Runs inside the MCP request, after the ASGI middleware has set the request
context. Listing tools, initialising and prompts are not gated, so an
unenrolled user can still connect and read the instructions to enroll.

It also enforces the per-user opt-in for write tools (see :mod:`.tool_prefs`):
a call to a write tool the user has not switched on at ``/account`` is refused
here, before the tool runs. That is the security boundary. The tool list hides
those tools from the model too, which only saves it from trying them.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from typing import Any

import mcp.types as mt
from fastmcp.exceptions import ResourceError, ToolError
from fastmcp.resources import ResourceResult
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import Tool, ToolResult

from ..credentials import (
    get_request_credentials,
    get_request_principal,
    get_request_token_state,
    get_request_tool_prefs,
    missing_credentials_message,
)
from ..logging import log_error
from .tool_prefs import (
    WriteDecision,
    decide,
    prefs_unreadable_message,
    write_tool_not_offered_message,
    write_tool_off_message,
)

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
    """Gate calls and reads behind a verified identity and an enrolled Canvas token.

    ``write_ceiling`` is the operator's ``ALLOWED_WRITE_TOOLS`` set (None: the tool
    registry itself is the ceiling) and ``account_url`` is where the refusal
    message sends the user to switch a write tool on.
    """

    def __init__(
        self,
        *,
        account_url: str | None = None,
        write_ceiling: Collection[str] | None = None,
    ) -> None:
        self._account_url = account_url
        self._ceiling: frozenset[str] | None = (
            None if write_ceiling is None else frozenset(write_ceiling)
        )

    @staticmethod
    def _enabled_write_tools() -> frozenset[str]:
        prefs = get_request_tool_prefs()
        return prefs.enabled if prefs is not None else frozenset()

    def _check_write_tool(self, name: str) -> None:
        """Refuse a write tool the user has not switched on (or the server does not offer)."""
        decision = decide(name, enabled=self._enabled_write_tools(), ceiling=self._ceiling)
        if decision is WriteDecision.ALLOWED:
            return
        if decision is WriteDecision.NOT_OFFERED:
            raise ToolError(write_tool_not_offered_message(name))
        prefs = get_request_tool_prefs()
        if prefs is not None and not prefs.readable:
            raise ToolError(prefs_unreadable_message())
        raise ToolError(write_tool_off_message(name, self._account_url))

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        _check_request_context(ToolError)
        self._check_write_tool(context.message.name)
        return await call_next(context)

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        tools = await call_next(context)
        enabled = self._enabled_write_tools()
        return [
            tool
            for tool in tools
            if decide(tool.name, enabled=enabled, ceiling=self._ceiling)
            is WriteDecision.ALLOWED
        ]

    async def on_read_resource(
        self,
        context: MiddlewareContext[mt.ReadResourceRequestParams],
        call_next: CallNext[mt.ReadResourceRequestParams, ResourceResult],
    ) -> ResourceResult:
        _check_request_context(ResourceError)
        return await call_next(context)
