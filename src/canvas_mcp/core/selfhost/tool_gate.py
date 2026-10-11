"""Refuse tool calls and resource reads that have no identity or no Canvas token.

Runs inside the MCP request, after the ASGI middleware has set the request
context. Listing tools, initialising and prompts are not gated, so an
unenrolled user can still connect and read the instructions to enroll.

It also enforces the per-user opt-in for write tools (see :mod:`.tool_prefs`):
a call to a write tool the user has not switched on at ``/account`` is refused
here, before the tool runs. That is the security boundary. The tool list hides
those tools from the model too, which only saves it from trying them.

When given the access cache (see :mod:`.principal_access`), it also refuses every
call and read of an account that is not active (disabled, waiting for approval, or
unknown). The request-context
middleware already refuses such a request up front; this is the second check, made
at the moment of each tool call, so a request that is already running cannot start a
further tool call after the change (the cache bounds how late another process's
change is noticed). A call whose Canvas requests were already sent is not
cancelled.

The same check refuses a call from a request whose Canvas credential was replaced,
removed, found dead or restored after the request began (the credential generation
the store reports, or this process has already heard of, is newer than the one the
request was authorized under). A change learned by this process is seen immediately; the next request on every
instance reads the committed account generation. Such a
request holds the old token; it is told to retry rather than start a further tool
call, which matters most for a write that was previewed under the old credential.
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
    get_request_credential_generation,
    get_request_credentials,
    get_request_principal,
    get_request_token_state,
    get_request_tool_prefs,
    missing_credentials_message,
    request_credential_is_stale,
)
from ..logging import log_error
from .mcp_state import MCP_READ
from .principal_access import (
    access_refusal_message,
    access_unavailable_message,
    snapshot_status,
)
from .tool_prefs import (
    WriteDecision,
    decide,
    prefs_unreadable_message,
    write_tool_not_offered_message,
    write_tool_off_message,
)

_NOT_SIGNED_IN = "Not signed in."
_CREDENTIAL_CHANGED = (
    "Your Canvas connection changed while this request was running. "
    "Nothing was sent to Canvas for this call. Try again."
)
_IDENTITY_MISMATCH = "Identity check failed; reconnect the connector."


def _check_generation_in_process(error_type: type[Exception]) -> None:
    """Refuse a call after this process learned a newer credential generation."""
    if request_credential_is_stale():
        raise error_type(_CREDENTIAL_CHANGED)


async def _check_access(error_type: type[Exception]) -> None:
    """Check the snapshot authorized for this request without another database read."""
    principal = get_request_principal()
    if principal is None:
        raise error_type(_NOT_SIGNED_IN)
    read = MCP_READ.get()
    if read is None or read.account_id != principal.key:
        raise error_type(access_unavailable_message())
    refusal = access_refusal_message(snapshot_status(read))
    if refusal is not None:
        raise error_type(refusal)
    held = get_request_credential_generation()
    if held is not None and read.snapshot.credential_generation > held:
        raise error_type(_CREDENTIAL_CHANGED)


def _check_local_identity(error_type: type[Exception]) -> None:
    """Like :func:`_check_identity`, for a token issued by this server (built-in authorization).

    The verified token and the request context must agree on the account, the issuer and
    the kind of token, and the principal must be one the local resolver made.
    """
    principal = get_request_principal()
    if principal is None:
        raise error_type(_NOT_SIGNED_IN)
    token = get_access_token()
    claims: Any = getattr(token, "claims", None)
    get = claims.get if hasattr(claims, "get") else (lambda _name: None)
    acct = get("acct")
    if (
        not isinstance(acct, str)
        or acct != principal.key
        or principal.provider_id != "local"
        or not principal.issuer
        or get("iss") != principal.issuer
        or get("token_use") != "access"
    ):
        log_error("identity mismatch between access token and request context")
        raise error_type(_IDENTITY_MISMATCH)


def _check_credentials(error_type: type[Exception]) -> None:
    """Raise ``error_type`` unless this request carries a usable Canvas credential."""
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
        decision = decide(
            name, enabled=self._enabled_write_tools(), ceiling=self._ceiling
        )
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
        _check_local_identity(ToolError)
        await _check_access(ToolError)
        _check_credentials(ToolError)
        _check_generation_in_process(ToolError)
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
        _check_local_identity(ResourceError)
        await _check_access(ResourceError)
        _check_credentials(ResourceError)
        _check_generation_in_process(ResourceError)
        return await call_next(context)
