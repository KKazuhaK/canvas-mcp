"""Telling a dead Canvas token from a permission error, at the Canvas call sites.

A 401 from Canvas does not always mean the token is dead: Canvas also answers
401 when a live token lacks permission for a resource. So a 401 is only a
*suspicion*, and only when it looks like a dead token (it carries a
``WWW-Authenticate`` header, or its error text says the access token is invalid
or expired). Every other 401, and every 403, keeps its usual meaning.

This module is the client-side half. It knows nothing about storage: a monitor
(registered by the self-hosted server, see ``selfhost.token_health``) confirms a
suspicion with a separate probe and records the outcome. Without a monitor, or
without a verified principal (stdio and the legacy HTTP modes), nothing here
does anything.

Within one request, a shared :class:`~canvas_mcp.core.credentials.RequestTokenState`
remembers that the token was found dead, so later paginated or gathered calls
stop at once instead of each hitting Canvas and getting another 401.
"""

from __future__ import annotations

import re
from typing import Protocol

import httpx

from .credentials import (
    RequestCredentials,
    get_request_principal,
    get_request_token_state,
)
from .write_outcome import RequestFailure, WriteOutcome

_DEAD_TEXT_RE = re.compile(r"invalid access token|expired", re.IGNORECASE)
_MAX_BODY_CHARS = 4096


class TokenHealthMonitor(Protocol):
    """What the Canvas client needs from the token-health service."""

    async def confirm_dead_token(
        self,
        principal_key: str,
        credentials: RequestCredentials,
        token_version: int | None,
        credential_generation: int | None = None,
    ) -> str | None:
        """The re-enroll message if Canvas confirms the token is dead, else None.

        ``credential_generation`` is the generation the rejected token was read
        under: a verdict about it is never recorded against a later token.
        """

    async def note_success(
        self, principal_key: str, credential_generation: int | None = None
    ) -> None:
        """Record that a Canvas call with the stored token succeeded."""


_monitor: TokenHealthMonitor | None = None


def set_token_health_monitor(monitor: TokenHealthMonitor | None) -> None:
    """Register (or remove) the monitor. Called once at startup of the self-hosted server."""
    global _monitor
    _monitor = monitor


def get_token_health_monitor() -> TokenHealthMonitor | None:
    return _monitor


async def _body_snippet(response: httpx.Response) -> str:
    """The start of a response body as text; reads a streamed body only as far as needed."""
    try:
        return response.text[:_MAX_BODY_CHARS]
    except httpx.ResponseNotRead:
        pass
    parts: list[bytes] = []
    size = 0
    try:
        async for chunk in response.aiter_bytes():
            parts.append(chunk)
            size += len(chunk)
            if size >= _MAX_BODY_CHARS:
                break
    except httpx.HTTPError:
        pass
    return b"".join(parts)[: _MAX_BODY_CHARS * 4].decode("utf-8", "replace")[:_MAX_BODY_CHARS]


async def looks_like_dead_token(response: httpx.Response) -> bool:
    """True for a 401 that is consistent with a revoked, expired or regenerated token."""
    if response.status_code != 401:
        return False
    if "www-authenticate" in response.headers:
        return True
    return _DEAD_TEXT_RE.search(await _body_snippet(response)) is not None


def dead_token_failure() -> RequestFailure | None:
    """The failure to return, without any request, when this request already found the token dead."""
    state = get_request_token_state()
    if state is not None and state.dead and state.message:
        return RequestFailure(state.message, WriteOutcome.NOT_DISPATCHED)
    return None


def dead_token_message() -> str | None:
    """The re-enroll message if this request already found the token dead."""
    state = get_request_token_state()
    if state is not None and state.dead and state.message:
        return state.message
    return None


async def check_for_dead_token(
    response: httpx.Response, credentials: RequestCredentials | None
) -> str | None:
    """Handle a 401 on a Canvas call; returns the re-enroll message if the token is dead.

    The caller returns that message instead of the raw 401. Anything that is not
    a suspicion, or that the probe does not confirm, returns None and the caller
    keeps its normal error handling.
    """
    if response.status_code != 401 or credentials is None:
        return None
    monitor = _monitor
    principal = get_request_principal()
    if monitor is None or principal is None:
        return None
    state = get_request_token_state()
    if state is not None and state.dead and state.message:
        return state.message
    if not await looks_like_dead_token(response):
        return None
    try:
        message = await monitor.confirm_dead_token(
            principal.key,
            credentials,
            state.token_version if state is not None else None,
            state.credential_generation if state is not None else None,
        )
    except Exception:  # noqa: BLE001 - a failing probe must never change the outcome
        return None
    if message and state is not None:
        state.dead = True
        state.message = message
    return message


async def note_canvas_success(credentials: RequestCredentials | None) -> None:
    """Tell the monitor a Canvas call succeeded (it rate-limits its own writes). Never raises."""
    monitor = _monitor
    if monitor is None or credentials is None:
        return
    principal = get_request_principal()
    if principal is None:
        return
    state = get_request_token_state()
    try:
        await monitor.note_success(
            principal.key, state.credential_generation if state is not None else None
        )
    except Exception:  # noqa: BLE001 - bookkeeping must never fail a request
        return
