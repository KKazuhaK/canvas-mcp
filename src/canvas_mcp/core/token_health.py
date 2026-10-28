"""Telling a dead Canvas token from a permission error, at the Canvas call sites.

A 401 from Canvas does not always mean the token is dead: Canvas also answers
401 when a live token lacks permission for a resource. So a 401 is only a
*suspicion*, and only when it looks like a dead token (it carries a
``WWW-Authenticate`` header, or its error text says the access token is invalid
or expired). Every other 401, and every 403, keeps its usual meaning.

This module is the client-side half. It knows nothing about storage: a monitor
(registered by the self-hosted server, see ``selfhost.token_health``) confirms a
suspicion with a separate probe and records the outcome. With neither a monitor
nor a verified principal, a request that carries its own token (the legacy and Azure
HTTP modes, where a platform injects ``X-Canvas-Token``) confirms the suspicion
with the same probe and records nothing. The same goes for stdio mode with the token in ``CANVAS_API_TOKEN``.

Within one request, a shared :class:`~canvas_mcp.core.credentials.RequestTokenState`
remembers that the token was found dead, so later paginated or gathered calls
stop at once instead of each hitting Canvas and getting another 401.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from dataclasses import dataclass
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
_PROBE_TIMEOUT_SECONDS = 10.0

#: What the caller is told when a stateless probe confirms the token is dead.
CREDENTIAL_REJECTED_MESSAGE = (
    "Canvas rejected the API token (it was revoked, expired, or regenerated). "
    "A new Canvas token is needed; ask the user to replace it."
)


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
    body = await _body_snippet(response)
    if _insufficient_scope(response, body):
        return False
    if "www-authenticate" in response.headers:
        return True
    return _DEAD_TEXT_RE.search(body) is not None


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
    if monitor is None and principal is None:
        # The legacy and Azure HTTP modes: a caller token, but no store behind it.
        return await _confirm_without_monitor(response, credentials)
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


_INSUFFICIENT_SCOPE_RE = re.compile(r"insufficient[ _]scope", re.IGNORECASE)
_INVALID_TOKEN_HEADER_RE = re.compile(r"invalid_token", re.IGNORECASE)

#: How long a probe verdict (dead or alive) is reused for the same token.
PROBE_CACHE_SECONDS = 60.0
_MAX_TRACKED_TOKENS = 1024
_clock = time.monotonic


def _insufficient_scope(response: httpx.Response, body: str) -> bool:
    """A 401 that says the token is fine but lacks scope: never a dead token."""
    return bool(
        _INSUFFICIENT_SCOPE_RE.search(response.headers.get("www-authenticate", ""))
        or _INSUFFICIENT_SCOPE_RE.search(body)
    )


def _says_token_is_dead(response: httpx.Response) -> bool:
    """A 401 whose headers or body say the token is invalid, expired or revoked.

    ``WWW-Authenticate`` alone is not enough (Canvas sends it on any 401), and
    "insufficient scope" overrides everything.
    """
    if response.status_code != 401:
        return False
    try:
        body = response.text[:_MAX_BODY_CHARS]
    except httpx.ResponseNotRead:
        return False
    if _insufficient_scope(response, body):
        return False
    return bool(
        _INVALID_TOKEN_HEADER_RE.search(response.headers.get("www-authenticate", ""))
        or _DEAD_TEXT_RE.search(body)
    )


async def _probe_rejects(credentials: RequestCredentials) -> bool:
    """True only if ``GET /users/self`` with this token answers 401 *and* says the token is dead."""
    from .client import _canvas_auth_headers

    headers = _canvas_auth_headers(credentials.api_token)
    headers["Accept"] = "application/json"
    try:
        async with httpx.AsyncClient(
            timeout=_PROBE_TIMEOUT_SECONDS, follow_redirects=False
        ) as client:
            probe = await client.get(
                credentials.api_url.rstrip("/") + "/users/self", headers=headers
            )
    except (httpx.HTTPError, ValueError):
        return False
    return _says_token_is_dead(probe)


@dataclass
class _Probe:
    loop: asyncio.AbstractEventLoop
    future: asyncio.Future[bool]
    dead: bool = False
    finished_at: float | None = None


_probes: dict[str, _Probe] = {}


def _token_key(credentials: RequestCredentials) -> str:
    """An opaque key for one token at one school; the token itself is never a key."""
    digest = hashlib.sha256()
    digest.update(credentials.api_url.rstrip("/").encode())
    digest.update(b"\0")
    digest.update(credentials.api_token.encode())
    return digest.hexdigest()


def _prune_probes() -> None:
    if len(_probes) < _MAX_TRACKED_TOKENS:
        return
    now = _clock()
    for key in [
        k
        for k, p in _probes.items()
        if p.finished_at is not None and now - p.finished_at >= PROBE_CACHE_SECONDS
    ]:
        del _probes[key]
    if len(_probes) >= _MAX_TRACKED_TOKENS:
        _probes.clear()


def reset_probe_cache() -> None:
    """Forget every probe verdict (test isolation)."""
    _probes.clear()


async def _token_is_dead(credentials: RequestCredentials) -> bool:
    """One probe per token at a time, and its verdict reused for a minute."""
    key = _token_key(credentials)
    loop = asyncio.get_running_loop()
    entry = _probes.get(key)
    if entry is not None and entry.loop is loop:
        if not entry.future.done():
            # shield(): cancelling this waiter must not cancel the shared probe.
            return await asyncio.shield(entry.future)
        if entry.finished_at is not None and _clock() - entry.finished_at < PROBE_CACHE_SECONDS:
            return entry.dead
    _prune_probes()
    entry = _Probe(loop=loop, future=loop.create_future())
    _probes[key] = entry
    dead = False
    try:
        dead = await _probe_rejects(credentials)
    except BaseException:
        _probes.pop(key, None)  # nothing learned: the next caller probes again
        raise
    else:
        entry.dead = dead
        entry.finished_at = _clock()
    finally:
        if not entry.future.done():
            entry.future.set_result(dead)
    return dead


async def _confirm_without_monitor(
    response: httpx.Response, credentials: RequestCredentials
) -> str | None:
    """Confirm a suspected dead token when there is no token store (legacy HTTP, stdio).

    Same rule as the self-hosted probe, but stricter: ``GET /users/self`` with the
    very same token must answer 401 and say the token is invalid, expired or
    revoked. A 401 about scope, or one that says nothing, is not a dead token.
    Nothing is recorded.
    """
    state = get_request_token_state()
    if state is not None and state.dead and state.message:
        return state.message
    if not await looks_like_dead_token(response):
        return None
    if not await _token_is_dead(credentials):
        return None
    if state is not None:
        state.dead = True
        state.message = CREDENTIAL_REJECTED_MESSAGE
    return CREDENTIAL_REJECTED_MESSAGE


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
