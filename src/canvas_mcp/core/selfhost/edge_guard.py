"""Outermost ASGI shim for the self-hosted app: scheme, abuse limits, cleanup.

Three jobs, all for requests that arrive from the open internet before any
sign-in:

* **Scheme.** The server sits behind a TLS-terminating proxy and runs uvicorn
  with ``proxy_headers=False`` (X-Forwarded-* is never believed), so every
  request looks like plain ``http``. Starlette builds its trailing-slash
  redirect from the request's own scheme, which would send a client's POST body
  (an MCP payload) to ``http://``. ``PUBLIC_BASE_URL`` must be https and every
  URL is built from it, so the scheme is simply pinned to https here.
* **Abuse limits.** ``POST /register`` (dynamic client registration) and
  ``/authorize`` need no sign-in and each call writes files to the data
  volume. They get a process-wide token bucket (the app cannot tell clients
  apart by IP: that is the reverse proxy's job, see the nginx example), a daily
  budget for registrations, and a size cap on the registration body.
* **Cleanup.** At most once per interval, after such a request, expired OAuth
  records are deleted from disk (the file store never does it on its own).
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..logging import log_warning
from .limits import InMemoryTokenBucket, RateLimiters, build_rate_limiters

REGISTER_PATH = "/register"
AUTHORIZE_PATH = "/authorize"

# Per-minute allowance for each of the two public endpoints (also the burst).
PUBLIC_REQUESTS_PER_MINUTE = 30
# Registrations per rolling day. Each one is a file that lives for
# DCR_CLIENT_TTL_SECONDS, so this bounds the number of records on the volume.
REGISTRATIONS_PER_DAY = 300
# Dynamic client registration documents are tiny; anything bigger is abuse.
MAX_REGISTER_BODY_BYTES = 16 * 1024
MAINTENANCE_INTERVAL_SECONDS = 3600

Maintenance = Callable[[], Awaitable[None]]


#: The in-process token bucket (moved to :mod:`.limits`; the name is kept).
TokenBucket = InMemoryTokenBucket


class SelfhostEdgeGuard:
    """Pure ASGI middleware wrapped around the whole self-hosted app."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        clock: Callable[[], float] = time.monotonic,
        maintenance: Maintenance | None = None,
        maintenance_interval: float = MAINTENANCE_INTERVAL_SECONDS,
        rate_limiters: RateLimiters | None = None,
    ) -> None:
        self.app = app
        self._clock = clock
        make = (rate_limiters or build_rate_limiters("memory")).token_bucket
        per_second = PUBLIC_REQUESTS_PER_MINUTE / 60.0
        self._register = make(PUBLIC_REQUESTS_PER_MINUTE, per_second, clock)
        self._register_daily = make(REGISTRATIONS_PER_DAY, REGISTRATIONS_PER_DAY / 86400.0, clock)
        self._authorize = make(PUBLIC_REQUESTS_PER_MINUTE, per_second, clock)
        self._maintenance = maintenance
        self._maintenance_interval = maintenance_interval
        self._last_maintenance: float | None = None
        self._background: set[asyncio.Task[None]] = set()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope["type"]
        if scope_type not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        # A copy, so the server's own scope dict is not changed under it.
        scope = dict(scope)
        scope["scheme"] = "https" if scope_type == "http" else "wss"

        if scope_type == "http":
            path = scope.get("path", "")
            method = scope.get("method", "")
            if path == REGISTER_PATH and method == "POST":
                await self._guarded_register(scope, receive, send)
                return
            if path == AUTHORIZE_PATH and method in ("GET", "POST"):
                retry = self._authorize.take()
                if retry > 0:
                    await _too_many_requests(send, retry)
                    return
                self._schedule_maintenance()
        await self.app(scope, receive, send)

    async def _guarded_register(self, scope: Scope, receive: Receive, send: Send) -> None:
        retry = self._register.take()
        if retry == 0.0:
            retry = self._register_daily.take()
            if retry > 0:
                self._register.give_back()
        if retry > 0:
            await _too_many_requests(send, retry)
            return

        body = await _read_capped_body(scope, receive, MAX_REGISTER_BODY_BYTES)
        if body is None:
            await _respond(send, 413, {"error": "invalid_client_metadata",
                                       "error_description": "registration request is too large"})
            return
        self._schedule_maintenance()

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    def _schedule_maintenance(self) -> None:
        if self._maintenance is None:
            return
        now = self._clock()
        if self._last_maintenance is not None and now - self._last_maintenance < self._maintenance_interval:
            return
        self._last_maintenance = now
        task = asyncio.ensure_future(self._run_maintenance(self._maintenance))
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    @staticmethod
    async def _run_maintenance(maintenance: Maintenance) -> None:
        try:
            await maintenance()
        except Exception:
            # The exception text can carry file paths; the reason is enough.
            log_warning("cleanup of expired OAuth records failed")


async def _read_capped_body(scope: Scope, receive: Receive, limit: int) -> bytes | None:
    """Read the whole request body, or None when it is bigger than ``limit``."""
    for name, value in scope.get("headers", []):
        if name == b"content-length":
            try:
                if int(value) > limit:
                    return None
            except ValueError:
                return None
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] != "http.request":
            return b"".join(chunks)  # disconnect: let the app see an empty or short body
        chunk = message.get("body", b"")
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)


async def _respond(send: Send, status: int, payload: dict[str, Any], *, retry_after: int | None = None) -> None:
    body = json.dumps(payload).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        (b"cache-control", b"no-store"),
    ]
    if retry_after is not None:
        headers.append((b"retry-after", str(retry_after).encode()))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


async def _too_many_requests(send: Send, retry_after_seconds: float) -> None:
    seconds = int(min(max(retry_after_seconds, 1.0), 86400.0)) + 1
    await _respond(
        send,
        429,
        {"error": "temporarily_unavailable", "error_description": "too many requests, try again later"},
        retry_after=seconds,
    )
