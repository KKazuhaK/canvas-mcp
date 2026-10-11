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
  ``/authorize`` need no sign-in and can create rows in the database.
  They get a process-wide token bucket (the app cannot tell clients
  apart by IP: that is the reverse proxy's job, see the nginx example), a daily
  budget for registrations, and a size cap on the registration body.
* **Cleanup.** At most once per interval, traffic schedules bounded native
  housekeeping. Expired ephemeral rows and retained OAuth records are culled
  according to their individual policies.

Two more endpoints reach the database without a sign-in and get a bucket as
well: ``POST /token`` and
``POST /revoke``; and their bodies, like ``POST /authorize``, are capped at 16 KiB. ``HEAD
/authorize`` is metered and answered with 405 (the handler would otherwise treat a HEAD
with a body as a full request).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config_snapshot import CURRENT_CONFIG
from .db.errors import StoreUnavailable
from .limits import InMemoryTokenBucket, RateLimiters, build_rate_limiters
from .maintenance import MAINTENANCE_INTERVAL_SECONDS, Maintenance, MaintenanceScheduler
from .mcp_state import MCP_READ, MCP_UNAVAILABLE

REGISTER_PATH = "/register"
AUTHORIZE_PATH = "/authorize"
TOKEN_PATH = "/token"
REVOKE_PATH = "/revoke"

# Per-minute allowance for each of the two public endpoints (also the burst).
PUBLIC_REQUESTS_PER_MINUTE = 30
# Registrations per rolling day. Each native client has a bounded lifetime,
# so this also bounds the number of retained database records.
REGISTRATIONS_PER_DAY = 300
# Dynamic client registration documents are tiny; anything bigger is abuse.
MAX_REGISTER_BODY_BYTES = 16 * 1024
# Local authorization server only: the token endpoint reads the database (and may fetch a
# client metadata document), so it gets a larger allowance than the other two, and the
# revocation endpoint the same as /authorize. Per minute, process-wide (also the burst).
TOKEN_REQUESTS_PER_MINUTE = 120
REVOKE_REQUESTS_PER_MINUTE = 30
# The form bodies of /token, /revoke and POST /authorize are a few hundred bytes.
MAX_OAUTH_FORM_BYTES = 16 * 1024


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
        self._register_daily = make(
            REGISTRATIONS_PER_DAY, REGISTRATIONS_PER_DAY / 86400.0, clock
        )
        self._authorize = make(PUBLIC_REQUESTS_PER_MINUTE, per_second, clock)
        self._token = make(
            TOKEN_REQUESTS_PER_MINUTE, TOKEN_REQUESTS_PER_MINUTE / 60.0, clock
        )
        self._revoke = make(
            REVOKE_REQUESTS_PER_MINUTE, REVOKE_REQUESTS_PER_MINUTE / 60.0, clock
        )
        self._maintenance = MaintenanceScheduler(
            maintenance, clock=clock, interval=maintenance_interval
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        config_marker = CURRENT_CONFIG.set(None)
        marker = MCP_READ.set(None)
        unavailable_marker = MCP_UNAVAILABLE.set(False)
        started = False

        async def record_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self._dispatch(scope, receive, record_send)
        except StoreUnavailable:
            if scope["type"] != "http" or started:
                raise
            await _respond(send, 503, {"error": "temporarily_unavailable"})
        finally:
            CURRENT_CONFIG.reset(config_marker)
            MCP_READ.reset(marker)
            MCP_UNAVAILABLE.reset(unavailable_marker)

    async def _dispatch(self, scope: Scope, receive: Receive, send: Send) -> None:
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
            if path == AUTHORIZE_PATH and method == "HEAD":
                # Starlette serves HEAD wherever GET is routed, and the SDK handler reads the
                # form of every non-GET request, so a HEAD with a body would be a whole
                # /authorize request (a transaction row, a metadata fetch) outside the
                # bucket and the body cap. Nobody needs HEAD here: meter it, then refuse it.
                retry = self._authorize.take()
                if retry > 0:
                    await _too_many_requests(send, retry)
                    return
                await _method_not_allowed(send, "GET, POST")
                return
            if path == AUTHORIZE_PATH and method in ("GET", "POST"):
                retry = self._authorize.take()
                if retry > 0:
                    await _too_many_requests(send, retry)
                    return
                self._maintenance.schedule()
                if method == "POST":
                    await self._capped_oauth_form(scope, receive, send)
                    return
            elif method == "POST" and path in (TOKEN_PATH, REVOKE_PATH):
                bucket = self._token if path == TOKEN_PATH else self._revoke
                retry = bucket.take()
                if retry > 0:
                    await _too_many_requests(send, retry)
                    return
                self._maintenance.schedule()
                await self._capped_oauth_form(scope, receive, send)
                return
        await self.app(scope, receive, send)

    async def _capped_oauth_form(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Pass the request on with its (small) form body read and replayed, or refuse it with 413."""
        body = await _read_capped_body(scope, receive, MAX_OAUTH_FORM_BYTES)
        if body is None:
            await _respond(
                send,
                413,
                {
                    "error": "invalid_request",
                    "error_description": "request is too large",
                },
            )
            return
        await self.app(scope, _replaying(body, receive), send)

    async def _guarded_register(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
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
            await _respond(
                send,
                413,
                {
                    "error": "invalid_client_metadata",
                    "error_description": "registration request is too large",
                },
            )
            return
        self._maintenance.schedule()
        await self.app(scope, _replaying(body, receive), send)


def _replaying(body: bytes, receive: Receive) -> Receive:
    """A receive callable that hands ``body`` to the app once, then whatever ``receive`` gives."""
    replayed = False

    async def replay() -> Message:
        nonlocal replayed
        if not replayed:
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replay


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
            return b"".join(
                chunks
            )  # disconnect: let the app see an empty or short body
        chunk = message.get("body", b"")
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)


async def _respond(
    send: Send, status: int, payload: dict[str, Any], *, retry_after: int | None = None
) -> None:
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


async def _method_not_allowed(send: Send, allow: str) -> None:
    headers = [
        (b"allow", allow.encode()),
        (b"content-length", b"0"),
        (b"cache-control", b"no-store"),
    ]
    await send({"type": "http.response.start", "status": 405, "headers": headers})
    await send({"type": "http.response.body", "body": b""})


async def _too_many_requests(send: Send, retry_after_seconds: float) -> None:
    seconds = int(min(max(retry_after_seconds, 1.0), 86400.0)) + 1
    await _respond(
        send,
        429,
        {
            "error": "temporarily_unavailable",
            "error_description": "too many requests, try again later",
        },
        retry_after=seconds,
    )
