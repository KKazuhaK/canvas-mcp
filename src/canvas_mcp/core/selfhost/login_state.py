"""One-time login state behind an interface (reserved for the next phase).

Today nothing is stored on the server for a sign-in: the OIDC ``state``, ``nonce``
and PKCE verifier of ``/account`` travel in an AES-GCM sealed ``__Host-`` cookie
(see ``account_web``). This module defines the interface a server-side store has
to satisfy, with an in-process implementation, so the later phase that needs
server-side state (a replaced OAuth proxy, a shared backend) has one contract
and one set of tests. It is not wired into any route yet.

Contract of :class:`LoginStateStore`:

* ``put`` returns an unguessable id and stores the payload for ``ttl_s`` seconds.
* ``pop`` returns the payload **at most once**: atomically, so two concurrent
  callers can never both receive it. A missing, already used and expired id are
  indistinguishable to the caller (all return ``None``).
* A storage error fails closed: it raises, it never returns a payload it cannot
  prove unused.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Protocol

MAX_ENTRIES = 10_000
MAX_TTL_SECONDS = 3600
MAX_PAYLOAD_BYTES = 4096


class LoginStateStore(Protocol):
    async def put(self, kind: str, payload: bytes, ttl_s: float) -> str:
        """Store ``payload`` under a new random id and return the id."""

    async def pop(self, kind: str, state_id: str) -> bytes | None:
        """Return and delete the payload; ``None`` if missing, used or expired."""


class InMemoryLoginStateStore:
    """Process-local store: a lock, random ids, a monotonic clock and a size bound."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = MAX_ENTRIES,
    ) -> None:
        self._clock = clock
        self._max_entries = max_entries
        self._entries: OrderedDict[tuple[str, str], tuple[float, bytes]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def put(self, kind: str, payload: bytes, ttl_s: float) -> str:
        if not kind or not 0 < ttl_s <= MAX_TTL_SECONDS or len(payload) > MAX_PAYLOAD_BYTES:
            raise ValueError("invalid login state")
        state_id = secrets.token_urlsafe(32)
        async with self._lock:
            now = self._clock()
            self._purge(now)
            while len(self._entries) >= self._max_entries:
                self._entries.popitem(last=False)
            self._entries[(kind, state_id)] = (now + ttl_s, bytes(payload))
        return state_id

    async def pop(self, kind: str, state_id: str) -> bytes | None:
        async with self._lock:
            entry = self._entries.pop((kind, state_id), None)
            if entry is None:
                return None
            expires_at, payload = entry
            return payload if self._clock() < expires_at else None

    def _purge(self, now: float) -> None:
        for key in [k for k, (expires, _) in self._entries.items() if expires <= now]:
            del self._entries[key]
