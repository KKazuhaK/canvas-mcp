"""One-time login state behind an interface.

The OIDC ``state``, ``nonce`` and PKCE verifier of the ``/account`` sign-in travel in an
AES-GCM sealed ``__Host-`` cookie (see ``account_web``) and need no server-side state.
The server's own authorization server (``SELFHOST_AUTH_MODE=local``) does: an
``/authorize`` request has to survive the redirects through the sign-in and the consent
page, so it is stored here (``authz.transactions.SqlLoginStateStore`` is the database
implementation; the in-process one below serves tests and one-process uses).

Contract of :class:`LoginStateStore`:

* ``put`` returns an unguessable id and stores the payload for ``ttl_s`` seconds. With a
  ``binding_hash`` the state belongs to the browser that holds the secret behind it.
* ``pop`` returns the payload **at most once**: atomically, so two concurrent
  callers can never both receive it. A missing, already used, expired and wrong-binding
  id are indistinguishable to the caller (all return ``None``), and a refused pop does
  not consume the state: knowing an id is not enough to destroy it.
* ``peek`` returns the payload of a bound state without consuming it (for the pages
  shown before the user decides).
* A bound state needs the matching ``binding_hash`` on ``pop`` and ``peek``; a state put
  without one is popped without one. A mismatch in either direction returns ``None``.
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
    async def put(
        self, kind: str, payload: bytes, ttl_s: float, *, binding_hash: str | None = None
    ) -> str:
        """Store ``payload`` under a new random id and return the id."""

    async def pop(
        self, kind: str, state_id: str, *, binding_hash: str | None = None
    ) -> bytes | None:
        """Return and delete the payload; ``None`` if missing, used, expired or not bound to
        ``binding_hash``."""

    async def peek(
        self, kind: str, state_id: str, *, binding_hash: str | None = None
    ) -> bytes | None:
        """Return the payload without deleting it, under the same conditions as ``pop``."""


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
        self._entries: OrderedDict[tuple[str, str], tuple[float, bytes, str | None]] = (
            OrderedDict()
        )
        self._lock = asyncio.Lock()

    async def put(
        self, kind: str, payload: bytes, ttl_s: float, *, binding_hash: str | None = None
    ) -> str:
        if not kind or not 0 < ttl_s <= MAX_TTL_SECONDS or len(payload) > MAX_PAYLOAD_BYTES:
            raise ValueError("invalid login state")
        state_id = secrets.token_urlsafe(32)
        async with self._lock:
            now = self._clock()
            self._purge(now)
            while len(self._entries) >= self._max_entries:
                self._entries.popitem(last=False)
            self._entries[(kind, state_id)] = (now + ttl_s, bytes(payload), binding_hash)
        return state_id

    async def pop(
        self, kind: str, state_id: str, *, binding_hash: str | None = None
    ) -> bytes | None:
        async with self._lock:
            entry = self._entries.get((kind, state_id))
            if entry is None:
                return None
            expires_at, payload, bound_to = entry
            if self._clock() >= expires_at:
                del self._entries[(kind, state_id)]
                return None
            if bound_to != binding_hash:
                return None  # a refused pop leaves the state for its rightful holder
            del self._entries[(kind, state_id)]
            return payload

    async def peek(
        self, kind: str, state_id: str, *, binding_hash: str | None = None
    ) -> bytes | None:
        async with self._lock:
            entry = self._entries.get((kind, state_id))
            if entry is None:
                return None
            expires_at, payload, bound_to = entry
            if self._clock() >= expires_at or bound_to != binding_hash:
                return None
            return payload

    def _purge(self, now: float) -> None:
        for key in [k for k, (expires, _, _) in self._entries.items() if expires <= now]:
            del self._entries[key]
