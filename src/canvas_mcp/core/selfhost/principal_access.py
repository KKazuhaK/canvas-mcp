"""Is this principal allowed to use the server at all? The MCP side of the answer.

Access is an authorization decision stored in the token database
(``accounts.status``, see :mod:`.token_store`), not a property of an enrollment
row. Every MCP request asks :class:`PrincipalAccessCache` before any Canvas
credential is loaded, and the credential gate asks again for every tool call and
resource read, so a disabled, pending or unknown account is refused wherever the
request came from: an MCP token issued before the change, a freshly refreshed one, or
a connection that survived a server restart.

The answer is cached for a few seconds per principal so the check costs one small
read per user per interval, not one per request. The cache is dropped for a
principal as soon as this process changes it (the admin page), so the process that
makes the change refuses the principal at once. A change made by another process
(a second worker, the operator CLI) reaches this process within the TTL; that is
the bounded delay. Failures are never cached and propagate, so callers fail closed.

What this cannot do: a request that already passed the check keeps running, and a
Canvas call that was already sent is not cancelled. The check is made before each
request and before each tool call, never inside a Canvas call.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Protocol

from .accounts import DENIAL_MESSAGES, DENY_ACCESS_DENIED, DENY_PENDING_APPROVAL
from .token_store import PrincipalStatus

#: How long one answer is reused. This is also the longest another process (or the
#: operator CLI) can take to be noticed by this one.
DEFAULT_ACCESS_CACHE_SECONDS = 5.0
_MAX_CACHED_PRINCIPALS = 4096


def access_disabled_message() -> str:
    """The refusal for a principal an administrator disabled (no way to fix it yourself)."""
    return (
        "Your access to this server was disabled by an administrator. "
        "Contact the server owner to have it restored."
    )


def access_unavailable_message() -> str:
    """The refusal when the access decision could not be read (fail closed)."""
    return "Your access could not be verified right now. Try again in a moment."


def access_pending_message() -> str:
    """The refusal for an account that waits for an owner's approval."""
    return DENIAL_MESSAGES[DENY_PENDING_APPROVAL]


def access_not_provisioned_message() -> str:
    """The refusal for a principal without an account (fail closed)."""
    return DENIAL_MESSAGES[DENY_ACCESS_DENIED]


def access_refusal_message(status: PrincipalStatus) -> str | None:
    """Why this account may not use the server, or None when it may."""
    if status.active:
        return None
    if status.disabled:
        return access_disabled_message()
    if status.pending:
        return access_pending_message()
    return access_not_provisioned_message()


class PrincipalStatusSource(Protocol):
    """The slice of the token store the cache reads."""

    def get_principal_status(self, principal_key: str) -> PrincipalStatus: ...


class PrincipalAccessCache:
    """Per-principal cache of the access status, valid for a short time.

    :meth:`status` reads the database at most once per ``ttl_seconds`` per
    principal; :meth:`invalidate` drops one principal (or all) at once. A read that
    started before an invalidation cannot store its possibly old answer afterwards.
    Synchronous and thread-safe; async callers use ``anyio.to_thread.run_sync``.
    """

    def __init__(
        self,
        source: PrincipalStatusSource,
        *,
        ttl_seconds: float = DEFAULT_ACCESS_CACHE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = _MAX_CACHED_PRINCIPALS,
    ) -> None:
        self._source = source
        self._ttl = ttl_seconds
        self._clock = clock
        self._max = max_entries
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, tuple[float, PrincipalStatus]] = OrderedDict()
        self._epoch = 0

    def status(self, principal_key: str) -> PrincipalStatus:
        """The current access status; raises when the database cannot be read."""
        now = self._clock()
        with self._lock:
            entry = self._entries.get(principal_key)
            if entry is not None and entry[0] > now:
                return entry[1]
            epoch = self._epoch
        fresh = self._source.get_principal_status(principal_key)
        with self._lock:
            if epoch == self._epoch:
                self._entries[principal_key] = (self._clock() + self._ttl, fresh)
                self._entries.move_to_end(principal_key)
                while len(self._entries) > self._max:
                    self._entries.popitem(last=False)
        return fresh

    def invalidate(self, principal_key: str | None = None) -> None:
        """Forget one principal (or everyone) so the next check goes to the database."""
        with self._lock:
            self._epoch += 1
            if principal_key is None:
                self._entries.clear()
            else:
                self._entries.pop(principal_key, None)
