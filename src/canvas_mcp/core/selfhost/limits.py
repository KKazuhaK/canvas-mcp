"""Rate-limiter interfaces of the self-hosted mode, with in-process implementations.

The server is a single instance, so per-process limits are the correct limits;
the in-memory implementations below are the code that used to live in
``account_web`` (sliding window) and ``edge_guard`` (token bucket), moved
unchanged. The Protocols are the seam for a shared backend (Redis) that a future
multi-instance mode can add behind ``SELFHOST_STATE_BACKEND``; selecting it today
fails closed at startup (see ``settings``).
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

Clock = Callable[[], float]


class SlidingWindowLimiter(Protocol):
    """At most ``limit`` attempts per key in a rolling window."""

    def allow(self, key: tuple[str, str]) -> bool:
        """Record an attempt; False when the key is over its limit."""


class TokenBucketLimiter(Protocol):
    """A refilling bucket of tokens shared by one class of requests."""

    def take(self) -> float:
        """Take one token. Returns 0 when allowed, else seconds until one is free."""

    def give_back(self) -> None:
        """Return a token taken for a request that was then refused elsewhere."""


class InMemorySlidingWindowLimiter:
    """Sliding-window attempt counter in a bounded in-memory table."""

    def __init__(
        self,
        limit: int,
        window: int,
        max_keys: int,
        clock: Clock,
    ) -> None:
        self._limit = limit
        self._window = window
        self._max_keys = max_keys
        self._clock = clock
        self._hits: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()

    def allow(self, key: tuple[str, str]) -> bool:
        now = self._clock()
        cutoff = now - self._window
        hits = self._hits.get(key)
        if hits is None:
            if len(self._hits) >= self._max_keys:
                self._purge(cutoff)
            while len(self._hits) >= self._max_keys:
                self._hits.popitem(last=False)
            hits = deque()
            self._hits[key] = hits
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if len(hits) >= self._limit:
            return False
        hits.append(now)
        return True

    def _purge(self, cutoff: float) -> None:
        for key in [k for k, h in self._hits.items() if not h or h[-1] <= cutoff]:
            del self._hits[key]


class InMemoryTokenBucket:
    """A thread-safe token bucket: ``capacity`` tokens, refilled continuously."""

    def __init__(
        self, capacity: float, refill_per_second: float, clock: Clock = time.monotonic
    ) -> None:
        self._capacity = float(capacity)
        self._rate = float(refill_per_second)
        self._clock = clock
        self._tokens = float(capacity)
        self._updated = clock()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._updated)
        self._updated = now
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)

    def take(self) -> float:
        """Take one token. Returns 0 when allowed, else seconds until one is free."""
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return 0.0
            return (1.0 - self._tokens) / self._rate if self._rate > 0 else float("inf")

    def give_back(self) -> None:
        """Return a token taken for a request that was then refused elsewhere."""
        with self._lock:
            self._tokens = min(self._capacity, self._tokens + 1.0)


@dataclass(frozen=True)
class RateLimiters:
    """Factories for the limiters of one state backend."""

    backend: str
    sliding_window: Callable[[int, int, int, Clock], SlidingWindowLimiter]
    token_bucket: Callable[[float, float, Clock], TokenBucketLimiter]


def build_rate_limiters(backend: Literal["memory"] = "memory") -> RateLimiters:
    """The limiter factories for ``SELFHOST_STATE_BACKEND`` (only ``memory`` exists)."""
    if backend != "memory":  # pragma: no cover - settings refuse every other value
        raise ValueError("unsupported state backend")
    return RateLimiters(
        backend="memory",
        sliding_window=InMemorySlidingWindowLimiter,
        token_bucket=InMemoryTokenBucket,
    )
