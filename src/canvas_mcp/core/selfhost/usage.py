"""Deduplicate best-effort last-use writes; never cache an authorization decision."""

import threading
import time
from collections import OrderedDict
from collections.abc import Callable

USAGE_INTERVAL_SECONDS = 300


class UsageDeduplicator:
    def __init__(
        self, *, clock: Callable[[], float] = time.monotonic, max_entries: int = 4096
    ) -> None:
        self._clock = clock
        self._max = max_entries
        self._lock = threading.Lock()
        self._entries: OrderedDict[tuple[str, str], float] = OrderedDict()

    def take(self, kind: str, identifier: str) -> bool:
        key, now = (kind, identifier), self._clock()
        with self._lock:
            deadline = self._entries.get(key)
            if deadline is not None and deadline > now:
                return False
            self._entries[key] = now + USAGE_INTERVAL_SECONDS
            self._entries.move_to_end(key)
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)
            return True
