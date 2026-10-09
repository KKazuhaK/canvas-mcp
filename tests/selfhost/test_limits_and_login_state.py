"""Contracts of the rate-limiter and one-time-state interfaces (in-memory implementations).

Any future backend (Redis is reserved) has to satisfy the same behaviour; these
tests are written against the Protocols, with the in-process implementations as
the subject.
"""

from __future__ import annotations

import asyncio

import pytest

from canvas_mcp.core.selfhost import account_web, edge_guard, limits
from canvas_mcp.core.selfhost.login_state import (
    InMemoryLoginStateStore,
    LoginStateStore,
)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class TestSlidingWindowContract:
    def test_the_limit_is_per_key_and_the_window_slides(self) -> None:
        clock = Clock()
        limiter = limits.build_rate_limiters("memory").sliding_window(2, 10, 100, clock)
        a, b = ("user", "a"), ("user", "b")
        assert limiter.allow(a) and limiter.allow(a)
        assert not limiter.allow(a)
        assert limiter.allow(b)  # another key has its own allowance
        clock.now += 11
        assert limiter.allow(a)  # the old attempts left the window

    def test_the_table_of_keys_is_bounded(self) -> None:
        clock = Clock()
        limiter = limits.InMemorySlidingWindowLimiter(1, 1000, 3, clock)
        for index in range(50):
            assert limiter.allow(("k", str(index)))
        assert len(limiter._hits) <= 3


class TestTokenBucketContract:
    def test_take_refills_and_give_back_returns_a_token(self) -> None:
        clock = Clock()
        bucket = limits.build_rate_limiters("memory").token_bucket(2, 1.0, clock)
        assert bucket.take() == 0 and bucket.take() == 0
        wait = bucket.take()
        assert wait == pytest.approx(1.0)
        clock.now += 1.5
        assert bucket.take() == 0
        bucket.give_back()
        assert bucket.take() == 0

    def test_a_bucket_that_never_refills_reports_infinity(self) -> None:
        bucket = limits.InMemoryTokenBucket(1, 0.0, Clock())
        assert bucket.take() == 0
        assert bucket.take() == float("inf")


class TestTheOldNamesStillResolve:
    def test_account_web_and_edge_guard_keep_their_classes(self) -> None:
        assert account_web._RateLimiter is limits.InMemorySlidingWindowLimiter
        assert edge_guard.TokenBucket is limits.InMemoryTokenBucket

    def test_the_guard_and_the_pages_build_their_limiters_from_the_factory(self) -> None:
        built: list[str] = []
        base = limits.build_rate_limiters("memory")

        def window(*args):  # type: ignore[no-untyped-def]
            built.append("window")
            return base.sliding_window(*args)

        def bucket(*args):  # type: ignore[no-untyped-def]
            built.append("bucket")
            return base.token_bucket(*args)

        async def app(scope, receive, send):  # type: ignore[no-untyped-def]
            return None

        edge_guard.SelfhostEdgeGuard(
            app, rate_limiters=limits.RateLimiters("test", window, bucket)
        )
        assert built == ["bucket", "bucket", "bucket"]


@pytest.fixture
def store() -> InMemoryLoginStateStore:
    return InMemoryLoginStateStore(clock=Clock())


class TestLoginStateContract:
    def test_the_in_memory_store_satisfies_the_protocol(self, store: InMemoryLoginStateStore) -> None:
        checked: LoginStateStore = store
        assert checked is store

    async def test_a_payload_is_returned_exactly_once(self, store: InMemoryLoginStateStore) -> None:
        state_id = await store.put("oidc", b"nonce+verifier", 60)
        assert await store.pop("oidc", state_id) == b"nonce+verifier"
        assert await store.pop("oidc", state_id) is None

    async def test_missing_used_expired_and_wrong_kind_look_the_same(self) -> None:
        clock = Clock()
        store = InMemoryLoginStateStore(clock=clock)
        state_id = await store.put("oidc", b"x", 30)
        assert await store.pop("other-kind", state_id) is None  # kind is part of the key
        assert await store.pop("oidc", "never-issued") is None
        clock.now += 31
        assert await store.pop("oidc", state_id) is None  # expired
        assert await store.pop("oidc", state_id) is None  # and gone

    async def test_ids_are_unguessable_and_unique(self, store: InMemoryLoginStateStore) -> None:
        ids = {await store.put("oidc", b"x", 60) for _ in range(200)}
        assert len(ids) == 200
        assert all(len(i) >= 40 for i in ids)

    async def test_concurrent_pops_hand_the_payload_to_exactly_one_caller(
        self, store: InMemoryLoginStateStore
    ) -> None:
        for _ in range(20):
            state_id = await store.put("oidc", b"secret", 60)
            results = await asyncio.gather(*(store.pop("oidc", state_id) for _ in range(16)))
            assert results.count(b"secret") == 1
            assert results.count(None) == 15

    async def test_the_store_is_bounded_and_drops_the_oldest(self) -> None:
        store = InMemoryLoginStateStore(clock=Clock(), max_entries=3)
        ids = [await store.put("oidc", bytes([i]), 60) for i in range(5)]
        assert await store.pop("oidc", ids[0]) is None
        assert await store.pop("oidc", ids[4]) == bytes([4])

    @pytest.mark.parametrize(
        ("kind", "payload", "ttl"),
        [("", b"x", 10), ("k", b"x", 0), ("k", b"x", -1), ("k", b"x", 10_000), ("k", b"x" * 5000, 10)],
    )
    async def test_invalid_input_is_refused(
        self, store: InMemoryLoginStateStore, kind: str, payload: bytes, ttl: float
    ) -> None:
        with pytest.raises(ValueError):
            await store.put(kind, payload, ttl)
