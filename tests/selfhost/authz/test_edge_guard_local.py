"""The edge guard in local mode: buckets and body caps for /token, /revoke and POST /authorize."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from canvas_mcp.core.selfhost import edge_guard, limits
from canvas_mcp.core.selfhost.edge_guard import SelfhostEdgeGuard


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class Inner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bytes]] = []

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        self.calls.append((scope["method"], scope["path"], body))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def request(
    guard: SelfhostEdgeGuard, method: str, path: str, body: bytes = b"", headers: Any = None
) -> tuple[int, dict[bytes, bytes], bytes]:
    sent: list[dict[str, Any]] = []
    chunks = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive() -> dict[str, Any]:
        return chunks.pop(0) if chunks else {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {"type": "http", "method": method, "path": path, "headers": headers or []}
    await guard(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], dict(start["headers"]), payload


def guard(inner: Inner, clock: Clock, *, local: bool) -> SelfhostEdgeGuard:
    return SelfhostEdgeGuard(inner, clock=clock, authz_local=local)


def test_the_limits_are_exported_with_the_documented_values() -> None:
    assert edge_guard.TOKEN_REQUESTS_PER_MINUTE == 120
    assert edge_guard.REVOKE_REQUESTS_PER_MINUTE == 30
    assert edge_guard.MAX_OAUTH_FORM_BYTES == 16 * 1024
    assert edge_guard.TOKEN_PATH == "/token" and edge_guard.REVOKE_PATH == "/revoke"


class TestLocalMode:
    async def test_token_requests_are_limited_per_minute(self) -> None:
        clock, inner = Clock(), Inner()
        g = guard(inner, clock, local=True)
        statuses = [(await request(g, "POST", "/token", b"a=b"))[0] for _ in range(125)]
        assert statuses[:120] == [200] * 120 and statuses[120:] == [429] * 5
        status, headers, body = await request(g, "POST", "/token", b"a=b")
        assert status == 429 and int(headers[b"retry-after"]) >= 1
        assert json.loads(body)["error"] == "temporarily_unavailable"
        clock.now += 60
        assert (await request(g, "POST", "/token", b"a=b"))[0] == 200

    async def test_revoke_requests_have_their_own_smaller_bucket(self) -> None:
        clock, inner = Clock(), Inner()
        g = guard(inner, clock, local=True)
        statuses = [(await request(g, "POST", "/revoke", b"a=b"))[0] for _ in range(32)]
        assert statuses[:30] == [200] * 30 and statuses[30:] == [429, 429]
        assert (await request(g, "POST", "/token", b"a=b"))[0] == 200  # the token bucket is separate

    @pytest.mark.parametrize("path", ["/token", "/revoke", "/authorize"])
    async def test_oversized_form_bodies_are_refused_before_the_app_sees_them(self, path: str) -> None:
        inner = Inner()
        g = guard(inner, Clock(), local=True)
        big = b"x=" + b"a" * (16 * 1024)
        status, _, body = await request(g, "POST", path, big)
        assert status == 413 and json.loads(body)["error"] == "invalid_request" and inner.calls == []
        status, _, _ = await request(g, "POST", path, b"x=" + b"a" * 1000)
        assert status == 200 and inner.calls[-1][2].startswith(b"x=")

    async def test_the_declared_length_is_enough_to_refuse(self) -> None:
        inner = Inner()
        g = guard(inner, Clock(), local=True)
        status, _, _ = await request(g, "POST", "/token", b"a=b", headers=[(b"content-length", b"999999")])
        assert status == 413 and inner.calls == []

    async def test_get_authorize_and_options_are_not_body_capped(self) -> None:
        inner = Inner()
        g = guard(inner, Clock(), local=True)
        assert (await request(g, "OPTIONS", "/token"))[0] == 200
        assert (await request(g, "GET", "/authorize"))[0] == 200
        assert (await request(g, "OPTIONS", "/revoke"))[0] == 200

    async def test_the_body_is_replayed_to_the_app_intact(self) -> None:
        inner = Inner()
        g = guard(inner, Clock(), local=True)
        await request(g, "POST", "/token", b"grant_type=refresh_token&refresh_token=abc")
        assert inner.calls == [("POST", "/token", b"grant_type=refresh_token&refresh_token=abc")]

    async def test_the_maintenance_runs_from_a_token_request(self) -> None:
        ran: list[int] = []

        async def maintenance() -> None:
            ran.append(1)

        clock, inner = Clock(), Inner()
        g = SelfhostEdgeGuard(inner, clock=clock, maintenance=maintenance, authz_local=True)
        await request(g, "POST", "/token", b"a=b")
        await asyncio.sleep(0.05)
        assert ran == [1]
        await request(g, "POST", "/revoke", b"a=b")
        await asyncio.sleep(0.05)
        assert ran == [1]  # at most once per interval


class TestDefaultMode:
    async def test_nothing_about_token_and_revoke_changes(self) -> None:
        inner = Inner()
        g = guard(inner, Clock(), local=False)
        big = b"x=" + b"a" * (64 * 1024)
        for _ in range(200):
            assert (await request(g, "POST", "/token", big))[0] == 200
            assert (await request(g, "POST", "/revoke", big))[0] == 200
        assert len(inner.calls) == 400

    async def test_the_two_extra_buckets_are_not_even_built(self) -> None:
        built: list[str] = []

        class Bucket:
            def take(self) -> float:
                return 0.0

            def give_back(self) -> None:
                return None

        def bucket(*_a: Any) -> Bucket:
            built.append("bucket")
            return Bucket()

        limiters = limits.RateLimiters("test", lambda *a: None, bucket)  # type: ignore[arg-type, return-value]
        SelfhostEdgeGuard(Inner(), rate_limiters=limiters)
        assert built == ["bucket"] * 3
        built.clear()
        SelfhostEdgeGuard(Inner(), rate_limiters=limiters, authz_local=True)
        assert built == ["bucket"] * 5

    async def test_authorize_post_is_not_capped_in_the_default_mode(self) -> None:
        inner = Inner()
        g = guard(inner, Clock(), local=False)
        assert (await request(g, "POST", "/authorize", b"x=" + b"a" * (64 * 1024)))[0] == 200
