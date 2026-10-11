"""The outermost shim: https scheme, limits on the open OAuth endpoints, cleanup.

Anyone on the internet can call ``POST /register`` and ``GET /authorize`` and
each call may create rows in the database, so these endpoints are rate limited, registrations are capped in size
and number, client records expire, and bounded native housekeeping removes expired rows (tested in test_v1_maintenance.py).
"""

import asyncio
import json
from typing import Any

import pytest
from sqlalchemy import select

from canvas_mcp.core.selfhost import edge_guard
from canvas_mcp.core.selfhost.authz.clients import DCR_TTL_SECONDS
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.edge_guard import (
    MAX_REGISTER_BODY_BYTES,
    PUBLIC_REQUESTS_PER_MINUTE,
    REGISTRATIONS_PER_DAY,
    SelfhostEdgeGuard,
    TokenBucket,
)

from .authz.stack import CLAUDE_REDIRECT, local_stack


def registration():
    return {
        "client_name": "Test client",
        "redirect_uris": [CLAUDE_REDIRECT],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "none",
    }


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Recorder:
    """A fake inner app: records what it was called with, answers 200."""

    def __init__(self) -> None:
        self.scopes: list[dict[str, Any]] = []
        self.bodies: list[bytes] = []

    async def __call__(self, scope, receive, send) -> None:
        self.scopes.append(scope)
        if scope["type"] != "http":
            return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        self.bodies.append(body)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def call(
    app,
    method: str,
    path: str,
    *,
    chunks: list[bytes] | None = None,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> tuple[int, dict[bytes, bytes]]:
    pending = list(chunks if chunks is not None else [b"{}"])
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        if pending:
            chunk = pending.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(pending)}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "scheme": "http",
        "headers": headers or [],
        "query_string": b"",
    }
    await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    return start["status"], dict(start["headers"])


class TestTokenBucket:
    def test_allows_the_burst_then_refuses_then_refills(self):
        clock = FakeClock()
        bucket = TokenBucket(3, 1.0, clock)
        assert [bucket.take() for _ in range(3)] == [0.0, 0.0, 0.0]
        assert bucket.take() > 0
        clock.now += 1.0
        assert bucket.take() == 0.0
        assert bucket.take() > 0

    def test_never_holds_more_than_its_capacity(self):
        clock = FakeClock()
        bucket = TokenBucket(2, 1.0, clock)
        clock.now += 3600
        assert [bucket.take() for _ in range(3)] == [0.0, 0.0, pytest.approx(1.0)]


class TestRegistrationLimits:
    async def test_the_31st_registration_in_a_minute_gets_429(self):
        clock = FakeClock()
        inner = Recorder()
        app = SelfhostEdgeGuard(inner, clock=clock)
        statuses = [
            (await call(app, "POST", "/register"))[0]
            for _ in range(PUBLIC_REQUESTS_PER_MINUTE + 1)
        ]
        assert (
            statuses[:PUBLIC_REQUESTS_PER_MINUTE] == [200] * PUBLIC_REQUESTS_PER_MINUTE
        )
        assert statuses[-1] == 429
        assert (
            len(inner.bodies) == PUBLIC_REQUESTS_PER_MINUTE
        )  # the refused call never reached FastMCP
        status, headers = await call(app, "POST", "/register")
        assert status == 429 and int(headers[b"retry-after"]) >= 1

    async def test_a_refused_call_recovers_after_the_bucket_refills(self):
        clock = FakeClock()
        app = SelfhostEdgeGuard(Recorder(), clock=clock)
        for _ in range(PUBLIC_REQUESTS_PER_MINUTE):
            await call(app, "POST", "/register")
        assert (await call(app, "POST", "/register"))[0] == 429
        clock.now += 60
        assert (await call(app, "POST", "/register"))[0] == 200

    async def test_a_daily_budget_stops_a_steady_trickle(self):
        clock = FakeClock()
        inner = Recorder()
        app = SelfhostEdgeGuard(inner, clock=clock)
        allowed = 0
        # One call every 3 seconds is far under the per-minute limit.
        for _ in range(REGISTRATIONS_PER_DAY + 50):
            clock.now += 3
            if (await call(app, "POST", "/register"))[0] == 200:
                allowed += 1
        assert REGISTRATIONS_PER_DAY <= allowed < REGISTRATIONS_PER_DAY + 50

    async def test_get_register_and_other_paths_are_not_counted(self):
        clock = FakeClock()
        inner = Recorder()
        app = SelfhostEdgeGuard(inner, clock=clock)
        for _ in range(200):
            assert (await call(app, "GET", "/account"))[0] == 200
            assert (await call(app, "GET", "/register"))[0] == 200
        assert (await call(app, "POST", "/register"))[0] == 200

    async def test_authorize_has_its_own_bucket(self):
        clock = FakeClock()
        app = SelfhostEdgeGuard(Recorder(), clock=clock)
        statuses = [
            (await call(app, "GET", "/authorize"))[0]
            for _ in range(PUBLIC_REQUESTS_PER_MINUTE + 1)
        ]
        assert statuses[-1] == 429 and set(statuses[:-1]) == {200}
        assert (await call(app, "POST", "/register"))[
            0
        ] == 200  # not starved by /authorize

    async def test_an_oversized_body_is_refused_before_the_app_sees_it(self):
        inner = Recorder()
        app = SelfhostEdgeGuard(inner, clock=FakeClock())
        length = str(MAX_REGISTER_BODY_BYTES + 1).encode()
        status, _ = await call(
            app, "POST", "/register", headers=[(b"content-length", length)]
        )
        assert status == 413
        big = [b"x" * 9000, b"y" * 9000]  # no content-length: counted while streaming
        status, _ = await call(app, "POST", "/register", chunks=big)
        assert status == 413
        assert inner.bodies == []

    async def test_a_normal_body_reaches_the_app_unchanged(self):
        inner = Recorder()
        app = SelfhostEdgeGuard(inner, clock=FakeClock())
        payload = json.dumps(
            {"client_name": "c", "redirect_uris": [CLAUDE_REDIRECT]}
        ).encode()
        status, _ = await call(
            app, "POST", "/register", chunks=[payload[:10], payload[10:]]
        )
        assert status == 200 and inner.bodies == [payload]


class TestSchemeIsPinnedToHttps:
    async def test_http_requests_reach_the_app_as_https(self):
        inner = Recorder()
        app = SelfhostEdgeGuard(inner, clock=FakeClock())
        await call(app, "GET", "/account/")
        assert inner.scopes[0]["scheme"] == "https"

    async def test_websocket_becomes_wss_and_lifespan_is_untouched(self):
        inner = Recorder()
        app = SelfhostEdgeGuard(inner, clock=FakeClock())
        await app({"type": "websocket", "scheme": "ws", "path": "/x"}, None, None)
        await app({"type": "lifespan"}, None, None)
        assert inner.scopes[0]["scheme"] == "wss"
        assert inner.scopes[1] == {"type": "lifespan"}

    async def test_the_servers_own_scope_is_not_modified(self):
        inner = Recorder()
        app = SelfhostEdgeGuard(inner, clock=FakeClock())
        original: dict[str, Any] = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "scheme": "http",
            "headers": [],
            "query_string": b"",
        }

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict[str, Any]) -> None:
            return None

        await app(original, receive, send)
        assert original["scheme"] == "http"


class TestMaintenance:
    async def test_cleanup_runs_at_most_once_per_interval(self):
        clock = FakeClock()
        runs: list[int] = []

        async def maintenance() -> None:
            runs.append(1)

        app = SelfhostEdgeGuard(
            Recorder(), clock=clock, maintenance=maintenance, maintenance_interval=3600
        )
        for _ in range(5):
            await call(app, "POST", "/register")
        await asyncio.gather(*app._maintenance.background)
        assert len(runs) == 1
        clock.now += 3601
        await call(app, "GET", "/authorize")
        await asyncio.sleep(0)
        assert len(runs) == 2

    async def test_a_failing_cleanup_never_breaks_the_request(self, caplog):
        async def maintenance() -> None:
            raise RuntimeError("secret path /data/fastmcp/x")

        app = SelfhostEdgeGuard(Recorder(), clock=FakeClock(), maintenance=maintenance)
        assert (await call(app, "POST", "/register"))[0] == 200
        await asyncio.sleep(0)
        assert "secret path" not in caplog.text


# ----------------------------------------------------------------------- real app


@pytest.fixture
def stack(tmp_path, monkeypatch):
    with local_stack(tmp_path, monkeypatch, clock=FakeClock()) as running:
        yield running


class TestThroughTheRealApp:
    def test_registration_budget_bounds_native_client_rows(self, stack):
        before = self.clients(stack)
        statuses = [
            stack.client.post("/register", json=registration()).status_code
            for _ in range(PUBLIC_REQUESTS_PER_MINUTE + 20)
        ]
        assert (
            statuses[:PUBLIC_REQUESTS_PER_MINUTE] == [201] * PUBLIC_REQUESTS_PER_MINUTE
        )
        assert set(statuses[PUBLIC_REQUESTS_PER_MINUTE:]) == {429}
        assert len(self.clients(stack)) - len(before) == PUBLIC_REQUESTS_PER_MINUTE

    @staticmethod
    def clients(stack):
        with stack.store.database.read() as conn:
            return conn.execute(select(s.oauth_clients)).mappings().all()

    def test_authorize_has_a_separate_public_budget(self, stack):
        client = stack.register()
        params = {
            "client_id": client,
            "response_type": "code",
            "redirect_uri": CLAUDE_REDIRECT,
            "code_challenge": "c" * 43,
            "code_challenge_method": "S256",
            "state": "s",
        }
        statuses = [
            stack.client.get("/authorize", params=params).status_code
            for _ in range(PUBLIC_REQUESTS_PER_MINUTE + 5)
        ]
        assert (
            statuses[:PUBLIC_REQUESTS_PER_MINUTE] == [302] * PUBLIC_REQUESTS_PER_MINUTE
        )
        assert set(statuses[PUBLIC_REQUESTS_PER_MINUTE:]) == {429}

    def test_oversized_registration_never_creates_a_row(self, stack):
        before = self.clients(stack)
        body = registration()
        body["client_name"] = "x" * (MAX_REGISTER_BODY_BYTES + 10)
        assert stack.client.post("/register", json=body).status_code == 413
        assert self.clients(stack) == before

    def test_native_dynamic_client_lifetime(self, stack):
        assert stack.client.post("/register", json=registration()).status_code == 201
        (row,) = self.clients(stack)
        assert row["expires_at"] - row["created_at"] == DCR_TTL_SECONDS
        assert len(row["id"]) == 36

    def test_redirects_through_http_are_https(self, stack):
        for path in ("/account", "/account/", "/account/admin", "/healthz/", "/mcp/"):
            for method in ("GET", "POST"):
                response = stack.client.request(
                    method, "http://canvas.example.test" + path
                )
                location = response.headers.get("location")
                assert location is None or location.startswith("https://"), (
                    path,
                    location,
                )
        assert stack.client.get("/account/").status_code == 200

    def test_other_routes_work_through_the_guard(self, stack):
        assert stack.client.get("/healthz").text == "ok"
        assert (
            stack.client.get("/.well-known/oauth-authorization-server").status_code
            == 200
        )
        assert stack.client.post("/mcp", json={}).status_code == 401


def test_module_exposes_the_limits_the_docs_quote():
    assert edge_guard.PUBLIC_REQUESTS_PER_MINUTE == 30
    assert edge_guard.REGISTRATIONS_PER_DAY == 300
