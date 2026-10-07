"""The outermost shim: https scheme, limits on the open OAuth endpoints, cleanup.

Anyone on the internet can call ``POST /register`` and ``GET /authorize`` and
each call writes a file to the data volume that also holds the Canvas token
database, so these endpoints are rate limited, registrations are capped in size
and number, client records expire, and expired records are swept from disk.
"""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import fastmcp
import pytest
from fastmcp import FastMCP
from starlette.testclient import TestClient

from canvas_mcp.core.selfhost import edge_guard
from canvas_mcp.core.selfhost.app import (
    build_selfhost_asgi_app,
    install_selfhost,
    prepare_selfhost,
)
from canvas_mcp.core.selfhost.edge_guard import (
    MAX_REGISTER_BODY_BYTES,
    PUBLIC_REQUESTS_PER_MINUTE,
    REGISTRATIONS_PER_DAY,
    SelfhostEdgeGuard,
    TokenBucket,
)
from canvas_mcp.core.selfhost.oauth import (
    DCR_CLIENT_TTL_SECONDS,
    build_entra_auth_provider,
    cull_expired_oauth_state,
    limit_client_record_lifetime,
)
from canvas_mcp.core.selfhost.settings import SelfhostSettings

from .test_oauth_wiring import BASE, CLAUDE_CALLBACK, _settings


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


async def call(app, method: str, path: str, *, chunks: list[bytes] | None = None,
               headers: list[tuple[bytes, bytes]] | None = None) -> tuple[int, dict[bytes, bytes]]:
    pending = list(chunks if chunks is not None else [b"{}"])
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        if pending:
            chunk = pending.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(pending)}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {"type": "http", "method": method, "path": path, "scheme": "http",
             "headers": headers or [], "query_string": b""}
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
        statuses = [(await call(app, "POST", "/register"))[0] for _ in range(PUBLIC_REQUESTS_PER_MINUTE + 1)]
        assert statuses[:PUBLIC_REQUESTS_PER_MINUTE] == [200] * PUBLIC_REQUESTS_PER_MINUTE
        assert statuses[-1] == 429
        assert len(inner.bodies) == PUBLIC_REQUESTS_PER_MINUTE  # the refused call never reached FastMCP
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
        statuses = [(await call(app, "GET", "/authorize"))[0] for _ in range(PUBLIC_REQUESTS_PER_MINUTE + 1)]
        assert statuses[-1] == 429 and set(statuses[:-1]) == {200}
        assert (await call(app, "POST", "/register"))[0] == 200  # not starved by /authorize

    async def test_an_oversized_body_is_refused_before_the_app_sees_it(self):
        inner = Recorder()
        app = SelfhostEdgeGuard(inner, clock=FakeClock())
        length = str(MAX_REGISTER_BODY_BYTES + 1).encode()
        status, _ = await call(app, "POST", "/register", headers=[(b"content-length", length)])
        assert status == 413
        big = [b"x" * 9000, b"y" * 9000]  # no content-length: counted while streaming
        status, _ = await call(app, "POST", "/register", chunks=big)
        assert status == 413
        assert inner.bodies == []

    async def test_a_normal_body_reaches_the_app_unchanged(self):
        inner = Recorder()
        app = SelfhostEdgeGuard(inner, clock=FakeClock())
        payload = json.dumps({"client_name": "c", "redirect_uris": [CLAUDE_CALLBACK]}).encode()
        status, _ = await call(app, "POST", "/register", chunks=[payload[:10], payload[10:]])
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
        original: dict[str, Any] = {"type": "http", "method": "GET", "path": "/", "scheme": "http",
                                    "headers": [], "query_string": b""}

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

        app = SelfhostEdgeGuard(Recorder(), clock=clock, maintenance=maintenance, maintenance_interval=3600)
        for _ in range(5):
            await call(app, "POST", "/register")
        await asyncio.sleep(0)
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
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SelfhostSettings:
    monkeypatch.setattr(fastmcp.settings, "test_mode", True)  # cheap key stretching
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path / "fastmcp")
    return _settings(tmp_path)


def _registration(name: str = "test client", redirect: str = CLAUDE_CALLBACK) -> dict[str, Any]:
    return {
        "client_name": name,
        "redirect_uris": [redirect],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "none",
    }


def _build(settings: SelfhostSettings, clock: FakeClock | None = None):
    config: Any = SimpleNamespace(canvas_api_url="https://canvas.example.edu/api/v1")
    runtime = prepare_selfhost(settings)
    provider = build_entra_auth_provider(settings)
    mcp = FastMCP("edge", auth=provider)
    install_selfhost(mcp, runtime, config)
    return provider, build_selfhost_asgi_app(mcp, runtime, config, clock=clock)


def _files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()]


def _records(root: Path, collection: str) -> list[Path]:
    """Record files of one FastMCP collection (directories are sanitized names)."""
    return [
        p for p in _files(root)
        if collection in p.parent.name and not p.name.endswith("-info.json")
    ]


class TestThroughTheRealApp:
    def test_unauthenticated_registrations_cannot_flood_the_data_volume(self, settings):
        clock = FakeClock()
        _, app = _build(settings, clock)
        home = settings.fastmcp_home
        with TestClient(app, base_url=BASE) as client:
            before = len(_files(home))
            statuses = [
                client.post("/register", json=_registration("x" * 2000)).status_code
                for _ in range(PUBLIC_REQUESTS_PER_MINUTE + 20)
            ]
            created = len(_files(home)) - before
        assert statuses.count(201) == PUBLIC_REQUESTS_PER_MINUTE
        assert set(statuses[PUBLIC_REQUESTS_PER_MINUTE:]) == {429}
        assert created <= PUBLIC_REQUESTS_PER_MINUTE + 2  # plus collection metadata files

    def test_unauthenticated_authorize_is_limited_too(self, settings):
        clock = FakeClock()
        _, app = _build(settings, clock)
        with TestClient(app, base_url=BASE) as client:
            client_id = client.post("/register", json=_registration()).json()["client_id"]
            params = {
                "response_type": "code", "client_id": client_id, "redirect_uri": CLAUDE_CALLBACK,
                "code_challenge": "c" * 43, "code_challenge_method": "S256", "state": "s",
            }
            statuses = [
                client.get("/authorize", params=params, follow_redirects=False).status_code
                for _ in range(PUBLIC_REQUESTS_PER_MINUTE + 5)
            ]
        assert statuses[:PUBLIC_REQUESTS_PER_MINUTE] == [302] * PUBLIC_REQUESTS_PER_MINUTE
        assert set(statuses[PUBLIC_REQUESTS_PER_MINUTE:]) == {429}

    def test_an_oversized_registration_is_refused(self, settings):
        _, app = _build(settings, FakeClock())
        with TestClient(app, base_url=BASE) as client:
            response = client.post("/register", json=_registration("x" * (MAX_REGISTER_BODY_BYTES + 10)))
        assert response.status_code == 413

    def test_a_registered_client_record_gets_a_lifetime(self, settings):
        _, app = _build(settings, FakeClock())
        with TestClient(app, base_url=BASE) as client:
            assert client.post("/register", json=_registration()).status_code == 201
        records = _records(settings.fastmcp_home, "mcp_oauth_proxy_clients")
        assert len(records) == 1
        entry = json.loads(records[0].read_text(encoding="utf-8"))
        assert entry["expires_at"], "a dynamic registration must not live for ever"
        from datetime import datetime

        created = datetime.fromisoformat(entry["created_at"])
        lifetime = (datetime.fromisoformat(entry["expires_at"]) - created).total_seconds()
        assert lifetime == pytest.approx(DCR_CLIENT_TTL_SECONDS, abs=5)

    def test_trailing_slash_redirects_never_leave_https(self, settings):
        """Behind the TLS proxy uvicorn reports scheme http; the 307 must stay on https."""
        _, app = _build(settings, FakeClock())
        with TestClient(app, base_url="http://canvas.example.test") as client:
            for path in ("/account/", "/account/admin/", "/healthz/", "/mcp/"):
                for method in ("GET", "POST"):
                    response = client.request(method, path, follow_redirects=False)
                    location = response.headers.get("location")
                    assert location is None or location.startswith("https://"), (path, location)
            redirect = client.get("/account/", follow_redirects=False)
            assert redirect.status_code == 307
            assert redirect.headers["location"] == "https://canvas.example.test/account"

    def test_other_routes_still_work_through_the_shim(self, settings):
        _, app = _build(settings, FakeClock())
        with TestClient(app, base_url=BASE) as client:
            assert client.get("/healthz").text == "ok"
            assert client.get("/.well-known/oauth-authorization-server").status_code == 200
            assert client.post("/mcp", json={}).status_code == 401


class TestStorageLifetimeAndCleanup:
    async def test_expired_oauth_records_are_deleted_from_disk(self, settings):
        provider = build_entra_auth_provider(settings)
        storage = provider._client_storage  # noqa: SLF001 - the same object FastMCP writes through
        await storage.put(key="stale", value={"a": 1}, collection="mcp-oauth-transactions", ttl=0.05)
        await storage.put(key="fresh", value={"a": 2}, collection="mcp-oauth-transactions", ttl=3600)
        await asyncio.sleep(0.2)
        names = {p.name for p in _records(settings.fastmcp_home, "mcp_oauth_transactions")}
        assert len(names) == 2  # an expired file stays until something removes it
        await cull_expired_oauth_state(provider)
        remaining = _records(settings.fastmcp_home, "mcp_oauth_transactions")
        assert len(remaining) == 1
        assert await storage.get(key="fresh", collection="mcp-oauth-transactions") == {"a": 2}

    async def test_records_that_bring_their_own_lifetime_keep_it(self, settings):
        provider = build_entra_auth_provider(settings)
        await provider._client_storage.put(  # noqa: SLF001
            key="txn", value={"a": 1}, collection="mcp-oauth-transactions", ttl=900
        )
        (record,) = _records(settings.fastmcp_home, "mcp_oauth_transactions")
        entry = json.loads(record.read_text(encoding="utf-8"))
        from datetime import datetime

        lifetime = (datetime.fromisoformat(entry["expires_at"]) - datetime.fromisoformat(entry["created_at"]))
        assert lifetime.total_seconds() == pytest.approx(900, abs=5)

    def test_it_refuses_to_start_if_fastmcp_moves_its_storage(self):
        fake: Any = SimpleNamespace(_client_storage=object())
        with pytest.raises(RuntimeError, match="encrypted file store"):
            limit_client_record_lifetime(fake)

    async def test_cleanup_for_an_unknown_provider_is_a_no_op(self):
        await cull_expired_oauth_state(object())


def test_module_exposes_the_limits_the_docs_quote():
    assert edge_guard.PUBLIC_REQUESTS_PER_MINUTE == 30
    assert edge_guard.REGISTRATIONS_PER_DAY == 300
