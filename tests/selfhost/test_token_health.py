"""Detecting a dead Canvas token: the suspicion, the probe, the single flight, the verdict.

Everything runs against the real Canvas client and the real token store; only
the Canvas servers are faked (respx / mock transports), so no network is used.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx

from canvas_mcp.core import audit, course_files
from canvas_mcp.core import client as cm
from canvas_mcp.core.credentials import (
    RequestCredentials,
    RequestTokenState,
    get_request_token_state,
    set_http_request_active,
    set_request_credentials,
    set_request_principal,
    set_request_token_state,
)
from canvas_mcp.core.selfhost.request_context import token_rejected_message
from canvas_mcp.core.selfhost.token_health import TokenHealth
from canvas_mcp.core.selfhost.token_store import (
    REASON_CANVAS_TOKEN_REJECTED,
    STATUS_ACTIVE,
    STATUS_INVALID,
    TokenStore,
)
from canvas_mcp.core.token_health import set_token_health_monitor
from canvas_mcp.core.write_outcome import RequestFailure, WriteOutcome

from .conftest import OID_A, TENANT, make_principal
from .test_token_store import Clock as StoreClock
from .test_token_store import _ring

CANVAS_HOST = "canvas.example.edu"
API_URL = f"https://{CANVAS_HOST}/api/v1"
ACCOUNT_URL = "https://mcp.example.test/account"
TOKEN = "canvas-token-for-user-A-0123456789"
PRINCIPAL_KEY = f"entra:{TENANT}:{OID_A}"
EXPECTED_MESSAGE = token_rejected_message(ACCOUNT_URL)


class MonoClock:
    """The probe cooldown clock, advanced by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class CanvasLog:
    """What the fake Canvas saw, split into ordinary calls and ``/users/self`` probes."""

    calls: list[str] = field(default_factory=list)
    probes: list[str] = field(default_factory=list)


@dataclass
class Env:
    store: TokenStore
    health: TokenHealth
    mono: MonoClock
    store_clock: StoreClock
    canvas: CanvasLog
    router: respx.MockRouter
    probe: dict[str, Any]
    updated_at: int

    def set_probe(self, handler: Callable[[httpx.Request], Any]) -> None:
        """Answer the ``/users/self`` probe with ``handler`` (sync or async)."""

        def recording(request: httpx.Request) -> Any:
            self.canvas.probes.append(request.headers.get("authorization", ""))
            return handler(request)

        self.probe["handler"] = recording

    def start_request(self) -> RequestTokenState:
        """Publish the per-request context the middleware would publish."""
        set_http_request_active(True)
        set_request_principal(make_principal(OID_A))
        set_request_credentials(RequestCredentials(api_token=TOKEN, api_url=API_URL))
        state = RequestTokenState(token_version=self.updated_at)
        set_request_token_state(state)
        return state

    def row(self) -> Any:
        info = self.store.info(PRINCIPAL_KEY)
        assert info is not None
        return info


def _json(status: int, body: Any, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, json=body, headers=headers)


DEAD_HEADERS = {"WWW-Authenticate": 'Bearer realm="canvas-lms"'}
DEAD_BODY = {"errors": [{"message": "Invalid access token."}]}
PERMISSION_BODY = {"status": "unauthorized", "errors": [{"message": "user not authorized to perform that action"}]}


@pytest.fixture
def env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    config = SimpleNamespace(
        canvas_api_url=API_URL,
        canvas_api_token="",
        max_concurrent_requests=10,
        api_timeout=5,
        log_api_requests=False,
        enable_data_anonymization=False,
        anonymization_debug=False,
    )
    monkeypatch.setattr("canvas_mcp.core.config.get_config", lambda: config)
    monkeypatch.setattr(course_files, "get_config", lambda: config)
    for name in ("http_client", "_http_client_loop_ref", "_request_semaphore", "_semaphore_loop_ref"):
        monkeypatch.setattr(cm, name, None)

    store_clock = StoreClock()
    store = TokenStore(tmp_path / "tokens.sqlite3", _ring(("k1", 1)), clock=store_clock)
    store.initialize()
    info = store.put(
        tenant_id=TENANT,
        object_id=OID_A,
        api_token=TOKEN,
        canvas_user_id="42",
        canvas_user_name="Ada",
        entra_display_name="Ada",
        entra_upn="ada@example.test",
        canvas_host=CANVAS_HOST,
    )
    mono = MonoClock()
    log = CanvasLog()

    holder: dict[str, Any] = {}

    def probe_transport(request: httpx.Request) -> Any:
        return holder["handler"](request)

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(probe_transport))

    health = TokenHealth(store, account_url=ACCOUNT_URL, clock=mono, client_factory=factory)
    set_token_health_monitor(health)

    def default_probe(request: httpx.Request) -> httpx.Response:
        log.probes.append(request.headers.get("authorization", ""))
        return _json(401, DEAD_BODY, DEAD_HEADERS)

    holder["handler"] = default_probe

    with respx.mock(assert_all_called=False) as router:
        environment = Env(
            store=store,
            health=health,
            mono=mono,
            store_clock=store_clock,
            canvas=log,
            router=router,
            probe=holder,
            updated_at=info.updated_at,
        )
        yield environment
    set_token_health_monitor(None)


def canvas_returns(env: Env, status: int, body: Any, headers: dict[str, str] | None = None) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        env.canvas.calls.append(request.url.path)
        return _json(status, body, headers)

    env.router.route(host=CANVAS_HOST).mock(side_effect=handler)


def set_probe(env: Env, handler: Callable[[httpx.Request], Any]) -> None:
    env.set_probe(handler)


def _raise_timeout(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("slow", request=request)


def _raise_connect(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("refused", request=request)


async def get_courses() -> Any:
    return await cm.make_canvas_request("get", "/courses")


class TestSuspicion:
    async def test_a_401_with_a_challenge_header_and_a_401_probe_invalidates(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)

        result = await get_courses()

        assert isinstance(result, RequestFailure)
        assert result["error"] == EXPECTED_MESSAGE
        assert result.outcome is WriteOutcome.REJECTED
        row = env.row()
        assert row.status == STATUS_INVALID
        assert row.invalid_reason == REASON_CANVAS_TOKEN_REJECTED
        assert row.invalid_since is not None
        assert env.canvas.calls == ["/api/v1/courses"]
        assert env.canvas.probes == [f"Bearer {TOKEN}"]
        # Nothing but the encrypted token is kept, and it is still readable for a re-check.
        assert env.store.get(PRINCIPAL_KEY).api_token == TOKEN  # type: ignore[union-attr]

    @pytest.mark.parametrize("text", ["Invalid access token.", "The access token has expired."])
    async def test_error_text_alone_is_a_suspicion(self, env: Env, text: str) -> None:
        env.start_request()
        canvas_returns(env, 401, {"errors": [{"message": text}]})

        result = await get_courses()

        assert result["error"] == EXPECTED_MESSAGE
        assert env.row().status == STATUS_INVALID
        assert len(env.canvas.probes) == 1

    async def test_a_permission_401_is_not_a_suspicion_and_sends_no_probe(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, PERMISSION_BODY)

        result = await get_courses()

        assert isinstance(result, RequestFailure)
        assert result["error"].startswith("HTTP error: 401")
        assert env.canvas.probes == []
        assert env.row().status == STATUS_ACTIVE
        state = get_request_token_state()
        assert state is not None and state.dead is False

    @pytest.mark.parametrize("status", [403, 404, 500])
    async def test_other_statuses_never_probe(self, env: Env, status: int) -> None:
        env.start_request()
        canvas_returns(env, status, DEAD_BODY, DEAD_HEADERS)
        result = await get_courses()
        assert result["error"].startswith(f"HTTP error: {status}")
        assert env.canvas.probes == []
        assert env.row().status == STATUS_ACTIVE

    async def test_the_probe_succeeding_means_a_permission_problem(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        set_probe(env, lambda request: _json(200, {"id": 42, "name": "Ada"}))

        result = await get_courses()

        assert result["error"].startswith("HTTP error: 401")  # the original error comes back
        assert len(env.canvas.probes) == 1
        assert env.row().status == STATUS_ACTIVE
        state = get_request_token_state()
        assert state is not None and state.dead is False

    @pytest.mark.parametrize(
        "outcome",
        [
            lambda request: _json(500, {"errors": []}),
            lambda request: _json(503, {"errors": []}),
            lambda request: _json(403, {"errors": []}),
            lambda request: _json(404, {"errors": []}),
            _raise_timeout,
            _raise_connect,
        ],
        ids=["500", "503", "403", "404", "timeout", "connect-error"],
    )
    async def test_an_unclear_probe_never_changes_state(self, env: Env, outcome: Any) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        set_probe(env, outcome)

        result = await get_courses()

        assert result["error"].startswith("HTTP error: 401")
        assert env.row().status == STATUS_ACTIVE
        state = get_request_token_state()
        assert state is not None and state.dead is False

    async def test_without_a_monitor_a_401_is_just_an_error(self, env: Env) -> None:
        set_token_health_monitor(None)
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        result = await get_courses()
        assert result["error"].startswith("HTTP error: 401")
        assert env.canvas.probes == []

    async def test_without_a_principal_nothing_is_probed(self, env: Env) -> None:
        env.start_request()
        set_request_principal(None)
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        result = await get_courses()
        assert result["error"].startswith("HTTP error: 401")
        assert env.canvas.probes == []
        assert env.row().status == STATUS_ACTIVE

    async def test_the_probe_goes_to_the_users_own_school_without_following_redirects(
        self, env: Env
    ) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        seen: list[httpx.Request] = []

        def probe(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return _json(401, DEAD_BODY, DEAD_HEADERS)

        set_probe(env, probe)
        await get_courses()
        assert [str(r.url) for r in seen] == [f"{API_URL}/users/self"]
        assert seen[0].headers["authorization"] == f"Bearer {TOKEN}"


class TestShortCircuit:
    async def test_after_the_token_is_found_dead_the_same_request_sends_nothing_more(
        self, env: Env
    ) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        await get_courses()
        assert len(env.canvas.calls) == 1

        again = await get_courses()
        paged = await cm.fetch_all_paginated_results("/courses")

        assert isinstance(again, RequestFailure)
        assert again["error"] == EXPECTED_MESSAGE
        assert again.outcome is WriteOutcome.NOT_DISPATCHED
        assert paged == {"error": EXPECTED_MESSAGE}
        assert len(env.canvas.calls) == 1
        assert len(env.canvas.probes) == 1

    async def test_the_authenticated_client_refuses_to_send_once_dead(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        await get_courses()
        with pytest.raises(PermissionError) as raised:
            async with cm.canvas_authenticated_client():
                pytest.fail("no client may be handed out")  # pragma: no cover
        assert str(raised.value) == EXPECTED_MESSAGE

    async def test_siblings_of_a_gather_share_one_probe_and_one_verdict(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        release = asyncio.Event()
        order: list[str] = []

        async def slow_probe(request: httpx.Request) -> httpx.Response:
            order.append("probe-started")
            await release.wait()
            order.append("probe-finished")
            return _json(401, DEAD_BODY, DEAD_HEADERS)

        set_probe(env, slow_probe)

        async def run() -> list[Any]:
            tasks = [asyncio.ensure_future(get_courses()) for _ in range(6)]
            for _ in range(50):
                await asyncio.sleep(0)
                if env.health._flights:  # a probe is in flight
                    break
            await asyncio.sleep(0.05)
            release.set()
            return await asyncio.gather(*tasks)

        results = await run()

        assert [r["error"] for r in results] == [EXPECTED_MESSAGE] * 6
        assert env.health.probe_count == 1
        assert len(env.canvas.probes) == 1
        assert order == ["probe-started", "probe-finished"]
        assert env.row().status == STATUS_INVALID

    async def test_a_gathered_call_that_starts_late_is_short_circuited(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        first_done = asyncio.Event()

        async def first() -> Any:
            try:
                return await get_courses()
            finally:
                first_done.set()

        async def later() -> Any:
            # Starts only once the verdict is known: no wall-clock guess.
            await first_done.wait()
            return await get_courses()

        first_result, second_result = await asyncio.gather(first(), later())
        assert first_result["error"] == second_result["error"] == EXPECTED_MESSAGE
        assert env.row().status == STATUS_INVALID
        # The late sibling never reached Canvas: one data call, one probe.
        assert len(env.canvas.calls) == 1 and len(env.canvas.probes) == 1


class TestSingleFlightAndCooldown:
    async def test_a_second_suspicion_within_the_cooldown_reuses_the_verdict(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        set_probe(env, lambda request: _json(200, {"id": 42}))

        await get_courses()
        await get_courses()
        assert env.health.probe_count == 1

        env.mono.now += 59
        await get_courses()
        assert env.health.probe_count == 1

        env.mono.now += 2  # 61 s after the probe finished
        await get_courses()
        assert env.health.probe_count == 2

    async def test_an_unclear_probe_is_not_repeated_within_the_cooldown_either(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        set_probe(env, lambda request: _json(503, {}))
        await get_courses()
        await get_courses()
        assert env.health.probe_count == 1
        assert env.row().status == STATUS_ACTIVE

    async def test_a_restored_token_is_probed_again_instead_of_reusing_a_rejected_verdict(
        self, env: Env
    ) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        await get_courses()
        assert env.row().status == STATUS_INVALID
        assert env.health.probe_count == 1

        # "Check again" succeeds: the row is active again with the same version.
        env.mono.now += 20
        assert env.store.restore_active(PRINCIPAL_KEY, expected_updated_at=env.updated_at)
        env.health.forget(PRINCIPAL_KEY)

        env.mono.now += 20  # still inside the 60 s cooldown of the old verdict
        env.start_request()
        set_probe(env, lambda request: _json(200, {"id": 42}))
        result = await get_courses()

        assert env.health.probe_count == 2  # the old REJECTED verdict was not reused
        assert result["error"].startswith("HTTP error: 401")  # a plain permission error
        assert env.row().status == STATUS_ACTIVE

    async def test_a_restored_token_that_died_again_is_marked_invalid_again(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        await get_courses()
        env.mono.now += 20
        assert env.store.restore_active(PRINCIPAL_KEY, expected_updated_at=env.updated_at)
        env.health.forget(PRINCIPAL_KEY)

        env.start_request()
        result = await get_courses()

        assert result["error"] == EXPECTED_MESSAGE
        assert env.health.probe_count == 2
        assert env.row().status == STATUS_INVALID

    async def test_forget_only_drops_the_finished_verdicts_of_that_principal(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        await get_courses()
        other = ("entra:other:principal", env.updated_at)
        env.health._flights[other] = env.health._flights[(PRINCIPAL_KEY, env.updated_at)]

        env.health.forget(PRINCIPAL_KEY)

        assert list(env.health._flights) == [other]

    async def test_a_new_token_is_probed_even_inside_the_cooldown(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        set_probe(env, lambda request: _json(200, {"id": 42}))
        await get_courses()
        assert env.health.probe_count == 1

        env.store_clock.now += 30
        info = env.store.put(
            tenant_id=TENANT, object_id=OID_A, api_token="the-replacement-token-0123456789",
            canvas_user_id="42", canvas_user_name="Ada", entra_display_name="Ada",
            entra_upn="ada@example.test", canvas_host=CANVAS_HOST,
        )
        state = env.start_request()
        state.token_version = info.updated_at
        set_request_credentials(
            RequestCredentials(api_token="the-replacement-token-0123456789", api_url=API_URL)
        )
        await get_courses()
        assert env.health.probe_count == 2

    async def test_a_token_replaced_while_the_probe_runs_is_not_invalidated(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)

        def probe(request: httpx.Request) -> httpx.Response:
            # While Canvas is being asked about the old token, the user enrolls a new one.
            env.store_clock.now += 30
            env.store.put(
                tenant_id=TENANT, object_id=OID_A, api_token="the-replacement-token-0123456789",
                canvas_user_id="42", canvas_user_name="Ada", entra_display_name="Ada",
                entra_upn="ada@example.test", canvas_host=CANVAS_HOST,
            )
            return _json(401, DEAD_BODY, DEAD_HEADERS)

        set_probe(env, probe)
        result = await get_courses()

        assert result["error"].startswith("HTTP error: 401")  # not reported as a dead token
        row = env.row()
        assert row.status == STATUS_ACTIVE
        assert env.store.get(PRINCIPAL_KEY).api_token == "the-replacement-token-0123456789"  # type: ignore[union-attr]

    async def test_a_cancelled_leader_does_not_strand_the_waiters(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        started = asyncio.Event()

        async def hanging_probe(request: httpx.Request) -> httpx.Response:
            started.set()
            await asyncio.sleep(30)
            return _json(401, DEAD_BODY, DEAD_HEADERS)  # pragma: no cover

        set_probe(env, hanging_probe)
        leader = asyncio.ensure_future(get_courses())
        await asyncio.wait_for(started.wait(), 5)
        waiter = asyncio.ensure_future(get_courses())
        await asyncio.sleep(0.05)
        leader.cancel()
        with pytest.raises(asyncio.CancelledError):
            await leader
        result = await asyncio.wait_for(waiter, 5)
        assert result["error"].startswith("HTTP error: 401")
        assert env.row().status == STATUS_ACTIVE


class TestNoRetryStorm:
    async def test_a_401_is_never_retried_or_backed_off(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        monkeypatch.setattr(cm.asyncio, "sleep", fake_sleep)
        set_token_health_monitor(None)  # the plain client path, as in stdio mode
        env.start_request()
        canvas_returns(env, 401, PERMISSION_BODY, DEAD_HEADERS)

        result = await get_courses()

        assert result["error"].startswith("HTTP error: 401")
        assert env.canvas.calls == ["/api/v1/courses"]  # one request, no retry
        assert sleeps == []

    async def test_a_dead_token_401_is_not_retried_either(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        monkeypatch.setattr(cm.asyncio, "sleep", fake_sleep)
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        await get_courses()
        assert env.canvas.calls == ["/api/v1/courses"]
        assert sleeps == []

    async def test_a_429_still_backs_off_and_recovers(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        monkeypatch.setattr(cm.asyncio, "sleep", fake_sleep)
        env.start_request()
        answers = iter([429, 200])

        def handler(request: httpx.Request) -> httpx.Response:
            env.canvas.calls.append(request.url.path)
            status = next(answers)
            return _json(status, [] if status == 200 else {}, {"Retry-After": "3"} if status == 429 else None)

        env.router.route(host=CANVAS_HOST).mock(side_effect=handler)
        assert await get_courses() == []
        assert sleeps == [3]
        assert env.health.probe_count == 0


class TestVerifiedBookkeeping:
    async def test_last_verified_is_written_at_most_once_per_interval(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env.start_request()
        env.router.route(host=CANVAS_HOST).mock(return_value=_json(200, []))
        writes: list[str] = []
        real = env.store.mark_verified

        def counting(*args: Any, **kwargs: Any) -> None:
            writes.append("write")
            real(*args, **kwargs)

        monkeypatch.setattr(env.store, "mark_verified", counting)

        for _ in range(8):
            await get_courses()
        assert writes == ["write"]

        env.mono.now += 601
        await get_courses()
        assert writes == ["write", "write"]

    async def test_a_successful_call_updates_the_stored_time(self, env: Env) -> None:
        env.start_request()
        env.router.route(host=CANVAS_HOST).mock(return_value=_json(200, []))
        env.store_clock.now += 1200
        await get_courses()
        assert env.row().last_verified_at == int(env.store_clock.now)

    async def test_a_failing_bookkeeping_write_never_fails_the_call(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env.start_request()
        env.router.route(host=CANVAS_HOST).mock(return_value=_json(200, [{"id": 1}]))

        def boom(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("disk on fire")

        monkeypatch.setattr(env.store, "mark_verified", boom)
        assert await get_courses() == [{"id": 1}]

    async def test_a_successful_probe_counts_as_verification(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        set_probe(env, lambda request: _json(200, {"id": 42}))
        env.store_clock.now += 1200
        await get_courses()
        assert env.row().last_verified_at == int(env.store_clock.now)


class TestOtherCallSites:
    async def test_a_file_download_that_gets_a_dead_token_401_reports_it(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        chunks: list[bytes] = []

        result = await course_files.stream_file_download(
            f"https://{CANVAS_HOST}/files/9/download?verifier=x", 1000, chunks.append
        )

        assert result == {"error": EXPECTED_MESSAGE}
        assert chunks == []
        assert env.row().status == STATUS_INVALID
        assert len(env.canvas.probes) == 1

    async def test_a_download_with_a_permission_401_keeps_its_plain_error(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, PERMISSION_BODY)
        result = await course_files.stream_file_download(
            f"https://{CANVAS_HOST}/files/9/download", 1000, lambda chunk: None
        )
        assert result == {"error": "HTTP 401 while downloading the file"}
        assert env.canvas.probes == []
        assert env.row().status == STATUS_ACTIVE

    async def test_a_download_after_the_token_died_sends_nothing(self, env: Env) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        await get_courses()
        before = len(env.canvas.calls)
        result = await course_files.stream_file_download(
            f"https://{CANVAS_HOST}/files/9/download", 1000, lambda chunk: None
        )
        assert result == {"error": EXPECTED_MESSAGE}
        assert len(env.canvas.calls) == before

    async def test_an_upload_confirmation_that_gets_a_dead_token_401_reports_it(
        self, env: Env, tmp_path: pathlib.Path
    ) -> None:
        env.start_request()
        source = tmp_path / "notes.txt"
        source.write_bytes(b"hello")
        storage = f"https://{CANVAS_HOST}/files_api/upload"
        env.router.post(storage).mock(
            return_value=httpx.Response(
                302, headers={"Location": f"https://{CANVAS_HOST}/api/v1/files/7/create_success?uuid=u"}
            )
        )
        env.router.get(host=CANVAS_HOST, path__startswith="/api/v1/files/").mock(
            return_value=_json(401, DEAD_BODY, DEAD_HEADERS)
        )

        result = await cm.upload_file_to_storage(storage, {"key": "v"}, str(source), "notes.txt", "text/plain")

        assert result == {"error": EXPECTED_MESSAGE}
        assert env.row().status == STATUS_INVALID


class TestAudit:
    @pytest.fixture
    def lines(self, monkeypatch: pytest.MonkeyPatch) -> list[str]:
        recorded: list[str] = []

        class Recorder:
            def info(self, line: str) -> None:
                recorded.append(line)

        monkeypatch.setattr(audit, "_audit_logger", Recorder())
        monkeypatch.setattr(audit, "_access_events_enabled", True)
        return recorded

    async def test_invalidation_is_audited_with_the_principal_and_reason_only(
        self, env: Env, lines: list[str]
    ) -> None:
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        await get_courses()
        await get_courses()  # short-circuited: no second event

        events = [json.loads(line) for line in lines if '"canvas_token"' in line]
        assert len(events) == 1
        event = events[0]
        assert event["action"] == "invalidated"
        assert event["reason"] == "canvas_token_rejected"
        assert event["principal"] == PRINCIPAL_KEY
        blob = json.dumps(event)
        assert TOKEN not in blob and "ada@example.test" not in blob and CANVAS_HOST not in blob

    async def test_nothing_is_audited_when_the_audit_log_is_off(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorded: list[str] = []

        class Recorder:
            def info(self, line: str) -> None:
                recorded.append(line)

        monkeypatch.setattr(audit, "_audit_logger", Recorder())
        monkeypatch.setattr(audit, "_access_events_enabled", False)
        env.start_request()
        canvas_returns(env, 401, DEAD_BODY, DEAD_HEADERS)
        await get_courses()
        assert recorded == []
        assert env.row().status == STATUS_INVALID

    async def test_a_permission_401_writes_no_token_event(self, env: Env, lines: list[str]) -> None:
        env.start_request()
        canvas_returns(env, 401, PERMISSION_BODY)
        await get_courses()
        assert not [line for line in lines if '"canvas_token"' in line]
