"""The MCP side of the access decision: cache, request-context middleware, tool gate.

A disabled principal is refused before any Canvas credential is loaded and before
any tool runs, whichever token it presents: one issued before the change, a freshly
refreshed one, or one used after a server restart.
"""

from __future__ import annotations

import base64
import json
import pathlib
from typing import Any

import pytest
from dbbackend import make_store as backend_store
from fastmcp import Client, FastMCP

from canvas_mcp.core.credentials import (
    RequestCredentials,
    set_request_credentials,
    set_request_principal,
)
from canvas_mcp.core.selfhost import tool_gate
from canvas_mcp.core.selfhost.principal_access import (
    PrincipalAccessCache,
    access_disabled_message,
    access_unavailable_message,
)
from canvas_mcp.core.selfhost.request_context import SelfhostRequestContextMiddleware
from canvas_mcp.core.selfhost.schools import SchoolPolicy
from canvas_mcp.core.selfhost.token_store import (
    DISABLE_REASON_OPERATOR,
    OPERATOR,
    Keyring,
    PrincipalStatus,
    TokenStore,
)
from canvas_mcp.core.selfhost.tool_gate import SelfhostCredentialGate

from .conftest import OID_A, OID_B, TENANT, make_principal
from .test_request_context import (
    ACCOUNT_URL,
    CANVAS_URL,
    POLICY,
    Probe,
    _claims,
    _run,
    _user,
)

KEY_A = f"entra:{TENANT}:{OID_A}"
KEY_B = f"entra:{TENANT}:{OID_B}"
TOKEN_A = "canvas-token-for-user-A-0123456789"
TOKEN_B = "canvas-token-for-user-B-0123456789"


class Tick:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class CountingSource:
    """A status source that counts reads and can be told to fail."""

    def __init__(self) -> None:
        self.disabled: set[str] = set()
        self.reads: list[str] = []
        self.fail: Exception | None = None
        self.on_read: Any = None

    def get_principal_status(self, principal_key: str) -> PrincipalStatus:
        self.reads.append(principal_key)
        if self.fail is not None:
            raise self.fail
        answer = PrincipalStatus(
            principal_key, status="disabled" if principal_key in self.disabled else "active"
        )
        if self.on_read is not None:
            self.on_read()  # a change that lands after the answer was read
        return answer


def make_store(tmp_path: pathlib.Path, name: str = "t.sqlite3") -> TokenStore:
    ring = Keyring.parse("k1:" + base64.b64encode(b"\x01" * 32).decode())
    store = backend_store(tmp_path / name, ring, clock=lambda: 1_800_000_000)
    store.initialize()
    return store


def enroll_both(store: TokenStore) -> None:
    for oid, token in ((OID_A, TOKEN_A), (OID_B, TOKEN_B)):
        store.put(
            tenant_id=TENANT, object_id=oid, api_token=token, canvas_user_id="1",
            canvas_user_name="n", entra_display_name="n", entra_upn="n@example.test",
            canvas_host="canvas.example.test",
        )


def disable(store: TokenStore, oid: str = OID_A) -> None:
    store.disable_principal(TENANT, oid, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)


class SpyStore:
    """Wraps the real store and records which Canvas credentials were loaded."""

    def __init__(self, inner: TokenStore) -> None:
        self.inner = inner
        self.gets: list[tuple[str, str]] = []

    def get(self, tenant_id: str, object_id: str) -> Any:
        self.gets.append((tenant_id, object_id))
        return self.inner.get(tenant_id, object_id)

    def touch(self, tenant_id: str, object_id: str, *, min_interval_seconds: int = 300) -> None:
        self.inner.touch(tenant_id, object_id, min_interval_seconds=min_interval_seconds)


def build(
    probe: Probe, store: TokenStore, cache: PrincipalAccessCache | None, *, spy: SpyStore | None = None
) -> SelfhostRequestContextMiddleware:
    return SelfhostRequestContextMiddleware(
        probe,
        mcp_path="/mcp",
        policy=POLICY,
        store=spy or SpyStore(store),
        schools=SchoolPolicy.pinned(CANVAS_URL),
        account_url=ACCOUNT_URL,
        access=cache,
        owners=store,
    )


class TestAccessCache:
    def test_one_read_serves_requests_within_the_ttl(self) -> None:
        source, clock = CountingSource(), Tick()
        cache = PrincipalAccessCache(source, ttl_seconds=5, clock=clock)
        for _ in range(4):
            assert cache.status(KEY_A).disabled is False
        assert source.reads == [KEY_A]
        clock.now += 5.1
        cache.status(KEY_A)
        assert source.reads == [KEY_A, KEY_A]

    def test_a_change_made_elsewhere_is_noticed_after_the_ttl_not_before(self) -> None:
        source, clock = CountingSource(), Tick()
        cache = PrincipalAccessCache(source, ttl_seconds=5, clock=clock)
        assert not cache.status(KEY_A).disabled
        source.disabled.add(KEY_A)  # another process (or the CLI) disabled the user
        clock.now += 4
        assert not cache.status(KEY_A).disabled  # the documented bounded delay
        clock.now += 1.5
        assert cache.status(KEY_A).disabled

    def test_invalidate_makes_the_change_visible_at_once(self) -> None:
        source = CountingSource()
        cache = PrincipalAccessCache(source, clock=Tick())
        assert not cache.status(KEY_A).disabled
        source.disabled.add(KEY_A)
        cache.invalidate(KEY_A)
        assert cache.status(KEY_A).disabled

    def test_invalidating_one_principal_keeps_the_others(self) -> None:
        source = CountingSource()
        cache = PrincipalAccessCache(source, clock=Tick())
        cache.status(KEY_A)
        cache.status(KEY_B)
        cache.invalidate(KEY_A)
        cache.status(KEY_A)
        cache.status(KEY_B)
        assert source.reads == [KEY_A, KEY_B, KEY_A]
        cache.invalidate()
        cache.status(KEY_B)
        assert source.reads[-1] == KEY_B and len(source.reads) == 4

    def test_a_read_that_started_before_an_invalidation_is_not_stored(self) -> None:
        source = CountingSource()
        cache = PrincipalAccessCache(source, clock=Tick())

        def change_during_read() -> None:
            source.on_read = None
            source.disabled.add(KEY_A)
            cache.invalidate(KEY_A)

        source.on_read = change_during_read
        first = cache.status(KEY_A)  # read the old answer, then the user was disabled
        assert not first.disabled
        assert cache.status(KEY_A).disabled  # the stale answer was not cached

    def test_a_failure_is_not_cached_and_propagates(self) -> None:
        source = CountingSource()
        cache = PrincipalAccessCache(source, clock=Tick())
        source.fail = RuntimeError("database is locked")
        with pytest.raises(RuntimeError):
            cache.status(KEY_A)
        source.fail = None
        assert not cache.status(KEY_A).disabled

    def test_the_table_is_bounded(self) -> None:
        source = CountingSource()
        cache = PrincipalAccessCache(source, clock=Tick(), max_entries=3)
        for i in range(10):
            cache.status(f"acct:{i}")
        cache.status("acct:9")
        assert source.reads.count("acct:9") == 1


class TestMiddlewareRefusesADisabledPrincipal:
    async def test_a_disabled_user_gets_403_and_no_credential_is_loaded(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        enroll_both(store)
        disable(store)
        probe, spy = Probe(), SpyStore(store)
        mw = build(probe, store, PrincipalAccessCache(store), spy=spy)
        call = await _run(mw, user=_user(_claims()))
        assert call.status == 403
        assert access_disabled_message() in call.body.decode()
        assert call.headers[b"cache-control"] == b"no-store"
        assert probe.calls == 0
        assert spy.gets == []  # the Canvas token was never even decrypted
        assert TOKEN_A not in call.body.decode()

    async def test_other_users_are_unaffected(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        enroll_both(store)
        disable(store, OID_A)
        probe = Probe()
        mw = build(probe, store, PrincipalAccessCache(store))
        call = await _run(mw, user=_user(_claims(oid=OID_B)))
        assert call.status == 200
        assert probe.seen["creds"].api_token == TOKEN_B

    async def test_deleting_the_enrollment_does_not_bring_a_disabled_user_back(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        enroll_both(store)
        disable(store)
        store.delete(TENANT, OID_A)
        probe = Probe()
        call = await _run(build(probe, store, PrincipalAccessCache(store)), user=_user(_claims()))
        assert call.status == 403 and probe.calls == 0

    async def test_a_user_who_was_never_enrolled_is_refused_too(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        disable(store)
        probe = Probe()
        call = await _run(build(probe, store, PrincipalAccessCache(store)), user=_user(_claims()))
        assert call.status == 403 and probe.calls == 0

    async def test_an_already_issued_and_a_freshly_refreshed_token_are_both_refused(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        enroll_both(store)
        probe = Probe()
        mw = build(probe, store, PrincipalAccessCache(store))
        old_token = _user(_claims(iat=1_799_990_000, exp=1_800_003_600))
        assert (await _run(mw, user=old_token)).status == 200
        disable(store)
        mw.access.invalidate(KEY_A)  # type: ignore[union-attr]
        assert (await _run(mw, user=old_token)).status == 403
        # A refresh at Entra still works for the account, and mints a new token with
        # valid roles and a later expiry: it changes nothing here.
        refreshed = _user(_claims(iat=1_800_000_100, exp=1_800_007_700))
        assert (await _run(mw, user=refreshed)).status == 403
        assert probe.calls == 1

    async def test_a_change_made_by_another_process_is_noticed_within_the_ttl(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        enroll_both(store)
        clock = Tick()
        cache = PrincipalAccessCache(store, ttl_seconds=5, clock=clock)
        probe = Probe()
        mw = build(probe, store, cache)
        assert (await _run(mw, user=_user(_claims()))).status == 200
        # The operator CLI is another process: it cannot invalidate our cache.
        disable(make_store_view(tmp_path))
        clock.now += 2
        assert (await _run(mw, user=_user(_claims()))).status == 200  # inside the bound
        clock.now += 4
        assert (await _run(mw, user=_user(_claims()))).status == 403

    async def test_the_decision_survives_a_server_restart(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        enroll_both(store)
        disable(store)
        # A new process: new store object, new cache, new middleware.
        restarted = make_store(tmp_path)
        probe = Probe()
        call = await _run(build(probe, restarted, PrincipalAccessCache(restarted)), user=_user(_claims()))
        assert call.status == 403 and probe.calls == 0

    async def test_enabling_again_restores_access_with_the_kept_enrollment(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        enroll_both(store)
        cache = PrincipalAccessCache(store)
        probe = Probe()
        mw = build(probe, store, cache)
        disable(store)
        cache.invalidate(KEY_A)
        assert (await _run(mw, user=_user(_claims()))).status == 403
        store.enable_principal(TENANT, OID_A, actor=OPERATOR)
        cache.invalidate(KEY_A)
        assert (await _run(mw, user=_user(_claims()))).status == 200
        assert probe.seen["creds"].api_token == TOKEN_A

    async def test_an_unreadable_status_fails_closed_with_503(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        enroll_both(store)
        source = CountingSource()
        source.fail = RuntimeError("database is locked: /secret/path")
        probe = Probe()
        call = await _run(build(probe, store, PrincipalAccessCache(source)), user=_user(_claims()))
        assert call.status == 503
        assert access_unavailable_message() in call.body.decode()
        assert "secret" not in call.body.decode()
        assert probe.calls == 0

    async def test_the_refusal_is_logged_without_the_token_or_the_key(
        self, tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        caplog.set_level(logging.WARNING)
        store = make_store(tmp_path)
        enroll_both(store)
        disable(store)
        await _run(build(Probe(), store, PrincipalAccessCache(store)), user=_user(_claims()))
        assert "principal_disabled" in caplog.text
        assert TOKEN_A not in caplog.text

    async def test_without_an_access_checker_nothing_changes(self, tmp_path: pathlib.Path) -> None:
        # Existing wiring (and the tests that build the middleware alone) is unchanged.
        store = make_store(tmp_path)
        enroll_both(store)
        disable(store)
        probe = Probe()
        call = await _run(build(probe, store, None), user=_user(_claims()))
        assert call.status == 200


def make_store_view(tmp_path: pathlib.Path) -> TokenStore:
    """A second store object on the same file: what another process would hold."""
    return make_store(tmp_path)


class TestOwnerDemotionFromRequestTokens:
    async def test_a_newer_token_without_the_owner_role_lowers_the_stored_flag(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        store.record_sign_in(KEY_A, is_owner=True)  # at 1_800_000_000
        cache = PrincipalAccessCache(store)
        mw = build(Probe(), store, cache)
        await _run(mw, user=_user(_claims(iat=1_800_000_500)))
        assert not store.get_principal_status(KEY_A).is_owner

    async def test_the_demotion_is_audited(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from canvas_mcp.core import audit

        lines: list[str] = []

        class Recorder:
            def info(self, line: str) -> None:
                lines.append(line)

        monkeypatch.setattr(audit, "_audit_logger", Recorder())
        monkeypatch.setattr(audit, "_access_events_enabled", True)
        store = make_store(tmp_path)
        store.record_sign_in(KEY_A, is_owner=True)
        mw = build(Probe(), store, PrincipalAccessCache(store))
        await _run(mw, user=_user(_claims(iat=1_800_000_500)))
        await _run(mw, user=_user(_claims(iat=1_800_000_600)))  # already lowered: no repeat
        events = [json.loads(line) for line in lines]
        assert [(e["event_type"], e["action"], e["principal"], e["reason"]) for e in events] == [
            ("principal_status", "owner_lost", KEY_A, "access_token_roles")
        ]

    async def test_a_token_issued_before_the_last_sign_in_does_not(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        store.record_sign_in(KEY_A, is_owner=True)
        mw = build(Probe(), store, PrincipalAccessCache(store))
        await _run(mw, user=_user(_claims(iat=1_799_990_000)))
        assert store.get_principal_status(KEY_A).is_owner

    async def test_a_token_that_still_carries_the_owner_role_changes_nothing(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        store.record_sign_in(KEY_A, is_owner=True)
        mw = build(Probe(), store, PrincipalAccessCache(store))
        await _run(mw, user=_user(_claims(roles=["Canvas.Owner"], iat=1_800_000_500)))
        assert store.get_principal_status(KEY_A).is_owner

    async def test_a_token_without_an_issue_time_is_no_evidence(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        store.record_sign_in(KEY_A, is_owner=True)
        mw = build(Probe(), store, PrincipalAccessCache(store))
        await _run(mw, user=_user(_claims()))
        assert store.get_principal_status(KEY_A).is_owner

    async def test_request_tokens_can_never_raise_the_flag(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        mw = build(Probe(), store, PrincipalAccessCache(store))
        await _run(mw, user=_user(_claims(roles=["Canvas.Owner"], iat=1_800_000_500)))
        assert not store.get_principal_status(KEY_A).is_owner


# -- the tool gate ---------------------------------------------------------------


class Body:
    runs = 0


@pytest.fixture
def gated(monkeypatch: pytest.MonkeyPatch) -> Any:
    Body.runs = 0
    source = CountingSource()
    cache = PrincipalAccessCache(source, clock=Tick())
    mcp = FastMCP("access-gate-test")
    mcp.add_middleware(SelfhostCredentialGate(access=cache))

    @mcp.tool()
    def get_my_profile() -> str:
        """Dummy tool."""
        Body.runs += 1
        return "ran"

    @mcp.resource("data://thing")
    def thing() -> str:
        Body.runs += 1
        return "resource body"

    from fastmcp.server.auth import AccessToken

    monkeypatch.setattr(
        tool_gate,
        "get_access_token",
        lambda: AccessToken(token="t", client_id="c", scopes=[], claims={"oid": OID_A}),
    )
    set_request_principal(make_principal(OID_A))
    set_request_credentials(RequestCredentials(api_token=TOKEN_A, api_url=CANVAS_URL))
    return mcp, source, cache


def text_of(result: Any) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


class TestGateRefusesADisabledPrincipal:
    async def test_an_active_principal_runs_the_tool(self, gated: Any) -> None:
        mcp, _source, _cache = gated
        async with Client(mcp) as client:
            result = await client.call_tool("get_my_profile", {}, raise_on_error=False)
        assert not result.is_error and Body.runs == 1

    async def test_a_disabled_principal_is_refused_before_the_body_runs(self, gated: Any) -> None:
        mcp, source, _cache = gated
        source.disabled.add(KEY_A)
        async with Client(mcp) as client:
            result = await client.call_tool("get_my_profile", {}, raise_on_error=False)
        assert result.is_error
        assert text_of(result) == access_disabled_message()
        assert Body.runs == 0

    async def test_the_second_call_of_a_running_request_sees_the_change(self, gated: Any) -> None:
        # In-flight semantics: a call that already started is not interrupted, but
        # the next call, even in the same request context, is refused.
        mcp, source, cache = gated
        async with Client(mcp) as client:
            first = await client.call_tool("get_my_profile", {}, raise_on_error=False)
            source.disabled.add(KEY_A)
            cache.invalidate(KEY_A)
            second = await client.call_tool("get_my_profile", {}, raise_on_error=False)
        assert not first.is_error and second.is_error
        assert Body.runs == 1

    async def test_a_resource_read_is_refused_too(self, gated: Any) -> None:
        mcp, source, _cache = gated
        source.disabled.add(KEY_A)
        async with Client(mcp) as client:
            with pytest.raises(Exception, match="disabled by an administrator"):
                await client.read_resource("data://thing")
        assert Body.runs == 0

    async def test_an_unreadable_status_fails_closed(self, gated: Any) -> None:
        mcp, source, _cache = gated
        source.fail = RuntimeError("boom")
        async with Client(mcp) as client:
            result = await client.call_tool("get_my_profile", {}, raise_on_error=False)
        assert result.is_error and text_of(result) == access_unavailable_message()
        assert Body.runs == 0

    async def test_a_new_connection_does_not_reuse_a_stale_verdict(self, gated: Any) -> None:
        mcp, source, cache = gated
        results: list[bool] = []
        for disable_before in (False, True):
            if disable_before:
                source.disabled.add(KEY_A)
                cache.invalidate(KEY_A)
            async with Client(mcp) as client:
                r = await client.call_tool("get_my_profile", {}, raise_on_error=False)
                results.append(r.is_error)
        assert results == [False, True]

