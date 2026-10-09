"""Credential generations: state is bound to the Canvas credential's lifecycle.

A principal's credential generation is raised by the token store whenever the
stored Canvas credential is saved, replaced, removed, found dead or restored, or the
principal is disabled or enabled. Course caches, course-policy decisions,
pseudonyms, health verdicts, pending write confirmations and background refreshes
are all bound to it, so nothing learned under one credential is used under another,
even for the same Entra identity at the same school.
"""

from __future__ import annotations

import asyncio
import base64
import pathlib
import threading
from typing import Any

import httpx
import pytest
from dbbackend import make_store as backend_store
from dbbackend import raw_connection
from fastmcp import Client, FastMCP
from fastmcp.server.auth import AccessToken

from canvas_mcp.core import anonymization, cache, course_policy
from canvas_mcp.core.credentials import (
    RequestCredentials,
    RequestTokenState,
    current_principal_key,
    get_request_credential_generation,
    get_request_credentials,
    get_request_token_state,
    known_credential_generation,
    note_credential_generation,
    register_credential_purge_listener,
    request_credential_is_stale,
    reset_credential_generations,
    run_pending_credential_purges,
    set_http_request_active,
    set_request_credential_generation,
    set_request_credentials,
    set_request_principal,
    set_request_token_state,
)
from canvas_mcp.core.selfhost import tool_gate
from canvas_mcp.core.selfhost.principal_access import PrincipalAccessCache
from canvas_mcp.core.selfhost.request_context import SelfhostRequestContextMiddleware
from canvas_mcp.core.selfhost.schools import SchoolPolicy
from canvas_mcp.core.selfhost.token_health import TokenHealth
from canvas_mcp.core.selfhost.token_store import (
    DISABLE_REASON_OPERATOR,
    OPERATOR,
    REASON_CANVAS_TOKEN_REJECTED,
    SCHEMA_VERSION,
    STATUS_ACTIVE,
    STATUS_INVALID,
    Keyring,
    PrincipalStatus,
    TokenStore,
)
from canvas_mcp.core.selfhost.tool_gate import SelfhostCredentialGate
from canvas_mcp.core.write_confirmation import ConfirmationGuard
from canvas_mcp.tools import discussions

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
TOKEN_1 = "canvas-token-first-0123456789abcdef"
TOKEN_2 = "canvas-token-second-0123456789abcdef"
HOST = "canvas.example.test"
API_URL = f"https://{HOST}/api/v1"


def make_store(tmp_path: pathlib.Path, name: str = "t.sqlite3") -> TokenStore:
    ring = Keyring.parse("k1:" + base64.b64encode(b"\x01" * 32).decode())
    store = backend_store(tmp_path / name, ring, clock=lambda: 1_800_000_000)
    store.initialize()
    return store


def put(store: TokenStore, token: str = TOKEN_1, oid: str = OID_A, *, user: str = "1",
        host: str = HOST) -> Any:
    return store.put(
        tenant_id=TENANT, object_id=oid, api_token=token, canvas_user_id=user,
        canvas_user_name=f"user {user}", entra_display_name="n", entra_upn="n@example.test",
        canvas_host=host,
    )


# ---------------------------------------------------------------------- the store


class TestStoreGenerations:
    def test_a_principal_that_never_changed_is_at_generation_zero(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        assert store.credential_generation(KEY_A) == 0
        assert store.get_principal_status(KEY_A).credential_generation == 0
        assert store.get(KEY_A) is None

    def test_saving_replacing_and_deleting_each_raise_it_and_it_never_goes_back(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        seen = [put(store).credential_generation]
        seen.append(put(store).credential_generation)  # the very same token again
        seen.append(put(store, TOKEN_2, user="2").credential_generation)  # another Canvas user
        assert store.delete(KEY_A) is True
        seen.append(store.credential_generation(KEY_A))
        seen.append(put(store).credential_generation)  # enrolling again after deleting
        assert seen == [1, 2, 3, 4, 5]
        assert store.credential_generation(KEY_B) == 0  # other principals are untouched

    def test_deleting_nothing_and_a_no_op_do_not_raise_it(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        assert store.delete(KEY_A) is False
        assert store.mark_invalid(KEY_A, reason=REASON_CANVAS_TOKEN_REJECTED) is False
        assert store.restore_active(KEY_A) is False
        assert store.credential_generation(KEY_A) == 0
        put(store)
        assert store.restore_active(KEY_A) is False  # already active
        assert store.credential_generation(KEY_A) == 1

    def test_dying_and_coming_back_to_life_are_new_generations(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        put(store)
        assert store.mark_invalid(KEY_A, reason=REASON_CANVAS_TOKEN_REJECTED) is True
        assert store.credential_generation(KEY_A) == 2
        assert store.mark_invalid(KEY_A, reason=REASON_CANVAS_TOKEN_REJECTED) is False
        assert store.restore_active(KEY_A) is True
        assert store.credential_generation(KEY_A) == 3

    def test_disabling_and_enabling_each_raise_it(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        put(store)
        store.disable_principal(KEY_A, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        assert store.get_principal_status(KEY_A).credential_generation == 2
        store.disable_principal(KEY_A, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)  # no-op
        assert store.credential_generation(KEY_A) == 2
        store.enable_principal(KEY_A, actor=OPERATOR)
        assert store.credential_generation(KEY_A) == 3
        # The enrollment is kept and now belongs to the newest generation.
        row = store.get(KEY_A)
        assert row is not None and row.credential_generation == 3

    def test_the_token_and_its_generation_are_read_together(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        put(store)
        first = store.get(KEY_A)
        put(store, TOKEN_2, user="2")
        second = store.get(KEY_A)
        assert first is not None and second is not None
        assert (first.api_token, first.credential_generation) == (TOKEN_1, 1)
        assert (second.api_token, second.credential_generation) == (TOKEN_2, 2)
        info = store.info(KEY_A)
        assert info is not None and info.credential_generation == 2
        assert [e.credential_generation for e in store.list_enrollments()] == [2]

    def test_it_survives_a_restart_and_a_deleted_row(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        put(store)
        store.delete(KEY_A)
        reopened = make_store(tmp_path)
        assert reopened.credential_generation(KEY_A) == 2
        assert put(reopened).credential_generation == 3

    def test_concurrent_enrollments_never_share_a_generation(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        results: list[int] = []
        lock = threading.Lock()

        def enroll(i: int) -> None:
            info = put(store, f"token-number-{i}-0123456789", user=str(i))
            with lock:
                results.append(info.credential_generation)

        threads = [threading.Thread(target=enroll, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(results) == list(range(1, 9))
        final = store.get(KEY_A)
        assert final is not None and final.credential_generation == 8

    def test_a_late_verdict_about_a_replaced_token_changes_nothing(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        old = put(store)
        put(store, TOKEN_2, user="2")  # replaced in the same second: updated_at is equal
        assert old.updated_at == store.info(KEY_A).updated_at  # type: ignore[union-attr]
        assert store.mark_invalid(
            KEY_A,
            reason=REASON_CANVAS_TOKEN_REJECTED,
            expected_updated_at=old.updated_at,
            expected_generation=old.credential_generation,
        ) is False
        row = store.info(KEY_A)
        assert row is not None and row.status == STATUS_ACTIVE
        assert store.credential_generation(KEY_A) == 2  # and it did not raise it
        # The same call for the current generation does take effect.
        assert store.mark_invalid(
            KEY_A, reason=REASON_CANVAS_TOKEN_REJECTED, expected_generation=2
        ) is True

    def test_a_late_restore_or_success_about_a_replaced_token_changes_nothing(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        put(store)
        store.mark_invalid(KEY_A, reason=REASON_CANVAS_TOKEN_REJECTED)
        generation_when_checked = store.credential_generation(KEY_A)
        put(store, TOKEN_2, user="2")  # replaced while the re-check was running
        assert store.restore_active(KEY_A, expected_generation=generation_when_checked) is False
        before = store.info(KEY_A)
        assert before is not None
        store.mark_verified(KEY_A, min_interval_seconds=0, expected_generation=1)
        after = store.info(KEY_A)
        assert after == before


class TestMigration:
    @pytest.mark.sqlite_only
    def test_a_version_3_database_gains_the_table_and_starts_at_zero(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        put(store)
        with raw_connection(store) as conn:
            conn.execute("DROP TABLE credential_generations")
            conn.execute("UPDATE meta SET value = '3' WHERE key = 'schema_version'")
        migrated = make_store(tmp_path)
        with raw_connection(migrated) as conn:
            version = conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()[0]
        assert version == str(SCHEMA_VERSION) == "4"
        row = migrated.get(KEY_A)
        assert row is not None and row.api_token == TOKEN_1 and row.credential_generation == 0
        # The first change after the upgrade is generation 1, and it only grows.
        assert put(migrated, TOKEN_2, user="2").credential_generation == 1
        assert make_store(tmp_path).credential_generation(KEY_A) == 1

    def test_an_older_server_refuses_the_new_database(self, tmp_path: pathlib.Path) -> None:
        # A version 3 server would save tokens without raising any generation.
        with raw_connection(make_store(tmp_path)) as conn:
            version = int(conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()[0])
        assert version > 3


# ---------------------------------------------------------------- the process registry


class TestRegistry:
    def test_it_only_ever_raises_and_reports_news(self) -> None:
        assert known_credential_generation(KEY_A) is None
        assert note_credential_generation(KEY_A, 3) is False  # first sighting: nothing older
        assert note_credential_generation(KEY_A, 3) is False
        assert note_credential_generation(KEY_A, 2) is False
        assert known_credential_generation(KEY_A) == 3
        assert note_credential_generation(KEY_A, 4) is True
        assert known_credential_generation(KEY_A) == 4

    def test_listeners_run_once_per_rise_on_the_draining_thread(self) -> None:
        calls: list[tuple[str, int]] = []
        listener = lambda key: calls.append((key, threading.get_ident()))  # noqa: E731
        register_credential_purge_listener(listener)
        register_credential_purge_listener(listener)  # registering twice does not double it
        note_credential_generation(KEY_A, 1)
        note_credential_generation(KEY_A, 2)
        note_credential_generation(KEY_A, 3)
        worker = threading.Thread(target=lambda: note_credential_generation(KEY_B, 1))
        worker.start()
        worker.join()
        assert calls == []  # recording never runs listeners
        run_pending_credential_purges()
        ours = [c for c in calls if c[0] == KEY_A]
        assert len(ours) == 1 and ours[0][1] == threading.get_ident()
        run_pending_credential_purges()
        assert len([c for c in calls if c[0] == KEY_A]) == 1

    def test_a_failing_listener_does_not_stop_the_others(self) -> None:
        calls: list[str] = []

        def boom(key: str) -> None:
            raise RuntimeError("x")

        register_credential_purge_listener(boom)
        register_credential_purge_listener(calls.append)
        note_credential_generation(KEY_A, 1)
        note_credential_generation(KEY_A, 2)
        run_pending_credential_purges()
        assert KEY_A in calls

    def test_the_store_reports_each_committed_change(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        put(store)
        assert known_credential_generation(KEY_A) == 1
        put(store, TOKEN_2, user="2")
        assert known_credential_generation(KEY_A) == 2
        store.delete(KEY_A)
        assert known_credential_generation(KEY_A) == 3

    def test_staleness_needs_a_principal_and_a_generation(self) -> None:
        assert request_credential_is_stale() is False  # stdio
        set_request_principal(make_principal(OID_A))
        assert request_credential_is_stale() is False  # no generation
        set_request_credential_generation(1)
        assert request_credential_is_stale() is False  # nothing newer known
        note_credential_generation(KEY_A, 1)
        assert request_credential_is_stale() is False
        note_credential_generation(KEY_A, 2)
        assert request_credential_is_stale() is True
        set_request_credential_generation(2)
        assert request_credential_is_stale() is False


# --------------------------------------------------------------------------- the key


def as_user(oid: str, generation: int | None, token: str = TOKEN_1, api_url: str = API_URL) -> None:
    set_http_request_active(True)
    set_request_principal(make_principal(oid))
    set_request_credentials(RequestCredentials(api_token=token, api_url=api_url))
    set_request_credential_generation(generation)


class TestKey:
    def test_the_key_names_the_generation_and_never_the_token(self) -> None:
        as_user(OID_A, 3)
        key = current_principal_key()
        assert key == f"{KEY_A}|{API_URL}|g3"
        assert TOKEN_1 not in key

    def test_same_identity_same_school_same_token_text_different_generation(self) -> None:
        as_user(OID_A, 1)
        first = current_principal_key()
        as_user(OID_A, 2)  # the user re-enrolled the very same token
        assert current_principal_key() != first

    def test_legacy_http_and_stdio_keys_do_not_know_generations(self) -> None:
        assert current_principal_key() == "local"
        set_http_request_active(True)
        set_request_credentials(RequestCredentials(api_token=TOKEN_1, api_url=API_URL))
        set_request_credential_generation(7)  # ignored without a principal
        assert current_principal_key().startswith("token:")
        assert "g7" not in current_principal_key()


# ------------------------------------------------------------------- course caches


COURSES_A = [{"id": 101, "course_code": "ICS 33", "name": "Intermediate Python"}]
COURSES_B = [{"id": 909, "course_code": "BIO 1", "name": "Biology"}]


class TestCourseCache:
    async def test_a_replaced_token_never_sees_the_old_courses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        lists = {TOKEN_1: COURSES_A, TOKEN_2: COURSES_B}
        reads: list[str] = []

        async def fake_list(path: str, params: Any = None) -> Any:
            creds = get_request_credentials()
            assert creds is not None
            reads.append(creds.api_token)
            return lists[creds.api_token]

        monkeypatch.setattr(cache, "fetch_all_paginated_results", fake_list)
        as_user(OID_A, 1, TOKEN_1)
        assert await cache.resolve_numeric_course_id("ICS 33") == ("101", None)
        assert await cache.resolve_numeric_course_id("ICS 33") == ("101", None)
        assert reads == [TOKEN_1]  # the second lookup came from this generation's cache

        # Same Entra identity, same host: now another Canvas user's token.
        as_user(OID_A, 2, TOKEN_2)
        numeric, error = await cache.resolve_numeric_course_id("ICS 33")
        assert numeric is None and error is not None  # the old alias is gone
        assert await cache.resolve_numeric_course_id("BIO 1") == ("909", None)
        assert reads == [TOKEN_1, TOKEN_2]

        # Only the new token's list is cached for the new generation.
        assert cache.current_cache_state().records == cache.course_records(COURSES_B)

    def test_the_purge_listener_drops_every_generation_of_a_principal(self) -> None:
        for generation in (1, 2):
            as_user(OID_A, generation)
            cache.current_cache_state().code_to_id["X"] = "1"
        as_user(OID_B, 1)
        cache.current_cache_state().code_to_id["Y"] = "2"
        note_credential_generation(KEY_A, 1)
        note_credential_generation(KEY_A, 3)
        run_pending_credential_purges()
        assert [k for k in cache._STATES if k.startswith(KEY_A)] == []
        assert [k for k in cache._STATES if k.startswith(KEY_B)] != []

    async def test_a_refresh_that_finishes_after_the_token_was_replaced_publishes_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        release = asyncio.Event()
        started = asyncio.Event()

        async def slow_list(path: str, params: Any = None) -> Any:
            started.set()
            await release.wait()
            return COURSES_A

        monkeypatch.setattr(cache, "fetch_all_paginated_results", slow_list)
        as_user(OID_A, 1, TOKEN_1)
        old_state = cache.current_cache_state()
        task = asyncio.get_running_loop().create_task(cache.refresh_course_cache())
        await started.wait()

        # The user replaces the token while the old refresh is still reading.
        note_credential_generation(KEY_A, 1)
        note_credential_generation(KEY_A, 2)
        release.set()
        assert await task is False

        assert old_state.records == [] and old_state.last_refresh_at is None
        as_user(OID_A, 2, TOKEN_2)
        fresh = cache.current_cache_state()
        assert fresh is not old_state
        assert fresh.records == [] and fresh.code_to_id == {}

    async def test_a_request_on_a_replaced_token_cannot_fill_the_new_cache(self) -> None:
        as_user(OID_A, 1)
        note_credential_generation(KEY_A, 1)
        note_credential_generation(KEY_A, 2)  # replaced while this request runs
        cache.remember_course_code("101", "ICS 33")
        state = cache.current_cache_state()
        state.code_to_id["ICS 33"] = "101"  # throwaway: nobody else can see it
        assert cache._STATES == {}  # nothing was registered for the replaced generation
        as_user(OID_A, 2)
        assert cache.current_cache_state().code_to_id == {}

    async def test_the_upstream_request_local_modes_are_unaffected(self) -> None:
        set_http_request_active(True)
        set_request_credentials(RequestCredentials(api_token=TOKEN_1, api_url=API_URL))
        first = cache.current_cache_state()
        assert first is not cache.current_cache_state()  # still a throwaway every time
        assert request_credential_is_stale() is False


# ------------------------------------------------------------ the other caches


class TestPolicyCache:
    async def test_a_cached_allow_is_not_served_to_a_token_with_fewer_permissions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bodies = {
            TOKEN_1: {"syllabus_body": "agent_writes: allow\nnote: teacher's view"},
            TOKEN_2: {"syllabus_body": "agent_writes: deny\nnote: reduced permissions"},
        }
        reads: list[str] = []

        async def fake_request(method: str, endpoint: str, **kwargs: Any) -> Any:
            creds = get_request_credentials()
            assert creds is not None
            reads.append(creds.api_token)
            return bodies[creds.api_token]

        monkeypatch.setattr(course_policy, "make_canvas_request", fake_request)
        as_user(OID_A, 1, TOKEN_1)
        assert (await course_policy.get_course_policy(7)).allow_writes is True
        assert (await course_policy.get_course_policy(7)).allow_writes is True
        assert reads == [TOKEN_1]

        as_user(OID_A, 2, TOKEN_2)  # same identity, same school, reduced permissions
        replaced = await course_policy.get_course_policy(7)
        assert replaced.allow_writes is False and replaced.note == "reduced permissions"
        assert reads == [TOKEN_1, TOKEN_2]

    def test_the_purge_listener_drops_the_decisions_of_every_generation(self) -> None:
        for principal, generation in ((OID_A, 1), (OID_A, 2), (OID_B, 1)):
            as_user(principal, generation)
            course_policy._policy_cache[(current_principal_key(), "7")] = (float("inf"), None)  # type: ignore[assignment]
        note_credential_generation(KEY_A, 1)
        note_credential_generation(KEY_A, 5)
        run_pending_credential_purges()
        assert [k[0] for k in course_policy._policy_cache if k[0].startswith(KEY_A)] == []
        assert [k[0] for k in course_policy._policy_cache if k[0].startswith(KEY_B)] != []


class TestPseudonymsAndHints:
    def test_pseudonym_maps_are_per_generation_and_purged(self) -> None:
        as_user(OID_A, 1)
        anonymization.generate_anonymous_id(5)
        assert anonymization.get_anonymization_stats()["total_anonymized_ids"] == 1
        as_user(OID_A, 2)
        assert anonymization.get_anonymization_stats()["total_anonymized_ids"] == 0
        anonymization.generate_anonymous_id(6)
        note_credential_generation(KEY_A, 1)
        note_credential_generation(KEY_A, 2)
        run_pending_credential_purges()
        assert [k for k in anonymization._anonymization_cache if k.startswith(KEY_A)] == []

    def test_discussion_hints_learned_under_one_token_are_not_used_under_the_next(self) -> None:
        as_user(OID_A, 1)
        discussions._unservable_topics[(current_principal_key(), "/courses/1", "5")] = float("inf")
        assert discussions._is_known_unservable("/courses/1", 5)
        as_user(OID_A, 2)
        assert not discussions._is_known_unservable("/courses/1", 5)
        as_user(OID_A, 1)
        note_credential_generation(KEY_A, 1)
        note_credential_generation(KEY_A, 2)
        run_pending_credential_purges()
        assert discussions._unservable_topics == {}


# ------------------------------------------------------- pending write confirmations


class TestPendingConfirmations:
    def preview(self, guard: ConfirmationGuard) -> tuple[str, str]:
        fingerprint = guard.fingerprint("delete_page", "course-1", "page-9")
        return guard.issue(fingerprint), fingerprint

    def test_a_preview_is_redeemable_while_the_credential_is_unchanged(self) -> None:
        guard = ConfirmationGuard()
        as_user(OID_A, 4)
        token, fingerprint = self.preview(guard)
        as_user(OID_A, 4)  # a later request of the same user
        assert guard.check(token, guard.fingerprint("delete_page", "course-1", "page-9")) is None
        assert fingerprint == guard.fingerprint("delete_page", "course-1", "page-9")

    @pytest.mark.parametrize(
        "after",
        [
            pytest.param({"token": TOKEN_1}, id="the-same-token-enrolled-again"),
            pytest.param({"token": TOKEN_2}, id="another-canvas-user-at-the-same-host"),
        ],
    )
    def test_a_preview_does_not_survive_re_enrollment_at_the_same_school(
        self, after: dict[str, str]
    ) -> None:
        guard = ConfirmationGuard()
        as_user(OID_A, 4)
        token, _ = self.preview(guard)
        as_user(OID_A, 5, after["token"])
        fingerprint = guard.fingerprint("delete_page", "course-1", "page-9")
        refusal = guard.check(token, fingerprint)
        assert refusal is not None and "does not match" in refusal
        assert "Canvas connection changed" in refusal
        # The mismatch burned the token: going back does not bring it back.
        as_user(OID_A, 4)
        again = guard.check(token, guard.fingerprint("delete_page", "course-1", "page-9"))
        assert again is not None and "already used" in again

    def test_removal_disablement_and_death_also_void_a_preview(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path)
        guard = ConfirmationGuard()
        for change in (
            lambda: store.delete(KEY_A),
            lambda: store.disable_principal(KEY_A, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR),
            lambda: store.enable_principal(KEY_A, actor=OPERATOR),
            lambda: store.mark_invalid(KEY_A, reason=REASON_CANVAS_TOKEN_REJECTED),
        ):
            put(store) if store.get(KEY_A) is None else None
            as_user(OID_A, store.credential_generation(KEY_A))
            token, _ = self.preview(guard)
            change()
            as_user(OID_A, store.credential_generation(KEY_A))
            assert guard.check(token, guard.fingerprint("delete_page", "course-1", "page-9"))


# ---------------------------------------------------------------------- token health


def probing_health(store: TokenStore, handler: Any) -> TokenHealth:
    return TokenHealth(
        store,
        account_url=ACCOUNT_URL,
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


def creds(token: str = TOKEN_1) -> RequestCredentials:
    return RequestCredentials(api_token=token, api_url=API_URL)


class TestTokenHealthVerdicts:
    async def test_a_verdict_about_the_old_token_is_not_reused_for_the_new_one(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        info = put(store)
        answers = iter([200, 200])
        health = probing_health(store, lambda request: httpx.Response(next(answers), json={}))
        assert await health.confirm_dead_token(KEY_A, creds(), info.updated_at, 1) is None
        assert health.probe_count == 1
        # Inside the cooldown, the same generation reuses the verdict ...
        assert await health.confirm_dead_token(KEY_A, creds(), info.updated_at, 1) is None
        assert health.probe_count == 1
        # ... and a replacement within the same second (same updated_at) does not.
        put(store, TOKEN_2, user="2")
        assert await health.confirm_dead_token(KEY_A, creds(TOKEN_2), info.updated_at, 2) is None
        assert health.probe_count == 2

    async def test_a_probe_of_the_old_token_that_finishes_after_replacement_invalidates_nothing(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        old = put(store)

        def handler(request: httpx.Request) -> httpx.Response:
            # While Canvas is answering "invalid token" for the old token, the user
            # enrolls a new one (same second, same host).
            put(store, TOKEN_2, user="2")
            return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"}, json={})

        health = probing_health(store, handler)
        message = await health.confirm_dead_token(
            KEY_A, creds(), old.updated_at, old.credential_generation
        )
        assert message is None  # no verdict is claimed about the new token
        row = store.info(KEY_A)
        assert row is not None and row.status == STATUS_ACTIVE
        assert row.credential_generation == 2

    async def test_a_rejected_probe_marks_the_current_generation_and_raises_it(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        info = put(store)
        health = probing_health(store, lambda request: httpx.Response(401, json={}))
        message = await health.confirm_dead_token(
            KEY_A, creds(), info.updated_at, info.credential_generation
        )
        assert message is not None
        row = store.info(KEY_A)
        assert row is not None and row.status == STATUS_INVALID
        assert row.credential_generation == 2

    async def test_a_success_recorded_for_the_old_token_does_not_verify_the_new_one(
        self, tmp_path: pathlib.Path
    ) -> None:
        clock = [1_800_000_000]
        ring = Keyring.parse("k1:" + base64.b64encode(b"\x01" * 32).decode())
        store = backend_store(tmp_path / "c.sqlite3", ring, clock=lambda: clock[0])
        store.initialize()
        put(store)
        put(store, TOKEN_2, user="2")
        clock[0] += 1000
        health = probing_health(store, lambda request: httpx.Response(200, json={}))
        await health.note_success(KEY_A, 1)  # a call that used the first token
        row = store.info(KEY_A)
        assert row is not None and row.last_verified_at == 1_800_000_000
        health2 = probing_health(store, lambda request: httpx.Response(200, json={}))
        await health2.note_success(KEY_A, 2)
        row = store.info(KEY_A)
        assert row is not None and row.last_verified_at == 1_800_001_000


# ---------------------------------------------------------------- the request context


class RealStore:
    """The real store behind the narrow interface the middleware reads."""

    def __init__(self, inner: TokenStore) -> None:
        self.inner = inner

    def get(self, tenant_id: str, object_id: str) -> Any:
        return self.inner.get(tenant_id, object_id)

    def touch(self, tenant_id: str, object_id: str, *, min_interval_seconds: int = 300) -> None:
        self.inner.touch(tenant_id, object_id, min_interval_seconds=min_interval_seconds)


class GenerationProbe(Probe):
    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        state = get_request_token_state()
        self.seen_generation = get_request_credential_generation()
        self.seen_state_generation = state.credential_generation if state is not None else None
        self.seen_stale = request_credential_is_stale()
        self.seen_cache_key = current_principal_key()
        await super().__call__(scope, receive, send)


class TestMiddlewarePublishesTheGeneration:
    def build(self, store: TokenStore, probe: Probe) -> SelfhostRequestContextMiddleware:
        return SelfhostRequestContextMiddleware(
            probe,
            mcp_path="/mcp",
            policy=POLICY,
            store=RealStore(store),
            schools=SchoolPolicy.pinned(CANVAS_URL),
            account_url=ACCOUNT_URL,
        )

    async def test_each_request_carries_the_generation_its_token_was_read_under(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        put(store, host="canvas.example.test")
        probe = GenerationProbe()
        mw = self.build(store, probe)
        await _run(mw, user=_user(_claims()))
        assert probe.seen_generation == probe.seen_state_generation == 1
        assert probe.seen_cache_key.endswith("|g1") and probe.seen_stale is False
        first_key = probe.seen_cache_key

        put(store, TOKEN_2, user="2", host="canvas.example.test")
        await _run(mw, user=_user(_claims()))
        assert probe.seen_generation == 2
        assert probe.seen["creds"].api_token == TOKEN_2
        assert probe.seen_cache_key != first_key and probe.seen_cache_key.endswith("|g2")
        # Nothing of the request outlives it.
        assert get_request_credential_generation() is None

    async def test_a_new_generation_drops_what_the_old_one_cached(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        put(store, host="canvas.example.test")
        probe = GenerationProbe()
        mw = self.build(store, probe)
        await _run(mw, user=_user(_claims()))
        as_user(OID_A, 1)
        cache.current_cache_state().code_to_id["ICS 33"] = "101"
        assert any("g1" in k for k in cache._STATES)

        put(store, TOKEN_2, user="2", host="canvas.example.test")
        await _run(mw, user=_user(_claims()))
        assert not any(k.startswith(KEY_A) for k in cache._STATES)

    async def test_a_dead_row_still_carries_its_generation_into_the_health_state(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        put(store, host="canvas.example.test")
        store.mark_invalid(KEY_A, reason=REASON_CANVAS_TOKEN_REJECTED)
        probe = GenerationProbe()
        await _run(self.build(store, probe), user=_user(_claims()))
        assert probe.seen["creds"] is None
        assert probe.seen_state_generation == 2

    async def test_a_disabled_and_re_enabled_user_starts_a_new_generation(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path)
        put(store, host="canvas.example.test")
        probe = GenerationProbe()
        mw = self.build(store, probe)
        await _run(mw, user=_user(_claims()))
        before = probe.seen_generation
        store.disable_principal(KEY_A, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        store.enable_principal(KEY_A, actor=OPERATOR)
        await _run(mw, user=_user(_claims()))
        assert probe.seen_generation == (before or 0) + 2


# ------------------------------------------------------------------------- the gate


class SourceAt:
    """An access source that reports a fixed credential generation."""

    def __init__(self, generation: int) -> None:
        self.generation = generation

    def get_principal_status(self, principal_key: str) -> PrincipalStatus:
        return PrincipalStatus(principal_key, credential_generation=self.generation)


class Ran:
    count = 0


def gate_server(source: SourceAt, monkeypatch: pytest.MonkeyPatch) -> FastMCP:
    Ran.count = 0
    mcp = FastMCP("generation-gate-test")
    mcp.add_middleware(SelfhostCredentialGate(access=PrincipalAccessCache(source)))

    @mcp.tool()
    def get_my_profile() -> str:
        """Dummy tool."""
        Ran.count += 1
        return "ran"

    monkeypatch.setattr(
        tool_gate,
        "get_access_token",
        lambda: AccessToken(token="t", client_id="c", scopes=[], claims={"oid": OID_A}),
    )
    return mcp


class TestGate:
    async def test_a_call_from_a_request_whose_token_was_replaced_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mcp = gate_server(SourceAt(3), monkeypatch)
        as_user(OID_A, 2)  # this request read the token under generation 2
        set_request_token_state(RequestTokenState(credential_generation=2))
        async with Client(mcp) as client:
            result = await client.call_tool("get_my_profile", {}, raise_on_error=False)
        assert result.is_error and "Canvas connection changed" in result.content[0].text  # type: ignore[union-attr]
        assert Ran.count == 0

    async def test_equal_generations_run_and_an_older_cached_answer_is_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for store_generation in (2, 1):
            mcp = gate_server(SourceAt(store_generation), monkeypatch)
            as_user(OID_A, 2)
            async with Client(mcp) as client:
                result = await client.call_tool("get_my_profile", {}, raise_on_error=False)
            assert not result.is_error and Ran.count == 1

    async def test_a_request_without_a_generation_is_not_judged_by_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mcp = gate_server(SourceAt(9), monkeypatch)
        as_user(OID_A, None)
        async with Client(mcp) as client:
            result = await client.call_tool("get_my_profile", {}, raise_on_error=False)
        assert not result.is_error


@pytest.fixture(autouse=True)
def fresh_registry() -> Any:
    reset_credential_generations()
    yield
    reset_credential_generations()
