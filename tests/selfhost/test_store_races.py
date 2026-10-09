"""Race tests for the token store, with two real database connections.

Two ``TokenStore`` instances on the same database have separate engines and
separate Python locks, so what serialises them is the database itself, as it does
between the server and the ``token_admin`` CLI. The interleavings are driven by the
store's pause hook and ``threading.Event`` objects (no sleeps decide an outcome;
the only timed waits are short negative checks that a blocked writer has not
finished yet). Runs on SQLite by default and on PostgreSQL with
``CANVAS_MCP_TEST_BACKEND=postgres``.
"""

from __future__ import annotations

import base64
import pathlib
import threading
from collections.abc import Callable
from typing import Any

import pytest
from dbbackend import make_store
from sqlalchemy import text

from canvas_mcp.core.selfhost.db import migrate
from canvas_mcp.core.selfhost.token_store import (
    DISABLE_REASON_ADMIN,
    DISABLE_REASON_OPERATOR,
    OPERATOR,
    REASON_CANVAS_TOKEN_REJECTED,
    STATUS_ACTIVE,
    STATUS_INVALID,
    AccessActionRefused,
    Keyring,
    PrincipalDisabledError,
    TokenStore,
)

TID = "11111111-2222-3333-4444-555555555555"
OID_A = "aaaaaaaa-0000-4000-8000-00000000000a"
OID_B = "bbbbbbbb-0000-4000-8000-00000000000b"
OID_C = "cccccccc-0000-4000-8000-00000000000c"
KEY_A = f"entra:{TID}:{OID_A}"
KEY_B = f"entra:{TID}:{OID_B}"
KEY_C = f"entra:{TID}:{OID_C}"
WAIT = 20  # seconds: far above any honest wait, only there to end a hung test


def _ring(*ids: str) -> Keyring:
    return Keyring.parse(
        ",".join(f"{kid}:{base64.b64encode(bytes([i + 1]) * 32).decode()}" for i, kid in enumerate(ids))
    )


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


class Gate:
    """Holds a store's transaction open at a named point until released."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.reached = threading.Event()
        self.release = threading.Event()

    def __call__(self, point: str) -> None:
        if point == self.name:
            self.reached.set()
            assert self.release.wait(WAIT), "the gate was never released"


class Runner:
    """Runs a callable in a thread and keeps its result or exception."""

    def __init__(self, fn: Callable[[], Any]) -> None:
        self.result: Any = None
        self.error: BaseException | None = None
        self.done = threading.Event()

        def run() -> None:
            try:
                self.result = fn()
            except BaseException as exc:  # noqa: BLE001 - reported by join()
                self.error = exc
            finally:
                self.done.set()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def still_blocked(self, seconds: float = 0.4) -> bool:
        return not self.done.wait(seconds)

    def join(self) -> Any:
        assert self.done.wait(WAIT), "the thread never finished"
        self.thread.join(WAIT)
        if self.error is not None:
            raise self.error
        return self.result


def _put(store: TokenStore, key: str = KEY_A, token: str = "7~" + "T" * 62, **kw: Any) -> Any:
    return store.put(
        principal_key=key,
        api_token=token,
        canvas_user_id="42",
        canvas_user_name="Ada",
        entra_display_name="Ada",
        entra_upn="ada@example.test",
        canvas_host="canvas.example.edu",
        **kw,
    )


@pytest.fixture
def pair(tmp_path: pathlib.Path) -> tuple[TokenStore, TokenStore, Clock]:
    """Two stores on one database: separate engines, separate Python locks."""
    clock = Clock()
    path = tmp_path / "data" / "tokens.sqlite3"
    first = make_store(path, _ring("k1"), clock=clock)
    first.initialize()
    second = make_store(path, _ring("k1"), clock=clock)
    return first, second, clock


def _make_owners(store: TokenStore, *keys: str) -> None:
    for key in keys:
        store.record_sign_in(key, is_owner=True)


class TestEnrollmentVersusDisable:
    def test_a_disable_waits_for_an_enrollment_that_has_read_the_gate(self, pair) -> None:
        enroller, admin, _ = pair
        gate = Gate("after_gate_read")
        enroller._pause_hook = gate
        put = Runner(lambda: _put(enroller))
        assert gate.reached.wait(WAIT)
        disable = Runner(
            lambda: admin.disable_principal(KEY_A, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        )
        assert disable.still_blocked()  # the enrollment holds the writer lock
        gate.release.set()
        info = put.join()
        assert disable.join() is True
        # The enrollment landed first and the disable followed it.
        status = admin.get_principal_status(KEY_A)
        assert status.disabled
        assert info.credential_generation == 1 and status.credential_generation == 2
        assert admin.info(KEY_A) is not None  # the row is kept; the principal is cut off

    def test_an_enrollment_that_waits_for_a_disable_is_refused(self, pair) -> None:
        enroller, admin, _ = pair
        _make_owners(admin, KEY_A, KEY_B)
        gate = Gate("after_owner_count")
        admin._pause_hook = gate
        disable = Runner(lambda: admin.disable_principal(KEY_A, actor=KEY_B, reason=DISABLE_REASON_ADMIN))
        assert gate.reached.wait(WAIT)
        put = Runner(lambda: _put(enroller))
        assert put.still_blocked()
        gate.release.set()
        assert disable.join() is True
        with pytest.raises(PrincipalDisabledError):
            put.join()
        assert enroller.info(KEY_A) is None  # nothing was saved for a disabled principal

    def test_generations_of_concurrent_changes_are_strictly_ordered(self, pair) -> None:
        first, second, _ = pair
        seen: list[int] = []
        lock = threading.Lock()

        def worker(store: TokenStore, n: int) -> None:
            for i in range(n):
                info = _put(store, token="7~" + str(i) * 62)
                with lock:
                    seen.append(info.credential_generation)

        runners = [Runner(lambda s=s: worker(s, 6)) for s in (first, second, first, second)]
        for runner in runners:
            runner.join()
        assert sorted(seen) == list(range(1, 25))  # unique, gap-free
        assert first.credential_generation(KEY_A) == 24


class TestOwnersDisablingEachOther:
    def test_exactly_one_of_two_owners_gets_to_disable_the_other(self, pair) -> None:
        one, two, _ = pair
        _make_owners(one, KEY_A, KEY_B)
        gate = Gate("after_owner_count")
        one._pause_hook = gate
        a_disables_b = Runner(
            lambda: one.disable_principal(KEY_B, actor=KEY_A, reason=DISABLE_REASON_ADMIN)
        )
        assert gate.reached.wait(WAIT)
        b_disables_a = Runner(
            lambda: two.disable_principal(KEY_A, actor=KEY_B, reason=DISABLE_REASON_ADMIN)
        )
        assert b_disables_a.still_blocked()
        gate.release.set()
        assert a_disables_b.join() is True
        # B was disabled in the meantime, so B is no longer an owner who may act.
        with pytest.raises(AccessActionRefused) as refused:
            b_disables_a.join()
        assert refused.value.code == AccessActionRefused.NOT_OWNER
        assert one.count_active_owners() == 1
        assert not one.get_principal_status(KEY_A).disabled

    def test_the_last_owner_guard_holds_when_the_other_owner_is_taken_concurrently(
        self, pair
    ) -> None:
        one, two, _ = pair
        _make_owners(one, KEY_A, KEY_B)
        gate = Gate("after_owner_count")
        one._pause_hook = gate
        first = Runner(
            lambda: one.disable_principal(KEY_B, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        )
        assert gate.reached.wait(WAIT)
        second = Runner(
            lambda: two.disable_principal(KEY_A, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        )
        assert second.still_blocked()
        gate.release.set()
        assert first.join() is True
        # Only A is left: the guard sees the committed first disable, not a stale count.
        with pytest.raises(AccessActionRefused) as refused:
            second.join()
        assert refused.value.code == AccessActionRefused.LAST_OWNER
        assert one.count_active_owners() == 1


class TestLateVerdictsAgainstAReplacement:
    """The regression tests for READ COMMITTED: a verdict about an old token must
    never land on the replacement saved while the verdict waited for the writer."""

    def _replace_while(self, pair, verdict: Callable[[TokenStore], Any]) -> tuple[Any, Any, Any]:
        enroller, prober, clock = pair
        old = _put(enroller)
        gate = Gate("after_gate_read")
        enroller._pause_hook = gate
        clock.now += 10
        put = Runner(lambda: _put(enroller, token="7~" + "N" * 62))
        assert gate.reached.wait(WAIT)
        late = Runner(lambda: verdict(prober))
        assert late.still_blocked()
        gate.release.set()
        new = put.join()
        return old, new, late.join()

    def test_a_late_rejection_does_not_invalidate_the_replacement(self, pair) -> None:
        old, new, changed = self._replace_while(
            pair,
            lambda s: s.mark_invalid(
                KEY_A, reason=REASON_CANVAS_TOKEN_REJECTED, expected_generation=1
            ),
        )
        assert changed is False
        assert new.credential_generation == 2
        row = pair[1].info(KEY_A)
        assert row is not None and row.status == STATUS_ACTIVE and row.credential_generation == 2

    def test_a_late_rejection_guarded_by_updated_at_is_refused_too(self, pair) -> None:
        enroller, prober, clock = pair
        old = _put(enroller)
        gate = Gate("after_gate_read")
        enroller._pause_hook = gate
        clock.now += 10
        put = Runner(lambda: _put(enroller, token="7~" + "N" * 62))
        assert gate.reached.wait(WAIT)
        late = Runner(
            lambda: prober.mark_invalid(
                KEY_A, reason=REASON_CANVAS_TOKEN_REJECTED, expected_updated_at=old.updated_at
            )
        )
        assert late.still_blocked()
        gate.release.set()
        put.join()
        assert late.join() is False
        assert prober.info(KEY_A).status == STATUS_ACTIVE  # type: ignore[union-attr]

    def test_a_late_restore_does_not_touch_the_replacement(self, pair) -> None:
        enroller, prober, clock = pair
        _put(enroller)
        enroller.mark_invalid(KEY_A, reason=REASON_CANVAS_TOKEN_REJECTED)
        stale_generation = enroller.credential_generation(KEY_A)  # 2: invalid
        gate = Gate("after_gate_read")
        enroller._pause_hook = gate
        clock.now += 10
        put = Runner(lambda: _put(enroller, token="7~" + "N" * 62))  # active again, gen 3
        assert gate.reached.wait(WAIT)
        late = Runner(lambda: prober.restore_active(KEY_A, expected_generation=stale_generation))
        assert late.still_blocked()
        gate.release.set()
        put.join()
        assert late.join() is False
        assert prober.credential_generation(KEY_A) == 3  # no extra bump from a no-op restore

    def test_a_late_success_is_not_recorded_on_the_replacement(self, pair) -> None:
        enroller, prober, clock = pair
        _put(enroller)
        gate = Gate("after_gate_read")
        enroller._pause_hook = gate
        clock.now += 100
        put = Runner(lambda: _put(enroller, token="7~" + "N" * 62))
        assert gate.reached.wait(WAIT)
        clock.now += 5000
        late = Runner(
            lambda: prober.mark_verified(KEY_A, min_interval_seconds=1, expected_generation=1)
        )
        assert late.still_blocked()
        gate.release.set()
        new = put.join()
        late.join()
        row = prober.info(KEY_A)
        assert row is not None and row.last_verified_at == new.last_verified_at

    def test_a_verdict_about_the_current_token_still_applies(self, pair) -> None:
        enroller, prober, _ = pair
        info = _put(enroller)
        assert prober.mark_invalid(
            KEY_A, reason=REASON_CANVAS_TOKEN_REJECTED, expected_generation=info.credential_generation
        )
        assert enroller.info(KEY_A).status == STATUS_INVALID  # type: ignore[union-attr]


class TestOtherWriters:
    def test_sign_in_and_disable_leave_one_consistent_history(self, tmp_path: pathlib.Path) -> None:
        for round_ in range(8):
            path = tmp_path / f"r{round_}.sqlite3"
            one = make_store(path, _ring("k1"))
            one.initialize()
            two = make_store(path, _ring("k1"))
            barrier = threading.Barrier(2)

            def sign_in(store: TokenStore = one, barrier: threading.Barrier = barrier) -> None:
                barrier.wait()
                store.record_sign_in(KEY_A, is_owner=True)

            def disable(store: TokenStore = two, barrier: threading.Barrier = barrier) -> None:
                barrier.wait()
                store.disable_principal(
                    KEY_A, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR, allow_last_owner=True
                )

            runners = [Runner(sign_in), Runner(disable)]
            for runner in runners:
                runner.join()
            status = one.get_principal_status(KEY_A)
            assert status.disabled and status.session_epoch == 1
            actions = [e.action for e in one.list_status_events(KEY_A)]
            assert actions.count("disabled") == 1
            assert actions.count("owner_gained") <= 1

    def test_rotate_and_enrollments_leave_every_row_readable_under_the_new_key(
        self, tmp_path: pathlib.Path
    ) -> None:
        old_ring = _ring("k1")
        path = tmp_path / "rot.sqlite3"
        old = make_store(path, old_ring)
        old.initialize()
        keys = [f"entra:{TID}:{n:08d}-0000-4000-8000-000000000000" for n in range(6)]
        for key in keys:
            _put(old, key)
        new_ring = Keyring.parse(
            f"k2:{base64.b64encode(bytes([9]) * 32).decode()},k1:{base64.b64encode(bytes([1]) * 32).decode()}"
        )
        rotator = make_store(path, new_ring)
        writer = make_store(path, new_ring)
        writer_keys = [f"entra:{TID}:{n:08d}-0000-4000-8000-0000000000ff" for n in range(6)]
        runners = [
            Runner(rotator.rotate),
            Runner(lambda: [_put(writer, k) for k in writer_keys]),
        ]
        for runner in runners:
            runner.join()
        rotator.rotate()  # rows saved under the old key after the first pass, if any
        assert rotator.database is not None
        for key in [*keys, *writer_keys]:
            row = rotator.get(key)
            assert row is not None and row.key_id == "k2"

    def test_concurrent_tool_preference_writers_never_leave_a_torn_record(self, pair) -> None:
        first, second, _ = pair
        sets = [["tool_a"], ["tool_b", "tool_c"], ["tool_d"], ["tool_e", "tool_f", "tool_g"]]
        barrier = threading.Barrier(len(sets))

        def writer(store: TokenStore, names: list[str]) -> None:
            barrier.wait()
            store.set_tool_prefs(KEY_A, names)

        runners = [
            Runner(lambda s=s, n=n: writer(s, n)) for s, n in zip((first, second) * 2, sets, strict=True)
        ]
        for runner in runners:
            runner.join()
        prefs = first.get_tool_prefs(KEY_A)
        assert prefs is not None
        assert sorted(prefs.enabled_write_tools) in [sorted(n) for n in sets]
        assert set(prefs.enabled_at) == set(prefs.enabled_write_tools)

    def test_two_starts_on_a_fresh_database_both_end_at_the_current_schema(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "fresh.sqlite3"
        one = make_store(path, _ring("k1"))
        two = make_store(path, _ring("k1"))
        barrier = threading.Barrier(2)

        def start(store: TokenStore) -> None:
            barrier.wait()
            store.initialize()

        runners = [Runner(lambda s=s: start(s)) for s in (one, two)]
        for runner in runners:
            runner.join()
        status = migrate.current(one.database)
        assert status.state == migrate.STATE_CURRENT
        assert status.alembic_revision == migrate.head_revision()


@pytest.mark.postgres
class TestPostgresTransactionShape:
    """What makes the PostgreSQL race tests above meaningful."""

    @pytest.fixture(autouse=True)
    def _only_on_postgres(self, pair) -> None:
        if pair[0].database.kind != "postgresql":
            pytest.skip("PostgreSQL only (CANVAS_MCP_TEST_BACKEND=postgres)")

    def test_writes_run_at_read_committed_with_the_writer_lock_held_first(self, pair) -> None:
        db = pair[0].database
        with db.write() as conn:
            level = conn.execute(text("SHOW transaction_isolation")).scalar_one()
            held = conn.execute(
                text(
                    "SELECT count(*) FROM pg_locks"
                    " WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted"
                )
            ).scalar_one()
        assert level == "read committed"
        assert held == 1

    def test_timeouts_are_set_on_every_connection(self, pair) -> None:
        db = pair[0].database
        with db.read() as conn:
            values = {
                name: conn.execute(text(f"SHOW {name}")).scalar_one()
                for name in ("statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout")
            }
            app = conn.execute(text("SHOW application_name")).scalar_one()
        assert values["statement_timeout"] == "15s"
        assert values["lock_timeout"] == "5s"
        assert values["idle_in_transaction_session_timeout"] == "30s"
        assert app == "canvas-mcp"
