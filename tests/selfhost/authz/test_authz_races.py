"""Atomicity of every consume, with two (or more) real database connections in threads.

Each "side" owns its own ``Database`` (its own engine, its own Python lock), so what
serialises them is the database itself, as it does between two server workers, or the
server and the ``token_admin`` CLI. Interleavings are driven by the store's pause hook and
``threading.Event`` objects; the only timed waits are short negative checks that a blocked
writer has not finished yet. Runs on SQLite by default and on PostgreSQL with
``CANVAS_MCP_TEST_BACKEND=postgres`` (where the second writer blocks on a row lock and
then re-evaluates its WHERE clause against the committed row).
"""

from __future__ import annotations

import pathlib
import threading
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest
from dbbackend import IS_POSTGRES, make_store, raw_sql
from sqlalchemy import text

from canvas_mcp.core.selfhost.authz import tokens as tk
from canvas_mcp.core.selfhost.authz.models import ExchangeOutcome as X
from canvas_mcp.core.selfhost.authz.models import RotateOutcome as R
from canvas_mcp.core.selfhost.authz.store import AuthzStore
from canvas_mcp.core.selfhost.authz.transactions import SqlLoginStateStore
from canvas_mcp.core.selfhost.settings import AuthzSettings
from canvas_mcp.core.selfhost.token_store import OPERATOR, Keyring, TokenStore

from ..conftest import OID_A, make_account
from .conftest import KEYS_RAW, Clock
from .helpers import CHALLENGE, CLIENT, REDIRECT, RESOURCE, SCOPE

WAIT = 20


class Gate:
    """Holds a transaction open at a named point until released."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.reached = threading.Event()
        self.release = threading.Event()

    def __call__(self, point: str) -> None:
        if point == self.name:
            self.reached.set()
            assert self.release.wait(WAIT), "the gate was never released"


class Runner:
    def __init__(self, fn: Callable[[], Any]) -> None:
        self.result: Any = None
        self.error: BaseException | None = None
        self.done = threading.Event()

        def run() -> None:
            try:
                self.result = fn()
            except BaseException as exc:  # noqa: BLE001 - re-raised by join()
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


@dataclass
class Side:
    """One server process: its own database connections, token store and authz store."""

    tokens: TokenStore
    authz: AuthzStore
    txns: SqlLoginStateStore


@dataclass
class World:
    sides: list[Side]
    clock: Clock
    account_key: str

    @property
    def a(self) -> Side:
        return self.sides[0]

    @property
    def b(self) -> Side:
        return self.sides[1]

    def new_side(self, tmp_path: pathlib.Path, keyring: Keyring, settings: AuthzSettings) -> Side:
        tokens = make_store(tmp_path / "races.sqlite3", keyring, clock=self.clock)
        side = Side(
            tokens,
            AuthzStore(tokens.database, clock=self.clock, settings=settings),
            SqlLoginStateStore(tokens.database, clock=self.clock),
        )
        self.sides.append(side)
        return side

    def code(self, side: Side | None = None, *, account_id: str | None = None) -> str:
        side = side or self.a
        raw = tk.new_auth_code()
        assert side.authz.create_code(
            code_hash=tk.hash_secret(raw), client_id=CLIENT, client_kind="dcr", client_name="App",
            client_host=None, account_id=account_id or self.account_key.removeprefix("acct:"),
            redirect_uri=REDIRECT, redirect_uri_explicit=True, redirect_host="claude.ai",
            code_challenge=CHALLENGE, scopes=(SCOPE,), resource=RESOURCE,
            upstream_auth_at=int(self.clock()),
        )
        return raw

    @staticmethod
    def exchange(side: Side, raw: str):
        return side.authz.exchange_code(
            code_hash=tk.hash_secret(raw), client_id=CLIENT, grant_id=str(uuid.uuid4()),
            refresh_hash=tk.hash_secret(tk.new_refresh_token()),
        )

    def grant(self) -> tuple[str, str]:
        """A live grant and its first raw refresh token."""
        raw_refresh = tk.new_refresh_token()
        result = self.a.authz.exchange_code(
            code_hash=tk.hash_secret(self.code()), client_id=CLIENT, grant_id=str(uuid.uuid4()),
            refresh_hash=tk.hash_secret(raw_refresh),
        )
        assert result.outcome is X.WON and result.grant is not None
        return result.grant.id, raw_refresh

    @staticmethod
    def rotate(side: Side, raw: str):
        new = tk.new_refresh_token()
        return side.authz.rotate_refresh(token_hash=tk.hash_secret(raw), new_hash=tk.hash_secret(new)), new


@pytest.fixture
def world(tmp_path: pathlib.Path) -> World:
    clock = Clock()
    keyring = Keyring.parse(KEYS_RAW)
    first = make_store(tmp_path / "races.sqlite3", keyring, clock=clock)
    first.initialize()
    world = World([], clock, make_account(first, OID_A))
    world.sides.append(
        Side(first, AuthzStore(first.database, clock=clock), SqlLoginStateStore(first.database, clock=clock))
    )
    world.new_side(tmp_path, keyring, AuthzSettings())
    return world


def grant_row(world: World, grant_id: str) -> tuple:
    return raw_sql(
        world.a.tokens, "SELECT revoked_at, revoked_reason FROM oauth_grants WHERE id = :g", {"g": grant_id}
    )[0]


class TestLoginStates:
    def test_two_pops_of_one_state_hand_the_payload_to_one_caller(self, world: World) -> None:
        for _ in range(5):
            sid = world.a.txns.put_sync("mcp_txn", b"payload", 60, binding_hash="h")
            gate = Gate("after_txn_select")
            world.a.txns.pause_hook = gate
            first = Runner(lambda s=sid: world.a.txns.pop_sync("mcp_txn", s, binding_hash="h"))
            assert gate.reached.wait(WAIT)
            second = Runner(lambda s=sid: world.b.txns.pop_sync("mcp_txn", s, binding_hash="h"))
            if not IS_POSTGRES:
                assert second.still_blocked()  # SQLite: the write lock is held by the first
            gate.release.set()
            results = [first.join(), second.join()]
            assert sorted(r is None for r in results) == [False, True]
            world.a.txns.pause_hook = None

    def test_the_wrong_binding_or_an_expired_state_gives_nothing(self, world: World) -> None:
        sid = world.a.txns.put_sync("mcp_txn", b"payload", 60, binding_hash="h")
        assert world.b.txns.pop_sync("mcp_txn", sid, binding_hash="other") is None
        assert world.b.txns.pop_sync("mcp_txn", sid) is None
        world.clock.advance(61)
        assert world.b.txns.pop_sync("mcp_txn", sid, binding_hash="h") is None

    def test_many_free_threads_one_winner(self, world: World, tmp_path: pathlib.Path) -> None:
        keyring = Keyring.parse(KEYS_RAW)
        sides = [world.new_side(tmp_path, keyring, AuthzSettings()) for _ in range(4)]
        sid = world.a.txns.put_sync("mcp_txn", b"payload", 60, binding_hash="h")
        runners = [
            Runner(lambda s=side: s.txns.pop_sync("mcp_txn", sid, binding_hash="h"))
            for side in sides + sides
        ]
        results = [r.join() for r in runners]
        assert results.count(b"payload") == 1 and results.count(None) == len(results) - 1


class TestAuthorizationCode:
    def test_the_second_exchange_waits_and_then_gets_a_sibling_not_the_death_of_the_grant(
        self, world: World
    ) -> None:
        raw = world.code()
        gate = Gate("after_code_consume")
        world.a.authz.pause_hook = gate
        first = Runner(lambda: world.exchange(world.a, raw))
        assert gate.reached.wait(WAIT)
        second = Runner(lambda: world.exchange(world.b, raw))
        assert second.still_blocked()  # it cannot see the code as unused, nor as used, yet
        gate.release.set()
        winner, duplicate = first.join(), second.join()
        assert winner.outcome is X.WON
        assert duplicate.outcome is X.GRACE and duplicate.grant.id == winner.grant.id
        assert grant_row(world, winner.grant.id)[0] is None  # the winner's grant survives

    def test_many_threads_exactly_one_winner_and_the_grant_lives(self, world: World, tmp_path) -> None:
        keyring = Keyring.parse(KEYS_RAW)
        sides = [world.new_side(tmp_path, keyring, AuthzSettings()) for _ in range(5)]
        raw = world.code()
        runners = [Runner(lambda s=side: world.exchange(s, raw)) for side in sides + [world.a]]
        results = [r.join() for r in runners]
        outcomes = Counter(r.outcome for r in results)
        assert outcomes[X.WON] == 1
        assert outcomes[X.GRACE] <= 2
        assert outcomes[X.GRACE] + outcomes[X.CAPPED] == len(results) - 1
        assert X.REPLAY_REVOKED not in outcomes and X.DEAD not in outcomes
        (winner,) = [r for r in results if r.outcome is X.WON]
        assert grant_row(world, winner.grant.id)[0] is None
        assert raw_sql(world.a.tokens, "SELECT COUNT(*) FROM oauth_grants")[0][0] == 1

    def test_a_replay_after_the_window_revokes_even_with_a_concurrent_first_use(self, world: World) -> None:
        raw = world.code()
        result = world.exchange(world.a, raw)
        world.clock.advance(31)
        assert world.exchange(world.b, raw).outcome is X.REPLAY_REVOKED
        assert grant_row(world, result.grant.id)[1] == "code_replay"


class TestRefreshRotation:
    def test_the_second_rotation_waits_and_then_gets_a_sibling(self, world: World) -> None:
        grant_id, refresh = world.grant()
        gate = Gate("after_refresh_mark")
        world.a.authz.pause_hook = gate
        first = Runner(lambda: world.rotate(world.a, refresh))
        assert gate.reached.wait(WAIT)
        second = Runner(lambda: world.rotate(world.b, refresh))
        assert second.still_blocked()
        gate.release.set()
        (won, a), (duplicate, b) = first.join(), second.join()
        assert won.outcome is R.ROTATED and duplicate.outcome is R.GRACE
        assert grant_row(world, grant_id)[0] is None
        # Using one sibling retires the other; the retired one is a reuse and revokes.
        world.a.authz.pause_hook = None
        assert world.rotate(world.a, a)[0].outcome is R.ROTATED
        assert world.rotate(world.b, b)[0].outcome is R.REUSE_REVOKED
        assert grant_row(world, grant_id)[1] == "refresh_reuse"

    def test_parallel_duplicates_leave_the_grant_alive_and_the_extras_are_capped(
        self, world: World, tmp_path
    ) -> None:
        keyring = Keyring.parse(KEYS_RAW)
        sides = [world.new_side(tmp_path, keyring, AuthzSettings()) for _ in range(5)]
        grant_id, refresh = world.grant()
        runners = [Runner(lambda s=side: world.rotate(s, refresh)) for side in sides + [world.a]]
        results = [r.join()[0] for r in runners]
        outcomes = Counter(r.outcome for r in results)
        assert outcomes[R.ROTATED] == 1 and outcomes[R.GRACE] <= 2
        assert outcomes[R.GRACE] + outcomes[R.CAPPED] == len(results) - 1
        assert set(outcomes) <= {R.ROTATED, R.GRACE, R.CAPPED}
        assert grant_row(world, grant_id)[0] is None

    def test_three_parallel_duplicates_do_not_hurt_the_grant(self, world: World, tmp_path) -> None:
        keyring = Keyring.parse(KEYS_RAW)
        sides = [world.new_side(tmp_path, keyring, AuthzSettings()) for _ in range(2)]
        grant_id, refresh = world.grant()
        results = [Runner(lambda s=side: world.rotate(s, refresh)).join()[0] for side in [world.a] + sides]
        assert Counter(r.outcome for r in results) == Counter({R.ROTATED: 1, R.GRACE: 2})
        assert grant_row(world, grant_id)[0] is None

    def test_the_absolute_expiry_is_kept_across_concurrent_rotations(self, world: World) -> None:
        grant_id, refresh = world.grant()
        cap = raw_sql(world.a.tokens, "SELECT expires_at FROM oauth_grants WHERE id = :g", {"g": grant_id})[0][0]
        world.clock.advance(1000)
        result, successor = world.rotate(world.b, refresh)
        world.clock.advance(1000)
        _, third = world.rotate(world.a, successor)
        rows = raw_sql(world.a.tokens, "SELECT DISTINCT expires_at FROM oauth_refresh_tokens")
        assert rows == [(cap,)] and result.outcome is R.ROTATED and third


class TestRevocationRaces:
    @pytest.mark.parametrize("revoke_first", [False, True])
    def test_a_revocation_and_a_rotation_end_with_the_grant_revoked(
        self, world: World, revoke_first: bool
    ) -> None:
        grant_id, refresh = world.grant()
        if revoke_first:
            assert world.b.authz.revoke_own_grant(grant_id, world.account_key)
            result, _ = world.rotate(world.a, refresh)
            assert result.outcome is R.DEAD
        else:
            gate = Gate("after_grant_lock")
            world.a.authz.pause_hook = gate
            rotation = Runner(lambda: world.rotate(world.a, refresh))
            assert gate.reached.wait(WAIT)
            revocation = Runner(lambda: world.b.authz.revoke_own_grant(grant_id, world.account_key))
            assert revocation.still_blocked()  # the rotation holds the grant row
            gate.release.set()
            (result, successor), revoked = rotation.join(), revocation.join()
            assert result.outcome is R.ROTATED and revoked is True
            world.a.authz.pause_hook = None
            assert world.rotate(world.b, successor)[0].outcome is R.DEAD  # nothing live survives
        assert grant_row(world, grant_id)[0] is not None
        assert world.a.authz.revoke_own_grant(grant_id, world.account_key) is False

    @pytest.mark.parametrize("disable_first", [False, True])
    def test_disabling_the_account_and_a_rotation_end_with_the_grant_revoked(
        self, world: World, disable_first: bool
    ) -> None:
        grant_id, refresh = world.grant()
        if disable_first:
            assert world.b.tokens.disable_principal(world.account_key, actor=OPERATOR, reason="operator_disabled")
            assert world.rotate(world.a, refresh)[0].outcome is R.DEAD
        else:
            gate = Gate("after_grant_lock")
            world.a.authz.pause_hook = gate
            rotation = Runner(lambda: world.rotate(world.a, refresh))
            assert gate.reached.wait(WAIT)
            disabling = Runner(
                lambda: world.b.tokens.disable_principal(
                    world.account_key, actor=OPERATOR, reason="operator_disabled"
                )
            )
            assert disabling.still_blocked()
            gate.release.set()
            result, successor = rotation.join()
            assert disabling.join() is True  # no deadlock within the lock timeouts
            assert result.outcome in (R.ROTATED, R.INACTIVE)
            world.a.authz.pause_hook = None
            if result.outcome is R.ROTATED:
                assert world.rotate(world.b, successor)[0].outcome is R.DEAD
        assert grant_row(world, grant_id) == (grant_row(world, grant_id)[0], "account_disabled")
        assert grant_row(world, grant_id)[0] is not None

    def test_two_revocations_of_one_grant_change_it_once(self, world: World) -> None:
        grant_id, _ = world.grant()
        results = [
            Runner(lambda s=side: s.authz.revoke_client_grant(grant_id)).join()
            for side in (world.a, world.b)
        ]
        assert sorted(results) == [False, True]


class TestClientDocuments:
    def test_concurrent_upserts_keep_the_newest_document(self, world: World, tmp_path) -> None:
        keyring = Keyring.parse(KEYS_RAW)
        sides = [world.new_side(tmp_path, keyring, AuthzSettings()) for _ in range(4)]
        url = "https://client.example/cimd.json"
        runners = [
            Runner(lambda s=side, n=n: s.authz.upsert_cimd(url, f'{{"n": {n}}}', fetched_at=1000 + n, fresh_until=5000))
            for n, side in zip((3, 1, 4, 2, 0, 5), (sides + sides)[:6], strict=True)
        ]
        for runner in runners:
            runner.join()
        snapshot = world.a.authz.cimd_snapshot(url)
        assert snapshot is not None and snapshot.doc_json == '{"n": 5}' and snapshot.fetched_at == 1005


@pytest.mark.postgres
class TestWriterLockOnPostgres:
    def test_row_write_takes_no_advisory_lock_and_write_does(self, world: World) -> None:
        db = world.a.tokens.database
        query = text(
            "SELECT count(*) FROM pg_locks"
            " WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted"
        )
        with db.row_write() as conn:
            assert conn.execute(query).scalar_one() == 0
            assert conn.execute(text("SHOW transaction_isolation")).scalar_one() == "read committed"
        with db.write() as conn:
            assert conn.execute(query).scalar_one() == 1
        assert IS_POSTGRES or db.kind == "postgresql"
