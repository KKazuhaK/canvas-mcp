"""Races around accounts: approval, sign-up and disablement, with two real connections.

Same method as ``test_store_races.py``: two ``TokenStore`` instances on one database,
interleavings driven by the pause hook and events (no sleep decides an outcome). Runs on
SQLite by default and on PostgreSQL with ``CANVAS_MCP_TEST_BACKEND=postgres``.
"""

from __future__ import annotations

import base64
import pathlib
import threading
from functools import partial
from typing import Any

import pytest
from dbbackend import make_store, raw_sql

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.accounts import AccessPolicy, AccessRule
from canvas_mcp.core.selfhost.token_store import (
    DISABLE_REASON_OPERATOR,
    OPERATOR,
    Keyring,
    PrincipalDisabledError,
    PrincipalPendingError,
    TokenStore,
)

from .conftest import TENANT, identity_service
from .test_store_races import WAIT, Clock, Gate, Runner

OID_A = "aaaaaaaa-0000-4000-8000-00000000000a"
OID_B = "bbbbbbbb-0000-4000-8000-00000000000b"
OID_C = "cccccccc-0000-4000-8000-00000000000c"
OID_OWNER = "00000000-0000-4000-8000-0000000000f1"
USER = AccessRule("entra", "role", "Canvas.User")
OWNER = AccessRule("entra", "role", "Canvas.Owner")
APPROVAL = AccessPolicy(mode="approval", owner_rules=(OWNER,))
RULES = AccessPolicy(mode="rules", rules=(USER,), fallback="deny", owner_rules=(OWNER,))
TOKEN = "7~" + "T" * 62


def _ring() -> Keyring:
    return Keyring.parse("k1:" + base64.b64encode(b"\x01" * 32).decode())


def claims(oid: str, *roles: str) -> dict[str, Any]:
    return {
        "tid": TENANT, "azp": "11111111-aaaa-4bbb-8ccc-222222222222", "oid": oid,
        "roles": list(roles), "name": "N", "preferred_username": f"{oid[:2]}@example.test",
        "iat": 1_800_000_000, "exp": 1_800_003_600,
    }


@pytest.fixture
def pair(tmp_path: pathlib.Path) -> tuple[TokenStore, TokenStore, Clock]:
    clock = Clock()
    path = tmp_path / "data" / "tokens.sqlite3"
    first = make_store(path, _ring(), clock=clock)
    first.initialize()
    second = make_store(path, _ring(), clock=clock)
    return first, second, clock


def _owner(store: TokenStore) -> str:
    return store.create_operator_account(
        provider_id="entra", issuer=acc.entra_issuer(TENANT), subject=OID_OWNER,
        status="active", role="owner",
    )


def _pending(store: TokenStore, oid: str = OID_A) -> str:
    return store.create_operator_account(
        provider_id="entra", issuer=acc.entra_issuer(TENANT), subject=oid, status="pending"
    )


def _put(store: TokenStore, key: str) -> Any:
    return store.put(principal_key=key, api_token=TOKEN, canvas_user_id="1", canvas_user_name="Ada")


class TestApprovalVersusEnrollment:
    def test_an_enrollment_that_waits_for_an_approval_succeeds(self, pair) -> None:
        approver, enroller, _ = pair
        owner = _owner(approver)
        key = _pending(approver)
        gate = Gate("after_account_read")
        approver._pause_hook = gate
        approve = Runner(lambda: approver.approve_account(key, actor=owner))
        assert gate.reached.wait(WAIT)
        put = Runner(lambda: _put(enroller, key))
        assert put.still_blocked()  # the approval holds the writer lock
        gate.release.set()
        assert approve.join() is True
        assert put.join().credential_generation == 1
        assert enroller.get_principal_status(key).active

    def test_an_enrollment_that_read_pending_is_refused_and_the_approval_follows(self, pair) -> None:
        approver, enroller, _ = pair
        owner = _owner(approver)
        key = _pending(approver)
        gate = Gate("after_gate_read")
        enroller._pause_hook = gate
        put = Runner(lambda: _put(enroller, key))
        assert gate.reached.wait(WAIT)
        approve = Runner(lambda: approver.approve_account(key, actor=owner))
        assert approve.still_blocked()
        gate.release.set()
        with pytest.raises(PrincipalPendingError):
            put.join()
        assert approve.join() is True
        assert enroller.count() == 0  # nothing was stored while it waited

    def test_approve_and_deny_at_once_exactly_one_wins(self, pair) -> None:
        one, two, _ = pair
        owner = _owner(one)
        key = _pending(one)
        gate = Gate("after_account_read")
        one._pause_hook = gate
        approve = Runner(lambda: one.approve_account(key, actor=owner))
        assert gate.reached.wait(WAIT)
        deny = Runner(lambda: two.deny_account(key, actor=owner))
        assert deny.still_blocked()
        gate.release.set()
        assert approve.join() is True
        assert deny.join() is False  # it re-read the row after the approval and found nothing pending
        st = one.get_principal_status(key)
        assert st.active and st.session_epoch == 0
        actions = [e.action for e in one.list_status_events(key)]
        assert actions.count("approved") == 1 and "denied" not in actions

    def test_deny_first_then_approve_changes_nothing(self, pair) -> None:
        one, two, _ = pair
        owner = _owner(one)
        key = _pending(one)
        gate = Gate("after_account_read")
        one._pause_hook = gate
        deny = Runner(lambda: one.deny_account(key, actor=owner))
        assert gate.reached.wait(WAIT)
        approve = Runner(lambda: two.approve_account(key, actor=owner))
        assert approve.still_blocked()
        gate.release.set()
        assert deny.join() is True
        assert approve.join() is False
        st = one.get_principal_status(key)
        assert st.disabled and st.disabled_reason == "approval_denied"

    def test_a_put_that_waits_for_a_deny_is_refused(self, pair) -> None:
        denier, enroller, _ = pair
        owner = _owner(denier)
        key = denier.create_operator_account(  # an owner, so the disable reaches the last-owner count
            provider_id="entra", issuer=acc.entra_issuer(TENANT), subject=OID_B,
            status="active", role="owner",
        )
        gate = Gate("after_owner_count")
        denier._pause_hook = gate
        deny = Runner(lambda: denier.disable_principal(key, actor=owner, reason="admin_disabled"))
        assert gate.reached.wait(WAIT)
        put = Runner(lambda: _put(enroller, key))
        assert put.still_blocked()
        gate.release.set()
        assert deny.join() is True
        with pytest.raises(PrincipalDisabledError):
            put.join()
        assert enroller.info(key) is None

    def test_an_approval_by_an_owner_disabled_in_the_meantime_is_refused(self, pair) -> None:
        from canvas_mcp.core.selfhost.token_store import AccessActionRefused

        one, two, _ = pair
        boss = _owner(one)
        other = one.create_operator_account(
            provider_id="entra", issuer=acc.entra_issuer(TENANT), subject=OID_B,
            status="active", role="owner",
        )
        key = _pending(one)
        gate = Gate("after_owner_count")
        one._pause_hook = gate
        disable = Runner(lambda: one.disable_principal(other, actor=boss, reason="admin_disabled"))
        assert gate.reached.wait(WAIT)
        approve = Runner(lambda: two.approve_account(key, actor=other))
        assert approve.still_blocked()
        gate.release.set()
        assert disable.join() is True
        with pytest.raises(AccessActionRefused):
            approve.join()  # the owner check ran inside the transaction, after the disable
        assert one.get_principal_status(key).pending


class TestFirstSight:
    def test_two_concurrent_sign_ups_of_one_identity_make_one_account(self, tmp_path: pathlib.Path) -> None:
        for round_ in range(6):
            path = tmp_path / f"s{round_}.sqlite3"
            one = make_store(path, _ring())
            one.initialize()
            two = make_store(path, _ring())
            barrier = threading.Barrier(2)

            def go(store: TokenStore, barrier: threading.Barrier = barrier) -> Any:
                svc = identity_service(store, policy=APPROVAL)
                barrier.wait()
                return svc.sign_in(claims(OID_A))

            runners = [Runner(lambda s=s: go(s)) for s in (one, two)]
            results = [r.join() for r in runners]
            assert results[0].principal_key == results[1].principal_key
            assert len(one.list_accounts()) == 1
            assert raw_sql(one, "SELECT COUNT(*) FROM external_identities")[0][0] == 1

    def test_a_sign_up_decided_before_a_disable_does_not_resurrect_the_account(self, pair) -> None:
        creator, admin, _ = pair
        key = _pending(admin)  # the operator pre-provisioned it ...
        gate = Gate("after_decision")
        creator._pause_hook = gate
        svc = identity_service(creator, policy=RULES)
        sign_in = Runner(lambda: svc.sign_in(claims(OID_A, "Canvas.User")))
        assert gate.reached.wait(WAIT)
        disable = Runner(
            lambda: admin.disable_principal(key, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        )
        assert disable.still_blocked()
        gate.release.set()
        out = sign_in.join()
        assert out.status.active  # the rule activated the waiting account first ...
        assert disable.join() is True  # ... and the disable then landed on it
        assert admin.get_principal_status(key).disabled
        denied = svc.sign_in(claims(OID_A, "Canvas.User"))
        assert isinstance(denied, acc.Denied) and denied.code == acc.DENY_ACCESS_DISABLED

    def test_a_disable_before_the_sign_in_wins_and_is_kept(self, pair) -> None:
        admin, creator, _ = pair
        _owner(admin)  # a second owner, so the disable is allowed
        key = admin.create_operator_account(
            provider_id="entra", issuer=acc.entra_issuer(TENANT), subject=OID_A,
            status="active", role="owner",
        )
        gate = Gate("after_owner_count")
        admin._pause_hook = gate
        disable = Runner(
            lambda: admin.disable_principal(key, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        )
        assert gate.reached.wait(WAIT)
        svc = identity_service(creator, policy=RULES)
        sign_in = Runner(lambda: svc.sign_in(claims(OID_A, "Canvas.Owner")))
        assert sign_in.still_blocked()
        gate.release.set()
        assert disable.join() is True
        out = sign_in.join()
        assert isinstance(out, acc.Denied) and out.code == acc.DENY_ACCESS_DISABLED
        st = admin.get_principal_status(key)
        assert st.disabled and st.session_epoch == 1 and st.role_source == "operator"  # nothing changed

    def test_the_pending_cap_holds_under_concurrency(self, tmp_path: pathlib.Path) -> None:
        capped = AccessPolicy(mode="approval", pending_limit=1)
        for round_ in range(4):
            path = tmp_path / f"c{round_}.sqlite3"
            one = make_store(path, _ring())
            one.initialize()
            two = make_store(path, _ring())
            barrier = threading.Barrier(2)

            def go(store: TokenStore, oid: str, barrier: threading.Barrier = barrier) -> Any:
                svc = identity_service(store, policy=capped)
                barrier.wait()
                return svc.sign_in(claims(oid))

            runners = [Runner(partial(go, one, OID_A)), Runner(partial(go, two, OID_B))]
            results = [r.join() for r in runners]
            assert sum(isinstance(r, acc.Denied) for r in results) == 1
            assert len(one.list_accounts()) == 1


class TestRolesAtOnce:
    def test_two_idp_demotions_keep_an_owner(self, tmp_path: pathlib.Path) -> None:
        for round_ in range(6):
            path = tmp_path / f"d{round_}.sqlite3"
            clock = Clock()
            one = make_store(path, _ring(), clock=clock)
            one.initialize()
            two = make_store(path, _ring(), clock=clock)
            svc = identity_service(one, policy=RULES)
            key_a = svc.sign_in(claims(OID_A, "Canvas.Owner")).principal_key
            key_b = svc.sign_in(claims(OID_B, "Canvas.Owner")).principal_key
            barrier = threading.Barrier(2)

            def demote(
                store: TokenStore,
                key: str,
                evidence: int = int(clock.now) + 500,
                barrier: threading.Barrier = barrier,
            ) -> Any:
                barrier.wait()
                return store.demote_owner(key, evidence_issued_at=evidence)

            results = [
                r.join()
                for r in (
                    Runner(partial(demote, one, key_a)),
                    Runner(partial(demote, two, key_b)),
                )
            ]
            assert sorted(results) == [False, True]
            assert one.count_active_owners() == 1

    def test_an_owner_sign_in_racing_the_last_owner_demotion_never_leaves_none(self, pair) -> None:
        one, two, clock = pair
        key_a = identity_service(one, policy=RULES).sign_in(claims(OID_A, "Canvas.Owner")).principal_key
        gate = Gate("after_owner_count")
        one._pause_hook = gate
        demote = Runner(lambda: one.demote_owner(key_a, evidence_issued_at=int(clock.now) + 500))
        assert gate.reached.wait(WAIT)
        svc = identity_service(two, policy=RULES)
        again = Runner(lambda: svc.sign_in(claims(OID_A, "Canvas.Owner")))
        assert again.still_blocked()
        gate.release.set()
        assert demote.join() is False  # sole owner: refused
        out = again.join()
        assert out.owner  # type: ignore[union-attr]
        assert one.count_active_owners() == 1
