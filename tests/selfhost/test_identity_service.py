"""IdentityService over a real store: admission, first sight, roles, history (both backends).

The pure table is tested in ``test_accounts_rules.py``; here the store runs it inside its
write transaction, so these tests prove the application of a decision: what is created,
what is left alone, what is recorded, and what stays consistent when two things happen at
once.
"""

from __future__ import annotations

import asyncio
import base64
import pathlib
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from dbbackend import make_store, raw_sql

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.accounts import AccessPolicy, AccessRule, BootstrapOwner
from canvas_mcp.core.selfhost.custody import CustodyAcknowledgement
from canvas_mcp.core.selfhost.identity import SignIn
from canvas_mcp.core.selfhost.maintenance import MaintenanceRunner
from canvas_mcp.core.selfhost.token_store import (
    OPERATOR,
    Keyring,
    PrincipalPendingError,
    TokenStore,
)

from .conftest import CLIENT, OID_A, OID_B, TENANT, identity_service

OID_C = "cccccccc-0000-4000-8000-00000000000c"
OID_D = "dddddddd-0000-4000-8000-00000000000d"
OID_E = "eeeeeeee-0000-4000-8000-00000000000e"
USER = AccessRule("entra", "role", "Canvas.User")
OWNER = AccessRule("entra", "role", "Canvas.Owner")
GROUP = "99999999-0000-4000-8000-000000000001"

RULES = AccessPolicy(mode="rules", rules=(USER,), fallback="deny", owner_rules=(OWNER,))
RULES_THEN_APPROVAL = AccessPolicy(
    mode="rules", rules=(USER,), fallback="approval", owner_rules=(OWNER,)
)
APPROVAL = AccessPolicy(mode="approval", owner_rules=(OWNER,))
OPEN = AccessPolicy(mode="open", owner_rules=(OWNER,))


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


def claims(oid: str, *roles: str, **extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "tid": TENANT,
        "azp": CLIENT,
        "oid": oid,
        "roles": list(roles),
        "name": f"User {oid[:2]}",
        "preferred_username": f"{oid[:2]}@example.test",
        "iat": 1_800_000_000,
        "exp": 1_800_003_600,
    }
    base.update(extra)
    return base


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path: pathlib.Path, clock: Clock) -> TokenStore:
    ring = Keyring.parse("k1:" + __import__("base64").b64encode(b"\x01" * 32).decode())
    s = make_store(tmp_path / "t.sqlite3", ring, clock=clock)
    s.initialize()
    return s


def maintain(store: TokenStore, clock: Clock) -> dict[str, int]:
    return asyncio.run(
        MaintenanceRunner(store.database, cimd_stale_max=86400, now=clock).run()
    )


def events(store: TokenStore, key: str) -> list[str]:
    return [e.action for e in store.iter_audit(account_id=key)]


def auth_rows(store: TokenStore) -> list[tuple[Any, ...]]:
    return [
        tuple(r)
        for r in raw_sql(
            store,
            "SELECT account_id, provider_id, surface, outcome, reason, ua_hash"
            " FROM auth_events ORDER BY id",
        )
    ]


class TestSignInCreation:
    def test_first_sign_in_creates_the_account_and_records_only_the_account_surface(
        self, store
    ):
        result = identity_service(store, policy=RULES).sign_in(
            claims(OID_A, "Canvas.User")
        )
        assert isinstance(result, SignIn) and result.status.active and not result.owner
        assert result.status.admitted_via == "rules"
        assert (
            store.lookup_identity("entra", acc.entra_issuer(TENANT), OID_A)
            == result.principal_key
        )
        assert events(store, result.principal_key) == ["account_created"]
        assert [(row[2], row[3], row[4]) for row in auth_rows(store)] == [
            ("account", "success", "account_created")
        ]

    def test_owner_evidence_is_taken_from_the_verified_sign_in(self, store):
        result = identity_service(store, policy=RULES).sign_in(
            claims(OID_A, "Canvas.Owner")
        )
        assert isinstance(result, SignIn) and result.owner and result.status.is_owner
        assert result.status.role_source == "rules"

    def test_repeated_sign_ins_and_independent_services_use_one_account(self, store):
        results = [
            identity_service(store, policy=RULES).sign_in(claims(OID_A, "Canvas.User"))
            for _ in range(3)
        ]
        assert all(isinstance(result, SignIn) for result in results)
        assert len({result.principal_key for result in results}) == 1
        assert len(list(store.iter_accounts())) == 1
        assert len(auth_rows(store)) == 3

    def test_an_unmatched_identity_creates_no_account(self, store):
        result = identity_service(store, policy=RULES).sign_in(claims(OID_A))
        assert isinstance(result, acc.Denied) and result.code == acc.DENY_ACCESS_DENIED
        assert list(store.iter_accounts()) == []
        assert len(auth_rows(store)) == 1

    def test_concurrent_first_sign_ins_in_two_instances_create_exactly_one_account(
        self, tmp_path
    ):
        keyring = Keyring.parse("k1:" + base64.b64encode(bytes(32)).decode())
        for round_ in range(6):
            path = tmp_path / f"first-sign-in-{round_}.sqlite3"
            one, two = make_store(path, keyring), make_store(path, keyring)
            one.initialize()
            barrier = threading.Barrier(2)

            def sign_in(store, barrier=barrier):
                barrier.wait(timeout=3)
                return identity_service(store, policy=RULES).sign_in(
                    claims(OID_A, "Canvas.User")
                )

            try:
                with ThreadPoolExecutor(max_workers=2) as workers:
                    first = workers.submit(sign_in, one)
                    second = workers.submit(sign_in, two)
                    a, b = first.result(timeout=6), second.result(timeout=6)
                assert isinstance(a, SignIn) and isinstance(b, SignIn)
                assert a.principal_key == b.principal_key
                assert len(list(one.iter_accounts())) == 1
                assert len(one.list_identities(a.principal_key)) == 1
            finally:
                one.close()
                two.close()


class TestSignIn:
    def test_a_sign_in_records_the_login_and_the_names_and_the_history(
        self, store: TokenStore, clock: Clock
    ) -> None:
        service = identity_service(store, policy=RULES)
        out = service.sign_in(
            claims(OID_A, "Canvas.User", name="Ada"),
            ip="unknown",
            ua_hash="0123456789abcdef",
        )
        assert isinstance(out, SignIn) and not out.pending and not out.owner
        st = store.get_principal_status(out.principal_key)
        assert st.display_name == "Ada" and st.last_login_at == int(clock.now)
        (account,) = list(store.iter_accounts())
        assert account.username == f"{OID_A[:2]}@example.test"
        (row,) = auth_rows(store)
        assert row[2:] == (
            "account",
            "success",
            "account_created",
            bytes.fromhex("0123456789abcdef"),
        )
        clock.now += 60
        service.sign_in(claims(OID_A, "Canvas.User", name="Ada B"))
        st = store.get_principal_status(out.principal_key)
        assert st.display_name == "Ada B" and st.last_login_at == int(clock.now)
        assert [r[3:5] for r in auth_rows(store)] == [
            ("success", "account_created"),
            ("success", "ok"),
        ]

    def test_the_sign_in_history_lists_the_newest_first_and_never_more_than_asked(
        self, store: TokenStore, clock: Clock
    ) -> None:
        service = identity_service(store, policy=RULES)
        for _ in range(25):
            out = service.sign_in(claims(OID_A, "Canvas.User"))
            clock.now += 1
        assert isinstance(out, SignIn)
        events_ = store.auth_events_page(out.principal_key, limit=20).items
        assert len(events_) == 20
        assert [e.id for e in events_] == sorted((e.id for e in events_), reverse=True)
        assert all(e.provider_id == "entra" and e.surface == "account" for e in events_)

    def test_a_refused_sign_in_is_recorded_without_an_account(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES)
        denied = service.sign_in(claims(OID_A))
        assert isinstance(denied, acc.Denied)
        assert auth_rows(store) == [
            (None, "entra", "account", "denied", "access_denied", None)
        ]
        assert list(store.iter_accounts()) == []

    def test_a_refusal_before_the_rules_run_is_recorded_too(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES)
        service.sign_in(claims(OID_A, "Canvas.User", tid=OID_B))
        assert [r[3:5] for r in auth_rows(store)] == [("denied", "wrong_tenant")]

    def test_a_disabled_account_is_refused_and_nothing_about_it_changes(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES)
        key = service.sign_in(claims(OID_A, "Canvas.User")).principal_key  # type: ignore[union-attr]
        store.disable_principal(
            key, actor=OPERATOR, reason="operator_disabled", allow_last_owner=True
        )
        before = store.get_principal_status(key)
        out = service.sign_in(claims(OID_A, "Canvas.Owner"))
        assert isinstance(out, acc.Denied) and out.code == acc.DENY_ACCESS_DISABLED
        after = store.get_principal_status(key)
        assert (after.status, after.session_epoch, after.role, after.last_login_at) == (
            before.status,
            before.session_epoch,
            before.role,
            before.last_login_at,
        )
        assert auth_rows(store)[-1][3:5] == ("denied", "access_disabled")

    def test_only_a_digest_of_the_user_agent_is_ever_stored(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES)
        service.sign_in(claims(OID_A, "Canvas.User"), ua_hash="a1b2c3d4e5f60718")
        text = repr(raw_sql(store, "SELECT * FROM auth_events"))
        assert bytes(auth_rows(store)[0][-1]) == bytes.fromhex("a1b2c3d4e5f60718"[:16])
        assert "Mozilla" not in text


class TestRoles:
    def test_the_owner_role_is_taken_at_sign_in_and_lost_with_the_rule(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES)
        service.sign_in(
            claims(OID_B, "Canvas.Owner")
        )  # a second owner keeps the guard happy
        out = service.sign_in(claims(OID_A, "Canvas.User"))
        assert isinstance(out, SignIn)
        up = service.sign_in(claims(OID_A, "Canvas.Owner"))
        assert (
            up.owner and up.status.is_owner and up.status.owner_change == "owner_gained"
        )  # type: ignore[union-attr]
        down = service.sign_in(claims(OID_A, "Canvas.User"))
        assert not down.owner and not down.status.is_owner  # type: ignore[union-attr]
        assert down.status.owner_change == "owner_lost"  # type: ignore[union-attr]
        assert events(store, out.principal_key)[:2] == ["role_changed", "role_changed"]
        assert [
            event.detail["role"]
            for event in list(store.iter_audit(account_id=out.principal_key))[:2]
        ] == ["user", "owner"]

    def test_the_last_owner_keeps_the_stored_role_but_not_the_admin_session(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES)
        service.sign_in(claims(OID_A, "Canvas.Owner"))
        out = service.sign_in(claims(OID_A, "Canvas.User"))
        assert not out.owner  # type: ignore[union-attr]
        assert out.status.is_owner and store.count_active_owners() == 1  # type: ignore[union-attr]
        assert events(store, out.principal_key)[0] == "owner_loss_refused_last_owner"

    def test_two_owners_losing_the_rule_at_once_leave_one(
        self, tmp_path: pathlib.Path
    ) -> None:
        for round_ in range(6):
            ring = Keyring.parse(
                "k1:" + __import__("base64").b64encode(b"\x01" * 32).decode()
            )
            path = tmp_path / f"o{round_}.sqlite3"
            one = make_store(path, ring)
            one.initialize()
            two = make_store(path, ring)
            identity_service(one, policy=RULES).sign_in(claims(OID_A, "Canvas.Owner"))
            identity_service(one, policy=RULES).sign_in(claims(OID_B, "Canvas.Owner"))
            barrier = threading.Barrier(2)

            def lose(
                store: TokenStore, oid: str, barrier: threading.Barrier = barrier
            ) -> None:
                svc = identity_service(store, policy=RULES)
                barrier.wait()
                svc.sign_in(claims(oid, "Canvas.User"))

            threads = [
                threading.Thread(target=lose, args=(one, OID_A)),
                threading.Thread(target=lose, args=(two, OID_B)),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert one.count_active_owners() >= 1

    def test_a_role_granted_by_the_operator_or_the_bootstrap_is_not_taken_back_by_the_rules(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES)
        a = service.sign_in(claims(OID_A, "Canvas.User")).principal_key  # type: ignore[union-attr]
        service.sign_in(claims(OID_B, "Canvas.User"))
        assert store.promote_owner(a, actor=OPERATOR)
        out = service.sign_in(claims(OID_A, "Canvas.User"))
        assert (
            out.owner and out.status.is_owner and out.status.role_source == "operator"
        )  # type: ignore[union-attr]

    def test_the_bootstrap_owner_is_an_owner_only_while_there_is_none(
        self, store: TokenStore
    ) -> None:
        boot = BootstrapOwner("entra", acc.entra_issuer(TENANT), OID_A)
        policy = AccessPolicy(mode="approval", owner_rules=(), bootstrap_owner=boot)
        service = identity_service(store, policy=policy)
        out = service.sign_in(claims(OID_A))  # not even a member by any rule
        assert out.owner and out.status.role_source == "bootstrap"  # type: ignore[union-attr]
        assert out.status.admitted_via == "bootstrap" and out.status.active  # type: ignore[union-attr]
        # A second sign-in of the bootstrap identity changes nothing; another person is not promoted.
        again = service.sign_in(claims(OID_A))
        assert again.owner  # type: ignore[union-attr]
        other = service.sign_in(claims(OID_B))
        assert other.pending and not other.owner  # type: ignore[union-attr]

    def test_the_bootstrap_identity_is_ordinary_once_an_owner_exists(
        self, store: TokenStore
    ) -> None:
        store.create_operator_account(
            provider_id="entra",
            issuer=acc.entra_issuer(TENANT),
            subject=OID_C,
            status="active",
            role="owner",
        )
        boot = BootstrapOwner("entra", acc.entra_issuer(TENANT), OID_A)
        service = identity_service(
            store, policy=AccessPolicy(mode="approval", bootstrap_owner=boot)
        )
        out = service.sign_in(claims(OID_A))
        assert out.pending and not out.owner  # type: ignore[union-attr]


class TestApprovalAndPending:
    def test_the_approval_policy_makes_everyone_wait(self, store: TokenStore) -> None:
        service = identity_service(store, policy=APPROVAL)
        out = service.sign_in(claims(OID_A, "Canvas.User"))
        assert isinstance(out, SignIn) and out.pending and out.status.pending
        assert out.status.admitted_via == "rules"  # nobody has admitted the person yet
        assert auth_rows(store)[-1][3:5] == ("pending", "pending_approval")

    def test_a_pending_sign_in_remains_bound_to_the_same_account(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=APPROVAL)
        denied = service.sign_in(claims(OID_A, "Canvas.User"))
        assert isinstance(denied, SignIn) and denied.pending
        (account,) = list(store.iter_accounts())
        assert account.status.pending
        again = service.sign_in(claims(OID_A, "Canvas.User"))
        assert isinstance(again, SignIn) and again.pending
        assert len(list(store.iter_accounts())) == 1

    def test_a_pending_account_cannot_enroll_a_token(self, store: TokenStore) -> None:
        service = identity_service(store, policy=APPROVAL)
        key = service.sign_in(claims(OID_A)).principal_key  # type: ignore[union-attr]
        with pytest.raises(PrincipalPendingError):
            store.put(
                principal_key=key,
                api_token="x" * 30,
                canvas_user_id="1",
                canvas_user_name="n",
                canvas_host="canvas.example.edu",
                custody=CustodyAcknowledgement(1, store._now()),
            )
        with pytest.raises(PrincipalPendingError):
            store.set_tool_prefs(key, ["send_message"])
        assert store.count() == 0

    def test_an_owner_approves_and_the_account_can_then_enroll(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=APPROVAL)
        owner = store.create_operator_account(
            provider_id="entra",
            issuer=acc.entra_issuer(TENANT),
            subject=OID_C,
            status="active",
            role="owner",
        )
        key = service.sign_in(claims(OID_A)).principal_key  # type: ignore[union-attr]
        assert store.approve_account(key, actor=owner) is True
        st = store.get_principal_status(key)
        assert st.active and st.admitted_via == "approval" and st.approved_by == owner
        store.put(
            principal_key=key,
            api_token="x" * 30,
            canvas_user_id="1",
            canvas_user_name="n",
            canvas_host="canvas.example.edu",
            custody=CustodyAcknowledgement(1, store._now()),
        )
        assert [e.action for e in store.iter_audit() if e.target == key][:2] == [
            "token_enrolled",
            "account_approved",
        ]
        assert (
            store.approve_account(key, actor=owner) is False
        )  # nothing left to approve

    def test_a_denied_account_is_disabled_and_its_session_ends(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=APPROVAL)
        key = service.sign_in(claims(OID_A)).principal_key  # type: ignore[union-attr]
        epoch = store.get_principal_status(key).session_epoch
        generation = store.credential_generation(key)
        assert store.deny_account(key, actor=OPERATOR) is True
        st = store.get_principal_status(key)
        assert st.disabled and st.disabled_reason == "approval_denied"
        assert (
            st.session_epoch == epoch + 1
            and store.credential_generation(key) == generation + 1
        )
        assert isinstance(service.sign_in(claims(OID_A)), acc.Denied)
        assert (
            store.enable_principal(key, actor=OPERATOR) is True
        )  # and it can be undone

    def test_a_denied_applicant_is_not_admitted_by_being_enabled(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES_THEN_APPROVAL)
        key = service.sign_in(claims(OID_A)).principal_key  # type: ignore[union-attr]
        assert store.deny_account(key, actor=OPERATOR) is True
        assert store.enable_principal(key, actor=OPERATOR) is True
        assert store.get_principal_status(key).admitted_via == "rules"
        refused = service.sign_in(claims(OID_A))
        assert (
            isinstance(refused, acc.Denied) and refused.code == acc.DENY_ACCESS_DENIED
        )
        assert isinstance(service.sign_in(claims(OID_A)), acc.Denied)

    def test_a_pending_account_that_is_disabled_and_enabled_is_not_admitted(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES_THEN_APPROVAL)
        key = service.sign_in(claims(OID_A)).principal_key  # type: ignore[union-attr]
        assert (
            store.disable_principal(key, actor=OPERATOR, reason="operator_disabled")
            is True
        )
        assert store.enable_principal(key, actor=OPERATOR) is True
        refused = service.sign_in(claims(OID_A))
        assert (
            isinstance(refused, acc.Denied) and refused.code == acc.DENY_ACCESS_DENIED
        )

    def test_an_approved_person_stays_admitted_through_a_disable_and_enable(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES_THEN_APPROVAL)
        key = service.sign_in(claims(OID_A)).principal_key  # type: ignore[union-attr]
        assert store.approve_account(key, actor=OPERATOR) is True
        assert (
            store.disable_principal(key, actor=OPERATOR, reason="operator_disabled")
            is True
        )
        assert store.enable_principal(key, actor=OPERATOR) is True
        assert store.get_principal_status(key).admitted_via == "approval"
        assert not isinstance(
            service.sign_in(claims(OID_A)), acc.Denied
        )  # no rule needed

    def test_only_an_owner_or_the_operator_may_decide(self, store: TokenStore) -> None:
        from canvas_mcp.core.selfhost.token_store import AccessActionRefused

        service = identity_service(store, policy=APPROVAL)
        key = service.sign_in(claims(OID_A)).principal_key  # type: ignore[union-attr]
        other = service.sign_in(claims(OID_B)).principal_key  # type: ignore[union-attr]
        for call in (store.approve_account, store.deny_account):
            with pytest.raises(AccessActionRefused):
                call(key, actor=other)
        assert store.get_principal_status(key).pending

    def test_a_rule_that_later_matches_activates_a_pending_account(
        self, store: TokenStore
    ) -> None:
        waiting = identity_service(store, policy=APPROVAL)
        key = waiting.sign_in(claims(OID_A, "Canvas.User")).principal_key  # type: ignore[union-attr]
        stricter = identity_service(store, policy=RULES_THEN_APPROVAL)
        out = stricter.sign_in(claims(OID_A, "Canvas.User"))
        assert isinstance(out, SignIn) and not out.pending and out.status.active
        assert (
            out.status.admitted_via == "rules"
            and events(store, key)[0] == "account_activated"
        )

    def test_a_sign_in_activates_a_pending_account_a_rule_now_admits(
        self, store: TokenStore
    ) -> None:
        key = (
            identity_service(store, policy=APPROVAL)
            .sign_in(claims(OID_A, "Canvas.User"))
            .principal_key
        )  # type: ignore[union-attr]
        principal = identity_service(store, policy=RULES).sign_in(
            claims(OID_A, "Canvas.User")
        )
        assert principal.principal_key == key  # type: ignore[union-attr]
        assert store.get_principal_status(key).active

    def test_the_fallback_sends_the_unmatched_to_the_queue(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES_THEN_APPROVAL)
        member = service.sign_in(claims(OID_A, "Canvas.User"))
        stranger = service.sign_in(claims(OID_B))
        assert not member.pending and stranger.pending  # type: ignore[union-attr]

    def test_the_queue_has_a_cap_and_pauses_sign_ups(self, store: TokenStore) -> None:
        capped = AccessPolicy(mode="approval", pending_limit=2)
        service = identity_service(store, policy=capped)
        assert service.sign_in(claims(OID_A)).pending  # type: ignore[union-attr]
        assert service.sign_in(claims(OID_B)).pending  # type: ignore[union-attr]
        refused = service.sign_in(claims(OID_C))
        assert (
            isinstance(refused, acc.Denied) and refused.code == acc.DENY_SIGNUPS_PAUSED
        )
        assert len(list(store.iter_accounts())) == 2
        # An identity that already waits is not "new": signing in again is fine.
        assert service.sign_in(claims(OID_A)).pending  # type: ignore[union-attr]

    def test_open_admits_everybody_the_tenant_signs(self, store: TokenStore) -> None:
        out = identity_service(store, policy=OPEN).sign_in(claims(OID_A))
        assert (
            isinstance(out, SignIn)
            and out.status.active
            and out.status.admitted_via == "open"
        )

    def test_a_personal_admission_survives_a_stricter_policy_and_a_rules_admission_does_not(
        self, store: TokenStore
    ) -> None:
        owner = store.create_operator_account(
            provider_id="entra",
            issuer=acc.entra_issuer(TENANT),
            subject=OID_C,
            status="active",
            role="owner",
        )
        approved = (
            identity_service(store, policy=APPROVAL)
            .sign_in(claims(OID_A))
            .principal_key
        )  # type: ignore[union-attr]
        store.approve_account(approved, actor=owner)
        by_rule = (
            identity_service(store, policy=RULES)
            .sign_in(claims(OID_B, "Canvas.User"))
            .principal_key
        )  # type: ignore[union-attr]
        strict = identity_service(store, policy=RULES)
        assert not isinstance(
            strict.sign_in(claims(OID_A)), acc.Denied
        )  # approved by a person
        assert isinstance(strict.sign_in(claims(OID_B)), acc.Denied)  # the rule is gone
        assert store.get_principal_status(
            by_rule
        ).active  # refused per request, not disabled


class TestRetention:
    def test_sign_in_events_are_kept_for_ninety_days(
        self, store: TokenStore, clock: Clock
    ) -> None:
        service = identity_service(store, policy=RULES)
        service.sign_in(claims(OID_A, "Canvas.User"))
        clock.now += 89 * 86400
        service.sign_in(claims(OID_A, "Canvas.User"))
        assert maintain(store, clock)["auth_events"] == 0
        clock.now += 2 * 86400  # the first one is now 91 days old
        assert maintain(store, clock)["auth_events"] == 1
        assert len(auth_rows(store)) == 1

    def test_pending_accounts_are_removed_after_thirty_days_with_their_identity(
        self, store: TokenStore, clock: Clock
    ) -> None:
        service = identity_service(store, policy=APPROVAL)
        service.sign_in(claims(OID_A))
        clock.now += 29 * 86400
        assert maintain(store, clock)["pending"] == 0
        clock.now += 2 * 86400
        assert maintain(store, clock)["pending"] == 1
        assert list(store.iter_accounts()) == []
        assert raw_sql(store, "SELECT COUNT(*) FROM external_identities")[0][0] == 0
        assert [e.action for e in store.iter_audit()][0] == "pending_purged"

    def test_an_approved_account_is_never_purged(
        self, store: TokenStore, clock: Clock
    ) -> None:
        service = identity_service(store, policy=APPROVAL)
        key = service.sign_in(claims(OID_A)).principal_key  # type: ignore[union-attr]
        store.approve_account(key, actor=OPERATOR)
        clock.now += 365 * 86400
        assert (
            maintain(store, clock)["pending"] == 0
            and len(list(store.iter_accounts())) == 1
        )


class TestGroupsClaimIsOnlyReadForGroupRules:
    def test_non_guid_groups_lock_nobody_out_under_the_default_policy(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES)
        odd = {"groups": ["CONTOSO\\students", "S-1-5-21-1-2-3-4"]}
        assert not isinstance(
            service.sign_in(claims(OID_A, "Canvas.User", **odd)), acc.Denied
        )
        out = service.sign_in(claims(OID_B, "Canvas.User", groups="not-a-list"))
        assert isinstance(out, SignIn) and out.status.active

    def test_with_a_group_rule_a_malformed_claim_only_fails_to_match_the_group(
        self, store: TokenStore
    ) -> None:
        policy = AccessPolicy(
            mode="rules",
            rules=(USER, AccessRule("entra", "group", GROUP)),
            fallback="deny",
        )
        service = identity_service(store, policy=policy)
        # a role holder with on-premises group names is still admitted ...
        assert not isinstance(
            service.sign_in(claims(OID_A, "Canvas.User", groups=["CONTOSO\\students"])),
            acc.Denied,
        )
        # ... and a malformed claim never admits through the group rule.
        refused = service.sign_in(claims(OID_B, groups=["CONTOSO\\students"]))
        assert (
            isinstance(refused, acc.Denied) and refused.code == acc.DENY_ACCESS_DENIED
        )
        assert not isinstance(
            service.sign_in(claims(OID_C, groups=[GROUP])), acc.Denied
        )


class TestOperatorAccounts:
    def test_pre_provisioning_blocks_someone_before_their_first_sign_in(
        self, store: TokenStore
    ) -> None:
        key = store.create_operator_account(
            provider_id="entra",
            issuer=acc.entra_issuer(TENANT),
            subject=OID_A,
            status="disabled",
            reason="operator_disabled",
        )
        st = store.get_principal_status(key)
        assert st.disabled and st.session_epoch == 1 and st.admitted_via == "rules"
        service = identity_service(store, policy=RULES)
        denied = service.sign_in(claims(OID_A, "Canvas.User"))
        assert (
            isinstance(denied, acc.Denied) and denied.code == acc.DENY_ACCESS_DISABLED
        )
        assert (
            len(list(store.iter_accounts())) == 1
        )  # no second account for the same identity

    def test_an_account_blocked_in_advance_is_decided_by_the_rules_once_enabled(
        self, store: TokenStore
    ) -> None:
        key = store.create_operator_account(
            provider_id="entra",
            issuer=acc.entra_issuer(TENANT),
            subject=OID_A,
            status="disabled",
            reason="operator_disabled",
        )
        assert store.enable_principal(key, actor=OPERATOR) is True
        st = store.get_principal_status(key)
        assert st.active and st.admitted_via == "rules"
        service = identity_service(store, policy=RULES)
        for call in (service.sign_in,):
            refused = call(claims(OID_A))  # no role: no rule admits the person
            assert (
                isinstance(refused, acc.Denied)
                and refused.code == acc.DENY_ACCESS_DENIED
            )
        assert not isinstance(service.sign_in(claims(OID_A, "Canvas.User")), acc.Denied)
        assert store.get_principal_status(key).admitted_via == "rules"

    def test_an_active_operator_account_is_a_personal_admission(
        self, store: TokenStore
    ) -> None:
        key = store.create_operator_account(
            provider_id="entra",
            issuer=acc.entra_issuer(TENANT),
            subject=OID_A,
            status="active",
        )
        assert store.get_principal_status(key).admitted_via == "operator"
        service = identity_service(store, policy=RULES)
        assert not isinstance(service.sign_in(claims(OID_A)), acc.Denied)

    def test_creating_it_twice_returns_the_same_account(
        self, store: TokenStore
    ) -> None:
        kw: dict[str, Any] = {
            "provider_id": "entra",
            "issuer": acc.entra_issuer(TENANT),
            "subject": OID_A,
            "status": "active",
        }
        assert store.create_operator_account(**kw) == store.create_operator_account(
            **kw
        )

    def test_bad_arguments_are_refused(self, store: TokenStore) -> None:
        kw: dict[str, Any] = {"provider_id": "entra", "issuer": "i", "subject": "s"}
        with pytest.raises(ValueError):
            store.create_operator_account(status="weird", **kw)
        with pytest.raises(ValueError):
            store.create_operator_account(status="disabled", **kw)  # needs a reason
        with pytest.raises(ValueError):
            store.create_operator_account(status="active", role="admin", **kw)
        with pytest.raises(ValueError):
            store.create_operator_account(
                status="active", account_id="not-a-uuid", **kw
            )

    def test_promotion_is_for_the_operator_only_and_only_for_an_active_account(
        self, store: TokenStore
    ) -> None:
        from canvas_mcp.core.selfhost.token_store import AccessActionRefused

        key = store.create_operator_account(
            provider_id="entra", issuer="i", subject="s", status="active"
        )
        with pytest.raises(AccessActionRefused):
            store.promote_owner(key, actor=key)
        assert store.promote_owner(key) is True
        assert store.promote_owner(key) is False  # already an owner
        waiting = store.create_operator_account(
            provider_id="entra", issuer="i", subject="t", status="pending"
        )
        assert store.promote_owner(waiting) is False
