"""IdentityService over a real store: admission, first sight, roles, history (both backends).

The pure table is tested in ``test_accounts_rules.py``; here the store runs it inside its
write transaction, so these tests prove the application of a decision: what is created,
what is left alone, what is recorded, and what stays consistent when two things happen at
once.
"""

from __future__ import annotations

import pathlib
import threading
from typing import Any

import pytest
from dbbackend import make_store, raw_sql

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.accounts import AccessPolicy, AccessRule, BootstrapOwner
from canvas_mcp.core.selfhost.identity import IdentityCache, SignIn
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
RULES_THEN_APPROVAL = AccessPolicy(mode="rules", rules=(USER,), fallback="approval", owner_rules=(OWNER,))
APPROVAL = AccessPolicy(mode="approval", owner_rules=(OWNER,))
OPEN = AccessPolicy(mode="open", owner_rules=(OWNER,))


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


def claims(oid: str, *roles: str, **extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "tid": TENANT, "azp": CLIENT, "oid": oid, "roles": list(roles),
        "name": f"User {oid[:2]}", "preferred_username": f"{oid[:2]}@example.test",
        "iat": 1_800_000_000, "exp": 1_800_003_600,
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


def events(store: TokenStore, key: str) -> list[str]:
    return [e.action for e in store.list_status_events(key)]


def auth_rows(store: TokenStore) -> list[tuple[Any, ...]]:
    return [
        tuple(r)
        for r in raw_sql(
            store,
            "SELECT account_id, provider_id, surface, outcome, reason, ip, ua_hash"
            " FROM auth_events ORDER BY id",
        )
    ]


class TestTheMcpPathCreatesAccountsOnFirstSight:
    def test_a_user_with_the_role_gets_an_active_account_and_the_request_goes_on(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES)
        principal = service.resolve_request(claims(OID_A, "Canvas.User"))
        assert not isinstance(principal, acc.Denied)
        key = principal.key  # type: ignore[union-attr]
        assert acc.valid_account_key(key)
        st = store.get_principal_status(key)
        assert st.active and st.role == "user" and st.admitted_via == "rules"
        assert store.lookup_identity("entra", acc.entra_issuer(TENANT), OID_A) == key
        assert principal.provider_id == "entra" and principal.subject == OID_A  # type: ignore[union-attr]
        assert principal.issuer == acc.entra_issuer(TENANT) and principal.object_id == OID_A  # type: ignore[union-attr]
        assert events(store, key) == ["account_created"]
        assert auth_rows(store) == [
            (key.removeprefix("acct:"), "entra", "mcp", "success", "account_created", "unknown", None)
        ]

    def test_the_owner_role_in_an_access_token_never_makes_an_owner_on_this_path(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES)
        principal = service.resolve_request(claims(OID_A, "Canvas.Owner"))
        key = principal.key  # type: ignore[union-attr]
        assert principal.is_owner  # the token says so, for this request only
        assert not store.get_principal_status(key).is_owner  # raising a role needs a sign-in
        assert store.count_active_owners() == 0

    def test_an_existing_account_is_only_read(self, store: TokenStore) -> None:
        service = identity_service(store, policy=RULES)
        service.resolve_request(claims(OID_A, "Canvas.User"))
        before = {
            "events": raw_sql(store, "SELECT COUNT(*) FROM auth_events")[0][0],
            "audit": len(store.list_audit()),
            "status": store.list_principal_statuses(),
        }
        for _ in range(5):
            assert not isinstance(service.resolve_request(claims(OID_A, "Canvas.User")), acc.Denied)
        assert raw_sql(store, "SELECT COUNT(*) FROM auth_events")[0][0] == before["events"]
        assert len(store.list_audit()) == before["audit"]
        assert store.list_principal_statuses() == before["status"]

    def test_each_identity_gets_exactly_one_account(self, store: TokenStore) -> None:
        service = identity_service(store, policy=RULES)
        keys = {service.resolve_request(claims(OID_A, "Canvas.User")).key for _ in range(3)}  # type: ignore[union-attr]
        keys |= {service.sign_in(claims(OID_A, "Canvas.User")).principal_key}  # type: ignore[union-attr]
        assert len(keys) == 1 and len(store.list_accounts()) == 1

    def test_the_same_person_through_a_cold_cache_and_a_second_service_is_the_same_account(
        self, store: TokenStore
    ) -> None:
        first = identity_service(store, policy=RULES).resolve_request(claims(OID_A, "Canvas.User"))
        second = identity_service(store, policy=RULES).resolve_request(claims(OID_A, "Canvas.User"))
        assert first.key == second.key  # type: ignore[union-attr]

    def test_two_concurrent_first_requests_make_one_account(self, tmp_path: pathlib.Path) -> None:
        for round_ in range(6):
            ring = Keyring.parse("k1:" + __import__("base64").b64encode(b"\x01" * 32).decode())
            path = tmp_path / f"r{round_}.sqlite3"
            one = make_store(path, ring)
            one.initialize()
            two = make_store(path, ring)
            barrier = threading.Barrier(2)
            results: list[Any] = []

            def go(store: TokenStore, barrier: threading.Barrier = barrier, results: list[Any] = results) -> None:
                svc = identity_service(store, policy=RULES)
                barrier.wait()
                results.append(svc.resolve_request(claims(OID_A, "Canvas.User")))

            threads = [threading.Thread(target=go, args=(s,)) for s in (one, two)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert len(one.list_accounts()) == 1
            assert {r.key for r in results} == {one.list_accounts()[0].principal_key}

    def test_a_user_without_a_matching_rule_creates_nothing(self, store: TokenStore) -> None:
        service = identity_service(store, policy=RULES)
        denied = service.resolve_request(claims(OID_A))
        assert isinstance(denied, acc.Denied) and denied.code == acc.DENY_ACCESS_DENIED
        assert store.list_accounts() == []
        assert auth_rows(store) == []  # a refused request leaves no row: it would be a free write
        assert raw_sql(store, "SELECT COUNT(*) FROM accounts")[0][0] == 0

    def test_a_group_overage_never_matches_and_never_calls_anyone(self, store: TokenStore) -> None:
        policy = AccessPolicy(
            mode="rules", rules=(AccessRule("entra", "group", GROUP),), fallback="deny", owner_rules=()
        )
        overage = claims(OID_A, **{"_claim_names": {"groups": "src1"}, "hasgroups": True})
        denied = identity_service(store, policy=policy).resolve_request(overage)
        assert isinstance(denied, acc.Denied) and denied.code == acc.DENY_ACCESS_DENIED
        member = identity_service(store, policy=policy).resolve_request(claims(OID_A, groups=[GROUP]))
        assert not isinstance(member, acc.Denied)

    def test_a_token_for_another_tenant_or_client_is_refused_before_the_store_is_touched(
        self, store: TokenStore
    ) -> None:
        service = identity_service(store, policy=RULES)
        assert service.resolve_request(claims(OID_A, "Canvas.User", tid=OID_B)).code == acc.DENY_WRONG_TENANT  # type: ignore[union-attr]
        assert service.resolve_request(claims(OID_A, "Canvas.User", azp=OID_B)).code == acc.DENY_WRONG_CLIENT  # type: ignore[union-attr]
        assert store.list_accounts() == []

    def test_the_identity_cache_is_not_a_source_of_truth_for_the_status(self, store: TokenStore) -> None:
        service = identity_service(store, policy=RULES)
        key = service.resolve_request(claims(OID_A, "Canvas.User")).key  # type: ignore[union-attr]
        assert len(service.cache) == 1
        store.create_operator_account(
            provider_id="entra", issuer=acc.entra_issuer(TENANT), subject=OID_B,
            status="active", role="owner",
        )
        # Disabled behind the cache's back: the next request still sees it (status is read, not cached here).
        owner = store.resolve_legacy_key(f"entra:{TENANT}:{OID_B}")
        assert owner is not None
        store.disable_principal(key, actor=owner, reason="admin_disabled")
        denied = service.resolve_request(claims(OID_A, "Canvas.User"))
        assert isinstance(denied, acc.Denied) and denied.code == acc.DENY_ACCESS_DISABLED


class TestSignIn:
    def test_a_sign_in_records_the_login_and_the_names_and_the_history(self, store: TokenStore, clock: Clock) -> None:
        service = identity_service(store, policy=RULES)
        out = service.sign_in(claims(OID_A, "Canvas.User", name="Ada"), ip="unknown", ua_hash="0123456789abcdef")
        assert isinstance(out, SignIn) and not out.pending and not out.owner
        st = store.get_principal_status(out.principal_key)
        assert st.display_name == "Ada" and st.last_login_at == int(clock.now)
        (account,) = store.list_accounts()
        assert account.username == f"{OID_A[:2]}@example.test"
        (row,) = auth_rows(store)
        assert row[2:] == ("account", "success", "account_created", "unknown", "0123456789abcdef")
        clock.now += 60
        service.sign_in(claims(OID_A, "Canvas.User", name="Ada B"))
        st = store.get_principal_status(out.principal_key)
        assert st.display_name == "Ada B" and st.last_login_at == int(clock.now)
        assert [r[3:5] for r in auth_rows(store)] == [("success", "account_created"), ("success", "ok")]

    def test_the_sign_in_history_lists_the_newest_first_and_never_more_than_asked(
        self, store: TokenStore, clock: Clock
    ) -> None:
        service = identity_service(store, policy=RULES)
        for _ in range(25):
            out = service.sign_in(claims(OID_A, "Canvas.User"))
            clock.now += 1
        assert isinstance(out, SignIn)
        events_ = store.list_auth_events(out.principal_key, 20)
        assert len(events_) == 20
        assert [e.id for e in events_] == sorted((e.id for e in events_), reverse=True)
        assert all(e.provider_id == "entra" and e.surface == "account" and e.ip == "unknown" for e in events_)

    def test_a_refused_sign_in_is_recorded_without_an_account(self, store: TokenStore) -> None:
        service = identity_service(store, policy=RULES)
        denied = service.sign_in(claims(OID_A))
        assert isinstance(denied, acc.Denied)
        assert auth_rows(store) == [(None, "entra", "account", "denied", "access_denied", "unknown", None)]
        assert store.list_accounts() == []

    def test_a_refusal_before_the_rules_run_is_recorded_too(self, store: TokenStore) -> None:
        service = identity_service(store, policy=RULES)
        service.sign_in(claims(OID_A, "Canvas.User", tid=OID_B))
        assert [r[3:5] for r in auth_rows(store)] == [("denied", "wrong_tenant")]

    def test_a_disabled_account_is_refused_and_nothing_about_it_changes(self, store: TokenStore) -> None:
        service = identity_service(store, policy=RULES)
        key = service.sign_in(claims(OID_A, "Canvas.User")).principal_key  # type: ignore[union-attr]
        store.disable_principal(key, actor=OPERATOR, reason="operator_disabled", allow_last_owner=True)
        before = store.get_principal_status(key)
        out = service.sign_in(claims(OID_A, "Canvas.Owner"))
        assert isinstance(out, acc.Denied) and out.code == acc.DENY_ACCESS_DISABLED
        after = store.get_principal_status(key)
        assert (after.status, after.session_epoch, after.role, after.last_login_at) == (
            before.status, before.session_epoch, before.role, before.last_login_at
        )
        assert auth_rows(store)[-1][3:5] == ("denied", "access_disabled")

    def test_only_a_digest_of_the_user_agent_is_ever_stored(self, store: TokenStore) -> None:
        service = identity_service(store, policy=RULES)
        service.sign_in(claims(OID_A, "Canvas.User"), ua_hash="a1b2c3d4e5f60718")
        text = repr(raw_sql(store, "SELECT * FROM auth_events"))
        assert "a1b2c3d4e5f60718" in text and "Mozilla" not in text


class TestRoles:
    def test_the_owner_role_is_taken_at_sign_in_and_lost_with_the_rule(self, store: TokenStore) -> None:
        service = identity_service(store, policy=RULES)
        service.sign_in(claims(OID_B, "Canvas.Owner"))  # a second owner keeps the guard happy
        out = service.sign_in(claims(OID_A, "Canvas.User"))
        assert isinstance(out, SignIn)
        up = service.sign_in(claims(OID_A, "Canvas.Owner"))
        assert up.owner and up.status.is_owner and up.status.owner_change == "owner_gained"  # type: ignore[union-attr]
        down = service.sign_in(claims(OID_A, "Canvas.User"))
        assert not down.owner and not down.status.is_owner  # type: ignore[union-attr]
        assert down.status.owner_change == "owner_lost"  # type: ignore[union-attr]
        assert events(store, out.principal_key)[:2] == ["owner_lost", "owner_gained"]

    def test_the_last_owner_keeps_the_stored_role_but_not_the_admin_session(self, store: TokenStore) -> None:
        service = identity_service(store, policy=RULES)
        service.sign_in(claims(OID_A, "Canvas.Owner"))
        out = service.sign_in(claims(OID_A, "Canvas.User"))
        assert not out.owner  # type: ignore[union-attr]
        assert out.status.is_owner and store.count_active_owners() == 1  # type: ignore[union-attr]
        assert events(store, out.principal_key)[0] == "owner_loss_refused_last_owner"

    def test_two_owners_losing_the_rule_at_once_leave_one(self, tmp_path: pathlib.Path) -> None:
        for round_ in range(6):
            ring = Keyring.parse("k1:" + __import__("base64").b64encode(b"\x01" * 32).decode())
            path = tmp_path / f"o{round_}.sqlite3"
            one = make_store(path, ring)
            one.initialize()
            two = make_store(path, ring)
            identity_service(one, policy=RULES).sign_in(claims(OID_A, "Canvas.Owner"))
            identity_service(one, policy=RULES).sign_in(claims(OID_B, "Canvas.Owner"))
            barrier = threading.Barrier(2)

            def lose(store: TokenStore, oid: str, barrier: threading.Barrier = barrier) -> None:
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
        assert out.owner and out.status.is_owner and out.status.role_source == "operator"  # type: ignore[union-attr]

    def test_the_bootstrap_owner_is_an_owner_only_while_there_is_none(self, store: TokenStore) -> None:
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

    def test_the_bootstrap_identity_is_ordinary_once_an_owner_exists(self, store: TokenStore) -> None:
        store.create_operator_account(
            provider_id="entra", issuer=acc.entra_issuer(TENANT), subject=OID_C, status="active", role="owner"
        )
        boot = BootstrapOwner("entra", acc.entra_issuer(TENANT), OID_A)
        service = identity_service(store, policy=AccessPolicy(mode="approval", bootstrap_owner=boot))
        out = service.sign_in(claims(OID_A))
        assert out.pending and not out.owner  # type: ignore[union-attr]

    def test_the_demotion_by_a_request_token_has_the_same_guards(self, store: TokenStore) -> None:
        service = identity_service(store, policy=RULES)
        a = service.sign_in(claims(OID_A, "Canvas.Owner")).principal_key  # type: ignore[union-attr]
        b = service.sign_in(claims(OID_B, "Canvas.Owner")).principal_key  # type: ignore[union-attr]
        assert store.demote_owner(a, evidence_issued_at=1_800_000_500) is True
        assert store.demote_owner(b, evidence_issued_at=1_800_000_500) is False  # the last owner stays
        assert store.get_principal_status(b).is_owner


class TestApprovalAndPending:
    def test_the_approval_policy_makes_everyone_wait(self, store: TokenStore) -> None:
        service = identity_service(store, policy=APPROVAL)
        out = service.sign_in(claims(OID_A, "Canvas.User"))
        assert isinstance(out, SignIn) and out.pending and out.status.pending
        assert out.status.admitted_via == "approval"
        assert auth_rows(store)[-1][3:5] == ("pending", "pending_approval")

    def test_a_pending_account_is_created_by_the_mcp_path_and_refused_there(self, store: TokenStore) -> None:
        service = identity_service(store, policy=APPROVAL)
        denied = service.resolve_request(claims(OID_A, "Canvas.User"))
        assert isinstance(denied, acc.Denied) and denied.code == acc.DENY_PENDING_APPROVAL
        (account,) = store.list_accounts()
        assert account.status.pending
        again = service.resolve_request(claims(OID_A, "Canvas.User"))
        assert isinstance(again, acc.Denied) and again.code == acc.DENY_PENDING_APPROVAL
        assert len(store.list_accounts()) == 1

    def test_a_pending_account_cannot_enroll_a_token(self, store: TokenStore) -> None:
        service = identity_service(store, policy=APPROVAL)
        key = service.sign_in(claims(OID_A)).principal_key  # type: ignore[union-attr]
        with pytest.raises(PrincipalPendingError):
            store.put(principal_key=key, api_token="x" * 30, canvas_user_id="1", canvas_user_name="n")
        with pytest.raises(PrincipalPendingError):
            store.set_tool_prefs(key, ["send_message"])
        assert store.count() == 0

    def test_an_owner_approves_and_the_account_can_then_enroll(self, store: TokenStore) -> None:
        service = identity_service(store, policy=APPROVAL)
        owner = store.create_operator_account(
            provider_id="entra", issuer=acc.entra_issuer(TENANT), subject=OID_C, status="active", role="owner"
        )
        key = service.sign_in(claims(OID_A)).principal_key  # type: ignore[union-attr]
        assert store.approve_account(key, actor=owner) is True
        st = store.get_principal_status(key)
        assert st.active and st.admitted_via == "approval" and st.approved_by == owner
        store.put(principal_key=key, api_token="x" * 30, canvas_user_id="1", canvas_user_name="n")
        assert [e.action for e in store.list_audit() if e.target == key][:2] == [
            "token_enrolled", "account_approved"
        ]
        assert store.approve_account(key, actor=owner) is False  # nothing left to approve

    def test_a_denied_account_is_disabled_and_its_session_ends(self, store: TokenStore) -> None:
        service = identity_service(store, policy=APPROVAL)
        key = service.sign_in(claims(OID_A)).principal_key  # type: ignore[union-attr]
        epoch = store.get_principal_status(key).session_epoch
        generation = store.credential_generation(key)
        assert store.deny_account(key, actor=OPERATOR) is True
        st = store.get_principal_status(key)
        assert st.disabled and st.disabled_reason == "approval_denied"
        assert st.session_epoch == epoch + 1 and store.credential_generation(key) == generation + 1
        assert isinstance(service.sign_in(claims(OID_A)), acc.Denied)
        assert store.enable_principal(key, actor=OPERATOR) is True  # and it can be undone

    def test_only_an_owner_or_the_operator_may_decide(self, store: TokenStore) -> None:
        from canvas_mcp.core.selfhost.token_store import AccessActionRefused

        service = identity_service(store, policy=APPROVAL)
        key = service.sign_in(claims(OID_A)).principal_key  # type: ignore[union-attr]
        other = service.sign_in(claims(OID_B)).principal_key  # type: ignore[union-attr]
        for call in (store.approve_account, store.deny_account):
            with pytest.raises(AccessActionRefused):
                call(key, actor=other)
        assert store.get_principal_status(key).pending

    def test_a_rule_that_later_matches_activates_a_pending_account(self, store: TokenStore) -> None:
        waiting = identity_service(store, policy=APPROVAL)
        key = waiting.sign_in(claims(OID_A, "Canvas.User")).principal_key  # type: ignore[union-attr]
        stricter = identity_service(store, policy=RULES_THEN_APPROVAL)
        out = stricter.sign_in(claims(OID_A, "Canvas.User"))
        assert isinstance(out, SignIn) and not out.pending and out.status.active
        assert out.status.admitted_via == "rules" and events(store, key)[0] == "activated"

    def test_the_mcp_path_activates_a_pending_account_a_rule_now_admits(self, store: TokenStore) -> None:
        key = identity_service(store, policy=APPROVAL).sign_in(claims(OID_A, "Canvas.User")).principal_key  # type: ignore[union-attr]
        principal = identity_service(store, policy=RULES).resolve_request(claims(OID_A, "Canvas.User"))
        assert principal.key == key  # type: ignore[union-attr]
        assert store.get_principal_status(key).active

    def test_the_fallback_sends_the_unmatched_to_the_queue(self, store: TokenStore) -> None:
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
        assert isinstance(refused, acc.Denied) and refused.code == acc.DENY_SIGNUPS_PAUSED
        assert len(store.list_accounts()) == 2
        # An identity that already waits is not "new": signing in again is fine.
        assert service.sign_in(claims(OID_A)).pending  # type: ignore[union-attr]

    def test_open_admits_everybody_the_tenant_signs(self, store: TokenStore) -> None:
        out = identity_service(store, policy=OPEN).sign_in(claims(OID_A))
        assert isinstance(out, SignIn) and out.status.active and out.status.admitted_via == "open"

    def test_a_personal_admission_survives_a_stricter_policy_and_a_rules_admission_does_not(
        self, store: TokenStore
    ) -> None:
        owner = store.create_operator_account(
            provider_id="entra", issuer=acc.entra_issuer(TENANT), subject=OID_C, status="active", role="owner"
        )
        approved = identity_service(store, policy=APPROVAL).sign_in(claims(OID_A)).principal_key  # type: ignore[union-attr]
        store.approve_account(approved, actor=owner)
        by_rule = identity_service(store, policy=RULES).sign_in(claims(OID_B, "Canvas.User")).principal_key  # type: ignore[union-attr]
        strict = identity_service(store, policy=RULES)
        assert not isinstance(strict.resolve_request(claims(OID_A)), acc.Denied)  # approved by a person
        assert isinstance(strict.resolve_request(claims(OID_B)), acc.Denied)  # the rule is gone
        assert store.get_principal_status(by_rule).active  # refused per request, not disabled


class TestRetention:
    def test_sign_in_events_are_kept_for_ninety_days(self, store: TokenStore, clock: Clock) -> None:
        service = identity_service(store, policy=RULES)
        service.sign_in(claims(OID_A, "Canvas.User"))
        clock.now += 89 * 86400
        service.sign_in(claims(OID_A, "Canvas.User"))
        assert store.prune_auth_events() == 0
        clock.now += 2 * 86400  # the first one is now 91 days old
        assert store.prune_auth_events() == 1
        assert len(auth_rows(store)) == 1

    def test_pending_accounts_are_removed_after_thirty_days_with_their_identity(
        self, store: TokenStore, clock: Clock
    ) -> None:
        service = identity_service(store, policy=APPROVAL)
        service.sign_in(claims(OID_A))
        clock.now += 29 * 86400
        assert store.purge_stale_pending() == 0
        clock.now += 2 * 86400
        assert store.purge_stale_pending() == 1
        assert store.list_accounts() == []
        assert raw_sql(store, "SELECT COUNT(*) FROM external_identities")[0][0] == 0
        assert [e.action for e in store.list_audit()][0] == "pending_purged"

    def test_an_approved_account_is_never_purged(self, store: TokenStore, clock: Clock) -> None:
        service = identity_service(store, policy=APPROVAL)
        key = service.sign_in(claims(OID_A)).principal_key  # type: ignore[union-attr]
        store.approve_account(key, actor=OPERATOR)
        clock.now += 365 * 86400
        assert store.purge_stale_pending() == 0 and len(store.list_accounts()) == 1


class TestIdentityCache:
    def test_it_remembers_hits_for_the_ttl_and_never_misses(self) -> None:
        now = [0.0]
        cache = IdentityCache(ttl_seconds=10, max_entries=2, clock=lambda: now[0])
        ident = ("entra", "iss", "sub")
        assert cache.get(ident) is None  # a miss is not cached
        cache.put(ident, "acct:1")
        assert cache.get(ident) == "acct:1"
        now[0] = 11
        assert cache.get(ident) is None

    def test_it_is_bounded(self) -> None:
        cache = IdentityCache(max_entries=3)
        for i in range(10):
            cache.put(("entra", "iss", str(i)), f"acct:{i}")
        assert len(cache) == 3
        assert cache.get(("entra", "iss", "9")) == "acct:9" and cache.get(("entra", "iss", "0")) is None

    def test_clear(self) -> None:
        cache = IdentityCache()
        cache.put(("e", "i", "s"), "acct:1")
        cache.clear()
        assert len(cache) == 0


class TestOperatorAccounts:
    def test_pre_provisioning_blocks_someone_before_their_first_sign_in(self, store: TokenStore) -> None:
        key = store.create_operator_account(
            provider_id="entra", issuer=acc.entra_issuer(TENANT), subject=OID_A,
            status="disabled", reason="operator_disabled",
        )
        st = store.get_principal_status(key)
        assert st.disabled and st.session_epoch == 1 and st.admitted_via == "operator"
        service = identity_service(store, policy=RULES)
        denied = service.sign_in(claims(OID_A, "Canvas.User"))
        assert isinstance(denied, acc.Denied) and denied.code == acc.DENY_ACCESS_DISABLED
        assert len(store.list_accounts()) == 1  # no second account for the same identity

    def test_creating_it_twice_returns_the_same_account(self, store: TokenStore) -> None:
        kw: dict[str, Any] = {
            "provider_id": "entra", "issuer": acc.entra_issuer(TENANT), "subject": OID_A,
            "status": "active",
        }
        assert store.create_operator_account(**kw) == store.create_operator_account(**kw)

    def test_bad_arguments_are_refused(self, store: TokenStore) -> None:
        kw: dict[str, Any] = {"provider_id": "entra", "issuer": "i", "subject": "s"}
        with pytest.raises(ValueError):
            store.create_operator_account(status="weird", **kw)
        with pytest.raises(ValueError):
            store.create_operator_account(status="disabled", **kw)  # needs a reason
        with pytest.raises(ValueError):
            store.create_operator_account(status="active", role="admin", **kw)
        with pytest.raises(ValueError):
            store.create_operator_account(status="active", account_id="not-a-uuid", **kw)

    def test_promotion_is_for_the_operator_only_and_only_for_an_active_account(self, store: TokenStore) -> None:
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
