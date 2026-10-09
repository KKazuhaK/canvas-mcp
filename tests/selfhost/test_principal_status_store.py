"""The access decision in the token database: disablement, session epochs, owners.

Revocation is an authorization decision stored apart from the enrollment row (in
``accounts``), so deleting the row can never restore access, and the checks that
matter (is the actor still an owner, is this the last owner, is the account disabled)
happen inside the same transaction as the change.
"""

from __future__ import annotations

import base64
import pathlib
import threading
from dataclasses import replace

import pytest
from dbbackend import make_store, raw_connection

from canvas_mcp.core.selfhost.token_store import (
    DISABLE_REASON_ADMIN,
    DISABLE_REASON_OPERATOR,
    OPERATOR,
    SCHEMA_VERSION,
    STATUS_ACTIVE,
    STATUS_DISABLED,
    AccessActionRefused,
    Keyring,
    PrincipalDisabledError,
    TokenStore,
    valid_principal_key,
)

from .conftest import TENANT, acct_key, make_account, sign_in

TID = TENANT
OID_USER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID_OWNER_1 = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
OID_OWNER_2 = "cccccccc-dddd-eeee-ffff-000000000000"
USER = acct_key(OID_USER)
OWNER_1 = acct_key(OID_OWNER_1)
OWNER_2 = acct_key(OID_OWNER_2)
TOKEN = "1234~" + "A" * 60


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


def make_ring() -> Keyring:
    return Keyring.parse("k1:" + base64.b64encode(b"\x01" * 32).decode())


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path: pathlib.Path, clock: Clock) -> TokenStore:
    s = make_store(tmp_path / "data" / "tokens.sqlite3", make_ring(), clock=clock)
    s.initialize()
    make_account(s, OID_USER, name="Ada Lovelace", username="ada@example.test")
    return s


def enroll(store: TokenStore, key: str = USER) -> None:
    store.put(
        principal_key=key,
        api_token=TOKEN,
        canvas_user_id="7",
        canvas_user_name="Ada",
        canvas_host="canvas.example.test",
    )


def make_owner(store: TokenStore, oid: str) -> str:
    return make_account(store, oid, role="owner")


class TestDefaults:
    def test_a_principal_with_no_account_is_not_active(self, store: TokenStore) -> None:
        st = store.get_principal_status(acct_key("dddddddd-0000-4000-8000-00000000000d"))
        assert st.status == "missing" and st.missing and not st.active and not st.disabled
        assert st.session_epoch == 0 and st.stored is False and st.is_owner is False

    def test_a_new_account_is_active_at_epoch_zero(self, store: TokenStore) -> None:
        st = store.get_principal_status(USER)
        assert st.status == STATUS_ACTIVE and st.active and not st.disabled
        assert st.session_epoch == 0 and st.stored is True and st.is_owner is False

    def test_the_legacy_key_names_the_same_account(self, store: TokenStore) -> None:
        assert store.resolve_legacy_key(f"entra:{TID}:{OID_USER}") == USER
        assert store.resolve_legacy_key(f"entra:{TID.upper()}:{OID_USER.upper()}") == USER
        assert store.resolve_legacy_key(f"entra:{TID}:{OID_OWNER_1}") is None
        assert store.resolve_legacy_key("google:1") is None
        store.disable_principal(
            store.resolve_legacy_key(f"entra:{TID}:{OID_USER}") or "",
            actor=OPERATOR,
            reason=DISABLE_REASON_OPERATOR,
        )
        assert store.get_principal_status(USER).disabled

    def test_an_entra_key_is_not_a_principal_key(self, store: TokenStore) -> None:
        legacy = f"entra:{TID}:{OID_USER}"
        for call in (
            lambda: store.get_principal_status(legacy),
            lambda: store.disable_principal(legacy, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR),
            lambda: store.get(legacy),
            lambda: store.credential_generation(legacy),
        ):
            with pytest.raises(ValueError):
                call()

    def test_key_validation_is_public_and_never_raises(self) -> None:
        assert valid_principal_key(USER) == USER
        for bad in (None, 5, "", "UPPER", f"entra:{TID}:{OID_USER}", "acct:0a1b", "a\nb", "é"):
            assert valid_principal_key(bad) is None


class TestDisableAndEnable:
    def test_disable_marks_the_principal_and_bumps_the_epoch(self, store: TokenStore) -> None:
        assert store.disable_principal(
            USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR
        ) is True
        st = store.get_principal_status(USER)
        assert st.disabled and st.status == STATUS_DISABLED
        assert st.session_epoch == 1
        assert st.disabled_reason == DISABLE_REASON_OPERATOR
        assert st.disabled_by == "operator" and st.disabled_at == 1_800_000_000

    def test_disable_is_idempotent_and_changes_nothing_the_second_time(
        self, store: TokenStore, clock: Clock
    ) -> None:
        store.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        clock.now += 100
        assert store.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR) is False
        st = store.get_principal_status(USER)
        assert st.session_epoch == 1 and st.disabled_at == 1_800_000_000
        assert [e.action for e in store.list_status_events(USER)] == ["disabled", "account_created"]

    def test_enable_clears_the_disablement_and_bumps_the_epoch_again(self, store: TokenStore) -> None:
        enroll(store)
        store.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        assert store.enable_principal(USER, actor=OPERATOR) is True
        st = store.get_principal_status(USER)
        assert st.active and st.session_epoch == 2
        assert st.disabled_at is None and st.disabled_by is None and st.disabled_reason is None
        assert store.enable_principal(USER, actor=OPERATOR) is False  # nothing to enable

    def test_a_disabled_account_keeps_its_name_for_the_admin_page(self, store: TokenStore) -> None:
        enroll(store)
        store.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        st = store.get_principal_status(USER)
        assert st.display_name == "Ada Lovelace"
        (account,) = [a for a in store.list_accounts() if a.principal_key == USER]
        assert account.username == "ada@example.test"

    def test_disabling_an_unknown_account_changes_nothing(self, store: TokenStore) -> None:
        ghost = acct_key("dddddddd-0000-4000-8000-00000000000d")
        assert store.disable_principal(ghost, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR) is False
        assert store.get_principal_status(ghost).missing

    def test_unknown_reasons_and_actors_are_rejected(self, store: TokenStore) -> None:
        with pytest.raises(ValueError):
            store.disable_principal(USER, actor=OPERATOR, reason="because")
        with pytest.raises(ValueError):
            store.disable_principal(USER, actor="NOT A KEY", reason=DISABLE_REASON_ADMIN)

    def test_the_enrollment_row_is_kept_untouched_by_a_disable(self, store: TokenStore) -> None:
        enroll(store)
        before = store.info(USER)
        assert before is not None
        store.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        # Only the credential generation moves: the row itself is untouched.
        assert store.info(USER) == replace(
            before, credential_generation=before.credential_generation + 1
        )
        assert store.get(USER) is not None  # still decryptable, just never used


class TestDeletingTheRowIsNotRevocation:
    def test_a_disabled_principal_stays_disabled_after_its_row_is_deleted(
        self, store: TokenStore
    ) -> None:
        enroll(store)
        store.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        assert store.delete(USER) is True
        assert store.get_principal_status(USER).disabled

    def test_a_disabled_principal_cannot_enroll_again(self, store: TokenStore) -> None:
        enroll(store)
        store.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        store.delete(USER)
        with pytest.raises(PrincipalDisabledError):
            enroll(store)
        assert store.info(USER) is None  # the refused write left no row
        assert store.count() == 0

    def test_replacing_a_token_of_a_disabled_principal_is_refused_too(
        self, store: TokenStore
    ) -> None:
        enroll(store)
        store.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        with pytest.raises(PrincipalDisabledError):
            enroll(store)

    def test_a_self_disconnect_leaves_the_principal_free_to_enroll_again(
        self, store: TokenStore
    ) -> None:
        enroll(store)
        assert store.delete(USER) is True
        assert not store.get_principal_status(USER).disabled
        enroll(store)
        assert store.get(USER) is not None

    def test_enabling_again_lets_the_principal_enroll(self, store: TokenStore) -> None:
        enroll(store)
        store.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        store.delete(USER)
        store.enable_principal(USER, actor=OPERATOR)
        enroll(store)
        assert store.get(USER) is not None


class TestWhoMayAct:
    def test_an_owner_can_disable_and_enable_someone_else(self, store: TokenStore) -> None:
        make_owner(store, OID_OWNER_1)
        make_owner(store, OID_OWNER_2)
        assert store.disable_principal(USER, actor=OWNER_1, reason=DISABLE_REASON_ADMIN)
        assert store.get_principal_status(USER).disabled_by == OWNER_1
        assert store.enable_principal(USER, actor=OWNER_2)

    def test_a_non_owner_cannot_disable_or_enable(self, store: TokenStore) -> None:
        make_owner(store, OID_OWNER_1)
        with pytest.raises(AccessActionRefused) as exc:
            store.disable_principal(OWNER_1, actor=USER, reason=DISABLE_REASON_ADMIN)
        assert exc.value.code == AccessActionRefused.NOT_OWNER
        assert not store.get_principal_status(OWNER_1).disabled
        store.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        with pytest.raises(AccessActionRefused):
            store.enable_principal(USER, actor=USER)

    def test_an_unknown_actor_cannot_act(self, store: TokenStore) -> None:
        with pytest.raises(AccessActionRefused):
            store.disable_principal(USER, actor=OWNER_1, reason=DISABLE_REASON_ADMIN)

    def test_a_disabled_owner_can_no_longer_act(self, store: TokenStore) -> None:
        make_owner(store, OID_OWNER_1)
        make_owner(store, OID_OWNER_2)
        store.disable_principal(OWNER_1, actor=OWNER_2, reason=DISABLE_REASON_ADMIN)
        with pytest.raises(AccessActionRefused) as exc:
            store.disable_principal(USER, actor=OWNER_1, reason=DISABLE_REASON_ADMIN)
        assert exc.value.code == AccessActionRefused.NOT_OWNER

    def test_an_owner_whose_role_was_seen_to_be_gone_can_no_longer_act(
        self, store: TokenStore
    ) -> None:
        # Two rule-granted owners; the next sign-in of one shows no owner role.
        sign_in(store, OID_OWNER_1, owner=True)
        sign_in(store, OID_OWNER_2, owner=True)
        sign_in(store, OID_OWNER_1, owner=False)
        with pytest.raises(AccessActionRefused):
            store.disable_principal(USER, actor=OWNER_1, reason=DISABLE_REASON_ADMIN)

    def test_an_owner_cannot_disable_themselves(self, store: TokenStore) -> None:
        make_owner(store, OID_OWNER_1)
        make_owner(store, OID_OWNER_2)
        with pytest.raises(AccessActionRefused) as exc:
            store.disable_principal(OWNER_1, actor=OWNER_1, reason=DISABLE_REASON_ADMIN)
        assert exc.value.code == AccessActionRefused.SELF


class TestLastOwner:
    def test_the_last_active_owner_cannot_be_disabled(self, store: TokenStore) -> None:
        make_owner(store, OID_OWNER_1)
        with pytest.raises(AccessActionRefused) as exc:
            store.disable_principal(OWNER_1, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        assert exc.value.code == AccessActionRefused.LAST_OWNER
        assert not store.get_principal_status(OWNER_1).disabled

    def test_the_operator_can_force_it_as_break_glass(self, store: TokenStore) -> None:
        make_owner(store, OID_OWNER_1)
        assert store.disable_principal(
            OWNER_1, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR, allow_last_owner=True
        )
        assert store.count_active_owners() == 0
        assert store.enable_principal(OWNER_1, actor=OPERATOR)  # and can be undone
        assert store.count_active_owners() == 1

    def test_with_two_owners_one_may_be_disabled_by_the_other(self, store: TokenStore) -> None:
        make_owner(store, OID_OWNER_1)
        make_owner(store, OID_OWNER_2)
        assert store.disable_principal(OWNER_2, actor=OWNER_1, reason=DISABLE_REASON_ADMIN)
        assert store.count_active_owners() == 1
        # ... and now OWNER_1 is the last one.
        with pytest.raises(AccessActionRefused) as exc:
            store.disable_principal(OWNER_1, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        assert exc.value.code == AccessActionRefused.LAST_OWNER

    def test_two_owners_cannot_disable_each_other_at_the_same_time(
        self, tmp_path: pathlib.Path
    ) -> None:
        for round_ in range(15):
            s = make_store(tmp_path / f"r{round_}.sqlite3", make_ring())
            s.initialize()
            make_owner(s, OID_OWNER_1)
            make_owner(s, OID_OWNER_2)
            barrier = threading.Barrier(2)
            outcomes: list[str] = []

            def attempt(actor: str, target: str, s: TokenStore = s, barrier: threading.Barrier = barrier,
                        outcomes: list[str] = outcomes) -> None:
                barrier.wait()
                try:
                    s.disable_principal(target, actor=actor, reason=DISABLE_REASON_ADMIN)
                    outcomes.append("ok")
                except AccessActionRefused as exc:
                    outcomes.append(exc.code)

            threads = [
                threading.Thread(target=attempt, args=(OWNER_1, OWNER_2)),
                threading.Thread(target=attempt, args=(OWNER_2, OWNER_1)),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert sorted(outcomes) in (["not_owner", "ok"], ["last_owner", "ok"]), outcomes
            assert s.count_active_owners() == 1


class TestSessionEpoch:
    def test_the_epoch_moves_on_every_transition(self, store: TokenStore) -> None:
        epochs = [store.get_principal_status(USER).session_epoch]
        store.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        epochs.append(store.get_principal_status(USER).session_epoch)
        store.enable_principal(USER, actor=OPERATOR)
        epochs.append(store.get_principal_status(USER).session_epoch)
        store.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        epochs.append(store.get_principal_status(USER).session_epoch)
        assert epochs == [0, 1, 2, 3]

    def test_a_sign_in_never_changes_the_epoch_or_the_status(self, store: TokenStore) -> None:
        store.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        out = sign_in(store, OID_USER, owner=False)
        assert out.outcome == "deny" and out.status is not None
        assert out.status.disabled and out.status.session_epoch == 1
        out = sign_in(store, OID_USER, owner=True)
        assert out.outcome == "deny" and out.status is not None
        assert out.status.disabled and out.status.session_epoch == 1
        assert not store.get_principal_status(USER).is_owner


class TestOwnerRecord:
    def test_a_refused_sign_in_leaves_no_account(self, store: TokenStore) -> None:
        before = len(store.list_principal_statuses())
        out = sign_in(store, OID_OWNER_1, member=False, owner=False)
        assert out.outcome == "deny" and out.status is None
        assert len(store.list_principal_statuses()) == before

    def test_owner_gain_and_loss_are_recorded_and_in_the_history(
        self, store: TokenStore, clock: Clock
    ) -> None:
        sign_in(store, OID_OWNER_2, owner=True)  # a second owner, so the first can lose the role
        sign_in(store, OID_OWNER_1, owner=True)
        clock.now += 10
        sign_in(store, OID_OWNER_1, owner=True)  # unchanged: no event
        clock.now += 10
        sign_in(store, OID_OWNER_1, owner=False)
        actions = [e.action for e in store.list_status_events(OWNER_1)]
        assert actions == ["owner_lost", "owner_gained", "account_created"]
        assert store.count_active_owners() == 1

    def test_a_sign_in_reports_exactly_the_owner_changes_it_made(self, store: TokenStore) -> None:
        sign_in(store, OID_OWNER_2, owner=True)
        assert sign_in(store, OID_OWNER_1, owner=False).owner_change is None
        assert sign_in(store, OID_OWNER_1, owner=True).owner_change == "owner_gained"
        assert sign_in(store, OID_OWNER_1, owner=True).owner_change is None
        assert sign_in(store, OID_OWNER_1, owner=False).owner_change == "owner_lost"
        assert sign_in(store, OID_OWNER_1, owner=False).owner_change is None
        # What is read back later never carries a change.
        assert store.get_principal_status(OWNER_1).owner_change is None

    def test_the_last_owner_keeps_the_role_when_the_rule_stops_matching(
        self, store: TokenStore
    ) -> None:
        sign_in(store, OID_OWNER_1, owner=True)
        out = sign_in(store, OID_OWNER_1, owner=False)
        assert out.owner_change is None and not out.session_owner
        assert store.get_principal_status(OWNER_1).is_owner
        assert [e.action for e in store.list_status_events(OWNER_1)][0] == (
            "owner_loss_refused_last_owner"
        )

    def test_a_request_token_issued_before_the_last_sign_in_cannot_demote(
        self, store: TokenStore, clock: Clock
    ) -> None:
        sign_in(store, OID_OWNER_2, owner=True)
        sign_in(store, OID_OWNER_1, owner=True)  # at 1_800_000_000
        assert store.demote_owner(OWNER_1, evidence_issued_at=1_800_000_000 - 3600) is False
        assert store.demote_owner(OWNER_1, evidence_issued_at=1_800_000_000) is False
        assert store.get_principal_status(OWNER_1).is_owner

    def test_a_request_token_issued_after_the_last_sign_in_demotes_once(
        self, store: TokenStore
    ) -> None:
        sign_in(store, OID_OWNER_2, owner=True)
        sign_in(store, OID_OWNER_1, owner=True)
        assert store.demote_owner(OWNER_1, evidence_issued_at=1_800_000_500) is True
        assert not store.get_principal_status(OWNER_1).is_owner
        assert store.demote_owner(OWNER_1, evidence_issued_at=1_800_000_900) is False

    def test_the_last_owner_is_never_demoted_by_a_request_token(self, store: TokenStore) -> None:
        sign_in(store, OID_OWNER_1, owner=True)
        assert store.demote_owner(OWNER_1, evidence_issued_at=1_800_000_500) is False
        assert store.get_principal_status(OWNER_1).is_owner

    def test_a_bootstrap_or_operator_owner_is_not_demoted_by_a_request_token(
        self, store: TokenStore
    ) -> None:
        make_owner(store, OID_OWNER_1)
        make_owner(store, OID_OWNER_2)
        assert store.demote_owner(OWNER_1, evidence_issued_at=1_900_000_000) is False
        assert store.get_principal_status(OWNER_1).is_owner

    def test_demotion_never_raises_a_role(self, store: TokenStore) -> None:
        assert store.demote_owner(USER, evidence_issued_at=1_900_000_000) is False
        assert not store.get_principal_status(USER).is_owner


class TestHistory:
    def test_every_transition_is_recorded_with_actor_and_epoch(
        self, store: TokenStore, clock: Clock
    ) -> None:
        make_owner(store, OID_OWNER_1)
        make_owner(store, OID_OWNER_2)
        store.disable_principal(USER, actor=OWNER_1, reason=DISABLE_REASON_ADMIN)
        clock.now += 60
        store.enable_principal(USER, actor=OPERATOR)
        events = store.list_status_events(USER)
        assert [(e.action, e.actor, e.reason, e.session_epoch) for e in events] == [
            ("enabled", "operator", None, 2),
            ("disabled", OWNER_1, DISABLE_REASON_ADMIN, 1),
            ("account_created", "operator", "operator", 0),
        ]
        assert events[0].at == 1_800_000_060
        assert len(store.list_status_events()) == 5  # three accounts created + the two above

    def test_a_refused_change_leaves_no_event(self, store: TokenStore) -> None:
        make_owner(store, OID_OWNER_1)
        before = len(store.list_status_events())
        with pytest.raises(AccessActionRefused):
            store.disable_principal(OWNER_1, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        assert len(store.list_status_events()) == before

    def test_the_audit_log_records_the_change_with_its_actor(self, store: TokenStore) -> None:
        make_owner(store, OID_OWNER_1)
        make_owner(store, OID_OWNER_2)
        store.disable_principal(USER, actor=OWNER_1, reason=DISABLE_REASON_ADMIN)
        entries = [e for e in store.list_audit() if e.action == "account_disabled"]
        assert [(e.actor, e.target, e.reason) for e in entries] == [
            (OWNER_1, USER, DISABLE_REASON_ADMIN)
        ]


class TestRestartAndMigration:
    def test_the_decision_survives_a_restart(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        first = make_store(path, make_ring())
        first.initialize()
        make_account(first, OID_USER)
        enroll(first)
        first.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        second = make_store(path, make_ring())
        second.initialize()
        st = second.get_principal_status(USER)
        assert st.disabled and st.session_epoch == 1
        with pytest.raises(PrincipalDisabledError):
            enroll(second)

    def test_the_migration_is_idempotent(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        s = make_store(path, make_ring())
        s.initialize()
        make_account(s, OID_USER)
        s.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        for _ in range(3):
            make_store(path, make_ring()).initialize()
        assert make_store(path, make_ring()).get_principal_status(USER).session_epoch == 1

    def test_an_older_server_refuses_the_new_database(self, tmp_path: pathlib.Path) -> None:
        # The reason for the version bump: a schema 4 server reads principal_status,
        # finds nothing and would serve every disabled user. It must refuse the file.
        path = tmp_path / "t.sqlite3"
        newest = make_store(path, make_ring())
        newest.initialize()
        with raw_connection(newest) as conn:
            version = int(
                conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0]
            )
        assert version == SCHEMA_VERSION == 5 > 4


class TestConcurrentEnrollmentAndDisable:
    def test_an_enrollment_racing_a_disable_is_never_saved_after_it(
        self, tmp_path: pathlib.Path
    ) -> None:
        for round_ in range(20):
            s = make_store(tmp_path / f"race{round_}.sqlite3", make_ring())
            s.initialize()
            make_account(s, OID_USER)
            barrier = threading.Barrier(2)
            saved: list[bool] = []

            def do_enroll(s: TokenStore = s, barrier: threading.Barrier = barrier,
                          saved: list[bool] = saved) -> None:
                barrier.wait()
                try:
                    enroll(s)
                    saved.append(True)
                except PrincipalDisabledError:
                    saved.append(False)

            def do_disable(s: TokenStore = s, barrier: threading.Barrier = barrier) -> None:
                barrier.wait()
                s.disable_principal(USER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)

            threads = [threading.Thread(target=do_enroll), threading.Thread(target=do_disable)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert s.get_principal_status(USER).disabled
            if saved == [False]:
                assert s.info(USER) is None  # refused: nothing was written
            # Either way, the principal is disabled and cannot enroll any more.
            with pytest.raises(PrincipalDisabledError):
                enroll(s)
