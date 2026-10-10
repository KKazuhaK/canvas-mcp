"""Linking and unlinking identities in the store: results, audit, and the races (both backends)."""

from __future__ import annotations

import base64
import pathlib
import threading
from collections.abc import Callable
from typing import Any

import pytest
from dbbackend import make_store

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.accounts import (
    AccessPolicy,
    ExternalClaims,
    Verdict,
    evaluate_admission,
)
from canvas_mcp.core.selfhost.token_store import (
    OPERATOR,
    AccessActionRefused,
    Keyring,
    TokenStore,
)

from ..conftest import OID_A, OID_B, acct_key, make_account, sign_in

WAIT = 20
KEY_A = acct_key(OID_A)
KEY_B = acct_key(OID_B)
ANY_GITHUB = AccessPolicy(
    mode="rules", rules=(acc.AccessRule("github", "user", "1001"),), owner_rules=()
)
OPEN = AccessPolicy(mode="open")
APPROVAL = AccessPolicy(mode="approval")


def gh(subject: str = "1001", *, email: str | None = "Octo@Example.test", verified: bool = True) -> ExternalClaims:
    return ExternalClaims(
        provider_id="github", issuer=acc.GITHUB_ISSUER, subject=subject, username="octocat",
        display_name="Octo", email=email, email_verified=verified,
    )


def google(subject: str = "g-1") -> ExternalClaims:
    return ExternalClaims(
        provider_id="google", issuer=acc.GOOGLE_ISSUER, subject=subject, username="g@example.test",
        email="g@example.test", email_verified=True, hd="example.test",
    )


def verdict_for(ext: ExternalClaims, policy: AccessPolicy = OPEN) -> Verdict:
    return evaluate_admission(ext, policy)


def epoch(store: TokenStore, key: str = KEY_A) -> int:
    return store.get_principal_status(key).session_epoch


def link(store: TokenStore, key: str, ext: ExternalClaims, *, policy: AccessPolicy = OPEN, expected: int | None = None) -> Any:
    return store.link_identity(
        key, ext, verdict_for(ext, policy), policy,
        expected_epoch=epoch(store, key) if expected is None else expected,
    )


class Clock:
    now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


def _ring() -> Keyring:
    return Keyring.parse("k1:" + base64.b64encode(bytes([1]) * 32).decode())


@pytest.fixture
def store(tmp_path: pathlib.Path) -> TokenStore:
    made = make_store(tmp_path / "data" / "tokens.sqlite3", _ring(), clock=Clock())
    made.initialize()
    make_account(made, OID_A, name="Ada")
    make_account(made, OID_B, name="Bea")
    return made


@pytest.fixture
def pair(tmp_path: pathlib.Path) -> tuple[TokenStore, TokenStore]:
    path = tmp_path / "data" / "tokens.sqlite3"
    first = make_store(path, _ring(), clock=Clock())
    first.initialize()
    make_account(first, OID_A, name="Ada")
    make_account(first, OID_B, name="Bea")
    return first, make_store(path, _ring(), clock=Clock())


def actions(store: TokenStore, action: str) -> list[Any]:
    return [e for e in store.list_audit(200) if e.action == action]


class TestLink:
    def test_linking_adds_the_identity_audits_it_and_records_the_email(self, store: TokenStore) -> None:
        result = link(store, KEY_A, gh())
        assert result.code == "linked" and result.ok and result.provider_id == "github"
        identities = store.list_identities(KEY_A)
        assert [i.provider_id for i in identities] == ["entra", "github"]
        added = identities[1]
        assert (added.subject, added.username, added.email, added.email_verified) == (
            "1001", "octocat", "Octo@Example.test", True,
        )
        assert store.lookup_identity("github", acc.GITHUB_ISSUER, "1001") == KEY_A
        entry = actions(store, "identity_linked")[0]
        assert entry.actor == KEY_A and entry.target == KEY_A and entry.detail == {"provider": "github"}
        event = store.list_auth_events(KEY_A)[0]
        assert (event.outcome, event.reason, event.provider_id) == ("success", "identity_linked", "github")

    def test_an_unverified_or_missing_email_is_stored_as_such(self, store: TokenStore) -> None:
        assert link(store, KEY_A, gh(email=None)).ok
        added = store.list_identities(KEY_A)[1]
        assert added.email is None and added.email_verified is False

    def test_linking_the_same_identity_again_changes_nothing(self, store: TokenStore) -> None:
        assert link(store, KEY_A, gh()).code == "linked"
        before = len(store.list_audit(200))
        again = link(store, KEY_A, gh())
        assert again.code == "already_linked" and again.ok
        assert len(store.list_identities(KEY_A)) == 2 and len(store.list_audit(200)) == before

    def test_an_identity_that_belongs_to_another_account_is_refused_and_nothing_merges(
        self, store: TokenStore
    ) -> None:
        assert link(store, KEY_B, gh()).ok
        result = link(store, KEY_A, gh())
        assert result.code == "identity_in_use" and not result.ok
        assert [i.provider_id for i in store.list_identities(KEY_A)] == ["entra"]
        assert [i.provider_id for i in store.list_identities(KEY_B)] == ["entra", "github"]
        refused = actions(store, "identity_link_refused")
        assert refused and refused[0].reason == "identity_in_use" and refused[0].target == KEY_A

    def test_one_identity_per_provider_per_account(self, store: TokenStore) -> None:
        assert link(store, KEY_A, gh("1001")).ok
        result = link(store, KEY_A, gh("2002"))
        assert result.code == "provider_already_linked"
        assert len(store.list_identities(KEY_A)) == 2
        assert actions(store, "identity_link_refused")[0].reason == "provider_already_linked"

    def test_an_identity_the_rules_would_refuse_cannot_be_attached(self, tmp_path: pathlib.Path) -> None:
        made = make_store(tmp_path / "rules.sqlite3", _ring(), clock=Clock())
        made.initialize()
        # An account the rules admitted (not a personal admission).
        sign_in(made, OID_A)
        result = link(made, KEY_A, gh("999"), policy=ANY_GITHUB)
        assert result.code == "access_denied"
        assert len(made.list_identities(KEY_A)) == 1
        assert link(made, KEY_A, gh("1001"), policy=ANY_GITHUB).code == "linked"

    def test_a_personally_admitted_account_may_link_any_identity(self, store: TokenStore) -> None:
        assert link(store, KEY_A, gh("999"), policy=ANY_GITHUB).code == "linked"

    def test_approval_mode_allows_linking(self, store: TokenStore) -> None:
        assert link(store, KEY_A, google(), policy=APPROVAL).ok

    def test_the_session_epoch_must_still_be_the_one_that_started_the_link(self, store: TokenStore) -> None:
        started = epoch(store)
        assert store.disable_principal(KEY_A, actor=OPERATOR, reason="operator_disabled")
        assert store.enable_principal(KEY_A, actor=OPERATOR)
        assert epoch(store) != started
        result = link(store, KEY_A, gh(), expected=started)
        assert result.code == "link_session_ended"
        assert len(store.list_identities(KEY_A)) == 1

    def test_a_disabled_or_unknown_account_cannot_be_linked_to(self, store: TokenStore) -> None:
        assert store.disable_principal(KEY_A, actor=OPERATOR, reason="operator_disabled")
        assert link(store, KEY_A, gh()).code == "link_session_ended"
        ghost = "acct:11111111-2222-4333-8444-555555555555"
        assert store.link_identity(ghost, gh(), verdict_for(gh()), OPEN, expected_epoch=0).code == "link_session_ended"

    def test_a_signed_in_linked_identity_reaches_the_same_account(self, store: TokenStore) -> None:
        assert link(store, KEY_A, google()).ok
        ext = google()
        resolution = store.resolve_identity(ext, verdict_for(ext), OPEN, purpose="sign_in")
        assert resolution.allowed and resolution.principal_key == KEY_A
        assert store.count() == 0 and len(store.list_principal_statuses()) == 2

    def test_a_first_sign_in_records_the_email_and_later_ones_refresh_it(self, store: TokenStore) -> None:
        ext = gh("77", email="first@example.test")
        first = store.resolve_identity(ext, verdict_for(ext), OPEN, purpose="sign_in")
        key = first.principal_key
        assert key is not None
        assert store.list_identities(key)[0].email == "first@example.test"
        later = gh("77", email="second@example.test", verified=False)
        store.resolve_identity(later, verdict_for(later), OPEN, purpose="sign_in")
        row = store.list_identities(key)[0]
        assert (row.email, row.email_verified) == ("second@example.test", False)
        silent = gh("77", email=None)
        store.resolve_identity(silent, verdict_for(silent), OPEN, purpose="sign_in")
        assert store.list_identities(key)[0].email == "second@example.test"


class TestUnlink:
    def two(self, store: TokenStore) -> int:
        assert link(store, KEY_A, gh()).ok
        return store.list_identities(KEY_A)[1].id

    def test_the_last_identity_cannot_be_unlinked_by_anyone(self, store: TokenStore) -> None:
        only = store.list_identities(KEY_A)[0].id
        for actor in (KEY_A, OPERATOR):
            result = store.unlink_identity(KEY_A, only, actor=actor)
            assert result.code == "last_identity" and not result.ok
        assert len(store.list_identities(KEY_A)) == 1
        owner = make_account(store, "cccccccc-0000-4000-8000-00000000000c", role="owner")
        assert store.unlink_identity(KEY_A, only, actor=owner).code == "last_identity"

    RULES_OWNER = AccessPolicy(
        mode="rules",
        rules=(acc.AccessRule("entra", "role", "Canvas.User"), acc.AccessRule("github", "user", "1001")),
        owner_rules=(acc.AccessRule("entra", "role", "Canvas.Owner"),),
    )

    def entra_id(self, store: TokenStore) -> int:
        return next(r.id for r in store.list_identities(KEY_A) if r.provider_id == "entra")

    def rules_owner(self, store: TokenStore) -> None:
        sign_in(store, OID_A, owner=True, policy=self.RULES_OWNER)
        assert store.get_principal_status(KEY_A).role == "owner"
        assert store.get_principal_status(KEY_A).role_source == "rules"
        assert link(store, KEY_A, gh(), policy=self.RULES_OWNER).ok

    def test_the_only_owner_of_an_entra_rule_keeps_its_last_entra_identity(self, store: TokenStore) -> None:
        self.rules_owner(store)
        entra = self.entra_id(store)
        before = epoch(store)
        for actor in (KEY_A, OPERATOR):
            result = store.unlink_identity(KEY_A, entra, actor=actor)
            assert result.code == "last_owner" and not result.ok
        assert [i.provider_id for i in store.list_identities(KEY_A)] == ["entra", "github"]
        assert epoch(store) == before

    def test_another_active_owner_lets_the_entra_identity_go(self, store: TokenStore) -> None:
        self.rules_owner(store)
        sign_in(store, OID_B, owner=True, policy=self.RULES_OWNER)
        assert store.count_active_owners() == 2
        assert store.unlink_identity(KEY_A, self.entra_id(store), actor=KEY_A).ok

    def test_an_operator_made_owner_may_unlink_entra(self, tmp_path: pathlib.Path) -> None:
        made = make_store(tmp_path / "op" / "tokens.sqlite3", _ring(), clock=Clock())
        made.initialize()
        key = make_account(made, OID_A, name="Ada", role="owner")
        assert made.get_principal_status(key).role_source == "operator"
        assert link(made, key, gh(), policy=self.RULES_OWNER).ok
        entra = next(r.id for r in made.list_identities(key) if r.provider_id == "entra")
        assert made.unlink_identity(key, entra, actor=key).ok

    def test_a_plain_user_may_unlink_entra(self, store: TokenStore) -> None:
        assert link(store, KEY_A, gh()).ok
        assert store.unlink_identity(KEY_A, self.entra_id(store), actor=KEY_A).ok

    def test_unlinking_removes_it_bumps_the_epoch_and_leaves_history(self, store: TokenStore) -> None:
        extra = self.two(store)
        before = epoch(store)
        result = store.unlink_identity(KEY_A, extra, actor=KEY_A, expected_epoch=before)
        assert result.ok and result.provider_id == "github" and result.session_epoch == before + 1
        assert epoch(store) == before + 1
        assert [i.provider_id for i in store.list_identities(KEY_A)] == ["entra"]
        assert store.lookup_identity("github", acc.GITHUB_ISSUER, "1001") is None
        entry = actions(store, "identity_unlinked")[0]
        assert entry.detail == {"provider": "github", "by": "self"}
        event = store.list_status_events(KEY_A)[0]
        assert event.action == "identity_unlinked" and event.actor == KEY_A and event.session_epoch == before + 1

    def test_an_unlinked_identity_is_a_stranger_at_its_next_sign_in(self, store: TokenStore) -> None:
        extra = self.two(store)
        assert store.unlink_identity(KEY_A, extra, actor=KEY_A).ok
        ext = gh()
        resolution = store.resolve_identity(ext, verdict_for(ext), OPEN, purpose="sign_in")
        assert resolution.created and resolution.principal_key != KEY_A

    def test_only_the_accounts_own_identity_can_be_named(self, store: TokenStore) -> None:
        self.two(store)
        assert link(store, KEY_B, google()).ok
        theirs = store.list_identities(KEY_B)[1].id
        assert store.unlink_identity(KEY_A, theirs, actor=KEY_A).code == "not_found"
        assert store.unlink_identity(KEY_A, 987654, actor=KEY_A).code == "not_found"
        assert len(store.list_identities(KEY_B)) == 2

    def test_an_owner_can_force_unlink_and_a_plain_user_cannot(self, store: TokenStore) -> None:
        extra = self.two(store)
        with pytest.raises(AccessActionRefused) as info:
            store.unlink_identity(KEY_A, extra, actor=KEY_B)
        assert info.value.code == "not_owner"
        assert len(store.list_identities(KEY_A)) == 2
        owner = make_account(store, "cccccccc-0000-4000-8000-00000000000c", role="owner")
        result = store.unlink_identity(KEY_A, extra, actor=owner)
        assert result.ok
        assert actions(store, "identity_unlinked")[0].detail["by"] == "owner"
        assert actions(store, "identity_unlinked")[0].actor == owner

    def test_the_operator_can_unlink_and_it_is_audited(self, store: TokenStore) -> None:
        extra = self.two(store)
        assert store.unlink_identity(KEY_A, extra, actor=OPERATOR).ok
        entry = actions(store, "identity_unlinked")[0]
        assert entry.actor == "operator" and entry.detail["by"] == "operator"

    def test_an_own_unlink_needs_the_session_that_made_it(self, store: TokenStore) -> None:
        extra = self.two(store)
        stale = epoch(store) - 1
        assert store.unlink_identity(KEY_A, extra, actor=KEY_A, expected_epoch=stale).code == "link_session_ended"
        assert store.disable_principal(KEY_A, actor=OPERATOR, reason="operator_disabled")
        assert store.unlink_identity(KEY_A, extra, actor=KEY_A).code == "link_session_ended"
        assert len(store.list_identities(KEY_A)) == 2

    def test_pending_authorization_codes_die_with_the_epoch_bump(self, store: TokenStore) -> None:
        extra = self.two(store)
        approved_in = epoch(store)
        assert store.unlink_identity(KEY_A, extra, actor=KEY_A).ok
        assert epoch(store) != approved_in  # a code carries ``approved_in``; /token compares epochs


class TestUsesTheWriterLock:
    def test_link_and_unlink_run_in_write_transactions_not_row_writes(self, store: TokenStore) -> None:
        db = store.database
        used: list[str] = []
        original_write, original_row = db.write, db.row_write

        def write() -> Any:
            used.append("write")
            return original_write()

        def row_write() -> Any:
            used.append("row_write")
            return original_row()

        db.write, db.row_write = write, row_write  # type: ignore[method-assign]
        try:
            assert link(store, KEY_A, gh()).ok
            extra = store.list_identities(KEY_A)[1].id
            assert store.unlink_identity(KEY_A, extra, actor=KEY_A).ok
        finally:
            db.write, db.row_write = original_write, original_row  # type: ignore[method-assign]
        assert used == ["write", "write"]


class Gate:
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
            except BaseException as exc:  # noqa: BLE001
                self.error = exc
            finally:
                self.done.set()

        threading.Thread(target=run, daemon=True).start()

    def blocked(self, seconds: float = 0.4) -> bool:
        return not self.done.wait(seconds)

    def join(self) -> Any:
        assert self.done.wait(WAIT), "the thread never finished"
        if self.error is not None:
            raise self.error
        return self.result


class TestRaces:
    def test_two_accounts_linking_the_same_identity_one_wins(self, pair: tuple[TokenStore, TokenStore]) -> None:
        first, second = pair
        gate = Gate("after_identity_lookup")
        first._pause_hook = gate
        winner = Runner(lambda: link(first, KEY_A, gh()))
        assert gate.reached.wait(WAIT)
        loser = Runner(lambda: link(second, KEY_B, gh()))
        assert loser.blocked()
        gate.release.set()
        assert winner.join().code == "linked"
        assert loser.join().code == "identity_in_use"
        assert first.lookup_identity("github", acc.GITHUB_ISSUER, "1001") == KEY_A
        assert len(first.list_identities(KEY_B)) == 1

    def test_two_concurrent_unlinks_of_a_two_identity_account_leave_one(
        self, pair: tuple[TokenStore, TokenStore]
    ) -> None:
        first, second = pair
        assert link(first, KEY_A, gh()).ok
        entra_id, github_id = (i.id for i in first.list_identities(KEY_A))
        gate = Gate("after_identity_count")
        first._pause_hook = gate
        one = Runner(lambda: first.unlink_identity(KEY_A, entra_id, actor=KEY_A))
        assert gate.reached.wait(WAIT)
        two = Runner(lambda: second.unlink_identity(KEY_A, github_id, actor=KEY_A))
        assert two.blocked()
        gate.release.set()
        results = sorted([one.join().code, two.join().code])
        assert results == ["last_identity", "unlinked"]
        assert len(first.list_identities(KEY_A)) == 1

    def test_a_link_racing_the_first_sign_in_of_the_same_identity_never_makes_two_rows(
        self, pair: tuple[TokenStore, TokenStore]
    ) -> None:
        first, second = pair
        ext = gh()
        gate = Gate("after_decision")
        first._pause_hook = gate
        signing_in = Runner(
            lambda: first.resolve_identity(ext, verdict_for(ext), OPEN, purpose="sign_in")
        )
        assert gate.reached.wait(WAIT)
        linking = Runner(lambda: link(second, KEY_A, gh()))
        assert linking.blocked()
        gate.release.set()
        created = signing_in.join()
        assert created.created
        assert linking.join().code == "identity_in_use"
        assert first.lookup_identity("github", acc.GITHUB_ISSUER, "1001") == created.principal_key
        assert len(first.list_identities(KEY_A)) == 1

    def test_the_link_wins_and_the_sign_in_then_resolves_to_the_linked_account(
        self, pair: tuple[TokenStore, TokenStore]
    ) -> None:
        first, second = pair
        gate = Gate("after_identity_lookup")
        first._pause_hook = gate
        linking = Runner(lambda: link(first, KEY_A, gh()))
        assert gate.reached.wait(WAIT)
        ext = gh()
        signing_in = Runner(
            lambda: second.resolve_identity(ext, verdict_for(ext), OPEN, purpose="sign_in")
        )
        assert signing_in.blocked()
        gate.release.set()
        assert linking.join().code == "linked"
        resolved = signing_in.join()
        assert resolved.allowed and not resolved.created and resolved.principal_key == KEY_A
        assert len(first.list_principal_statuses()) == 2

    def test_a_force_unlink_by_an_owner_who_was_just_disabled_is_refused(
        self, pair: tuple[TokenStore, TokenStore]
    ) -> None:
        first, second = pair
        owner = make_account(first, "cccccccc-0000-4000-8000-00000000000c", role="owner")
        make_account(first, "dddddddd-0000-4000-8000-00000000000d", role="owner")
        assert link(first, KEY_A, gh()).ok
        extra = first.list_identities(KEY_A)[1].id
        gate = Gate("after_owner_count")
        first._pause_hook = gate
        disabling = Runner(lambda: first.disable_principal(owner, actor=OPERATOR, reason="operator_disabled"))
        assert gate.reached.wait(WAIT)
        unlinking = Runner(lambda: second.unlink_identity(KEY_A, extra, actor=owner))
        assert unlinking.blocked()
        gate.release.set()
        assert disabling.join() is True
        with pytest.raises(AccessActionRefused):
            unlinking.join()
        assert len(first.list_identities(KEY_A)) == 2

    def test_a_link_waiting_behind_a_disable_is_refused(self, pair: tuple[TokenStore, TokenStore]) -> None:
        first, second = pair
        started = epoch(first)
        # Hold a disable of an owner account open at its owner count (it holds the writer lock).
        gate = Gate("after_owner_count")
        first._pause_hook = gate
        owner = make_account(first, "cccccccc-0000-4000-8000-00000000000c", role="owner")
        make_account(first, "dddddddd-0000-4000-8000-00000000000d", role="owner")
        disabling = Runner(lambda: first.disable_principal(owner, actor=OPERATOR, reason="operator_disabled"))
        assert gate.reached.wait(WAIT)
        linking = Runner(lambda: link(second, KEY_A, gh(), expected=started))
        assert linking.blocked()  # the writer lock serialises the two transactions
        gate.release.set()
        assert disabling.join() is True
        assert linking.join().code == "linked"  # A was untouched
        # And once A itself is disabled, a link started before is refused.
        assert second.disable_principal(KEY_A, actor=OPERATOR, reason="operator_disabled")
        assert link(second, KEY_A, google(), expected=started).code == "link_session_ended"
