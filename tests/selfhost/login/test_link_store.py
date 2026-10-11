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

from ..conftest import OID_A, OID_B, TENANT, acct_key, external, make_account, sign_in

WAIT = 20
KEY_A = acct_key(OID_A)
KEY_B = acct_key(OID_B)
ANY_GITHUB = AccessPolicy(
    mode="rules", rules=(acc.AccessRule("github", "user", "1001"),), owner_rules=()
)
OPEN = AccessPolicy(mode="open")
APPROVAL = AccessPolicy(mode="approval")


def gh(
    subject: str = "1001",
    *,
    email: str | None = "Octo@Example.test",
    verified: bool = True,
) -> ExternalClaims:
    return ExternalClaims(
        provider_id="github",
        issuer=acc.GITHUB_ISSUER,
        subject=subject,
        username="octocat",
        display_name="Octo",
        email=email,
        email_verified=verified,
    )


def google(subject: str = "g-1") -> ExternalClaims:
    return ExternalClaims(
        provider_id="google",
        issuer=acc.GOOGLE_ISSUER,
        subject=subject,
        username="g@example.test",
        email="g@example.test",
        email_verified=True,
        hd="example.test",
    )


def verdict_for(ext: ExternalClaims, policy: AccessPolicy = OPEN) -> Verdict:
    return evaluate_admission(ext, policy)


def epoch(store: TokenStore, key: str = KEY_A) -> int:
    return store.get_principal_status(key).session_epoch


def link(
    store: TokenStore,
    key: str,
    ext: ExternalClaims,
    *,
    policy: AccessPolicy = OPEN,
    expected: int | None = None,
) -> Any:
    return store.link_identity(
        key,
        ext,
        verdict_for(ext, policy),
        policy,
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
    return [e for e in list(store.iter_audit()) if e.action == action]


class TestLink:
    def test_linking_adds_the_identity_audits_it_and_records_the_email(
        self, store: TokenStore
    ) -> None:
        result = link(store, KEY_A, gh())
        assert result.code == "linked" and result.ok and result.provider_id == "github"
        identities = store.list_identities(KEY_A)
        assert [i.provider_id for i in identities] == ["entra", "github"]
        added = identities[1]
        assert (added.subject, added.username, added.email, added.email_verified) == (
            "1001",
            "octocat",
            "Octo@Example.test",
            True,
        )
        assert store.lookup_identity("github", acc.GITHUB_ISSUER, "1001") == KEY_A
        entry = actions(store, "identity_linked")[0]
        assert (
            entry.actor == KEY_A
            and entry.target == KEY_A
            and entry.detail == {"provider": "github"}
        )
        event = store.auth_events_page(KEY_A).items[0]
        assert (event.outcome, event.reason, event.provider_id) == (
            "success",
            "identity_linked",
            "github",
        )

    def test_an_unverified_or_missing_email_is_stored_as_such(
        self, store: TokenStore
    ) -> None:
        assert link(store, KEY_A, gh(email=None)).ok
        added = store.list_identities(KEY_A)[1]
        assert added.email is None and added.email_verified is False

    def test_linking_the_same_identity_again_changes_nothing(
        self, store: TokenStore
    ) -> None:
        assert link(store, KEY_A, gh()).code == "linked"
        before = len(list(store.iter_audit()))
        again = link(store, KEY_A, gh())
        assert again.code == "already_linked" and again.ok
        assert (
            len(store.list_identities(KEY_A)) == 2
            and len(list(store.iter_audit())) == before
        )

    def test_an_identity_that_belongs_to_another_account_is_refused_and_nothing_merges(
        self, store: TokenStore
    ) -> None:
        assert link(store, KEY_B, gh()).ok
        result = link(store, KEY_A, gh())
        assert result.code == "identity_in_use" and not result.ok
        assert [i.provider_id for i in store.list_identities(KEY_A)] == ["entra"]
        assert [i.provider_id for i in store.list_identities(KEY_B)] == [
            "entra",
            "github",
        ]
        refused = actions(store, "identity_link_refused")
        assert (
            refused
            and refused[0].reason == "identity_in_use"
            and refused[0].target == KEY_A
        )

    def test_one_identity_per_provider_per_account(self, store: TokenStore) -> None:
        assert link(store, KEY_A, gh("1001")).ok
        result = link(store, KEY_A, gh("2002"))
        assert result.code == "provider_already_linked"
        assert len(store.list_identities(KEY_A)) == 2
        assert (
            actions(store, "identity_link_refused")[0].reason
            == "provider_already_linked"
        )

    def test_an_identity_the_rules_would_refuse_cannot_be_attached(
        self, tmp_path: pathlib.Path
    ) -> None:
        made = make_store(tmp_path / "rules.sqlite3", _ring(), clock=Clock())
        made.initialize()
        # An account the rules admitted (not a personal admission).
        sign_in(made, OID_A)
        result = link(made, KEY_A, gh("999"), policy=ANY_GITHUB)
        assert result.code == "access_denied"
        assert len(made.list_identities(KEY_A)) == 1
        assert link(made, KEY_A, gh("1001"), policy=ANY_GITHUB).code == "linked"

    def test_a_personally_admitted_account_may_link_any_identity(
        self, store: TokenStore
    ) -> None:
        assert link(store, KEY_A, gh("999"), policy=ANY_GITHUB).code == "linked"

    def test_approval_mode_allows_linking(self, store: TokenStore) -> None:
        assert link(store, KEY_A, google(), policy=APPROVAL).ok

    def test_the_session_epoch_must_still_be_the_one_that_started_the_link(
        self, store: TokenStore
    ) -> None:
        started = epoch(store)
        assert store.disable_principal(
            KEY_A, actor=OPERATOR, reason="operator_disabled"
        )
        assert store.enable_principal(KEY_A, actor=OPERATOR)
        assert epoch(store) != started
        result = link(store, KEY_A, gh(), expected=started)
        assert result.code == "link_session_ended"
        assert len(store.list_identities(KEY_A)) == 1

    def test_a_disabled_or_unknown_account_cannot_be_linked_to(
        self, store: TokenStore
    ) -> None:
        assert store.disable_principal(
            KEY_A, actor=OPERATOR, reason="operator_disabled"
        )
        assert link(store, KEY_A, gh()).code == "link_session_ended"
        ghost = "11111111-2222-4333-8444-555555555555"
        assert (
            store.link_identity(
                ghost, gh(), verdict_for(gh()), OPEN, expected_epoch=0
            ).code
            == "link_session_ended"
        )

    def test_a_signed_in_linked_identity_reaches_the_same_account(
        self, store: TokenStore
    ) -> None:
        assert link(store, KEY_A, google()).ok
        ext = google()
        resolution = store.resolve_identity(
            ext, verdict_for(ext), OPEN, purpose="sign_in"
        )
        assert resolution.allowed and resolution.principal_key == KEY_A
        assert store.count() == 0 and store.account_counts()["total"] == 2

    def test_a_first_sign_in_records_the_email_and_later_ones_refresh_it(
        self, store: TokenStore
    ) -> None:
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
    def two(self, store: TokenStore) -> str:
        assert link(store, KEY_A, gh()).ok
        return store.list_identities(KEY_A)[1].id

    def test_the_last_identity_cannot_be_unlinked_by_anyone(
        self, store: TokenStore
    ) -> None:
        only = store.list_identities(KEY_A)[0].id
        for actor in (KEY_A, OPERATOR):
            result = store.unlink_identity(KEY_A, only, actor=actor)
            assert result.code == "last_identity" and not result.ok
        assert len(store.list_identities(KEY_A)) == 1
        owner = make_account(
            store, "cccccccc-0000-4000-8000-00000000000c", role="owner"
        )
        assert store.unlink_identity(KEY_A, only, actor=owner).code == "last_identity"

    RULES_OWNER = AccessPolicy(
        mode="rules",
        rules=(
            acc.AccessRule("entra", "role", "Canvas.User"),
            acc.AccessRule("github", "user", "1001"),
        ),
        owner_rules=(acc.AccessRule("entra", "role", "Canvas.Owner"),),
    )

    def entra_id(self, store: TokenStore) -> str:
        return next(
            r.id for r in store.list_identities(KEY_A) if r.provider_id == "entra"
        )

    def rules_owner(self, store: TokenStore) -> None:
        sign_in(store, OID_A, owner=True, policy=self.RULES_OWNER)
        assert store.get_principal_status(KEY_A).role == "owner"
        assert store.get_principal_status(KEY_A).role_source == "rules"
        assert link(store, KEY_A, gh(), policy=self.RULES_OWNER).ok

    def test_the_only_owner_of_an_entra_rule_keeps_its_last_entra_identity(
        self, store: TokenStore
    ) -> None:
        self.rules_owner(store)
        entra = self.entra_id(store)
        before = epoch(store)
        for actor in (KEY_A, OPERATOR):
            result = store.unlink_identity(KEY_A, entra, actor=actor)
            assert result.code == "last_owner" and not result.ok
        assert [i.provider_id for i in store.list_identities(KEY_A)] == [
            "entra",
            "github",
        ]
        assert epoch(store) == before

    def test_another_active_owner_lets_the_entra_identity_go(
        self, store: TokenStore
    ) -> None:
        self.rules_owner(store)
        sign_in(store, OID_B, owner=True, policy=self.RULES_OWNER)
        assert store.count_active_owners() == 2
        assert store.unlink_identity(KEY_A, self.entra_id(store), actor=KEY_A).ok

    def test_an_operator_made_owner_may_unlink_entra(
        self, tmp_path: pathlib.Path
    ) -> None:
        made = make_store(tmp_path / "op" / "tokens.sqlite3", _ring(), clock=Clock())
        made.initialize()
        key = make_account(made, OID_A, name="Ada", role="owner")
        assert made.get_principal_status(key).role_source == "operator"
        assert link(made, key, gh(), policy=self.RULES_OWNER).ok
        entra = next(
            r.id for r in made.list_identities(key) if r.provider_id == "entra"
        )
        assert made.unlink_identity(key, entra, actor=key).ok

    def test_a_plain_user_may_unlink_entra(self, store: TokenStore) -> None:
        assert link(store, KEY_A, gh()).ok
        assert store.unlink_identity(KEY_A, self.entra_id(store), actor=KEY_A).ok

    def test_unlinking_removes_it_bumps_the_epoch_and_leaves_history(
        self, store: TokenStore
    ) -> None:
        extra = self.two(store)
        before = epoch(store)
        result = store.unlink_identity(KEY_A, extra, actor=KEY_A, expected_epoch=before)
        assert (
            result.ok
            and result.provider_id == "github"
            and result.session_epoch == before + 1
        )
        assert epoch(store) == before + 1
        assert [i.provider_id for i in store.list_identities(KEY_A)] == ["entra"]
        assert store.lookup_identity("github", acc.GITHUB_ISSUER, "1001") is None
        entry = actions(store, "identity_unlinked")[0]
        assert entry.detail == {"provider": "github", "by": "self"}
        assert entry.actor == KEY_A and entry.target == KEY_A
        assert result.session_epoch == store.get_principal_status(KEY_A).session_epoch

    def test_an_unlinked_identity_is_a_stranger_at_its_next_sign_in(
        self, store: TokenStore
    ) -> None:
        extra = self.two(store)
        assert store.unlink_identity(KEY_A, extra, actor=KEY_A).ok
        ext = gh()
        resolution = store.resolve_identity(
            ext, verdict_for(ext), OPEN, purpose="sign_in"
        )
        assert resolution.created and resolution.principal_key != KEY_A

    def test_only_the_accounts_own_identity_can_be_named(
        self, store: TokenStore
    ) -> None:
        self.two(store)
        assert link(store, KEY_B, google()).ok
        theirs = store.list_identities(KEY_B)[1].id
        assert store.unlink_identity(KEY_A, theirs, actor=KEY_A).code == "not_found"
        assert (
            store.unlink_identity(
                KEY_A, "11111111-2222-4333-8444-555555555555", actor=KEY_A
            ).code
            == "not_found"
        )
        assert len(store.list_identities(KEY_B)) == 2

    def test_an_owner_can_force_unlink_and_a_plain_user_cannot(
        self, store: TokenStore
    ) -> None:
        extra = self.two(store)
        with pytest.raises(AccessActionRefused) as info:
            store.unlink_identity(KEY_A, extra, actor=KEY_B)
        assert info.value.code == "not_owner"
        assert len(store.list_identities(KEY_A)) == 2
        owner = make_account(
            store, "cccccccc-0000-4000-8000-00000000000c", role="owner"
        )
        result = store.unlink_identity(KEY_A, extra, actor=owner)
        assert result.ok
        assert actions(store, "identity_unlinked")[0].detail["by"] == "owner"
        assert actions(store, "identity_unlinked")[0].actor == owner

    def test_the_operator_can_unlink_and_it_is_audited(self, store: TokenStore) -> None:
        extra = self.two(store)
        assert store.unlink_identity(KEY_A, extra, actor=OPERATOR).ok
        entry = actions(store, "identity_unlinked")[0]
        assert entry.actor == "operator" and entry.detail["by"] == "operator"

    def test_an_own_unlink_needs_the_session_that_made_it(
        self, store: TokenStore
    ) -> None:
        extra = self.two(store)
        stale = epoch(store) - 1
        assert (
            store.unlink_identity(KEY_A, extra, actor=KEY_A, expected_epoch=stale).code
            == "link_session_ended"
        )
        assert store.disable_principal(
            KEY_A, actor=OPERATOR, reason="operator_disabled"
        )
        assert (
            store.unlink_identity(KEY_A, extra, actor=KEY_A).code
            == "link_session_ended"
        )
        assert len(store.list_identities(KEY_A)) == 2

    def test_pending_authorization_codes_die_with_the_epoch_bump(
        self, store: TokenStore
    ) -> None:
        extra = self.two(store)
        approved_in = epoch(store)
        assert store.unlink_identity(KEY_A, extra, actor=KEY_A).ok
        assert (
            epoch(store) != approved_in
        )  # a code carries ``approved_in``; /token compares epochs


class TestUsesTheWriterLock:
    def test_link_and_unlink_run_in_write_transactions_not_row_writes(
        self, store: TokenStore
    ) -> None:
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
    def test_two_accounts_linking_the_same_identity_one_wins(
        self, pair: tuple[TokenStore, TokenStore]
    ) -> None:
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
            lambda: first.resolve_identity(
                ext, verdict_for(ext), OPEN, purpose="sign_in"
            )
        )
        assert gate.reached.wait(WAIT)
        linking = Runner(lambda: link(second, KEY_A, gh()))
        assert linking.blocked()
        gate.release.set()
        created = signing_in.join()
        assert created.created
        assert linking.join().code == "identity_in_use"
        assert (
            first.lookup_identity("github", acc.GITHUB_ISSUER, "1001")
            == created.principal_key
        )
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
            lambda: second.resolve_identity(
                ext, verdict_for(ext), OPEN, purpose="sign_in"
            )
        )
        assert signing_in.blocked()
        gate.release.set()
        assert linking.join().code == "linked"
        resolved = signing_in.join()
        assert (
            resolved.allowed
            and not resolved.created
            and resolved.principal_key == KEY_A
        )
        assert first.account_counts()["total"] == 2

    def test_a_force_unlink_by_an_owner_who_was_just_disabled_is_refused(
        self, pair: tuple[TokenStore, TokenStore]
    ) -> None:
        first, second = pair
        owner = make_account(
            first, "cccccccc-0000-4000-8000-00000000000c", role="owner"
        )
        make_account(first, "dddddddd-0000-4000-8000-00000000000d", role="owner")
        assert link(first, KEY_A, gh()).ok
        extra = first.list_identities(KEY_A)[1].id
        gate = Gate("after_owner_count")
        first._pause_hook = gate
        disabling = Runner(
            lambda: first.disable_principal(
                owner, actor=OPERATOR, reason="operator_disabled"
            )
        )
        assert gate.reached.wait(WAIT)
        unlinking = Runner(lambda: second.unlink_identity(KEY_A, extra, actor=owner))
        assert unlinking.blocked()
        gate.release.set()
        assert disabling.join() is True
        with pytest.raises(AccessActionRefused):
            unlinking.join()
        assert len(first.list_identities(KEY_A)) == 2

    def test_a_link_waiting_behind_a_disable_is_refused(
        self, pair: tuple[TokenStore, TokenStore]
    ) -> None:
        first, second = pair
        started = epoch(first)
        # Hold a disable of an owner account open at its owner count (it holds the writer lock).
        gate = Gate("after_owner_count")
        first._pause_hook = gate
        owner = make_account(
            first, "cccccccc-0000-4000-8000-00000000000c", role="owner"
        )
        make_account(first, "dddddddd-0000-4000-8000-00000000000d", role="owner")
        disabling = Runner(
            lambda: first.disable_principal(
                owner, actor=OPERATOR, reason="operator_disabled"
            )
        )
        assert gate.reached.wait(WAIT)
        linking = Runner(lambda: link(second, KEY_A, gh(), expected=started))
        assert linking.blocked()  # the writer lock serialises the two transactions
        gate.release.set()
        assert disabling.join() is True
        assert linking.join().code == "linked"  # A was untouched
        # And once A itself is disabled, a link started before is refused.
        assert second.disable_principal(
            KEY_A, actor=OPERATOR, reason="operator_disabled"
        )
        assert (
            link(second, KEY_A, google(), expected=started).code == "link_session_ended"
        )


# -- the usable owner: unlink, the bootstrap owner and the predicate -------------------------------

OID_C = "cccccccc-0000-4000-8000-00000000000c"
KEY_C = acct_key(OID_C)
LISTED = frozenset({"entra", "github"})
RULES_OWNER = TestUnlink.RULES_OWNER


def rules_owner(store: TokenStore, oid: str, key: str, github_subject: str) -> str:
    """Make ``key`` an owner through the Entra owner rule and link a GitHub identity; returns its Entra id."""
    sign_in(store, oid, owner=True, policy=RULES_OWNER)
    status = store.get_principal_status(key)
    assert (status.role, status.role_source) == ("owner", "rules")
    assert link(store, key, gh(github_subject), policy=OPEN).ok
    return provider_identity(store, key, "entra")


def provider_identity(store: TokenStore, key: str, provider: str) -> str:
    return next(r.id for r in store.list_identities(key) if r.provider_id == provider)


def providers(store: TokenStore, key: str) -> list[str]:
    return [r.provider_id for r in store.list_identities(key)]


class TestUsableOwnerUnlink:
    def test_two_rules_owners_unlinking_entra_in_turn_the_second_is_refused(
        self, store: TokenStore
    ) -> None:
        entra_a = rules_owner(store, OID_A, KEY_A, "1001")
        entra_b = rules_owner(store, OID_B, KEY_B, "1002")
        assert store.count_usable_owners(LISTED) == 2
        assert store.unlink_identity(
            KEY_A, entra_a, actor=KEY_A, listed_providers=LISTED
        ).ok
        assert store.count_usable_owners(LISTED) == 1
        before = epoch(store, KEY_B)
        refused = store.unlink_identity(
            KEY_B, entra_b, actor=KEY_B, listed_providers=LISTED
        )
        assert refused.code == "last_owner" and not refused.ok
        assert (
            providers(store, KEY_B) == ["entra", "github"]
            and epoch(store, KEY_B) == before
        )
        # B's GitHub identity is not what makes it an owner, but an account keeps one identity.
        github_b = provider_identity(store, KEY_B, "github")
        assert store.unlink_identity(
            KEY_B, github_b, actor=KEY_B, listed_providers=LISTED
        ).ok
        assert store.count_usable_owners(LISTED) == 1

    def test_the_refusal_holds_for_the_operator_too(self, store: TokenStore) -> None:
        entra_a = rules_owner(store, OID_A, KEY_A, "1001")
        for actor in (KEY_A, OPERATOR):
            assert (
                store.unlink_identity(
                    KEY_A, entra_a, actor=actor, listed_providers=LISTED
                ).code
                == "last_owner"
            )
        assert providers(store, KEY_A) == ["entra", "github"]

    @pytest.mark.parametrize("source", ["operator", "bootstrap"])
    def test_an_owner_not_made_by_the_rules_may_unlink_entra_while_a_listed_identity_remains(
        self, store: TokenStore, source: str
    ) -> None:
        if source == "operator":
            assert store.promote_owner(KEY_A)
            key = KEY_A
        else:
            boot = AccessPolicy(
                mode="open",
                bootstrap_owner=acc.BootstrapOwner(
                    "entra", acc.entra_issuer(TENANT), OID_A
                ),
            )
            sign_in(store, OID_A, member=False, policy=boot)
            key = KEY_A
        assert store.get_principal_status(key).role_source == source
        assert link(store, key, gh(), policy=OPEN).ok
        assert store.count_usable_owners(LISTED) == 1
        entra = provider_identity(store, key, "entra")
        assert store.unlink_identity(key, entra, actor=key, listed_providers=LISTED).ok
        assert providers(store, key) == ["github"]
        assert (
            store.count_usable_owners(LISTED) == 1
        )  # still a usable owner through GitHub

    def test_a_non_rules_owner_cannot_unlink_its_last_listed_identity(
        self, store: TokenStore
    ) -> None:
        assert store.promote_owner(KEY_A)
        key = KEY_A
        assert link(store, key, gh(), policy=OPEN).ok
        github = provider_identity(store, key, "github")
        entra = provider_identity(store, key, "entra")
        only_github = frozenset({"github"})  # Entra was delisted
        assert (
            store.unlink_identity(
                key, github, actor=key, listed_providers=only_github
            ).code
            == "last_owner"
        )
        assert store.unlink_identity(
            key, entra, actor=key, listed_providers=only_github
        ).ok  # unlisted anyway

    def test_an_owner_that_is_already_unusable_may_change_its_identities(
        self, store: TokenStore
    ) -> None:
        entra_a = rules_owner(store, OID_A, KEY_A, "1001")
        only_github = frozenset(
            {"github"}
        )  # Entra delisted: the rules owner is stranded already
        assert store.count_usable_owners(only_github) == 0
        assert store.unlink_identity(
            KEY_A, entra_a, actor=KEY_A, listed_providers=only_github
        ).ok

    def test_an_owner_force_unlinking_anothers_last_usable_identity_is_refused(
        self, store: TokenStore
    ) -> None:
        assert store.promote_owner(KEY_A)
        target = KEY_A
        assert link(store, target, gh("1001"), policy=OPEN).ok
        github = provider_identity(store, target, "github")
        only_github = frozenset({"github"})
        actor = make_account(
            store, OID_C, role="owner"
        )  # Entra only: no usable sign-in
        assert store.count_usable_owners(only_github) == 1
        refused = store.unlink_identity(
            target, github, actor=actor, listed_providers=only_github
        )
        assert refused.code == "last_owner"
        assert providers(store, target) == ["entra", "github"]
        # A second usable owner makes the same force-unlink fine.
        assert link(store, actor, gh("1003"), policy=OPEN).ok
        assert store.unlink_identity(
            target, github, actor=actor, listed_providers=only_github
        ).ok
        assert actions(store, "identity_unlinked")[0].detail["by"] == "owner"

    def test_an_entra_only_deployment_keeps_its_rule(self, store: TokenStore) -> None:
        entra_only = frozenset({"entra"})
        entra_a = rules_owner(
            store, OID_A, KEY_A, "1001"
        )  # a stray identity at a provider that is not listed
        assert (
            store.unlink_identity(
                KEY_A, entra_a, actor=KEY_A, listed_providers=entra_only
            ).code
            == "last_owner"
        )
        github = provider_identity(store, KEY_A, "github")
        assert store.unlink_identity(
            KEY_A, github, actor=KEY_A, listed_providers=entra_only
        ).ok
        # A plain user is never held back.
        assert link(store, KEY_B, gh("1002"), policy=OPEN).ok
        entra_b = provider_identity(store, KEY_B, "entra")
        assert store.unlink_identity(
            KEY_B, entra_b, actor=KEY_B, listed_providers=entra_only
        ).ok

    def test_without_a_listed_set_every_provider_counts_as_listed(
        self, store: TokenStore
    ) -> None:
        entra_a = rules_owner(store, OID_A, KEY_A, "1001")
        assert store.count_usable_owners(None) == 1
        assert store.unlink_identity(KEY_A, entra_a, actor=KEY_A).code == "last_owner"

    def test_a_disabled_owner_does_not_count_as_usable(self, store: TokenStore) -> None:
        entra_a = rules_owner(store, OID_A, KEY_A, "1001")
        rules_owner(store, OID_B, KEY_B, "1002")
        assert store.disable_principal(
            KEY_B, actor=OPERATOR, reason="operator_disabled"
        )
        assert store.count_usable_owners(LISTED) == 1
        assert (
            store.unlink_identity(
                KEY_A, entra_a, actor=KEY_A, listed_providers=LISTED
            ).code
            == "last_owner"
        )

    def test_the_sql_count_is_the_pure_predicate(self, store: TokenStore) -> None:
        """``usable_owner_ids`` (a statement) and ``owner_is_usable`` (Python) agree on every combination."""
        db, repos = store.database, store._repos
        identity_sets = [
            (),
            ("entra",),
            ("github",),
            ("google",),
            ("entra", "github"),
            ("github", "google"),
            ("entra", "oidc:corp"),
            ("oidc:corp",),
        ]
        listed_sets: list[frozenset[str] | None] = [
            None,
            frozenset({"entra"}),
            frozenset({"github"}),
            frozenset({"entra", "google"}),
            frozenset({"oidc:corp"}),
            frozenset(),
        ]
        made: list[tuple[str, str, str, str | None, tuple[str, ...]]] = []
        n = 0
        with db.write() as conn:
            for role in ("owner", "user"):
                for status in ("active", "disabled", "pending"):
                    for source in (None, "rules", "bootstrap", "operator"):
                        for held in identity_sets:
                            n += 1
                            account_id = f"00000000-0000-4000-8000-{n:012d}"
                            repos.accounts.insert(
                                conn,
                                account_id=account_id,
                                status=status,
                                role=role,
                                role_source=source,
                                admitted_via="rules",
                                display_name="",
                                now=1,
                                approved_by=None,
                                disabled_reason="operator_disabled"
                                if status == "disabled"
                                else None,
                                disabled_by="operator"
                                if status == "disabled"
                                else None,
                            )
                            for i, provider in enumerate(held):
                                repos.identities.insert(
                                    conn,
                                    account_id=account_id,
                                    provider_id=provider,
                                    issuer=f"https://issuer.test/{provider}",
                                    subject=f"s{n}-{i}",
                                    username="",
                                    email=None,
                                    email_verified=False,
                                    now=1,
                                )
                            made.append((account_id, status, role, source, held))
        for listed in listed_sets:
            want = sorted(
                a
                for a, status, role, source, held in made
                if acc.owner_is_usable(
                    role=role,
                    status=status,
                    role_source=source,
                    identity_providers=held,
                    listed=listed,
                )
            )
            with db.read() as conn:
                got = sorted(
                    repos.accounts.usable_owner_ids(
                        conn, None if listed is None else sorted(listed)
                    )
                )
            assert got == want, listed
            assert store.count_usable_owners(listed) == len(want)


class TestBootstrapOwnerWithUnusableOwners:
    """Decision: the bootstrap owner applies while there is no usable owner (it is audited then)."""

    GOOGLE_ONLY = frozenset({"google"})
    BOOT = AccessPolicy(
        mode="open",
        ack_public=True,
        bootstrap_owner=acc.BootstrapOwner("google", acc.GOOGLE_ISSUER, "boot-1"),
    )

    def sign(
        self, store: TokenStore, ext: ExternalClaims, listed: frozenset[str] | None
    ) -> Any:
        return store.resolve_identity(
            ext,
            verdict_for(ext, self.BOOT),
            self.BOOT,
            purpose="sign_in",
            listed_providers=listed,
        )

    def test_it_fires_beside_owners_nobody_can_use_and_is_audited(
        self, store: TokenStore
    ) -> None:
        rules_owner(
            store, OID_A, KEY_A, "1001"
        )  # an Entra-rule owner; Entra is delisted below
        resolution = self.sign(store, google("boot-1"), self.GOOGLE_ONLY)
        assert resolution.created and resolution.session_owner
        key = resolution.principal_key
        assert key is not None
        status = store.get_principal_status(key)
        assert (status.role, status.role_source) == ("owner", "bootstrap")
        assert (
            store.get_principal_status(KEY_A).role == "owner"
        )  # the stranded owner stays an owner
        entry = next(e for e in actions(store, "role_changed") if e.target == key)
        assert entry.detail == {
            "role": "owner",
            "source": "bootstrap",
            "via": "sign_in",
            "unusable_owners": 1,
        }
        assert store.count_usable_owners(self.GOOGLE_ONLY) == 1

    def test_it_does_not_fire_while_a_usable_owner_exists(
        self, store: TokenStore
    ) -> None:
        rules_owner(store, OID_A, KEY_A, "1001")
        resolution = self.sign(store, google("boot-1"), frozenset({"entra", "google"}))
        assert resolution.created and not resolution.session_owner
        key = resolution.principal_key
        assert key is not None and store.get_principal_status(key).role == "user"

    def test_an_existing_account_of_the_bootstrap_identity_becomes_an_owner_too(
        self, store: TokenStore
    ) -> None:
        rules_owner(store, OID_A, KEY_A, "1001")
        first = self.sign(store, google("boot-1"), frozenset({"entra", "google"}))
        key = first.principal_key
        assert key is not None and store.get_principal_status(key).role == "user"
        again = self.sign(store, google("boot-1"), self.GOOGLE_ONLY)
        assert (
            again.session_owner
            and store.get_principal_status(key).role_source == "bootstrap"
        )
        entry = next(e for e in actions(store, "role_changed") if e.target == key)
        assert entry.detail["unusable_owners"] == 1

    def test_another_google_identity_never_becomes_an_owner(
        self, store: TokenStore
    ) -> None:
        rules_owner(store, OID_A, KEY_A, "1001")
        resolution = self.sign(store, google("someone-else"), self.GOOGLE_ONLY)
        assert resolution.created and not resolution.session_owner
        key = resolution.principal_key
        assert key is not None and store.get_principal_status(key).role == "user"
        assert store.count_usable_owners(self.GOOGLE_ONLY) == 0

    def test_without_any_owner_nothing_is_overridden_and_nothing_extra_is_audited(
        self, store: TokenStore
    ) -> None:
        resolution = self.sign(store, google("boot-1"), self.GOOGLE_ONLY)
        assert resolution.session_owner and resolution.principal_key is not None
        assert actions(store, "role_changed") == []


class TestStrandedOwnerAndTheBootstrapIdentity:
    """The bootstrap identity's own account is an owner no sign-in can use (Entra was delisted)."""

    GOOGLE_ONLY = frozenset({"google"})
    BOTH = frozenset({"entra", "google"})
    BOOT = TestBootstrapOwnerWithUnusableOwners.BOOT

    def sign(
        self,
        store: TokenStore,
        ext: ExternalClaims,
        listed: frozenset[str],
        policy: AccessPolicy = BOOT,
    ) -> Any:
        return store.resolve_identity(
            ext,
            verdict_for(ext, policy),
            policy,
            purpose="sign_in",
            listed_providers=listed,
        )

    def stranded(self, store: TokenStore) -> None:
        """A became an owner through the Entra owner rule and linked the bootstrap Google identity."""
        sign_in(store, OID_A, owner=True, policy=RULES_OWNER)
        assert store.get_principal_status(KEY_A).role_source == "rules"
        assert link(store, KEY_A, google("boot-1")).ok

    def test_its_own_sign_in_re_sources_the_owner_to_bootstrap(
        self, store: TokenStore
    ) -> None:
        self.stranded(store)
        assert store.count_usable_owners(self.BOTH) == 1  # usable while Entra is listed
        assert store.count_usable_owners(self.GOOGLE_ONLY) == 0
        resolution = self.sign(store, google("boot-1"), self.GOOGLE_ONLY)
        assert resolution.outcome == "allow" and resolution.session_owner
        assert resolution.principal_key == KEY_A and not resolution.created
        status = store.get_principal_status(KEY_A)
        assert (status.role, status.role_source) == ("owner", "bootstrap")
        assert store.count_usable_owners(self.GOOGLE_ONLY) == 1
        entry = next(e for e in actions(store, "role_changed") if e.target == KEY_A)
        # The account itself is not "an owner this overrides": nothing else was stranded.
        assert entry.detail == {
            "role": "owner",
            "source": "bootstrap",
            "via": "sign_in",
            "was": "rules",
        }
        # It was an owner already: the history says it was re-sourced, not that it gained the role.
        assert resolution.owner_change == acc.EVENT_OWNER_RESOURCED
        assert entry.action == "role_changed" and entry.detail["was"] == "rules"
        # A second sign-in changes nothing more and is still an owner session.
        before = len(list(store.iter_audit()))
        again = self.sign(store, google("boot-1"), self.GOOGLE_ONLY)
        assert again.session_owner and len(list(store.iter_audit())) == before

    def test_other_stranded_owners_are_counted_but_the_account_itself_is_not(
        self, store: TokenStore
    ) -> None:
        self.stranded(store)
        sign_in(
            store, OID_B, owner=True, policy=RULES_OWNER
        )  # a second owner nobody can use
        self.sign(store, google("boot-1"), self.GOOGLE_ONLY)
        entry = next(e for e in actions(store, "role_changed") if e.target == KEY_A)
        assert entry.detail["unusable_owners"] == 1 and entry.detail["was"] == "rules"

    def test_it_is_left_alone_while_a_usable_owner_exists(
        self, store: TokenStore
    ) -> None:
        self.stranded(store)
        store.create_operator_account(
            provider_id="google",
            issuer=acc.GOOGLE_ISSUER,
            subject="someone-else",
            status="active",
            role="owner",
        )
        assert store.count_usable_owners(self.GOOGLE_ONLY) == 1
        resolution = self.sign(store, google("boot-1"), self.GOOGLE_ONLY)
        assert resolution.outcome == "allow" and not resolution.session_owner
        assert store.get_principal_status(KEY_A).role_source == "rules"

    def test_a_usable_rules_owner_is_not_re_sourced(self, store: TokenStore) -> None:
        self.stranded(store)
        resolution = self.sign(store, google("boot-1"), self.BOTH)
        assert not resolution.session_owner  # Google data never shows an owner role
        assert store.get_principal_status(KEY_A).role_source == "rules"

    def test_promote_owner_re_sources_an_unusable_owner_to_operator(
        self, store: TokenStore
    ) -> None:
        self.stranded(store)
        assert store.promote_owner(KEY_A, listed_providers=self.GOOGLE_ONLY) is True
        status = store.get_principal_status(KEY_A)
        assert (status.role, status.role_source) == ("owner", "operator")
        assert store.count_usable_owners(self.GOOGLE_ONLY) == 1
        entry = next(
            e
            for e in actions(store, "role_changed")
            if e.target == KEY_A and e.actor == "operator"
        )
        assert entry.detail == {
            "role": "owner",
            "source": "operator",
            "was": "rules",
        }  # A was already personal
        assert (
            store.promote_owner(KEY_A, listed_providers=self.GOOGLE_ONLY) is False
        )  # nothing left to do

    def test_promote_owner_leaves_a_usable_owner_alone(self, store: TokenStore) -> None:
        self.stranded(store)
        assert store.promote_owner(KEY_A) is False  # every provider listed
        assert store.promote_owner(KEY_A, listed_providers=self.BOTH) is False
        assert store.get_principal_status(KEY_A).role_source == "rules"

    def test_promote_owner_does_not_touch_an_owner_it_could_not_make_usable(
        self, store: TokenStore
    ) -> None:
        sign_in(store, OID_A, owner=True, policy=RULES_OWNER)  # an Entra identity only
        assert store.promote_owner(KEY_A, listed_providers=self.GOOGLE_ONLY) is False
        assert store.get_principal_status(KEY_A).role_source == "rules"

    def test_an_active_account_the_rules_no_longer_admit_is_admitted_as_the_bootstrap_identity(
        self, store: TokenStore
    ) -> None:
        domain = lambda d: AccessPolicy(  # noqa: E731
            mode="rules",
            rules=(acc.AccessRule("google", "domain", d),),
            owner_rules=(),
            bootstrap_owner=self.BOOT.bootstrap_owner,
            ack_public=True,
        )
        sign_in(store, OID_A, owner=True, policy=RULES_OWNER)  # a usable owner, for now
        created = self.sign(store, google("boot-1"), self.BOTH, domain("example.test"))
        assert created.created and not created.session_owner
        key = created.principal_key
        assert (
            key is not None and store.get_principal_status(key).admitted_via == "rules"
        )
        # The domain rule moves on. While an owner is usable the account is refused, as before.
        refused = self.sign(store, google("boot-1"), self.BOTH, domain("other.edu"))
        assert refused.outcome == "deny" and refused.reason == "access_denied"
        # With no usable owner the bootstrap identity is admitted, like a new or pending one.
        admitted = self.sign(
            store, google("boot-1"), self.GOOGLE_ONLY, domain("other.edu")
        )
        assert admitted.outcome == "allow" and admitted.session_owner
        assert store.get_principal_status(key).role_source == "bootstrap"
        # Another account of the same rules stays refused.
        assert (
            self.sign(
                store, google("someone"), self.GOOGLE_ONLY, domain("other.edu")
            ).outcome
            == "deny"
        )

    def test_the_bootstrap_owner_the_rules_do_not_admit_can_sign_in_again(
        self, store: TokenStore
    ) -> None:
        domain = lambda d: AccessPolicy(  # noqa: E731
            mode="rules",
            rules=(acc.AccessRule("google", "domain", d),),
            owner_rules=(),
            bootstrap_owner=self.BOOT.bootstrap_owner,
            ack_public=True,
        )
        sign_in(store, OID_A, owner=True, policy=RULES_OWNER)
        created = self.sign(store, google("boot-1"), self.BOTH, domain("example.test"))
        key = created.principal_key
        assert (
            key is not None and store.get_principal_status(key).admitted_via == "rules"
        )
        first = self.sign(
            store, google("boot-1"), self.GOOGLE_ONLY, domain("other.edu")
        )
        assert first.session_owner
        status = store.get_principal_status(key)
        assert (status.role_source, status.admitted_via) == ("bootstrap", "bootstrap")
        entry = next(e for e in actions(store, "role_changed") if e.target == key)
        assert entry.detail["admitted_via"] == "bootstrap"
        # It is a usable owner now, so the bootstrap no longer applies, and the rules must not
        # lock it out: every later sign-in is an owner session.
        assert store.count_usable_owners(self.GOOGLE_ONLY) == 1
        for _ in range(2):
            again = self.sign(
                store, google("boot-1"), self.GOOGLE_ONLY, domain("other.edu")
            )
            assert again.outcome == "allow" and again.session_owner
        # Another account of the same rules is still refused.
        assert (
            self.sign(
                store, google("someone"), self.GOOGLE_ONLY, domain("other.edu")
            ).outcome
            == "deny"
        )

    def stranded_by_rules(self, store: TokenStore) -> str:
        """Like :meth:`stranded`, for a new account the owner rule admitted (``admitted_via='rules'``)."""
        sign_in(store, OID_C, owner=True, policy=RULES_OWNER)
        status = store.get_principal_status(KEY_C)
        assert (status.role_source, status.admitted_via) == ("rules", "rules")
        assert link(store, KEY_C, google("boot-1")).ok
        return KEY_C

    OTHER_DOMAIN = AccessPolicy(
        mode="rules",
        rules=(acc.AccessRule("google", "domain", "other.edu"),),
        owner_rules=(),
        bootstrap_owner=BOOT.bootstrap_owner,
        ack_public=True,
    )

    def test_a_re_sourced_owner_the_rules_do_not_admit_can_sign_in_again(
        self, store: TokenStore
    ) -> None:
        # The stranded Entra-rule owner (admitted by the owner rule) links Google, the rules move
        # on, and the bootstrap sign-in must not be the owner's last.
        key = self.stranded_by_rules(store)
        first = self.sign(store, google("boot-1"), self.GOOGLE_ONLY, self.OTHER_DOMAIN)
        assert first.outcome == "allow" and first.session_owner
        assert store.get_principal_status(key).admitted_via == "bootstrap"
        entry = next(e for e in actions(store, "role_changed") if e.target == key)
        assert entry.detail["admitted_via"] == "bootstrap"
        for _ in range(2):
            again = self.sign(
                store, google("boot-1"), self.GOOGLE_ONLY, self.OTHER_DOMAIN
            )
            assert again.outcome == "allow" and again.session_owner

    def test_promoting_an_already_personally_admitted_user_keeps_its_admission(
        self, store: TokenStore
    ) -> None:
        sign_in(store, OID_B)
        before = store.get_principal_status(KEY_B)
        assert before.role == "user"
        assert store.promote_owner(KEY_B, listed_providers=self.BOTH) is True
        after = store.get_principal_status(KEY_B)
        assert (after.role, after.role_source) == ("owner", "operator")
        assert after.admitted_via == before.admitted_via
        entry = next(e for e in actions(store, "role_changed") if e.target == KEY_B)
        assert entry.detail == {"role": "owner", "source": "operator"}

    def test_a_promoted_owner_the_rules_do_not_admit_can_sign_in_again(
        self, store: TokenStore
    ) -> None:
        key = self.stranded_by_rules(store)
        no_bootstrap = AccessPolicy(
            mode="rules",
            rules=(acc.AccessRule("google", "domain", "other.edu"),),
            owner_rules=(),
            ack_public=True,
        )
        assert (
            self.sign(store, google("boot-1"), self.GOOGLE_ONLY, no_bootstrap).outcome
            == "deny"
        )
        assert store.promote_owner(key, listed_providers=self.GOOGLE_ONLY) is True
        assert store.get_principal_status(key).admitted_via == "operator"
        entry = next(
            e
            for e in actions(store, "role_changed")
            if e.target == key and e.actor == "operator"
        )
        assert entry.detail == {
            "role": "owner",
            "source": "operator",
            "was": "rules",
            "admitted_via": "operator",
        }
        again = self.sign(store, google("boot-1"), self.GOOGLE_ONLY, no_bootstrap)
        assert again.outcome == "allow"


class TestUsableOwnerGuards:
    """UO-1: disabling and demoting count usable owners, so a stranded owner is no replacement."""

    def stranded_pair(self, store: TokenStore) -> None:
        """A and B are rules owners; A unlinked Entra, so A is a stranded owner and B the only usable one."""
        entra_a = rules_owner(store, OID_A, KEY_A, "1001")
        rules_owner(store, OID_B, KEY_B, "1002")
        assert store.unlink_identity(
            KEY_A, entra_a, actor=KEY_A, listed_providers=LISTED
        ).ok
        assert store.count_usable_owners(LISTED) == 1
        assert store.get_principal_status(KEY_A).role == "owner"

    def test_the_operator_cannot_disable_the_last_usable_owner_beside_a_stranded_one(
        self, store: TokenStore
    ) -> None:
        self.stranded_pair(store)
        with pytest.raises(AccessActionRefused) as excinfo:
            store.disable_principal(
                KEY_B,
                actor=OPERATOR,
                reason="operator_disabled",
                listed_providers=LISTED,
            )
        assert excinfo.value.code == AccessActionRefused.LAST_OWNER
        assert store.get_principal_status(KEY_B).status == "active"
        assert store.count_usable_owners(LISTED) == 1
        # The operator's explicit override still works.
        assert store.disable_principal(
            KEY_B,
            actor=OPERATOR,
            reason="operator_disabled",
            allow_last_owner=True,
            listed_providers=LISTED,
        )

    def test_disabling_a_stranded_owner_or_a_usable_owner_beside_another_usable_one_is_fine(
        self, store: TokenStore
    ) -> None:
        self.stranded_pair(store)
        assert store.disable_principal(
            KEY_A, actor=OPERATOR, reason="operator_disabled", listed_providers=LISTED
        )
        assert store.count_usable_owners(LISTED) == 1
        assert store.enable_principal(KEY_A, actor=OPERATOR)
        third = make_account(store, OID_C, role="owner")
        assert link(store, third, gh("1003"), policy=OPEN).ok
        assert store.disable_principal(
            KEY_B, actor=OPERATOR, reason="operator_disabled", listed_providers=LISTED
        )

    def test_the_last_active_owner_of_any_kind_is_still_protected(
        self, store: TokenStore
    ) -> None:
        entra_a = rules_owner(store, OID_A, KEY_A, "1001")
        assert (
            store.unlink_identity(
                KEY_A, entra_a, actor=KEY_A, listed_providers=LISTED
            ).code
            == "last_owner"
        )
        only_github = frozenset(
            {"github"}
        )  # Entra delisted: A is the one active owner and is unusable
        assert store.count_usable_owners(only_github) == 0
        with pytest.raises(AccessActionRefused):
            store.disable_principal(
                KEY_A,
                actor=OPERATOR,
                reason="operator_disabled",
                listed_providers=only_github,
            )

    def test_a_disable_and_an_unlink_racing_for_the_last_usable_owner_serialise(
        self, pair: tuple[TokenStore, TokenStore]
    ) -> None:
        first, second = pair
        entra_a = rules_owner(first, OID_A, KEY_A, "1001")
        rules_owner(first, OID_B, KEY_B, "1002")
        gate = Gate("after_owner_count")
        first._pause_hook = gate
        disabling = Runner(
            lambda: first.disable_principal(
                KEY_B,
                actor=OPERATOR,
                reason="operator_disabled",
                listed_providers=LISTED,
            )
        )
        assert gate.reached.wait(WAIT)
        unlinking = Runner(
            lambda: second.unlink_identity(
                KEY_A, entra_a, actor=KEY_A, listed_providers=LISTED
            )
        )
        assert unlinking.blocked()
        gate.release.set()
        assert disabling.join() is True  # B was disabled while A was still usable
        assert (
            unlinking.join().code == "last_owner"
        )  # and then A is the last usable owner
        assert first.count_usable_owners(LISTED) == 1

    # Bearer-token owner demotion belonged to the retired Entra proxy.
    # Native owner changes come from verified sign-in and retain the guards below.

    def test_a_sign_in_without_the_owner_role_does_not_demote_the_last_usable_owner(
        self, store: TokenStore
    ) -> None:
        self.stranded_pair(store)
        ext = external(OID_B)
        resolution = store.resolve_identity(
            ext,
            Verdict(admitted_by_rule=True, owner_by_rule=False),
            TestUnlink.RULES_OWNER,
            purpose="sign_in",
            listed_providers=LISTED,
        )
        assert resolution.allowed and not resolution.session_owner
        assert store.get_principal_status(KEY_B).role == "owner"
        assert store.count_usable_owners(LISTED) == 1
        assert any(
            e.target == KEY_B and e.reason == "last_owner"
            for e in actions(store, "owner_loss_refused_last_owner")
        )

    def test_a_sign_in_without_the_owner_role_demotes_beside_a_usable_owner(
        self, store: TokenStore
    ) -> None:
        rules_owner(store, OID_A, KEY_A, "1001")
        rules_owner(store, OID_B, KEY_B, "1002")
        store.resolve_identity(
            external(OID_B),
            Verdict(admitted_by_rule=True, owner_by_rule=False),
            TestUnlink.RULES_OWNER,
            purpose="sign_in",
            listed_providers=LISTED,
        )
        assert store.get_principal_status(KEY_B).role == "user"


class TestUsableOwnerRaces:
    def test_two_rules_owners_unlinking_entra_at_once_exactly_one_is_refused(
        self, pair: tuple[TokenStore, TokenStore]
    ) -> None:
        first, second = pair
        entra_a = rules_owner(first, OID_A, KEY_A, "1001")
        entra_b = rules_owner(first, OID_B, KEY_B, "1002")
        gate = Gate("after_owner_count")
        first._pause_hook = gate
        one = Runner(
            lambda: first.unlink_identity(
                KEY_A, entra_a, actor=KEY_A, listed_providers=LISTED
            )
        )
        assert gate.reached.wait(WAIT)
        two = Runner(
            lambda: second.unlink_identity(
                KEY_B, entra_b, actor=KEY_B, listed_providers=LISTED
            )
        )
        assert two.blocked()  # the writer lock serialises the two transactions
        gate.release.set()
        assert sorted([one.join().code, two.join().code]) == ["last_owner", "unlinked"]
        assert first.count_usable_owners(LISTED) == 1
        stranded = [k for k in (KEY_A, KEY_B) if "entra" not in providers(first, k)]
        assert len(stranded) == 1

    def test_owners_force_unlinking_each_others_entra_identity_never_empty_the_set(
        self, pair: tuple[TokenStore, TokenStore]
    ) -> None:
        first, second = pair
        entra_a = rules_owner(first, OID_A, KEY_A, "1001")
        rules_owner(first, OID_B, KEY_B, "1002")
        entra_b = provider_identity(first, KEY_B, "entra")
        gate = Gate("after_owner_count")
        first._pause_hook = gate
        one = Runner(
            lambda: first.unlink_identity(
                KEY_A, entra_a, actor=KEY_B, listed_providers=LISTED
            )
        )
        assert gate.reached.wait(WAIT)
        two = Runner(
            lambda: second.unlink_identity(
                KEY_B, entra_b, actor=KEY_A, listed_providers=LISTED
            )
        )
        assert two.blocked()
        gate.release.set()
        assert sorted([one.join().code, two.join().code]) == ["last_owner", "unlinked"]
        assert first.count_usable_owners(LISTED) == 1
