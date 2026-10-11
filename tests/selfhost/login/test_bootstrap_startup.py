"""The bootstrap identity at startup and sign-in when its own account is an owner nobody can use."""

from __future__ import annotations

import pathlib

import pytest

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.accounts import (
    AccessPolicy,
    AccountFacts,
    BootstrapOwner,
    ExternalClaims,
    bootstrap_sign_in_gives_owner,
    evaluate_admission,
)
from canvas_mcp.core.selfhost.app import prepare_selfhost
from canvas_mcp.core.selfhost.settings import (
    SelfhostConfigError,
    load_selfhost_settings,
)

from ..authz.stack import default_env
from ..conftest import OID_A, acct_key, sign_in
from .test_provider_settings import GOOGLE_ID, GOOGLE_SECRET

GSUB = "1234567890"
BOTH = {
    "SELFHOST_LOGIN_PROVIDERS": "entra,google",
    "GOOGLE_CLIENT_ID": GOOGLE_ID,
    "GOOGLE_CLIENT_SECRET": GOOGLE_SECRET,
    "ACCESS_POLICY": "open",
    "ACCESS_OPEN_ACKNOWLEDGE_PUBLIC": "true",
}
NO_ENTRA = {
    "SELFHOST_LOGIN_PROVIDERS": "google",
    "ENTRA_TENANT_ID": "",
    "ENTRA_CLIENT_ID": "",
    "ENTRA_CLIENT_SECRET": "",
}


def gext() -> ExternalClaims:
    return ExternalClaims(
        provider_id="google", issuer=acc.GOOGLE_ISSUER, subject=GSUB,
        email="x@example.edu", email_verified=True, hd="example.edu",
    )


def link_google(store, key: str) -> None:  # type: ignore[no-untyped-def]
    ext = gext()
    policy = AccessPolicy(mode="open")
    result = store.link_identity(
        key, ext, evaluate_admission(ext, policy), policy,
        expected_epoch=store.get_principal_status(key).session_epoch,
    )
    assert result.ok, result


def test_a_stranded_rules_owner_named_as_the_bootstrap_identity_signs_in_as_an_owner(
    tmp_path: pathlib.Path,
) -> None:
    # entra + google: X becomes an owner through the Entra owner rule and links Google.
    base_env = default_env(tmp_path, **BOTH)  # built once: on PostgreSQL building it resets the schema
    first = prepare_selfhost(load_selfhost_settings(base_env))
    sign_in(first.store, OID_A, owner=True)
    key = acct_key(OID_A)
    link_google(first.store, key)
    first.store.close()

    # Entra is delisted and no bootstrap is named: refused, recommending SELFHOST_BOOTSTRAP_OWNER.
    google_only = {**base_env, **NO_ENTRA}
    with pytest.raises(SelfhostConfigError) as info:
        prepare_selfhost(load_selfhost_settings(google_only))
    assert "SELFHOST_BOOTSTRAP_OWNER" in info.value.problems[0]

    # The operator names X's own Google identity: the server starts, and the sign-in is an owner session.
    named = {**google_only, "SELFHOST_BOOTSTRAP_OWNER": f"google:{GSUB}"}
    runtime = prepare_selfhost(load_selfhost_settings(named))
    try:
        listed = runtime.settings.login_providers.ids
        assert runtime.store.count_usable_owners(listed) == 0
        signed = runtime.identity.sign_in_external(gext())
        assert not isinstance(signed, acc.Denied) and signed.owner
        status = runtime.store.get_principal_status(key)
        assert (status.role, status.role_source) == ("owner", "bootstrap")
        assert runtime.store.count_usable_owners(listed) == 1
        entry = next(
            e for e in runtime.store.list_audit(100) if e.action == "role_changed" and e.target == key
        )
        assert entry.detail["was"] == "rules" and "unusable_owners" not in entry.detail
        assert runtime.store.list_status_events(key)[0].action == "owner_re_sourced"
    finally:
        runtime.store.close()
    # With a usable owner the startup check is satisfied without the bootstrap identity.
    again = prepare_selfhost(load_selfhost_settings(google_only))
    again.store.close()


def test_promote_owner_fixes_the_same_stranded_owner_for_the_operator(tmp_path: pathlib.Path) -> None:
    base_env = default_env(tmp_path, **BOTH)
    first = prepare_selfhost(load_selfhost_settings(base_env))
    sign_in(first.store, OID_A, owner=True)
    key = acct_key(OID_A)
    link_google(first.store, key)
    try:
        google = frozenset({"google"})
        assert first.store.count_usable_owners(google) == 0
        assert first.store.promote_owner(key, listed_providers=google) is True
        assert first.store.count_usable_owners(google) == 1
        assert first.store.get_principal_status(key).role_source == "operator"
    finally:
        first.store.close()
    # The operator's choice now starts a google-only server with no bootstrap identity at all.
    runtime = prepare_selfhost(load_selfhost_settings({**base_env, **NO_ENTRA}))
    runtime.store.close()


def test_a_bootstrap_account_the_rules_no_longer_admit_does_not_stop_the_server(
    tmp_path: pathlib.Path,
) -> None:
    rules = {
        **BOTH, **NO_ENTRA, "ACCESS_POLICY": "rules", "ACCESS_RULES": "google:domain:example.edu",
    }
    base_env = default_env(tmp_path, **rules, SELFHOST_BOOTSTRAP_OWNER="token_admin")
    first = prepare_selfhost(load_selfhost_settings(base_env))
    # X signs in once as a user, admitted by the domain rule.
    assert not isinstance(first.identity.sign_in_external(gext()), acc.Denied)
    xkey = first.store.lookup_identity("google", acc.GOOGLE_ISSUER, GSUB)
    assert xkey is not None and first.store.get_principal_status(xkey).role == "user"
    # A stranded owner (an Entra identity only), so startup needs the bootstrap.
    first.store.create_operator_account(
        provider_id="entra", issuer=acc.entra_issuer("11111111-2222-3333-4444-555555555555"),
        subject="ffffffff-0000-4000-8000-00000000000f", status="active", role="owner",
    )
    first.store.close()
    # The domain rule changes: X's account (admitted through the rule) is no longer admitted.
    moved = {**base_env, "ACCESS_RULES": "google:domain:other.edu", "SELFHOST_BOOTSTRAP_OWNER": f"google:{GSUB}"}
    runtime = prepare_selfhost(load_selfhost_settings(moved))
    try:
        listed = runtime.settings.login_providers.ids
        assert runtime.store.count_usable_owners(listed) == 0
        signed = runtime.identity.sign_in_external(gext())
        assert not isinstance(signed, acc.Denied) and signed.owner
        assert runtime.store.get_principal_status(xkey).role_source == "bootstrap"
        assert runtime.store.count_usable_owners(listed) == 1
        entry = next(
            e for e in runtime.store.list_audit(100) if e.action == "role_changed" and e.target == xkey
        )
        assert entry.detail["unusable_owners"] == 1  # the Entra-only owner, not X itself
    finally:
        runtime.store.close()
    # The rules still do not admit X, but the owner is a personal admission now: it can sign in
    # again, also after a restart (the bootstrap no longer applies, so only that admission holds).
    for _ in range(2):
        restarted = prepare_selfhost(load_selfhost_settings(moved))
        try:
            assert restarted.store.get_principal_status(xkey).admitted_via == "bootstrap"
            signed = restarted.identity.sign_in_external(gext())
            assert not isinstance(signed, acc.Denied) and signed.owner
            again = restarted.identity.sign_in_external(gext())
            assert not isinstance(again, acc.Denied) and again.owner
        finally:
            restarted.store.close()


def test_a_re_sourced_owner_the_rules_do_not_admit_keeps_signing_in_after_a_restart(
    tmp_path: pathlib.Path,
) -> None:
    # X: an Entra-rule owner (admitted by the owner rule while the policy was open) who linked Google.
    base_env = default_env(tmp_path, **BOTH)
    first = prepare_selfhost(load_selfhost_settings(base_env))
    sign_in(first.store, OID_A, owner=True)
    key = acct_key(OID_A)
    link_google(first.store, key)
    assert first.store.get_principal_status(key).admitted_via == "rules"
    first.store.close()
    # Entra is delisted, the policy becomes rules that do not admit Google, and the operator
    # names X's Google identity as the bootstrap owner.
    named = {
        **base_env, **NO_ENTRA, "ACCESS_POLICY": "rules", "ACCESS_RULES": "google:domain:other.edu",
        "SELFHOST_BOOTSTRAP_OWNER": f"google:{GSUB}",
    }
    for _ in range(3):  # three starts, each followed by a sign-in
        runtime = prepare_selfhost(load_selfhost_settings(named))
        try:
            signed = runtime.identity.sign_in_external(gext())
            assert not isinstance(signed, acc.Denied) and signed.owner, signed
            status = runtime.store.get_principal_status(key)
            assert (status.role_source, status.admitted_via) == ("bootstrap", "bootstrap")
        finally:
            runtime.store.close()


def test_the_record_of_a_refused_start_is_the_list_it_was_refused_for(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from canvas_mcp.core.selfhost import token_admin

    base_env = default_env(tmp_path, **BOTH)
    first = prepare_selfhost(load_selfhost_settings(base_env))
    sign_in(first.store, OID_A, owner=True)
    key = acct_key(OID_A)
    link_google(first.store, key)
    assert first.store.recorded_login_providers() == frozenset({"entra", "google"})
    first.store.close()
    # Entra is delisted and nobody is named: startup refuses and recommends token_admin.
    google_only = {**base_env, **NO_ENTRA}
    with pytest.raises(SelfhostConfigError) as info:
        prepare_selfhost(load_selfhost_settings(google_only))
    assert "promote-owner ACCOUNT" in info.value.problems[0]
    # The operator follows it from a shell with the new variables: the stale list ("entra,google")
    # must not make X look usable ("nothing to do ... already an owner").
    for name, value in google_only.items():
        monkeypatch.setenv(name, value)
    capsys.readouterr()
    assert token_admin.main(["promote-owner", key]) == 0
    assert "promoted 1 account to owner" in capsys.readouterr().out
    runtime = prepare_selfhost(load_selfhost_settings(google_only))
    try:
        assert runtime.store.recorded_login_providers() == frozenset({"google"})
        assert runtime.store.get_principal_status(key).role_source == "operator"
        # And an operator owner is not locked out by the rules either.
        assert runtime.store.get_principal_status(key).admitted_via == "operator"
    finally:
        runtime.store.close()


class TestBootstrapSignInGivesOwner:
    """The pure answer the startup check uses: the same table as the sign-in."""

    POLICY = AccessPolicy(
        mode="rules",
        rules=(acc.AccessRule("google", "domain", "other.edu"),),
        bootstrap_owner=BootstrapOwner("google", acc.GOOGLE_ISSUER, GSUB),
    )

    def answer(self, existing: AccountFacts | None, policy: AccessPolicy = POLICY) -> bool:
        return bootstrap_sign_in_gives_owner(existing, policy)

    def test_the_states_where_the_sign_in_makes_an_owner(self) -> None:
        assert self.answer(None)  # no account yet: created as the owner, whatever the rules say
        assert self.answer(AccountFacts("pending"))
        assert self.answer(AccountFacts("active"))  # admitted whatever the rules say
        assert self.answer(AccountFacts("active", "owner", "rules"))  # re-sourced to bootstrap
        assert self.answer(AccountFacts("active", "owner", "bootstrap"))
        assert self.answer(AccountFacts("active", "owner", "operator"))

    def test_the_states_where_it_cannot(self) -> None:
        assert not self.answer(AccountFacts("disabled"))
        assert not self.answer(AccountFacts("disabled", "owner", "bootstrap"))
        assert not self.answer(None, AccessPolicy(mode="rules"))  # no bootstrap identity named


class TestBootstrapAdmissionIsPersonal:
    """``decide`` marks the account the bootstrap admits or promotes as personally admitted."""

    POLICY = TestBootstrapSignInGivesOwner.POLICY
    FACTS = acc.DecisionFacts(
        active_owner_count=1, usable_owner_count=0, is_bootstrap_identity=True,
        existing_owner_usable=False,
    )
    VERDICT = acc.Verdict(admitted_by_rule=False, owner_by_rule=False, owner_evidence=False)

    def decision(self, existing: AccountFacts, *, purpose: str = "sign_in") -> acc.Decision:
        return acc.decide(existing, self.VERDICT, self.POLICY, self.FACTS, purpose)  # type: ignore[arg-type]

    @pytest.mark.parametrize("via", ["rules", "open"])
    def test_a_rules_or_open_admission_becomes_bootstrap(self, via: str) -> None:
        for existing in (
            AccountFacts("active", "user", None, via),
            AccountFacts("active", "owner", "rules", via),
        ):
            decision = self.decision(existing)
            assert decision.outcome == "allow" and decision.session_owner
            assert (decision.role, decision.role_source) == ("owner", "bootstrap")
            assert decision.admitted_via == "bootstrap"

    @pytest.mark.parametrize("via", ["operator", "approval", "bootstrap"])
    def test_a_personal_admission_is_kept(self, via: str) -> None:
        decision = self.decision(AccountFacts("active", "owner", "rules", via))
        assert decision.session_owner and decision.admitted_via is None

    def test_the_request_path_changes_nothing(self) -> None:
        decision = self.decision(AccountFacts("active", "user", None, "rules"), purpose="request")
        assert decision.outcome == "allow" and decision.role is None and decision.admitted_via is None
        assert not decision.writes


def test_the_server_records_the_providers_it_runs_with(tmp_path: pathlib.Path) -> None:
    both = default_env(tmp_path, **BOTH)
    entra_only = {
        k: v for k, v in both.items()
        if k not in ("SELFHOST_LOGIN_PROVIDERS", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
                     "ACCESS_OPEN_ACKNOWLEDGE_PUBLIC", "ACCESS_POLICY")
    }
    # A deployment with Entra alone and no earlier record keeps its database as it was.
    plain = prepare_selfhost(load_selfhost_settings(entra_only))
    assert plain.store.recorded_login_providers() is None
    plain.store.close()
    # Listing more providers records them (a restart with the same list writes nothing new).
    runtime = prepare_selfhost(load_selfhost_settings(both))
    assert runtime.store.recorded_login_providers() == frozenset({"entra", "google"})
    runtime.store.close()
    again = prepare_selfhost(load_selfhost_settings(both))
    assert again.store.recorded_login_providers() == frozenset({"entra", "google"})
    again.store.close()
    # Going back to Entra alone replaces the record, so a stale list is never read.
    back = prepare_selfhost(load_selfhost_settings(entra_only))
    assert back.store.recorded_login_providers() == frozenset({"entra"})
    back.store.close()
