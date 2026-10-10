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
        assert entry.detail["unusable_owners"] == 1 and entry.detail["was"] == "rules"
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
