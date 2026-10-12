"""Provider-instance association and immutable, provider-neutral ownership."""

from dataclasses import replace

import pytest
from sqlalchemy import insert, update

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.db.errors import TokenStoreError

from .test_link_store import KEY_A, KEY_B, OPEN, google, verdict_for
from .test_link_store import store as store_fixture

store = store_fixture


def signin(store, ext):
    return store.resolve_identity(ext, verdict_for(ext), OPEN, purpose="sign_in")


def enable(store, provider, automatic):
    with store._db.write() as conn:
        store._repos.providers.ensure(conn, provider, now=1)
        conn.execute(
            update(s.login_providers)
            .where(s.login_providers.c.id == provider)
            .values(configured=True, auto_link_email=automatic)
        )


def test_google_then_entra_enters_same_account_without_mailbox_challenge(store):
    first = signin(store, google())
    assert first.created
    key = first.status.principal_key
    ext = acc.ExternalClaims(
        provider_id="entra",
        issuer=acc.entra_issuer("11111111-2222-3333-4444-555555555555"),
        subject="new-object",
        username="g@example.test",
        email_verified=False,
    )
    enable(store, "entra", True)
    second = signin(store, ext)
    assert second.outcome == "allow" and second.status.principal_key == key
    assert not second.created
    assert {i.provider_id for i in store.list_identities(key)} == {"google", "entra"}
    # Mutable matching claims cannot transfer an already bound subject.
    changed = signin(store, replace(ext, username="somebody-else@example.test"))
    assert changed.status.principal_key == key


def test_custom_oidc_instances_have_independent_switches(store):
    first = signin(store, google())
    one = acc.ExternalClaims(
        provider_id="oidc:one",
        issuer="https://sso.one.test",
        subject="immutable-1",
        email="g@example.test",
    )
    two = replace(
        one,
        provider_id="oidc:two",
        issuer="https://sso.two.test",
        subject="immutable-2",
    )
    enable(store, one.provider_id, True)
    enable(store, two.provider_id, False)
    assert signin(store, one).status.principal_key == first.status.principal_key
    separate = signin(store, two)
    assert (
        separate.created and separate.status.principal_key != first.status.principal_key
    )


def test_google_can_associate_to_existing_entra_upn_after_account_upn_rename(store):
    from canvas_mcp.core.selfhost.login.account_names import AccountNames

    ext = acc.ExternalClaims(
        provider_id="entra",
        issuer=acc.entra_issuer("11111111-2222-3333-4444-555555555555"),
        subject="existing-object",
        username="G@Example.Test",
    )
    first = signin(store, ext)
    key = first.status.principal_key
    AccountNames(store._db).save(
        "chosen.account.upn",
        account_id=key,
        expected_epoch=first.status.session_epoch,
        now=2,
    )
    enable(store, "google", True)
    second = signin(store, google())
    assert second.status.principal_key == key and not second.created
    assert {identity.provider_id for identity in store.list_identities(key)} == {
        "entra",
        "google",
    }
    assert AccountNames(store._db).read(key)["upn"] == "chosen.account.upn"


@pytest.mark.parametrize("restriction", ["lock", "allowlist", "multiple"])
def test_account_restrictions_precede_automatic_association(store, restriction):
    first = signin(store, google())
    key = first.status.principal_key
    with store._db.write() as conn:
        values = {"account_id": key}
        if restriction == "lock":
            values["sso_lock_provider"] = "google"
        elif restriction == "allowlist":
            values["restrict_providers"] = True
        else:
            values["allow_multiple"] = False
        conn.execute(insert(s.account_login_policy).values(**values))
    ext = acc.ExternalClaims(
        provider_id="oidc:other",
        issuer="https://other.test",
        subject="other",
        email="g@example.test",
    )
    enable(store, ext.provider_id, True)
    result = signin(store, ext)
    assert result.outcome == "deny" and not result.created
    assert [i.provider_id for i in store.list_identities(key)] == ["google"]


def test_same_canonical_subject_cannot_be_owned_by_two_accounts(store):
    with store._db.write() as conn:
        store._repos.identities.insert(
            conn,
            account_id=KEY_A,
            provider_id="oidc:one",
            issuer="https://same.test",
            subject="same",
            username="",
            email=None,
            email_verified=False,
            now=1,
        )
    with pytest.raises(TokenStoreError, match="already belongs"):
        with store._db.write() as conn:
            store._repos.identities.insert(
                conn,
                account_id=KEY_B,
                provider_id="oidc:two",
                issuer="https://same.test",
                subject="same",
                username="",
                email=None,
                email_verified=False,
                now=1,
            )


def test_first_sso_lock_and_admin_unlock_preserve_identity(store):
    from canvas_mcp.core.selfhost.login.policy_store import AccountPolicyStore

    enable(store, "entra", False)
    with store._db.write() as conn:
        conn.execute(
            update(s.accounts)
            .where(s.accounts.c.id == KEY_A)
            .values(role="owner", role_source="bootstrap")
        )
    policies = AccountPolicyStore(store._db)
    revision = policies.read()["revision"]
    policies.save(
        {
            "allow_multiple": True,
            "lock_first_sso": True,
            "block_conflicting_registration": False,
        },
        revision=revision,
        actor=KEY_A,
        now=2,
    )
    first = signin(store, google())
    key = first.status.principal_key
    assert policies.read(key)["policy"]["sso_lock_provider"] == "google"
    original = store.list_identities(key)
    revision = policies.read()["revision"]
    policies.save(
        {}, account_id=key, unlock=True, revision=revision, actor=KEY_A, now=3
    )
    assert store.list_identities(key) == original
    assert policies.read(key)["policy"]["sso_lock_provider"] is None
    assert policies.read(key)["policy"]["sso_lock_exempt"]
    ext = acc.ExternalClaims(
        provider_id="oidc:unlocked",
        issuer="https://unlocked.test",
        subject="second",
        email="g@example.test",
    )
    enable(store, ext.provider_id, True)
    assert signin(store, ext).status.principal_key == key
    assert policies.read(key)["policy"]["sso_lock_provider"] is None
    audit = next(
        item
        for item in store.iter_audit(account_id=key)
        if item.action == "account_sso_unlocked"
    )
    assert audit.detail["old_sso_lock_provider"] == "google"
    assert audit.detail["new_sso_lock_provider"] is None
    assert audit.detail["new_allow_multiple"] is True


def test_last_administrator_allowlist_change_rolls_back(store):
    from canvas_mcp.core.selfhost.login.policy_store import AccountPolicyStore
    from canvas_mcp.core.selfhost.login.provider_config import (
        ProviderConfigurationError,
    )

    enable(store, "entra", False)
    with store._db.write() as conn:
        conn.execute(
            update(s.accounts)
            .where(s.accounts.c.id == KEY_A)
            .values(role="owner", role_source="bootstrap")
        )
    policies = AccountPolicyStore(store._db)
    revision = policies.read()["revision"]
    epoch = store.get_principal_status(KEY_A).session_epoch
    with pytest.raises(ProviderConfigurationError, match="last_owner"):
        policies.save(
            {"allow_multiple": None, "allowed_providers": []},
            account_id=KEY_A,
            revision=revision,
            actor=KEY_A,
            now=2,
        )
    assert policies.read()["revision"] == revision
    assert policies.read(KEY_A)["policy"]["allowed_providers"] is None
    assert store.get_principal_status(KEY_A).session_epoch == epoch


def test_local_password_and_upn_rename_keep_external_account_and_identity(store):
    from types import SimpleNamespace

    from canvas_mcp.core.selfhost.login.account_names import AccountNames
    from canvas_mcp.core.selfhost.login.local_accounts import LocalAccounts

    first = signin(store, google())
    key = first.status.principal_key
    enable(store, "local", False)
    local = LocalAccounts(SimpleNamespace(database=store._db, repos=store._repos))
    local.add_password(
        key,
        "a very long local test password",
        expected_epoch=first.status.session_epoch,
        now=2,
    )
    assert (
        local.authenticate(
            "g@example.test", "a very long local test password", now=3
        ).id
        == key
    )
    identities = store.list_identities(key)
    before = store.get_principal_status(key).session_epoch
    AccountNames(store._db).save(
        "renamed@example.test", account_id=key, expected_epoch=before, now=4
    )
    assert store.list_identities(key) == identities
    assert (
        local.authenticate(
            "renamed@example.test", "a very long local test password", now=5
        ).id
        == key
    )
    from canvas_mcp.core.selfhost.login.provider_config import (
        ProviderConfigurationError,
    )

    with pytest.raises(ProviderConfigurationError, match="local_login_failed"):
        local.authenticate("g@example.test", "a very long local test password", now=5)
    changed = signin(
        store, replace(google(), email="changed-provider-mail@example.test")
    )
    assert changed.status.principal_key == key
    assert AccountNames(store._db).read(key)["upn"] == "renamed@example.test"


def test_name_selection_gate_closes_before_oauth_authorization(store):
    from canvas_mcp.core.selfhost.authz.store import _standing_ok
    from canvas_mcp.core.selfhost.login.account_names import AccountNames

    ext = acc.ExternalClaims(
        provider_id="oidc:no-email", issuer="https://no-email.test", subject="immutable"
    )
    created = signin(store, ext)
    key = created.status.principal_key
    with store._db.read() as conn:
        row = store._repos.accounts.get(conn, key)
        assert row.upn_required and not _standing_ok(row, row.session_epoch)
    AccountNames(store._db).save(
        "chosen@example.test",
        account_id=key,
        expected_epoch=created.status.session_epoch,
        now=2,
    )
    with store._db.read() as conn:
        row = store._repos.accounts.get(conn, key)
        assert _standing_ok(row, row.session_epoch)


def test_local_login_rechecks_upn_after_password_verification(store, monkeypatch):
    from types import SimpleNamespace

    from canvas_mcp.core.selfhost.login import local_accounts
    from canvas_mcp.core.selfhost.login.account_names import AccountNames
    from canvas_mcp.core.selfhost.login.provider_config import (
        ProviderConfigurationError,
    )

    first = signin(store, google())
    key = first.status.principal_key
    enable(store, "local", False)
    local = local_accounts.LocalAccounts(
        SimpleNamespace(database=store._db, repos=store._repos)
    )
    local.add_password(
        key,
        "a very long test password",
        expected_epoch=first.status.session_epoch,
        now=2,
    )
    verify = local_accounts.verify_password

    def rename_during_verification(password, saved):
        valid = verify(password, saved)
        AccountNames(store._db).save(
            "new-upn@example.test",
            account_id=key,
            expected_epoch=store.get_principal_status(key).session_epoch,
            now=3,
        )
        return valid

    monkeypatch.setattr(local_accounts, "verify_password", rename_during_verification)
    with pytest.raises(ProviderConfigurationError, match="local_login_failed"):
        local.authenticate("g@example.test", "a very long test password", now=4)


def test_block_conflicting_registration_checks_bare_upn_without_associating(store):
    from canvas_mcp.core.selfhost.login.policy_store import AccountPolicyStore

    enable(store, "entra", False)
    with store._db.write() as conn:
        conn.execute(
            update(s.accounts)
            .where(s.accounts.c.id == KEY_A)
            .values(role="owner", role_source="bootstrap", upn="existing.user")
        )
    policies = AccountPolicyStore(store._db)
    policies.save(
        {
            "allow_multiple": True,
            "lock_first_sso": False,
            "block_conflicting_registration": True,
        },
        revision=policies.read()["revision"],
        actor=KEY_A,
        now=2,
    )
    ext = acc.ExternalClaims(
        provider_id="oidc:conflict",
        issuer="https://conflict.test",
        subject="new",
        username="Existing.User",
    )
    enable(store, ext.provider_id, False)
    before = store.list_identities(KEY_A)
    result = signin(store, ext)
    assert result.outcome == "deny" and not result.created
    assert result.reason == "use_existing_sign_in"
    assert store.list_identities(KEY_A) == before


def test_upn_collision_is_account_wide_and_case_insensitive(store):
    from canvas_mcp.core.selfhost.login.account_names import AccountNames
    from canvas_mcp.core.selfhost.login.provider_config import (
        ProviderConfigurationError,
    )

    first = signin(store, google())
    second = signin(store, replace(google("second"), email="second@example.test"))
    names = AccountNames(store._db)
    names.save(
        "  Shared.UPN  ",
        account_id=first.status.principal_key,
        expected_epoch=first.status.session_epoch,
        now=2,
    )
    with pytest.raises(ProviderConfigurationError, match="local_username_taken"):
        names.save(
            "shared.upn",
            account_id=second.status.principal_key,
            expected_epoch=second.status.session_epoch,
            now=3,
        )
    assert names.read(first.status.principal_key)["upn"] == "shared.upn"
    assert names.read(second.status.principal_key)["upn"] == "second@example.test"
