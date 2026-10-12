"""A remaining SSO owner never replaces the final local administrator entrance."""

from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import delete, select, update

from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.login.local_accounts import LocalAccounts
from canvas_mcp.core.selfhost.login.policy_store import AccountPolicyStore
from canvas_mcp.core.selfhost.login.provider_config import ProviderConfigurationError
from canvas_mcp.core.selfhost.token_store import OPERATOR, AccessActionRefused

from ..authz.stack import BASE
from .test_database_login_api import installation
from .test_local_accounts import PASSWORD, initialize


def revision(runtime):
    with runtime.store.database.read() as conn:
        return conn.execute(select(s.server_state.c.settings_revision)).scalar_one()


def admin(runtime):
    return (
        LocalAccounts(runtime.provider_store).authenticate("admin", PASSWORD, now=10).id
    )


def sso_owner(runtime, actor):
    runtime.provider_store.save(
        "google",
        config={"client_id": "test-google-client.apps.googleusercontent.com"},
        client_secret="test-private-google-client-secret",
        enabled=True,
        rank=1,
        revision=revision(runtime),
        actor=actor,
        now=11,
    )
    return runtime.store.create_operator_account(
        provider_id="google",
        issuer="https://accounts.google.com",
        subject="sso-owner",
        status="active",
        role="owner",
    )


def second_local(runtime, actor):
    key, _ = LocalAccounts(runtime.provider_store).create(
        name="backup-admin",
        password=PASSWORD,
        owner=True,
        actor=actor,
        revision=revision(runtime),
        now=12,
    )
    return key


@pytest.mark.parametrize("operation", ["disable", "forced_disable", "delete", "unlink"])
def test_sso_owner_does_not_allow_removing_final_local_owner(tmp_path, operation):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        key = admin(runtime)
        other = sso_owner(runtime, key)
        before = runtime.store.get_principal_status(key)
        if operation == "unlink":
            identity = runtime.store.list_identities(key)[0]
            result = runtime.store.unlink_identity(key, identity.id, actor=other)
            assert result.code == "last_local_owner"
        else:
            with pytest.raises(AccessActionRefused) as refused:
                if operation == "delete":
                    runtime.store.delete_account(key)
                else:
                    runtime.store.disable_principal(
                        key,
                        actor=OPERATOR,
                        reason="operator_disabled",
                        allow_last_owner=operation == "forced_disable",
                    )
            assert refused.value.code == "last_local_owner"
        assert runtime.store.get_principal_status(key) == before
        assert admin(runtime) == key
        assert runtime.store.has_local_admin()


def test_final_local_policy_and_provider_changes_roll_back_with_sso_owner(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        key = admin(runtime)
        other = sso_owner(runtime, key)
        before = revision(runtime)
        policies = AccountPolicyStore(runtime.store.database)
        for change in ("provider", "allowlist"):
            with pytest.raises(ProviderConfigurationError, match="last_local_owner"):
                if change == "provider":
                    runtime.provider_store.save(
                        "local",
                        config={},
                        client_secret=None,
                        enabled=False,
                        rank=0,
                        revision=before,
                        actor=other,
                        now=13,
                    )
                else:
                    policies.save(
                        {"allow_multiple": False, "allowed_providers": ["google"]},
                        account_id=key,
                        revision=before,
                        actor=other,
                        now=13,
                    )
            assert revision(runtime) == before
            assert admin(runtime) == key
        assert policies.read(key)["policy"]["allowed_providers"] is None


def test_second_local_owner_allows_rotation_but_not_removing_both(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        key = admin(runtime)
        backup = second_local(runtime, key)
        assert runtime.store.disable_principal(
            key, actor=backup, reason="admin_disabled"
        )
        with pytest.raises(AccessActionRefused, match="last_local_owner"):
            runtime.store.delete_account(backup)
        assert (
            LocalAccounts(runtime.provider_store)
            .authenticate("backup-admin", PASSWORD, now=13)
            .id
            == backup
        )


def test_concurrent_local_unlinks_preserve_one_password_and_owner(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        first = admin(runtime)
        sso_owner(runtime, first)
        second = second_local(runtime, first)
        identities = []
        with runtime.store.database.write() as conn:
            for key in (first, second):
                runtime.store._repos.identities.insert(
                    conn,
                    account_id=key,
                    provider_id="google",
                    issuer="https://accounts.google.com",
                    subject=key,
                    username="",
                    email=None,
                    email_verified=False,
                    now=15,
                )
                identities.append(
                    next(
                        row.id
                        for row in runtime.store._repos.identities.for_account(
                            conn, key
                        )
                        if row.provider_id == "local"
                    )
                )
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(
                executor.map(
                    lambda item: (
                        runtime.store.unlink_identity(
                            item[0], item[1], actor=OPERATOR
                        ).code
                    ),
                    zip((first, second), identities, strict=True),
                )
            )
        assert sorted(results) == ["last_local_owner", "unlinked"]
        with runtime.store.database.read() as conn:
            assert len(runtime.store._repos.accounts.local_owner_ids(conn)) == 1
            assert len(list(conn.execute(select(s.local_credentials)).scalars())) == 1


def test_rules_owner_password_is_not_an_independent_local_admin(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        key = admin(runtime)
        with runtime.store.database.write() as conn:
            conn.execute(
                update(s.accounts)
                .where(s.accounts.c.id == key)
                .values(role_source="rules")
            )
        assert not runtime.store.has_local_admin()
        assert (
            client.post(
                "/api/v1/login/local",
                headers={"Origin": BASE},
                json={"username": "admin", "password": PASSWORD},
            ).status_code
            == 200
        )
        assert client.get("/api/v1/admin/settings").status_code == 403


def test_existing_sso_only_installation_can_create_independent_local_admin(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        key = admin(runtime)
        other = sso_owner(runtime, key)
        with runtime.store.database.write() as conn:
            conn.execute(delete(s.local_credentials))
        assert not runtime.store.has_local_admin()
        backup = second_local(runtime, other)
        assert runtime.store.has_local_admin()
        response = client.post(
            "/api/v1/login/local",
            headers={"Origin": BASE},
            json={"username": "backup-admin", "password": PASSWORD},
        )
        assert response.status_code == 200
        settings = client.get("/api/v1/admin/settings")
        assert settings.status_code == 200 and settings.json()["local_admin"] == {
            "ready": True
        }
        assert runtime.store.get_principal_status(backup).role_source == "operator"


def test_browser_admin_creation_is_explicit_csrf_protected_and_never_exposes_password(
    tmp_path,
):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        assert (
            client.post(
                "/api/v1/login/local",
                headers={"Origin": BASE},
                json={"username": "admin", "password": PASSWORD},
            ).status_code
            == 200
        )
        me = client.get("/api/v1/me").json()
        body = {
            "revision": revision(runtime),
            "username": "rescue-admin",
            "password": PASSWORD,
            "owner": True,
        }
        route = "/api/v1/admin/local-accounts"
        assert (
            client.post(route, headers={"Origin": BASE}, json=body).status_code == 403
        )
        headers = {"Origin": BASE, "X-CSRF-Token": me["csrf_token"]}
        assert (
            client.post(
                route, headers=headers, json={**body, "owner": "true"}
            ).status_code
            == 422
        )
        created = client.post(route, headers=headers, json=body)
        assert created.status_code == 200 and PASSWORD not in created.text
        account = created.json()["account_id"]
        assert runtime.store.get_principal_status(account).role_source == "operator"
        client.cookies.clear()
        assert (
            client.post(
                "/api/v1/login/local",
                headers={"Origin": BASE},
                json={"username": "rescue-admin", "password": PASSWORD},
            ).status_code
            == 200
        )
        assert client.get("/api/v1/admin/settings").status_code == 200
