"""Local credentials share SQL accounts, epochs and governed provider configuration."""

import pytest
from sqlalchemy import insert, select, update

from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.login.local_accounts import LocalAccounts
from canvas_mcp.core.selfhost.login.provider_config import ProviderConfigurationError
from canvas_mcp.core.selfhost.token_store import OPERATOR

from ..authz.stack import BASE
from ..authz.test_authz_schema import _grant_fields
from .test_database_login_api import installation

PASSWORD = "a long private local password"


def initialize(client, code):
    return client.post(
        "/api/v1/setup",
        headers={"Origin": BASE},
        json={
            "revision": 0,
            "code": code,
            "local_account": {"username": "admin", "password": PASSWORD},
        },
    )


def test_local_installation_creates_owner_and_login_uses_existing_session(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        response = initialize(client, code)
        assert response.status_code == 200, response.text
        assert client.get("/api/v1/setup").json()["initialized"] is True
        assert client.get("/api/v1/providers").json()["providers"][0]["id"] == "local"
        response = client.post(
            "/api/v1/login/local",
            headers={"Origin": BASE},
            json={"username": "ADMIN", "password": PASSWORD},
        )
        assert response.status_code == 200, response.text
        me = client.get("/api/v1/me")
        assert me.status_code == 200 and me.json()["account"]["role"] == "owner"
        with runtime.store.database.read() as conn:
            saved = conn.execute(select(s.local_credentials)).mappings().one()
            assert PASSWORD not in str(saved)
            assert saved["password_hash"].startswith("scrypt$")
            event = conn.execute(select(s.auth_events)).mappings().one()
            assert event["provider_id"] == "local" and event["outcome"] == "success"


def test_setup_origin_and_authority_are_required_and_never_create_accounts(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, "X" * 43).status_code == 403
        response = client.post(
            "/api/v1/setup",
            json={
                "revision": 0,
                "code": code,
                "local_account": {"username": "admin", "password": PASSWORD},
            },
        )
        assert response.status_code == 403
        with runtime.store.database.read() as conn:
            assert conn.execute(select(s.accounts)).first() is None


def test_bad_password_and_unknown_user_are_indistinguishable(tmp_path):
    with installation(tmp_path) as (client, _runtime, code):
        assert initialize(client, code).status_code == 200
        errors = [
            client.post(
                "/api/v1/login/local",
                headers={"Origin": BASE},
                json={"username": user, "password": "wrong password"},
            )
            for user in ["admin", "unknown"]
        ]
        assert all(r.status_code == 401 for r in errors)
        assert all(r.json()["error"]["code"] == "local_login_failed" for r in errors)


def test_invalid_optional_provider_rolls_back_entire_installation(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        body = {
            "revision": 0,
            "code": code,
            "local_account": {"username": "admin", "password": PASSWORD},
            "provider_id": "google",
            "config": {},
            "client_secret": "invalid",
        }
        response = client.post("/api/v1/setup", headers={"Origin": BASE}, json=body)
        assert response.status_code == 422
        assert runtime.installation.verify(code)
        with runtime.store.database.read() as conn:
            assert conn.execute(select(s.accounts)).first() is None


def test_last_local_owner_cannot_disable_local_signin(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        with pytest.raises(ProviderConfigurationError, match="last_owner"):
            runtime.provider_store.save(
                "local",
                config={},
                client_secret=None,
                enabled=False,
                rank=0,
                revision=1,
                actor=None,
                now=1,
            )


def test_password_change_invalidates_old_password_and_sessions(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        local = LocalAccounts(runtime.provider_store)
        account = local.authenticate("admin", PASSWORD, now=10)
        with runtime.store.database.write() as conn:
            local.repos.grants.insert(conn, **_grant_fields(account.id))
            conn.execute(
                insert(s.oauth_codes).values(
                    code_hash=b"c" * 32,
                    client_id="test-client",
                    account_id=account.id,
                    redirect_uri="https://claude.ai/callback",
                    redirect_uri_explicit=True,
                    code_challenge="challenge",
                    scopes="Canvas.Access",
                    resource=BASE + "/mcp",
                    client_kind="dcr",
                    upstream_auth_at=10,
                    session_epoch=account.session_epoch,
                    created_at=10,
                    expires_at=100,
                )
            )
        local.change_password(
            account.id, PASSWORD, "another very long private password", now=11
        )
        with pytest.raises(ProviderConfigurationError, match="local_login_failed"):
            local.authenticate("admin", PASSWORD, now=12)
        changed = local.authenticate(
            "admin", "another very long private password", now=12
        )
        assert changed.session_epoch == account.session_epoch + 1
        with runtime.store.database.read() as conn:
            assert conn.execute(select(s.oauth_codes)).first() is None
            grant = conn.execute(select(s.oauth_grants)).mappings().one()
            assert (
                grant["revoked_at"] == 11
                and grant["revoked_reason"] == "admission_lost"
            )


def login(client, name="admin", password=PASSWORD, **extra):
    return client.post(
        "/api/v1/login/local",
        headers={"Origin": BASE},
        json={"username": name, "password": password, **extra},
    )


def test_admin_create_requires_owner_csrf_and_revision_and_does_not_allow_signup(
    tmp_path,
):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        body = {"revision": 1, "username": "student", "password": PASSWORD}
        assert (
            client.post(
                "/api/v1/admin/local-accounts", headers={"Origin": BASE}, json=body
            ).status_code
            == 401
        )
        assert login(client).status_code == 200
        me = client.get("/api/v1/me").json()
        assert (
            client.post(
                "/api/v1/admin/local-accounts", headers={"Origin": BASE}, json=body
            ).status_code
            == 403
        )
        headers = {"Origin": BASE, "X-CSRF-Token": me["csrf_token"]}
        stale = client.post(
            "/api/v1/admin/local-accounts",
            headers=headers,
            json={**body, "revision": 0},
        )
        assert stale.status_code == 409
        response = client.post(
            "/api/v1/admin/local-accounts", headers=headers, json=body
        )
        assert response.status_code == 200, response.text
        assert PASSWORD not in response.text
        client.cookies.clear()
        assert login(client, "student").status_code == 200
        assert client.get("/api/v1/me").json()["account"]["role"] == "user"
        assert (
            client.post(
                "/api/v1/admin/local-accounts", headers={"Origin": BASE}, json=body
            ).status_code
            == 403
        )
        runtime.store.disable_principal(
            response.json()["account_id"], actor=OPERATOR, reason="operator_disabled"
        )
        assert client.get("/api/v1/me").status_code == 401
        assert login(client, "student").status_code == 401


def test_password_api_requires_csrf_and_ends_cookie(tmp_path):
    with installation(tmp_path) as (client, _runtime, code):
        assert initialize(client, code).status_code == 200
        assert login(client).status_code == 200
        csrf = client.get("/api/v1/me").json()["csrf_token"]
        body = {
            "current_password": PASSWORD,
            "new_password": "new password with many characters",
        }
        assert (
            client.put(
                "/api/v1/me/password", headers={"Origin": BASE}, json=body
            ).status_code
            == 403
        )
        response = client.put(
            "/api/v1/me/password",
            headers={"Origin": BASE, "X-CSRF-Token": csrf},
            json=body,
        )
        assert response.status_code == 200, response.text
        assert client.get("/api/v1/me").status_code == 401
        assert login(client).status_code == 401
        assert login(client, password=body["new_password"]).status_code == 200


@pytest.mark.parametrize(
    "provider_id,config",
    [
        ("google", {"client_id": "123.apps.googleusercontent.com"}),
        ("github", {"client_id": "github-client"}),
        (
            "oidc:work",
            {"client_id": "work-client", "issuer": "https://identity.example.com"},
        ),
    ],
)
def test_optional_external_providers_can_be_configured_at_installation(
    tmp_path, provider_id, config
):
    with installation(tmp_path) as (client, runtime, code):
        response = client.post(
            "/api/v1/setup",
            headers={"Origin": BASE},
            json={
                "revision": 0,
                "code": code,
                "local_account": {"username": "admin", "password": PASSWORD},
                "provider_id": provider_id,
                "config": config,
                "client_secret": "a-long-external-client-secret",
            },
        )
        assert response.status_code == 200, response.text
        assert {p.id for p in runtime.provider_store.load_enabled()} == {
            "local",
            provider_id,
        }
        assert login(client).status_code == 200


def test_login_origin_rate_limit_and_transaction_binding(tmp_path):
    with installation(tmp_path) as (client, _runtime, code):
        assert initialize(client, code).status_code == 200
        assert (
            client.post(
                "/api/v1/login/local", json={"username": "admin", "password": PASSWORD}
            ).status_code
            == 403
        )
        assert login(client, txn="x" * 43).status_code == 400
        for _ in range(9):
            assert login(client, password="wrong").status_code == 401
        assert login(client).status_code == 429


def test_password_verified_before_concurrent_reset_cannot_create_new_session(
    tmp_path, monkeypatch
):
    from canvas_mcp.core.selfhost.login import local_accounts

    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        original = local_accounts.verify_password

        def reset_after_verify(password, saved):
            result = original(password, saved)
            with runtime.store.database.write() as conn:
                conn.execute(
                    update(s.local_credentials).values(
                        password_hash=local_accounts.password_hash(
                            "a replacement long password"
                        )
                    )
                )
                conn.execute(
                    update(s.accounts).values(
                        session_epoch=s.accounts.c.session_epoch + 1
                    )
                )
            return result

        monkeypatch.setattr(local_accounts, "verify_password", reset_after_verify)
        assert login(client).status_code == 401
        assert client.get("/api/v1/me").status_code == 401


def test_local_registration_without_password_has_no_secret_and_cannot_be_linked(
    tmp_path,
):
    with installation(tmp_path) as (client, _runtime, code):
        assert initialize(client, code).status_code == 200
        assert login(client).status_code == 200
        settings = client.get("/api/v1/admin/login-providers")
        assert settings.status_code == 200
        assert settings.json()["providers"][0]["secret_present"] is False


def test_local_login_completes_pkce_consent_and_password_change_revokes_mcp(
    tmp_path, monkeypatch
):
    from canvas_mcp.core.selfhost.custody import CustodyAcknowledgement
    from canvas_mcp.core.selfhost.settings import load_selfhost_settings

    from ..authz import stack as stack_module
    from ..authz.stack import (
        CANVAS_HOST,
        CLAUDE_REDIRECT,
        Browser,
        local_stack,
        pkce,
        query_of,
    )

    # This installation exercises native database setup, not the harness's
    # explicit legacy environment-adoption adapter.
    monkeypatch.setattr(stack_module, "load_provider_environment", load_selfhost_settings)
    with local_stack(
        tmp_path,
        monkeypatch,
        env={
            "ENTRA_TENANT_ID": "",
            "ENTRA_CLIENT_ID": "",
            "ENTRA_CLIENT_SECRET": "",
        },
    ) as stack:
        code = stack.runtime.installation.issue()
        assert initialize(stack.client, code).status_code == 200
        browser = Browser(stack)
        client_id = stack.register()
        verifier, challenge = pkce()
        started = browser.start(stack.authorize_params(client_id, challenge))
        assert started.status_code == 302
        choice = browser.get(started.headers["location"])
        assert choice.status_code == 303
        txn = query_of(choice.headers["location"])["txn"]
        signed_in = browser.api(
            "POST",
            "/login/local",
            body={
                "username": "admin",
                "password": PASSWORD,
                "txn": txn,
            },
        )
        assert signed_in.status_code == 200, signed_in.text
        me = browser.api("GET", "/me").json()
        stack.store.put(
            principal_key=me["account"]["key"],
            api_token="local-test-pat-0123456789",
            canvas_user_id="1",
            canvas_user_name="Local Owner",
            canvas_host=CANVAS_HOST,
            custody=CustodyAcknowledgement(1, int(stack.clock())),
        )
        approved = browser.decide_api(signed_in.json()["redirect_to"])
        token = stack.token(
            grant_type="authorization_code",
            code=approved.query["code"],
            client_id=client_id,
            redirect_uri=CLAUDE_REDIRECT,
            code_verifier=verifier,
        )
        assert token.status_code == 200, token.text
        bundle = token.json()
        assert stack.mcp_status(bundle["access_token"]) == 200
        changed = browser.api(
            "PUT",
            "/me/password",
            csrf=me["csrf_token"],
            body={
                "current_password": PASSWORD,
                "new_password": "a replacement local password",
            },
        )
        assert changed.status_code == 200, changed.text
        assert stack.mcp_status(bundle["access_token"]) == 401
        refreshed = stack.token(
            grant_type="refresh_token",
            refresh_token=bundle["refresh_token"],
            client_id=client_id,
        )
        assert refreshed.status_code == 401, refreshed.text
        assert refreshed.json()["error"] == "invalid_grant"
