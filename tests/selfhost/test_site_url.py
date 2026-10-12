"""Canonical origin persistence, governed changes and restart boundaries."""

import pytest
from sqlalchemy import insert, select, update

from canvas_mcp.core.selfhost.app import prepare_selfhost
from canvas_mcp.core.selfhost.config_store import ConfigStore
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.db.errors import StoreUnavailable
from canvas_mcp.core.selfhost.db.settings_repo import save_setting
from canvas_mcp.core.selfhost.login.local_accounts import LocalAccounts
from canvas_mcp.core.selfhost.settings import (
    SelfhostConfigError,
    load_selfhost_settings,
)
from canvas_mcp.core.selfhost.site_url import SITE_URL_KEY, validate_site_url

from .authz.stack import BASE, default_env
from .authz.test_authz_schema import _grant_fields
from .login.test_database_login_api import installation
from .login.test_local_accounts import PASSWORD, initialize, login

NEW_BASE = "https://new.canvas.example.test"


def test_first_start_adopts_origin_once_and_restart_can_omit_environment_value(
    tmp_path,
):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        environment = default_env(tmp_path)
        environment.pop("PUBLIC_BASE_URL")
        assert load_selfhost_settings(environment).public_base_url == BASE
        environment["PUBLIC_BASE_URL"] = "http://ignored-invalid-environment"
        assert load_selfhost_settings(environment).public_base_url == BASE
        with runtime.store.database.read() as conn:
            row = (
                conn.execute(select(s.settings).where(s.settings.c.key == SITE_URL_KEY))
                .mappings()
                .one()
            )
            assert row["value"] == BASE
            assert row["updated_by"] is None


@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        False,
        "http://example.com",
        "https://example.com/path",
        "https://u:p@example.com",
        "https://example.com:443",
        "https://example.com:0",
        "https://example.com?x=y",
        "https://example.com\\evil",
        "https://%65xample.com",
        "https://bad_host.com",
        "https://example.com.",
        "https://example.com\x00",
    ],
)
def test_invalid_site_addresses_fail_closed(value):
    with pytest.raises(ValueError):
        validate_site_url(value)


def test_owner_save_invalidates_credentials_and_restart_uses_database_origin(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        assert login(client).status_code == 200
        me = client.get("/api/v1/me").json()
        account = LocalAccounts(runtime.provider_store).authenticate(
            "admin", PASSWORD, now=10
        )
        headers = {"Origin": BASE, "X-CSRF-Token": me["csrf_token"]}
        body = {"revision": 1, "public_base_url": NEW_BASE, "confirm": True}
        assert (
            client.put(
                "/api/v1/admin/settings/site", headers={"Origin": BASE}, json=body
            ).status_code
            == 403
        )
        assert (
            client.put(
                "/api/v1/admin/settings/site",
                headers=headers,
                json={**body, "confirm": False},
            ).status_code
            == 422
        )
        assert (
            client.put(
                "/api/v1/admin/settings/site",
                headers=headers,
                json={**body, "revision": 0},
            ).status_code
            == 409
        )
        with runtime.store.database.write() as conn:
            runtime.store._repos.grants.insert(conn, **_grant_fields(account.id))
            conn.execute(
                insert(s.login_states).values(
                    kind="login",
                    id_hash=b"s" * 32,
                    payload=b"state",
                    created_at=10,
                    expires_at=100,
                )
            )
        response = client.put("/api/v1/admin/settings/site", headers=headers, json=body)
        assert response.status_code == 200, response.text
        assert response.json()["site"] == {
            "public_base_url": NEW_BASE,
            "active_base_url": BASE,
            "restart_required": True,
        }
        with runtime.store.database.read() as conn:
            assert (
                conn.execute(
                    select(s.accounts.c.session_epoch).where(
                        s.accounts.c.id == account.id
                    )
                ).scalar_one()
                == account.session_epoch + 1
            )
            assert (
                conn.execute(select(s.oauth_grants.c.revoked_at)).scalar_one()
                is not None
            )
            assert conn.execute(select(s.login_states)).first() is None
        assert client.get("/api/v1/me").status_code == 503
        assert login(client).status_code == 503
        with pytest.raises(StoreUnavailable):
            runtime.snapshots.get(response.json()["revision"])
        environment = default_env(tmp_path)
        environment.pop("PUBLIC_BASE_URL")
        restarted = prepare_selfhost(load_selfhost_settings(environment))
        try:
            assert restarted.settings.public_base_url == NEW_BASE
            assert restarted.settings.public_host == "new.canvas.example.test"
            assert restarted.settings.mcp_url == NEW_BASE + "/mcp"
            assert (
                LocalAccounts(restarted.provider_store)
                .authenticate("admin", PASSWORD, now=20)
                .id
                == account.id
            )
        finally:
            restarted.store.close()


def test_same_address_save_keeps_sessions_and_password_grants(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        assert login(client).status_code == 200
        me = client.get("/api/v1/me").json()
        response = client.put(
            "/api/v1/admin/settings/site",
            headers={"Origin": BASE, "X-CSRF-Token": me["csrf_token"]},
            json={"revision": 1, "public_base_url": BASE + "/", "confirm": True},
        )
        assert response.status_code == 200, response.text
        assert response.json()["site"]["restart_required"] is False
        assert client.get("/api/v1/me").status_code == 200


def test_invalid_stored_value_cannot_fall_back_to_environment(tmp_path):
    with installation(tmp_path) as (_client, runtime, _code):
        with runtime.store.database.write() as conn:
            conn.execute(
                update(s.settings)
                .where(s.settings.c.key == SITE_URL_KEY)
                .values(value="http://invalid")
            )
        with pytest.raises(SelfhostConfigError, match="site address"):
            load_selfhost_settings(default_env(tmp_path))


def test_generic_save_and_reset_cannot_bypass_site_address_revocation(tmp_path):
    with installation(tmp_path) as (_client, runtime, _code):
        with pytest.raises(ValueError, match="revocation"):
            with runtime.store.database.write() as conn:
                save_setting(
                    conn,
                    SITE_URL_KEY,
                    NEW_BASE,
                    expected_revision=0,
                    now=1,
                    actor_id=None,
                )
        with pytest.raises(ValueError, match="cannot be reset"):
            ConfigStore(runtime.snapshots).setting(
                SITE_URL_KEY, None, revision=0, actor=None, now=1, reset=True
            )
