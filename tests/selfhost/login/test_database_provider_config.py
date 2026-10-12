"""Database-owned provider credentials, independent of environment values."""

import pytest
from sqlalchemy import insert, select, update

from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.db.sealed import verify
from canvas_mcp.core.selfhost.db.settings_repo import (
    SettingsAccessDenied,
    SettingsConflict,
)
from canvas_mcp.core.selfhost.db.types import new_id
from canvas_mcp.core.selfhost.login.provider_config import ProviderConfigurationError
from canvas_mcp.core.selfhost.login.provider_store import ProviderConfigStore
from canvas_mcp.core.selfhost.token_store import Keyring

from .. import test_server_settings

db = test_server_settings.db

SECRET = "client-secret-kept-out-of-responses"
CONFIG = {
    "tenant_id": "11111111-2222-3333-4444-555555555555",
    "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
}


@pytest.fixture
def providers(db):  # noqa: F811
    return ProviderConfigStore(db, Keyring([("k1", b"1" * 32)]))


def revision(db):
    with db.read() as conn:
        return conn.execute(select(s.server_state.c.settings_revision)).scalar_one()


def save(providers, db, **changes):
    values = {
        "config": CONFIG,
        "client_secret": SECRET,
        "enabled": True,
        "rank": 0,
        "revision": revision(db),
        "actor": None,
        "now": 100,
    }
    values.update(changes)
    return providers.save("entra", **values)


def test_secret_is_sealed_and_only_runtime_can_read_it(providers, db):
    save(providers, db)
    view = providers.list_public()[0]
    assert view["secret_present"] is True
    assert view["config_source"] == "db"
    assert SECRET not in repr(view)
    runtime = providers.load_enabled()[0]
    assert runtime.client_secret == SECRET
    assert SECRET not in repr(runtime)
    with db.read() as conn:
        row = conn.execute(select(s.login_providers)).mappings().one()
        assert SECRET.encode() not in bytes(row["secret_ciphertext"])
        assert "client_secret" not in row["config"]
        assert verify(conn, providers.keys, all_values=True) == 1
        audit = conn.execute(select(s.audit_log)).mappings().one()
        assert SECRET not in repr(audit)


def test_secret_omission_preserves_ciphertext_and_survives_new_store(providers, db):
    save(providers, db)
    with db.read() as conn:
        before = conn.execute(
            select(s.login_providers.c.secret_ciphertext)
        ).scalar_one()
    save(providers, db, client_secret=None, rank=2)
    with db.read() as conn:
        assert (
            conn.execute(select(s.login_providers.c.secret_ciphertext)).scalar_one()
            == before
        )
    recreated = ProviderConfigStore(db, providers.keys)
    assert recreated.load_enabled()[0].client_secret == SECRET


def test_stale_save_rolls_back_configuration_secret_and_audit(providers, db):
    old = revision(db)
    save(providers, db)
    with pytest.raises(SettingsConflict):
        save(providers, db, revision=old, client_secret="different-client-secret")
    assert providers.load_enabled()[0].client_secret == SECRET
    with db.read() as conn:
        assert len(conn.execute(select(s.audit_log)).all()) == 1


@pytest.mark.parametrize(
    "config,secret",
    [
        ({**CONFIG, "client_secret": SECRET}, SECRET),
        ({**CONFIG, "tenant_id": "common"}, SECRET),
        (CONFIG, ""),
        (CONFIG, "short"),
        (CONFIG, None),
    ],
)
def test_invalid_first_save_writes_nothing(providers, db, config, secret):
    old = revision(db)
    with pytest.raises(ProviderConfigurationError) as error:
        save(providers, db, config=config, client_secret=secret)
    assert SECRET not in str(error.value)
    assert revision(db) == old
    assert providers.list_public() == ()


def test_ciphertext_tamper_and_wrong_key_fail_closed(providers, db):
    save(providers, db)
    wrong = ProviderConfigStore(db, Keyring([("k1", b"2" * 32)]))
    with pytest.raises(ProviderConfigurationError):
        wrong.load_enabled()
    with db.write() as conn:
        conn.execute(update(s.login_providers).values(secret_ciphertext=b"damaged"))
    with pytest.raises(ProviderConfigurationError):
        providers.load_enabled()


def test_damaged_public_configuration_cannot_leak_a_secret(providers, db):
    save(providers, db)
    with db.write() as conn:
        conn.execute(
            update(s.login_providers).values(config={**CONFIG, "client_secret": SECRET})
        )
    with pytest.raises(ProviderConfigurationError) as error:
        providers.list_public()
    assert SECRET not in str(error.value)


def add_account(db, *, role="owner", status="active", provider="entra"):
    account = new_id()
    with db.write() as conn:
        conn.execute(
            insert(s.accounts).values(
                id=account,
                role=role,
                status=status,
                role_source="operator",
                admitted_via="operator",
                created_at=100,
                updated_at=100,
                disabled_at=100 if status == "disabled" else None,
            )
        )
        conn.execute(
            insert(s.external_identities).values(
                id=new_id(),
                account_id=account,
                provider_id=provider,
                issuer="https://login.microsoftonline.com/"
                + CONFIG["tenant_id"]
                + "/v2.0",
                subject=account,
                linked_at=100,
            )
        )
    return account


@pytest.mark.parametrize(
    "role,status",
    [
        ("user", "active"),
        ("owner", "pending"),
        ("owner", "disabled"),
    ],
)
def test_non_active_owner_cannot_save(providers, db, role, status):
    save(providers, db)
    account = add_account(db, role=role, status=status)
    old = revision(db)
    with pytest.raises(SettingsAccessDenied):
        save(providers, db, actor=account)
    assert revision(db) == old


def test_disabling_the_last_usable_owner_provider_rolls_back(providers, db):
    save(providers, db)
    owner = add_account(db)
    old = revision(db)
    with pytest.raises(ProviderConfigurationError, match="last_owner"):
        save(providers, db, actor=owner, enabled=False, client_secret=None)
    assert revision(db) == old
    assert providers.load_enabled()[0].id == "entra"


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "99999999-2222-3333-4444-555555555555"),
        ("client_id", "99999999-bbbb-cccc-dddd-eeeeeeeeeeee"),
    ],
)
def test_an_enrolled_provider_cannot_change_identity_binding(
    providers, db, field, value
):
    save(providers, db)
    owner = add_account(db)
    old = revision(db)
    with pytest.raises(
        ProviderConfigurationError, match="provider_identity_binding_changed"
    ):
        save(providers, db, config={**CONFIG, field: value}, actor=owner)
    assert revision(db) == old


@pytest.mark.parametrize(
    "identifier,config",
    [
        ("google", {"client_id": "123-example.apps.googleusercontent.com"}),
        ("github", {"client_id": "Iv1.example123"}),
        (
            "oidc:school",
            {"issuer": "https://idp.example.edu", "client_id": "web-client"},
        ),
    ],
)
def test_all_supported_protocols_load_from_database(providers, db, identifier, config):
    providers.save(
        identifier,
        config=config,
        client_secret=SECRET,
        enabled=True,
        rank=0,
        revision=revision(db),
        actor=None,
        now=100,
    )
    runtime = providers.load_enabled()[0]
    assert runtime.id == identifier
    assert runtime.client_secret == SECRET
    assert providers.list_public()[0]["config"]["client_id"] == config["client_id"]


def test_disabled_provider_does_not_load_and_db_row_survives_env_reconcile(
    providers, db
):
    save(providers, db)
    save(providers, db, enabled=False, client_secret=None)
    with db.write() as conn:
        providers.repos.providers.reconcile(conn, ["entra"], now=110)
    assert providers.load_enabled() == ()
    assert providers.list_public()[0]["enabled"] is False
