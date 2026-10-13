"""Every ciphertext column participates in startup probing and bounded rotation."""

import base64

import pytest
from dbbackend import make_store
from sqlalchemy import insert, select, update

from canvas_mcp.core.selfhost.custody import CustodyAcknowledgement
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.db.sealed import SEALED, verify
from canvas_mcp.core.selfhost.db.types import new_id
from canvas_mcp.core.selfhost.token_store import Keyring, KeyringError

NOW = 1_800_000_000


def keyring(active="k1", *, both=False):
    values = [(active, b"1" * 32 if active == "k1" else b"2" * 32)]
    if both:
        values.append(("k1", b"1" * 32))
    return Keyring.parse(
        ",".join(kid + ":" + base64.b64encode(key).decode() for kid, key in values)
    )


def populate_sealed(store, ring):
    account = store.create_operator_account(
        provider_id="oidc:school",
        issuer="https://idp.example.edu",
        subject="student",
        status="active",
    )
    info = store.put(
        principal_key=account,
        api_token="pat-secret",
        canvas_user_id="17",
        canvas_user_name="Student",
        canvas_host="canvas.example.edu",
        custody=CustodyAcknowledgement(1, NOW),
    )
    provider = next(value for value in SEALED if value.table is s.login_providers)
    app = next(value for value in SEALED if value.table is s.canvas_oauth_apps)
    kid, nonce, ciphertext = ring.encrypt(
        b"provider-secret",
        provider.aad({"id": "oidc:school", "secret_key_id": ring.active_key_id}),
    )
    with store.database.write() as conn:
        conn.execute(
            update(s.login_providers)
            .where(s.login_providers.c.id == "oidc:school")
            .values(
                secret_key_id=kid,
                secret_nonce=nonce,
                secret_ciphertext=ciphertext,
                config={"issuer": "https://idp.example.edu"},
            )
        )
        kid, nonce, ciphertext = ring.encrypt(
            b"app-secret",
            app.aad(
                {
                    "canvas_host": "canvas.example.edu",
                    "client_id": "institution-key",
                    "secret_key_id": kid,
                }
            ),
        )
        conn.execute(
            insert(s.canvas_oauth_apps).values(
                id=new_id(),
                canvas_host="canvas.example.edu",
                client_id="institution-key",
                enabled=False,
                secret_key_id=kid,
                secret_nonce=nonce,
                secret_ciphertext=ciphertext,
                created_at=NOW,
                updated_at=NOW,
            )
        )
    mail = next(value for value in SEALED if value.table is s.mail_settings)
    kid, nonce, ciphertext = ring.encrypt(
        b"smtp-secret", mail.aad({"id": "smtp", "key_id": ring.active_key_id})
    )
    from canvas_mcp.core.selfhost.mail import DEFAULTS

    with store.database.write() as conn:
        conn.execute(
            insert(s.mail_settings).values(
                id="smtp",
                config={
                    key: value
                    for key, value in DEFAULTS.items()
                    if key != "reminder_days"
                },
                key_id=kid,
                nonce=nonce,
                ciphertext=ciphertext,
                updated_at=NOW,
            )
        )
    return account, info


@pytest.fixture
def sealed_store(tmp_path):
    ring = keyring()
    store = make_store(tmp_path / "sealed.sqlite3", ring, clock=lambda: NOW)
    store.initialize()
    account, info = populate_sealed(store, ring)
    try:
        yield store, ring, account, info
    finally:
        store.close()


def test_registry_covers_every_ciphertext_column_and_uses_one_layout():
    actual = {(entry.table.name, entry.ciphertext) for entry in SEALED}
    expected = {
        (table.name, column.name)
        for table in s.metadata.tables.values()
        for column in table.c
        if column.name.endswith("ciphertext")
    }
    assert actual == expected and len(actual) == 4
    credential = next(entry for entry in SEALED if entry.table is s.canvas_credentials)
    assert credential.fields == ("account_id", "canvas_host", "kind", "key_id")


def test_rotation_covers_reserved_secrets_and_preserves_all_other_fields(sealed_store):
    store, _, account, info = sealed_store
    with store.database.read() as conn:
        before = {
            entry.table.name: dict(conn.execute(select(entry.table)).mappings().one())
            for entry in SEALED
        }
    store._keyring = keyring("k2", both=True)
    assert store.rotate() == 4 and store.rotate() == 0
    assert store.get(account).api_token == "pat-secret"
    from canvas_mcp.core.selfhost.mail import MailStore

    assert MailStore(store.database, keyring("k2")).load().password == "smtp-secret"
    assert store.info(account).credential_generation == info.credential_generation
    with store.database.read() as conn:
        assert verify(conn, keyring("k2"), all_values=True) == 4
        for entry in SEALED:
            row = dict(conn.execute(select(entry.table)).mappings().one())
            assert row[entry.key_id] == "k2"
            for name in (entry.key_id, entry.nonce, entry.ciphertext):
                del row[name]
                del before[entry.table.name][name]
            assert row == before[entry.table.name]


@pytest.mark.parametrize(
    "table", ["login_providers", "canvas_oauth_apps", "mail_settings"]
)
@pytest.mark.parametrize("failure", ["missing", "wrong"])
def test_startup_probes_reserved_secrets(sealed_store, table, failure):
    store, ring, _, _ = sealed_store
    entry = next(value for value in SEALED if value.table.name == table)
    with store.database.write() as conn:
        values = (
            {entry.key_id: "absent"}
            if failure == "missing"
            else {entry.ciphertext: b"damaged ciphertext"}
        )
        conn.execute(update(entry.table).values(values))
    with pytest.raises(KeyringError, match="missing key|does not match"):
        store.initialize()


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "google"),
        ("secret_key_id", "other"),
    ],
)
def test_provider_secret_is_bound_to_provider_and_key(sealed_store, field, value):
    store, ring, _, _ = sealed_store
    from canvas_mcp.core.selfhost.token_store import TokenDecryptionError

    entry = next(item for item in SEALED if item.table is s.login_providers)
    with store.database.read() as conn:
        row = dict(conn.execute(select(entry.table)).mappings().one())
    changed = dict(row, **{field: value})
    with pytest.raises(TokenDecryptionError):
        ring.decrypt(
            row[entry.key_id],
            row[entry.nonce],
            row[entry.ciphertext],
            entry.aad(changed),
        )
