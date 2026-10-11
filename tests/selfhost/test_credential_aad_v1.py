"""Native credential AEAD binds account, explicit school, kind and key ID."""

import base64
from dataclasses import replace

import pytest
from dbbackend import make_store
from sqlalchemy import select

from canvas_mcp.core.selfhost.custody import CustodyAcknowledgement
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.token_store import (
    Keyring,
    TokenDecryptionError,
    credential_aad,
)

from .conftest import OID_A, OID_B, make_account
from .test_request_context import native_snapshot

HOST = "canvas.school-a.edu"


@pytest.fixture
def sealed(tmp_path):
    # Equal key material proves key IDs themselves are authenticated.
    material = base64.b64encode(b"x" * 32).decode()
    ring = Keyring.parse(f"k1:{material},k2:{material}")
    store = make_store(tmp_path / "aad.sqlite3", ring, clock=lambda: 1_800_000_000)
    store.initialize()
    try:
        account = make_account(store, OID_A)
        store.put(
            principal_key=account,
            api_token="credential-A",
            canvas_host=HOST,
            canvas_user_id="1",
            canvas_user_name="Ada",
            custody=CustodyAcknowledgement(1, 1_800_000_000),
        )
        with store.database.read() as conn:
            row = dict(conn.execute(select(s.canvas_credentials)).mappings().one())
        yield store, ring, account, row
    finally:
        store.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("account_id", "019a1234-5678-7000-8000-000000000099"),
        ("canvas_host", "canvas.school-b.edu"),
        ("kind", "oauth"),
        ("key_id", "k2"),
    ],
)
def test_each_native_aad_field_is_authenticated(sealed, field, value):
    _, ring, _, row = sealed
    changed = dict(row, **{field: value})
    aad = credential_aad(
        *(changed[key] for key in ("account_id", "canvas_host", "kind", "key_id"))
    )
    with pytest.raises(TokenDecryptionError):
        ring.decrypt(changed["key_id"], row["nonce"], row["ciphertext"], aad)


@pytest.mark.parametrize("field", ["nonce", "ciphertext"])
def test_bit_flips_are_refused_by_the_store(sealed, field):
    store, _, account, row = sealed
    damaged = bytes([row[field][0] ^ 1]) + row[field][1:]
    with store.database.write() as conn:
        conn.execute(s.canvas_credentials.update().values(**{field: damaged}))
    with pytest.raises(TokenDecryptionError):
        store.get(account)


def test_copying_a_seal_to_another_account_cannot_reveal_the_original_token(sealed):
    store, _, account, row = sealed
    other = make_account(store, OID_B)
    store.put(
        principal_key=other,
        api_token="credential-B",
        canvas_host=HOST,
        canvas_user_id="2",
        canvas_user_name="Bob",
        custody=CustodyAcknowledgement(1, 1_800_000_000),
    )
    with store.database.write() as conn:
        conn.execute(
            s.canvas_credentials.update()
            .where(s.canvas_credentials.c.account_id == other)
            .values(nonce=row["nonce"], ciphertext=row["ciphertext"])
        )
    with pytest.raises(TokenDecryptionError):
        store.get(other)
    assert store.get(account).api_token == "credential-A"


def test_old_layouts_and_missing_schools_cannot_fall_back_to_the_native_aad(sealed):
    _, ring, account, row = sealed
    for aad in (f"{account}|k1".encode(), f"acct:{account}|{HOST}|k1".encode()):
        with pytest.raises(TokenDecryptionError):
            ring.decrypt(row["key_id"], row["nonce"], row["ciphertext"], aad)


def test_snapshot_decrypt_uses_the_native_binding_and_refuses_different_account(sealed):
    store, _, account, row = sealed
    snapshot = native_snapshot(
        credential_id=row["id"],
        canvas_host=HOST,
        kind=row["kind"],
        key_id=row["key_id"],
        nonce=row["nonce"],
        ciphertext=row["ciphertext"],
        generation=row["generation"],
        credential_generation=row["generation"],
    )
    assert store.decrypt_snapshot(account, snapshot) == "credential-A"
    with pytest.raises(TokenDecryptionError):
        store.decrypt_snapshot("019a1234-5678-7000-8000-000000000099", snapshot)
    with pytest.raises(TokenDecryptionError):
        store.decrypt_snapshot(
            account, replace(snapshot, canvas_host="canvas.school-b.edu")
        )
