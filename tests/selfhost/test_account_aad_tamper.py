"""The ciphertext of a Canvas token is bound to its account, school and key.

Each row is sealed with associated data that names the account (``acct:<uuid>``), the
Canvas host when the row records one, and the key id. Anything copied, moved or edited
behind the store's back therefore fails to decrypt instead of being read as someone
else's token. Runs on both backends.
"""

from __future__ import annotations

import base64
import pathlib
from typing import Any

import pytest
from dbbackend import make_store, raw_sql

from canvas_mcp.core.selfhost.db import accounts_v5
from canvas_mcp.core.selfhost.token_store import (
    Keyring,
    TokenDecryptionError,
    TokenStore,
)

from .conftest import make_account

OID_A = "aaaaaaaa-0000-4000-8000-00000000000a"
OID_B = "bbbbbbbb-0000-4000-8000-00000000000b"
HOST = "canvas.example.edu"
OTHER_HOST = "canvas.other.edu"
TOKEN_A = "7~" + "A" * 62
TOKEN_B = "7~" + "B" * 62


def _ring(*ids: str) -> Keyring:
    return Keyring.parse(
        ",".join(f"{kid}:{base64.b64encode(bytes([i + 1]) * 32).decode()}" for i, kid in enumerate(ids))
    )


@pytest.fixture
def store(tmp_path: pathlib.Path) -> TokenStore:
    s = make_store(tmp_path / "t.sqlite3", _ring("k1", "k2"))
    s.initialize()
    return s


def _enroll(store: TokenStore, oid: str, token: str, host: str | None) -> str:
    key = make_account(store, oid)
    store.put(
        principal_key=key, api_token=token, canvas_user_id="1", canvas_user_name="n", canvas_host=host
    )
    return key


def _seal(store: TokenStore, aad: bytes, token: str = TOKEN_A) -> tuple[str, bytes, bytes]:
    return store._keyring.encrypt(token.encode(), aad)  # type: ignore[no-any-return]


def _replace(store: TokenStore, key: str, kid: str, nonce: bytes, ciphertext: bytes) -> None:
    raw_sql(
        store,
        "UPDATE canvas_tokens SET key_id = :k, nonce = :n, ciphertext = :c WHERE principal_key = :p",
        {"k": kid, "n": nonce, "c": ciphertext, "p": key},
    )


class TestMovedRows:
    @pytest.mark.parametrize("host", [HOST, None])
    def test_a_row_copied_to_another_account_does_not_decrypt(
        self, store: TokenStore, host: str | None
    ) -> None:
        a = _enroll(store, OID_A, TOKEN_A, host)
        b = _enroll(store, OID_B, TOKEN_B, host)
        kid, nonce, ct = raw_sql(
            store,
            "SELECT key_id, nonce, ciphertext FROM canvas_tokens WHERE principal_key = :p",
            {"p": a},
        )[0]
        _replace(store, b, kid, bytes(nonce), bytes(ct))
        with pytest.raises(TokenDecryptionError):
            store.get(b)
        got = store.get(a)
        assert got is not None and got.api_token == TOKEN_A

    def test_renaming_the_owner_of_a_row_fails(self, store: TokenStore) -> None:
        a = _enroll(store, OID_A, TOKEN_A, HOST)
        b = make_account(store, OID_B)
        raw_sql(store, "UPDATE canvas_tokens SET principal_key = :b WHERE principal_key = :a", {"a": a, "b": b})
        with pytest.raises(TokenDecryptionError):
            store.get(b)

    def test_changing_the_school_of_a_row_fails(self, store: TokenStore) -> None:
        a = _enroll(store, OID_A, TOKEN_A, HOST)
        raw_sql(store, "UPDATE canvas_tokens SET canvas_host = :h", {"h": OTHER_HOST})
        with pytest.raises(TokenDecryptionError):
            store.get(a)

    def test_removing_the_school_of_a_row_fails(self, store: TokenStore) -> None:
        a = _enroll(store, OID_A, TOKEN_A, HOST)
        raw_sql(store, "UPDATE canvas_tokens SET canvas_host = NULL")
        with pytest.raises(TokenDecryptionError):
            store.get(a)

    def test_adding_a_school_to_a_default_school_row_fails(self, store: TokenStore) -> None:
        a = _enroll(store, OID_A, TOKEN_A, None)
        raw_sql(store, "UPDATE canvas_tokens SET canvas_host = :h", {"h": HOST})
        with pytest.raises(TokenDecryptionError):
            store.get(a)

    def test_changing_the_key_id_of_a_row_fails(self, store: TokenStore) -> None:
        a = _enroll(store, OID_A, TOKEN_A, HOST)
        raw_sql(store, "UPDATE canvas_tokens SET key_id = 'k2'")
        with pytest.raises(TokenDecryptionError):
            store.get(a)


class TestLayouts:
    """A ciphertext sealed for a different layout never opens, even for the right account."""

    def test_a_row_sealed_with_the_wrong_layout_fails(self, store: TokenStore) -> None:
        a = _enroll(store, OID_A, TOKEN_A, HOST)
        kid = store._keyring.active_key_id
        wrong: list[bytes] = [
            accounts_v5.aad_v3(a, kid),  # a host row sealed as host-less
            accounts_v5.aad_v2(a, OTHER_HOST, kid),  # another school
            accounts_v5.aad_v2(a.removeprefix("acct:"), HOST, kid),  # without the account prefix
            accounts_v5.aad_v1("t", OID_A, kid),  # the legacy layout
        ]
        for aad in wrong:
            k, nonce, ct = _seal(store, aad)
            _replace(store, a, k, nonce, ct)
            with pytest.raises(TokenDecryptionError):
                store.get(a)
        k, nonce, ct = _seal(store, accounts_v5.aad_v2(a, HOST, kid))  # the right one works again
        _replace(store, a, k, nonce, ct)
        got = store.get(a)
        assert got is not None and got.api_token == TOKEN_A

    def test_a_default_school_row_is_sealed_for_the_account_and_the_key_only(self, store: TokenStore) -> None:
        a = _enroll(store, OID_A, TOKEN_A, None)
        kid = store._keyring.active_key_id
        k, nonce, ct = _seal(store, accounts_v5.aad_v3(a, kid))
        _replace(store, a, k, nonce, ct)  # a fresh sealing with the documented layout opens
        assert store.get(a).api_token == TOKEN_A  # type: ignore[union-attr]
        k, nonce, ct = _seal(store, accounts_v5.aad_v2(a, HOST, kid))
        _replace(store, a, k, nonce, ct)
        with pytest.raises(TokenDecryptionError):
            store.get(a)

    def test_the_layouts_are_domain_separated(self) -> None:
        key = "acct:11111111-1111-4111-8111-111111111111"
        layouts: list[Any] = [
            accounts_v5.aad_v1("t", "o", "k1"),
            accounts_v5.aad_v2(key, "h", "k1"),
            accounts_v5.aad_v3(key, "k1"),
        ]
        assert len({bytes(x) for x in layouts}) == 3
        prefixes = (accounts_v5._AAD_PREFIX_V1, accounts_v5._AAD_PREFIX_V2, accounts_v5._AAD_PREFIX_V3)
        assert len(set(prefixes)) == 3  # the prefix alone tells them apart
        assert all(x.startswith(p) for x, p in zip(layouts, prefixes, strict=True))

    def test_the_separator_cannot_be_used_to_forge_another_host(self) -> None:
        key = "acct:11111111-1111-4111-8111-111111111111"
        # host "a" + key "k1" is not the same message as host "a<sep>k1" + key "": prefix and parts differ
        assert accounts_v5.aad_v2(key, "a", "k1") != accounts_v5.aad_v2(key, "a", "k1x")
        assert accounts_v5.aad_v3(key, "k1") != accounts_v5.aad_v3(key + "x", "k1")


class TestOtherEdits:
    def test_flipping_a_bit_of_the_ciphertext_or_nonce_fails(self, store: TokenStore) -> None:
        a = _enroll(store, OID_A, TOKEN_A, HOST)
        kid, nonce, ct = raw_sql(
            store, "SELECT key_id, nonce, ciphertext FROM canvas_tokens WHERE principal_key = :p", {"p": a}
        )[0]
        nonce, ct = bytes(nonce), bytes(ct)
        _replace(store, a, kid, nonce, bytes([ct[0] ^ 1]) + ct[1:])
        with pytest.raises(TokenDecryptionError):
            store.get(a)
        _replace(store, a, kid, bytes([nonce[0] ^ 1]) + nonce[1:], ct)
        with pytest.raises(TokenDecryptionError):
            store.get(a)
        _replace(store, a, kid, nonce, ct)
        assert store.get(a).api_token == TOKEN_A  # type: ignore[union-attr]

    def test_a_failed_row_does_not_stop_the_others_from_being_read(self, store: TokenStore) -> None:
        a = _enroll(store, OID_A, TOKEN_A, HOST)
        b = _enroll(store, OID_B, TOKEN_B, HOST)
        raw_sql(store, "UPDATE canvas_tokens SET canvas_host = :h WHERE principal_key = :p", {"h": OTHER_HOST, "p": a})
        with pytest.raises(TokenDecryptionError):
            store.get(a)
        assert store.get(b).api_token == TOKEN_B  # type: ignore[union-attr]
