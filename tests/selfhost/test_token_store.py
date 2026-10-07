"""Tests for the encrypted Canvas token store."""

from __future__ import annotations

import base64
import os
import pathlib
import sqlite3
import stat
import sys
import threading

import pytest

from canvas_mcp.core.selfhost.token_store import (
    EnrollmentInfo,
    Keyring,
    KeyringError,
    StoredToken,
    TokenDecryptionError,
    TokenStore,
    TokenStoreError,
    token_db_path,
)

TID = "11111111-2222-3333-4444-555555555555"
OID_A = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID_B = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
TOKEN_A = "1234~" + "A" * 60
TOKEN_B = "1234~" + "B" * 60


def _key(byte: int = 1, n: int = 32) -> bytes:
    return bytes([byte]) * n


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _ring(*pairs: tuple[str, int]) -> Keyring:
    return Keyring.parse(",".join(f"{kid}:{_b64(_key(b))}" for kid, b in pairs))


class Clock:
    def __init__(self, now: float = 1_700_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path: pathlib.Path, clock: Clock) -> TokenStore:
    s = TokenStore(tmp_path / "data" / "tokens.sqlite3", _ring(("k1", 1)), clock=clock)
    s.initialize()
    return s


def _put(store: TokenStore, oid: str = OID_A, token: str = TOKEN_A, **kw):
    args: dict[str, str] = {
        "tenant_id": TID,
        "object_id": oid,
        "api_token": token,
        "canvas_user_id": "42",
        "canvas_user_name": "Ada Lovelace",
        "entra_display_name": "Ada",
        "entra_upn": "ada@example.test",
    }
    args.update(kw)
    return store.put(**args)


def _raw(store: TokenStore) -> sqlite3.Connection:
    return sqlite3.connect(str(store._path), isolation_level=None)


# -- Keyring -----------------------------------------------------------------


class TestKeyring:
    def test_parse_roundtrip_and_active_key(self) -> None:
        ring = Keyring.parse(f"k2:{_b64(_key(2))}, k1:{_b64(_key(1))}")
        assert ring.active_key_id == "k2"
        assert ring.key_ids == ("k2", "k1")
        kid, nonce, ct = ring.encrypt(b"hello", b"aad")
        assert kid == "k2" and len(nonce) == 12
        assert ring.decrypt(kid, nonce, ct, b"aad") == b"hello"

    def test_url_safe_and_padless_accepted(self) -> None:
        raw = bytes(range(250, 250 - 32, -1))
        std = base64.b64encode(raw).decode()
        urlsafe = base64.urlsafe_b64encode(raw).decode()
        assert "-" in urlsafe or "_" in urlsafe  # the fixture really differs
        for text in (std, std.rstrip("="), urlsafe, urlsafe.rstrip("=")):
            assert Keyring.parse(f"k:{text}").key_ids == ("k",)

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "   ",
            "nocolon",
            ":" + _b64(_key()),
            "bad kid:" + _b64(_key()),
            "x" * 33 + ":" + _b64(_key()),
            "k:" + _b64(_key(1, 31)),
            "k:" + _b64(_key(1, 33)),
            "k:not base64!!",
            "k:",
            f"k:{_b64(_key(1))},k:{_b64(_key(2))}",
            f"k:{_b64(_key(1))},",
            f"k:{_b64(_key(1))},,j:{_b64(_key(2))}",
        ],
    )
    def test_parse_rejects(self, raw: str) -> None:
        with pytest.raises(KeyringError) as exc:
            Keyring.parse(raw)
        # no key material in the message
        assert _b64(_key(1)) not in str(exc.value)
        assert _b64(_key(2)) not in str(exc.value)

    def test_unknown_kid_and_bad_tag_raise_without_secrets(self) -> None:
        ring = _ring(("k1", 1))
        kid, nonce, ct = ring.encrypt(b"secret-value", b"aad")
        with pytest.raises(TokenDecryptionError) as exc:
            ring.decrypt("other", nonce, ct, b"aad")
        assert str(exc.value) == "stored token could not be decrypted"
        with pytest.raises(TokenDecryptionError):
            ring.decrypt(kid, nonce, ct, b"different aad")
        with pytest.raises(TokenDecryptionError):
            ring.decrypt(kid, nonce, ct[:-1] + bytes([ct[-1] ^ 1]), b"aad")

    def test_repr_hides_keys(self) -> None:
        text = repr(_ring(("k1", 1)))
        assert _b64(_key(1)) not in text and "k1" in text


# -- TokenStore --------------------------------------------------------------


class TestRoundtrip:
    def test_put_get_roundtrip(self, store: TokenStore, clock: Clock) -> None:
        info = _put(store)
        assert isinstance(info, EnrollmentInfo)
        assert info.key_id == "k1" and info.created_at == int(clock.now)
        got = store.get(TID, OID_A)
        assert isinstance(got, StoredToken)
        assert got.api_token == TOKEN_A
        assert got.canvas_user_name == "Ada Lovelace"
        assert got.entra_upn == "ada@example.test"
        assert store.get(TID, OID_B) is None

    def test_raw_database_does_not_contain_token(self, store: TokenStore) -> None:
        _put(store)
        # Force the WAL into the main file, then scan every file of the store.
        with _raw(store) as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        blob = b"".join(
            p.read_bytes() for p in store._path.parent.iterdir() if p.is_file()
        )
        assert TOKEN_A.encode() not in blob
        assert b"Ada Lovelace" in blob  # metadata is plaintext by design

    def test_reprs_hide_the_token(self, store: TokenStore) -> None:
        info = _put(store)
        got = store.get(TID, OID_A)
        assert got is not None
        assert TOKEN_A not in repr(got) and "api_token" not in repr(got)
        assert TOKEN_A not in repr(info)
        assert not hasattr(info, "api_token")

    def test_nonces_are_unique_across_puts(self, store: TokenStore) -> None:
        seen = set()
        for i in range(50):
            _put(store, token=f"{i:02d}~" + "y" * 40)
            with _raw(store) as conn:
                n = conn.execute("SELECT nonce FROM canvas_tokens").fetchone()[0]
            assert len(n) == 12
            seen.add(n)
        assert len(seen) == 50

    def test_created_at_preserved_on_replace(
        self, store: TokenStore, clock: Clock
    ) -> None:
        first = _put(store)
        clock.now += 1000
        second = _put(store, token=TOKEN_B, canvas_user_name="Ada B")
        assert second.created_at == first.created_at
        assert second.updated_at == first.updated_at + 1000
        got = store.get(TID, OID_A)
        assert got is not None and got.api_token == TOKEN_B
        assert got.canvas_user_name == "Ada B"
        assert store.count() == 1

    def test_guid_validation_and_lowercasing(self, store: TokenStore) -> None:
        with pytest.raises(ValueError):
            _put(store, oid="not-a-guid")
        with pytest.raises(ValueError):
            _put(store, tenant_id="")
        with pytest.raises(ValueError):
            store.get("x", OID_A)
        with pytest.raises(ValueError):
            store.delete(TID, "x")
        with pytest.raises(ValueError):
            _put(store, token="")
        info = _put(store, oid=OID_A.upper(), tenant_id=TID.upper())
        assert info.object_id == OID_A and info.tenant_id == TID
        got = store.get(TID.upper(), OID_A.upper())
        assert got is not None and got.object_id == OID_A

    def test_names_are_truncated(self, store: TokenStore) -> None:
        info = _put(
            store,
            canvas_user_name="n" * 500,
            entra_display_name="d" * 500,
            entra_upn="u" * 500,
        )
        assert len(info.canvas_user_name) == 200
        assert len(info.entra_display_name) == 200
        assert len(info.entra_upn) == 254

    def test_list_count_info_delete(self, store: TokenStore, clock: Clock) -> None:
        assert store.count() == 0 and store.list_enrollments() == []
        _put(store, oid=OID_B)
        clock.now += 10
        _put(store, oid=OID_A)
        rows = store.list_enrollments()
        assert [r.object_id for r in rows] == [OID_B, OID_A]  # by created_at
        assert store.count() == 2
        info = store.info(TID, OID_A)
        assert info is not None and info.canvas_user_id == "42"
        assert store.delete(TID, OID_A) is True
        assert store.delete(TID, OID_A) is False
        assert store.info(TID, OID_A) is None
        assert store.count() == 1


class TestTamperResistance:
    def test_tampered_ciphertext_or_nonce(self, store: TokenStore) -> None:
        _put(store)
        with _raw(store) as conn:
            ct, nonce = conn.execute(
                "SELECT ciphertext, nonce FROM canvas_tokens"
            ).fetchone()
            conn.execute(
                "UPDATE canvas_tokens SET ciphertext = ?",
                (bytes([ct[0] ^ 1]) + ct[1:],),
            )
        with pytest.raises(TokenDecryptionError):
            store.get(TID, OID_A)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET ciphertext = ?", (ct,))
            conn.execute(
                "UPDATE canvas_tokens SET nonce = ?",
                (bytes([nonce[0] ^ 1]) + nonce[1:],),
            )
        with pytest.raises(TokenDecryptionError):
            store.get(TID, OID_A)

    def test_swapping_ciphertext_between_rows_fails(self, store: TokenStore) -> None:
        _put(store, oid=OID_A, token=TOKEN_A)
        _put(store, oid=OID_B, token=TOKEN_B)
        with _raw(store) as conn:
            nonce_b, ct_b = conn.execute(
                "SELECT nonce, ciphertext FROM canvas_tokens WHERE object_id = ?",
                (OID_B,),
            ).fetchone()
            conn.execute(
                "UPDATE canvas_tokens SET nonce = ?, ciphertext = ?"
                " WHERE object_id = ?",
                (nonce_b, ct_b, OID_A),
            )
        with pytest.raises(TokenDecryptionError):
            store.get(TID, OID_A)
        got = store.get(TID, OID_B)
        assert got is not None and got.api_token == TOKEN_B

    def test_editing_key_id_fails(self, tmp_path: pathlib.Path) -> None:
        ring = _ring(("k1", 1), ("k2", 2))
        store = TokenStore(tmp_path / "t.sqlite3", ring)
        store.initialize()
        _put(store)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET key_id = 'k2'")
        with pytest.raises(TokenDecryptionError):
            store.get(TID, OID_A)


class TestInitialize:
    def test_missing_kid_refused(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        old = TokenStore(path, _ring(("k1", 1)))
        old.initialize()
        _put(old)
        with pytest.raises(KeyringError) as exc:
            TokenStore(path, _ring(("k2", 2))).initialize()
        assert str(exc.value) == "CANVAS_TOKEN_KEYS is missing key id(s): k1"

    def test_wrong_key_under_same_kid_refused(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        old = TokenStore(path, _ring(("k1", 1)))
        old.initialize()
        _put(old)
        with pytest.raises(KeyringError) as exc:
            TokenStore(path, _ring(("k1", 9))).initialize()
        assert str(exc.value) == (
            "CANVAS_TOKEN_KEYS key k1 does not match the stored data"
        )

    def test_initialize_is_idempotent_and_keeps_rows(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "t.sqlite3"
        s = TokenStore(path, _ring(("k1", 1)))
        s.initialize()
        _put(s)
        s.initialize()
        TokenStore(path, _ring(("k1", 1))).initialize()
        assert s.count() == 1

    def test_schema_version_present_and_future_refused(
        self, store: TokenStore
    ) -> None:
        with _raw(store) as conn:
            assert conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone() == ("1",)
            conn.execute("UPDATE meta SET value = '2' WHERE key = 'schema_version'")
        with pytest.raises(TokenStoreError, match="newer"):
            store.initialize()
        with _raw(store) as conn:
            conn.execute("UPDATE meta SET value = 'x' WHERE key = 'schema_version'")
        with pytest.raises(TokenStoreError):
            store.initialize()

    def test_wal_mode_enabled(self, store: TokenStore) -> None:
        with _raw(store) as conn:
            assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    def test_posix_permissions(self, tmp_path: pathlib.Path) -> None:
        path = token_db_path(tmp_path / "state")
        s = TokenStore(path, _ring(("k1", 1)))
        s.initialize()
        _put(s)
        assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_token_db_path(self) -> None:
        p = token_db_path(pathlib.Path("/data"))
        assert p.parts[-2:] == ("canvas-mcp", "tokens.sqlite3")


class TestRotation:
    def test_rotate_reencrypts_and_old_key_can_be_dropped(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "t.sqlite3"
        old = TokenStore(path, _ring(("k1", 1)))
        old.initialize()
        _put(old, oid=OID_A, token=TOKEN_A)
        _put(old, oid=OID_B, token=TOKEN_B)
        both = TokenStore(path, _ring(("k2", 2), ("k1", 1)))
        both.initialize()
        assert both.rotate() == 2
        assert both.rotate() == 0
        with _raw(both) as conn:
            kids = {r[0] for r in conn.execute("SELECT key_id FROM canvas_tokens")}
        assert kids == {"k2"}
        only_new = TokenStore(path, _ring(("k2", 2)))
        only_new.initialize()  # proves no row needs k1
        got = only_new.get(TID, OID_B)
        assert got is not None and got.api_token == TOKEN_B
        with pytest.raises(KeyringError):
            TokenStore(path, _ring(("k1", 1))).initialize()

    def test_rotate_rolls_back_when_a_row_is_corrupt(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "t.sqlite3"
        old = TokenStore(path, _ring(("k1", 1)))
        old.initialize()
        _put(old, oid=OID_A)
        _put(old, oid=OID_B)
        with _raw(old) as conn:
            conn.execute(
                "UPDATE canvas_tokens SET ciphertext = X'00' WHERE object_id = ?",
                (OID_B,),
            )
        both = TokenStore(path, _ring(("k2", 2), ("k1", 1)))
        with pytest.raises(TokenDecryptionError):
            both.rotate()
        with _raw(both) as conn:
            kids = {r[0] for r in conn.execute("SELECT key_id FROM canvas_tokens")}
        assert kids == {"k1"}  # nothing half-rotated


class TestTouch:
    def test_touch_is_throttled(self, store: TokenStore, clock: Clock) -> None:
        _put(store)
        info = store.info(TID, OID_A)
        assert info is not None and info.last_used_at is None
        store.touch(TID, OID_A)
        t0 = int(clock.now)
        info = store.info(TID, OID_A)
        assert info is not None and info.last_used_at == t0
        clock.now += 100
        store.touch(TID, OID_A)
        info = store.info(TID, OID_A)
        assert info is not None and info.last_used_at == t0  # inside 300 s
        clock.now += 300
        store.touch(TID, OID_A)
        info = store.info(TID, OID_A)
        assert info is not None and info.last_used_at == int(clock.now)

    def test_touch_unknown_row_and_bad_ids_never_raise(
        self, store: TokenStore
    ) -> None:
        store.touch(TID, OID_B)
        store.touch("nope", "nope")

    def test_touch_swallows_sqlite_errors(
        self, tmp_path: pathlib.Path, clock: Clock
    ) -> None:
        s = TokenStore(tmp_path / "missing" / "t.sqlite3", _ring(("k1", 1)))
        s.touch(TID, OID_A)  # directory and database do not exist


class TestConcurrency:
    def test_concurrent_put_and_get(self, store: TokenStore) -> None:
        oids = [f"00000000-0000-0000-0000-{i:012d}" for i in range(8)]
        errors: list[BaseException] = []

        def work(oid: str, n: int) -> None:
            try:
                for i in range(15):
                    tok = f"{n}~{i:03d}" + "z" * 30
                    _put(store, oid=oid, token=tok)
                    got = store.get(TID, oid)
                    assert got is not None and got.api_token == tok
                    store.touch(TID, oid, min_interval_seconds=0)
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [
            threading.Thread(target=work, args=(oid, n)) for n, oid in enumerate(oids)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert store.count() == 8
