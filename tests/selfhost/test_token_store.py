"""Tests for the encrypted Canvas token store."""

from __future__ import annotations

import base64
import os
import pathlib
import stat
import sys
import threading

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dbbackend import make_store, raw_connection

from canvas_mcp.core.selfhost import token_store as token_store_module
from canvas_mcp.core.selfhost.token_store import (
    OPERATOR,
    SCHEMA_VERSION,
    EnrollmentInfo,
    Keyring,
    KeyringError,
    PrincipalDisabledError,
    PrincipalMissingError,
    PrincipalPendingError,
    StoredToken,
    TokenDecryptionError,
    TokenStore,
    TokenStoreError,
    token_db_path,
)

from .conftest import TENANT, acct_key, make_account

TID = TENANT
OID_A = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID_B = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
PK_A = acct_key(OID_A)
PK_B = acct_key(OID_B)
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
    s = make_store(tmp_path / "data" / "tokens.sqlite3", _ring(("k1", 1)), clock=clock)
    s.initialize()
    make_account(s, OID_A)
    make_account(s, OID_B)
    return s


def _put(store: TokenStore, token: str = TOKEN_A, **kw):  # type: ignore[no-untyped-def]
    args: dict[str, object] = {
        "principal_key": PK_A,
        "api_token": token,
        "canvas_user_id": "42",
        "canvas_user_name": "Ada Lovelace",
    }
    args.update(kw)
    return store.put(**args)  # type: ignore[arg-type]


def _raw(store: TokenStore):  # type: ignore[no-untyped-def]
    return raw_connection(store)


def _columns(path: pathlib.Path) -> list[str]:
    import sqlite3

    conn = sqlite3.connect(str(path))
    try:
        return [r[1] for r in conn.execute("PRAGMA table_info(canvas_tokens)")]
    finally:
        conn.close()


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
        got = store.get(PK_A)
        assert isinstance(got, StoredToken)
        assert got.api_token == TOKEN_A
        assert got.canvas_user_name == "Ada Lovelace"
        assert got.principal_key == PK_A
        assert store.get(PK_B) is None

    @pytest.mark.sqlite_only

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
        got = store.get(PK_A)
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
        got = store.get(PK_A)
        assert got is not None and got.api_token == TOKEN_B
        assert got.canvas_user_name == "Ada B"
        assert store.count() == 1

    def test_key_validation(self, store: TokenStore) -> None:
        with pytest.raises(ValueError):
            _put(store, principal_key="not-a-key")
        with pytest.raises(ValueError):
            _put(store, principal_key="")
        with pytest.raises(ValueError):
            _put(store, principal_key=PK_A.upper())
        with pytest.raises(ValueError):
            store.get(f"entra:{TID}:{OID_A}")
        with pytest.raises(ValueError):
            store.delete(f"entra:{TID}:{OID_A}")
        with pytest.raises(ValueError):
            _put(store, token="")
        assert store.count() == 0

    def test_names_are_truncated(self, store: TokenStore) -> None:
        info = _put(store, canvas_user_name="n" * 500)
        assert len(info.canvas_user_name) == 200

    def test_list_count_info_delete(self, store: TokenStore, clock: Clock) -> None:
        assert store.count() == 0 and store.list_enrollments() == []
        _put(store, principal_key=PK_B)
        clock.now += 10
        _put(store, principal_key=PK_A)
        rows = store.list_enrollments()
        assert [r.principal_key for r in rows] == [PK_B, PK_A]  # by created_at
        assert store.count() == 2
        info = store.info(PK_A)
        assert info is not None and info.canvas_user_id == "42"
        assert store.delete(PK_A) is True
        assert store.delete(PK_A) is False
        assert store.info(PK_A) is None
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
            store.get(PK_A)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET ciphertext = ?", (ct,))
            conn.execute(
                "UPDATE canvas_tokens SET nonce = ?",
                (bytes([nonce[0] ^ 1]) + nonce[1:],),
            )
        with pytest.raises(TokenDecryptionError):
            store.get(PK_A)

    def test_a_decryption_failure_carries_the_version_of_the_row_that_failed(
        self, store: TokenStore
    ) -> None:
        info = _put(store)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET ciphertext = x'00'")
        with pytest.raises(TokenDecryptionError) as exc:
            store.get(PK_A)
        assert exc.value.updated_at == info.updated_at

    def test_swapping_ciphertext_between_rows_fails(self, store: TokenStore) -> None:
        _put(store, principal_key=PK_A, token=TOKEN_A)
        _put(store, principal_key=PK_B, token=TOKEN_B)
        with _raw(store) as conn:
            nonce_b, ct_b = conn.execute(
                "SELECT nonce, ciphertext FROM canvas_tokens WHERE principal_key = ?",
                (PK_B,),
            ).fetchone()
            conn.execute(
                "UPDATE canvas_tokens SET nonce = ?, ciphertext = ?"
                " WHERE principal_key = ?",
                (nonce_b, ct_b, PK_A),
            )
        with pytest.raises(TokenDecryptionError):
            store.get(PK_A)
        got = store.get(PK_B)
        assert got is not None and got.api_token == TOKEN_B

    def test_editing_key_id_fails(self, tmp_path: pathlib.Path) -> None:
        ring = _ring(("k1", 1), ("k2", 2))
        store = make_store(tmp_path / "t.sqlite3", ring)
        store.initialize()
        make_account(store, OID_A)
        _put(store)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET key_id = 'k2'")
        with pytest.raises(TokenDecryptionError):
            store.get(PK_A)


class TestInitialize:
    def test_missing_kid_refused(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        old = make_store(path, _ring(("k1", 1)))
        old.initialize()
        make_account(old, OID_A)
        _put(old)
        with pytest.raises(KeyringError) as exc:
            make_store(path, _ring(("k2", 2))).initialize()
        assert str(exc.value) == "CANVAS_TOKEN_KEYS is missing key id(s): k1"

    def test_wrong_key_under_same_kid_refused(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        old = make_store(path, _ring(("k1", 1)))
        old.initialize()
        make_account(old, OID_A)
        _put(old)
        with pytest.raises(KeyringError) as exc:
            make_store(path, _ring(("k1", 9))).initialize()
        assert str(exc.value) == (
            "CANVAS_TOKEN_KEYS key k1 does not match the stored data"
        )

    def test_initialize_is_idempotent_and_keeps_rows(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "t.sqlite3"
        s = make_store(path, _ring(("k1", 1)))
        s.initialize()
        make_account(s, OID_A)
        _put(s)
        s.initialize()
        make_store(path, _ring(("k1", 1))).initialize()
        assert s.count() == 1

    def test_schema_version_present_and_future_refused(
        self, store: TokenStore
    ) -> None:
        with _raw(store) as conn:
            assert conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone() == (str(SCHEMA_VERSION),)
            conn.execute("UPDATE meta SET value = '6' WHERE key = 'schema_version'")
        with pytest.raises(TokenStoreError, match="newer"):
            store.initialize()
        with _raw(store) as conn:
            conn.execute("UPDATE meta SET value = 'x' WHERE key = 'schema_version'")
        with pytest.raises(TokenStoreError):
            store.initialize()

    @pytest.mark.sqlite_only

    def test_wal_mode_enabled(self, store: TokenStore) -> None:
        with _raw(store) as conn:
            assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"

    @pytest.mark.sqlite_only
    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    def test_posix_permissions(self, tmp_path: pathlib.Path) -> None:
        path = token_db_path(tmp_path / "state")
        s = make_store(path, _ring(("k1", 1)))
        s.initialize()
        make_account(s, OID_A)
        _put(s)
        assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_token_db_path(self) -> None:
        p = token_db_path(pathlib.Path("/data"))
        assert p.parts[-2:] == ("canvas-mcp", "tokens.sqlite3")

    def test_a_row_known_to_be_unreadable_does_not_fail_the_keyring_check(
        self, tmp_path: pathlib.Path
    ) -> None:
        """A decrypt_failed row proves nothing about the keys; the healthy rows do."""
        path = tmp_path / "t.sqlite3"
        first = make_store(path, _ring(("k1", 1)))
        first.initialize()
        make_account(first, OID_A)
        make_account(first, OID_B)
        _put(first, principal_key=PK_A)
        _put(first, principal_key=PK_B, token=TOKEN_B)
        with _raw(first) as conn:
            conn.execute("UPDATE canvas_tokens SET ciphertext = x'00' WHERE principal_key = ?", (PK_A,))
        first.mark_invalid(PK_A, reason="decrypt_failed")
        make_store(path, _ring(("k1", 1))).initialize()
        with pytest.raises(KeyringError):
            make_store(path, _ring(("k1", 9))).initialize()


class TestRotation:
    def test_rotate_reencrypts_and_old_key_can_be_dropped(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "t.sqlite3"
        old = make_store(path, _ring(("k1", 1)))
        old.initialize()
        make_account(old, OID_A)
        make_account(old, OID_B)
        _put(old, principal_key=PK_A, token=TOKEN_A)
        _put(old, principal_key=PK_B, token=TOKEN_B)
        both = make_store(path, _ring(("k2", 2), ("k1", 1)))
        both.initialize()
        assert both.rotate() == 2
        assert both.rotate() == 0
        with _raw(both) as conn:
            kids = {r[0] for r in conn.execute("SELECT key_id FROM canvas_tokens")}
        assert kids == {"k2"}
        only_new = make_store(path, _ring(("k2", 2)))
        only_new.initialize()  # proves no row needs k1
        got = only_new.get(PK_B)
        assert got is not None and got.api_token == TOKEN_B
        with pytest.raises(KeyringError):
            make_store(path, _ring(("k1", 1))).initialize()

    def test_rotate_rolls_back_when_a_row_is_corrupt(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "t.sqlite3"
        old = make_store(path, _ring(("k1", 1)))
        old.initialize()
        make_account(old, OID_A)
        make_account(old, OID_B)
        _put(old, principal_key=PK_A)
        _put(old, principal_key=PK_B)
        with _raw(old) as conn:
            conn.execute(
                "UPDATE canvas_tokens SET ciphertext = X'00' WHERE principal_key = ?",
                (PK_B,),
            )
        both = make_store(path, _ring(("k2", 2), ("k1", 1)))
        with pytest.raises(TokenDecryptionError):
            both.rotate()
        with _raw(both) as conn:
            kids = {r[0] for r in conn.execute("SELECT key_id FROM canvas_tokens")}
        assert kids == {"k1"}  # nothing half-rotated


class TestTouch:
    def test_touch_is_throttled(self, store: TokenStore, clock: Clock) -> None:
        _put(store)
        info = store.info(PK_A)
        assert info is not None and info.last_used_at is None
        store.touch(PK_A)
        t0 = int(clock.now)
        info = store.info(PK_A)
        assert info is not None and info.last_used_at == t0
        clock.now += 100
        store.touch(PK_A)
        info = store.info(PK_A)
        assert info is not None and info.last_used_at == t0  # inside 300 s
        clock.now += 300
        store.touch(PK_A)
        info = store.info(PK_A)
        assert info is not None and info.last_used_at == int(clock.now)

    def test_touch_unknown_row_and_bad_ids_never_raise(
        self, store: TokenStore
    ) -> None:
        store.touch(PK_B)
        store.touch("nope")
        store.touch(f"entra:{TID}:{OID_A}")

    def test_touch_swallows_sqlite_errors(
        self, tmp_path: pathlib.Path, clock: Clock
    ) -> None:
        s = make_store(tmp_path / "missing" / "t.sqlite3", _ring(("k1", 1)))
        s.touch(PK_A)  # directory and database do not exist


class TestConcurrency:
    def test_concurrent_put_and_get(self, store: TokenStore) -> None:
        oids = [f"00000000-0000-0000-0000-{i:012d}" for i in range(8)]
        for oid in oids:
            make_account(store, oid)
        errors: list[BaseException] = []

        def work(oid: str, n: int) -> None:
            try:
                for i in range(15):
                    tok = f"{n}~{i:03d}" + "z" * 30
                    _put(store, principal_key=acct_key(oid), token=tok)
                    got = store.get(acct_key(oid))
                    assert got is not None and got.api_token == tok
                    store.touch(acct_key(oid), min_interval_seconds=0)
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


HOST_A = "canvas.school-a.edu"
HOST_B = "canvas.school-b.edu"


class TestCanvasHost:
    def test_host_roundtrip_in_get_info_and_list(self, store: TokenStore) -> None:
        info = _put(store, canvas_host=HOST_A)
        assert info.canvas_host == HOST_A
        got = store.get(PK_A)
        assert got is not None and got.canvas_host == HOST_A and got.api_token == TOKEN_A
        assert store.info(PK_A).canvas_host == HOST_A  # type: ignore[union-attr]
        assert [r.canvas_host for r in store.list_enrollments()] == [HOST_A]

    def test_no_host_means_the_default_school(self, store: TokenStore) -> None:
        assert _put(store).canvas_host is None
        got = store.get(PK_A)
        assert got is not None and got.canvas_host is None

    @pytest.mark.parametrize(
        "bad", ["", "Canvas.School.EDU", "canvas.school.edu\n", "café.edu", "a" * 254, "a\x1fb.edu", 5]
    )
    def test_put_validates_the_host(self, store: TokenStore, bad: object) -> None:
        with pytest.raises(ValueError):
            _put(store, canvas_host=bad)
        assert store.count() == 0

    def test_default_hosts_that_are_not_school_names_are_storable(self, store: TokenStore) -> None:
        for host in ("127.0.0.1", "canvas.lan", "localhost"):
            _put(store, canvas_host=host)
            assert store.get(PK_A).canvas_host == host  # type: ignore[union-attr]

    def test_replacing_a_row_can_change_the_school(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        _put(store, token=TOKEN_B, canvas_host=HOST_B)
        got = store.get(PK_A)
        assert got is not None and (got.canvas_host, got.api_token) == (HOST_B, TOKEN_B)

    def test_replacing_a_default_school_row_with_a_host_changes_the_layout(
        self, store: TokenStore
    ) -> None:
        _put(store)
        _put(store, canvas_host=HOST_A)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET canvas_host = NULL")
        with pytest.raises(TokenDecryptionError):
            store.get(PK_A)

    def test_aad_layouts(self) -> None:
        v2 = token_store_module._aad_v2
        v3 = token_store_module._aad_v3
        with_host = v2(PK_A, HOST_A, "k1")
        default_school = v3(PK_A, "k1")
        assert with_host.startswith(b"canvas-mcp/canvas-token/v2\x1f")
        assert default_school.startswith(b"canvas-mcp/canvas-token/v3\x1f")
        assert with_host == (
            b"canvas-mcp/canvas-token/v2\x1f"
            + PK_A.encode()
            + b"\x1f"
            + HOST_A.encode()
            + b"\x1f"
            + b"k1"
        )
        assert default_school == (
            b"canvas-mcp/canvas-token/v3\x1f" + PK_A.encode() + b"\x1f" + b"k1"
        )
        assert default_school != with_host
        assert v2(PK_A, HOST_A, "k1") != v2(PK_A, HOST_B, "k1")
        assert v2(PK_A, HOST_A, "k1") != v2(PK_B, HOST_A, "k1")
        assert v2(PK_A, HOST_A, "k1") != v2(PK_A, HOST_A, "k2")
        assert v3(PK_A, "k1") != v3(PK_B, "k1") and v3(PK_A, "k1") != v3(PK_A, "k2")
        # The field boundaries cannot be shifted into one another.
        assert v2("a", "b.edu", "k1") != v2("a\x1fb", ".edu", "k1")
        assert v3("a", "k1") != v3("a\x1fk", "1")

    def test_aad_for_a_principal_picks_the_layout_from_the_host(self) -> None:
        aad = token_store_module._aad_for_principal
        assert aad(PK_A, HOST_A, "k1") == token_store_module._aad_v2(PK_A, HOST_A, "k1")
        assert aad(PK_A, None, "k1") == token_store_module._aad_v3(PK_A, "k1")
        with pytest.raises(ValueError):
            aad("google:12345", None, "k1")
        with pytest.raises(ValueError):
            aad(f"entra:{TID}:{OID_A}", None, "k1")

    def test_the_database_value_is_used_exactly_as_read(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET canvas_host = ?", (HOST_A.upper(),))
        with pytest.raises(TokenDecryptionError):
            store.get(PK_A)


class TestHostTamper:
    def test_swapping_the_host_fails_and_never_decrypts(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        _put(store, principal_key=PK_B, token=TOKEN_B, canvas_host=HOST_B)
        with _raw(store) as conn:
            conn.execute(
                "UPDATE canvas_tokens SET canvas_host = ? WHERE principal_key = ?", (HOST_B, PK_A)
            )
        with pytest.raises(TokenDecryptionError):
            store.get(PK_A)
        other = store.get(PK_B)
        assert other is not None and other.api_token == TOKEN_B

    def test_nulling_a_host_fails(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET canvas_host = NULL")
        with pytest.raises(TokenDecryptionError):
            store.get(PK_A)

    def test_adding_a_host_to_a_default_school_row_fails(self, store: TokenStore) -> None:
        _put(store)
        assert store.get(PK_A).api_token == TOKEN_A  # type: ignore[union-attr]
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET canvas_host = ?", (HOST_A,))
        with pytest.raises(TokenDecryptionError):
            store.get(PK_A)

    def test_a_tampered_probe_row_is_a_keyring_error_at_open(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        s = make_store(path, _ring(("k1", 1)))
        s.initialize()
        make_account(s, OID_A)
        _put(s, canvas_host=HOST_A)
        with _raw(s) as conn:
            conn.execute("UPDATE canvas_tokens SET canvas_host = ?", (HOST_B,))
        with pytest.raises(KeyringError):
            make_store(path, _ring(("k1", 1))).initialize()

    def test_wrong_key_with_v2_rows_is_a_keyring_error(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        s = make_store(path, _ring(("k1", 1)))
        s.initialize()
        make_account(s, OID_A)
        _put(s, canvas_host=HOST_A)
        make_store(path, _ring(("k1", 1))).initialize()
        with pytest.raises(KeyringError):
            make_store(path, _ring(("k1", 9))).initialize()


class TestMixedRotation:
    def test_rotation_keeps_hosts_and_both_aad_kinds(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        old = make_store(path, _ring(("k1", 1)))
        old.initialize()
        make_account(old, OID_A)
        make_account(old, OID_B)
        _put(old, principal_key=PK_A, token=TOKEN_A)  # no host: layout v3
        _put(old, principal_key=PK_B, token=TOKEN_B, canvas_host=HOST_B)  # layout v2
        both = make_store(path, _ring(("k2", 2), ("k1", 1)))
        both.initialize()
        assert both.rotate() == 2
        assert both.rotate() == 0
        only_new = make_store(path, _ring(("k2", 2)))
        only_new.initialize()
        a = only_new.get(PK_A)
        b = only_new.get(PK_B)
        assert a is not None and (a.api_token, a.canvas_host, a.key_id) == (TOKEN_A, None, "k2")
        assert b is not None and (b.api_token, b.canvas_host, b.key_id) == (TOKEN_B, HOST_B, "k2")
        with pytest.raises(KeyringError):
            make_store(path, _ring(("k1", 1))).initialize()


# -- principal keys, the AAD layouts, the account gate -------------------------------------


class TestPrincipalKey:
    def test_methods_take_the_principal_key(self, store: TokenStore) -> None:
        info = _put(store, canvas_host=HOST_A)
        assert info.principal_key == PK_A
        got = store.get(PK_A)
        assert got is not None and got.api_token == TOKEN_A and got.principal_key == PK_A
        assert store.info(PK_A).principal_key == PK_A  # type: ignore[union-attr]
        assert [r.principal_key for r in store.list_enrollments()] == [PK_A]
        store.touch(PK_A, min_interval_seconds=0)
        assert store.info(PK_A).last_used_at is not None  # type: ignore[union-attr]
        assert store.delete(PK_A) is True
        assert store.get(PK_A) is None and store.delete(PK_A) is False

    def test_the_legacy_entra_key_is_not_accepted_anywhere(self, store: TokenStore) -> None:
        legacy = f"entra:{TID}:{OID_A}"
        _put(store, canvas_host=HOST_A)
        for call in (
            lambda: store.get(legacy),
            lambda: store.info(legacy),
            lambda: store.delete(legacy),
            lambda: store.mark_invalid(legacy, reason="canvas_token_rejected"),
            lambda: store.restore_active(legacy),
            lambda: store.credential_generation(legacy),
            lambda: store.get_tool_prefs(legacy),
            lambda: store.set_tool_prefs(legacy, []),
            lambda: _put(store, principal_key=legacy),
        ):
            with pytest.raises(ValueError):
                call()
        assert store.count() == 1

    def test_the_legacy_key_is_mapped_through_the_identity_table(self, store: TokenStore) -> None:
        assert store.resolve_legacy_key(f"entra:{TID}:{OID_A}") == PK_A
        assert token_store_module.entra_principal_key(TID.upper(), OID_A.upper()) == (
            f"entra:{TID}:{OID_A}"
        )

    def test_the_key_matches_the_identity_module(self) -> None:
        from canvas_mcp.core.selfhost.identity import principal_key

        assert token_store_module.entra_principal_key(TID, OID_A) == principal_key(TID, OID_A)

    def test_put_needs_an_account_key(self, store: TokenStore) -> None:
        with pytest.raises(TypeError):
            store.put(  # type: ignore[call-arg]
                api_token=TOKEN_A, canvas_user_id="1", canvas_user_name="x", canvas_host=HOST_A,
            )
        with pytest.raises(TypeError):
            store.put(  # type: ignore[call-arg]
                tenant_id=TID, object_id=OID_A, api_token=TOKEN_A, canvas_user_id="1",
                canvas_user_name="x", canvas_host=HOST_A,
            )
        assert store.count() == 0

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "Acct:" + PK_A[5:],
            PK_A.upper(),
            "acct:not-a-uuid",
            "acct:",
            f"entra:{TID}:{OID_A}",
            "google:abc\x1fdef",
            "google:café",
            "google:1234567890",
            "x" * 257,
            5,
        ],
    )
    def test_bad_principal_keys_are_refused(self, store: TokenStore, bad: object) -> None:
        with pytest.raises(ValueError):
            _put(store, principal_key=bad)  # type: ignore[arg-type]
        assert store.count() == 0

    def test_a_host_less_row_needs_an_account_principal(self, store: TokenStore) -> None:
        with pytest.raises(ValueError):
            _put(store, principal_key="google:1234567890", canvas_host=None)
        assert store.count() == 0

    def test_the_principal_key_is_stored_in_the_row(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        with _raw(store) as conn:
            assert conn.execute("SELECT principal_key FROM canvas_tokens").fetchall() == [(PK_A,)]


class TestTheAccountGate:
    def test_only_an_active_account_can_enroll(self, tmp_path: pathlib.Path) -> None:
        s = make_store(tmp_path / "t.sqlite3", _ring(("k1", 1)))
        s.initialize()
        pending = make_account(s, "cccccccc-0000-4000-8000-00000000000c", status="pending")
        disabled = make_account(s, "dddddddd-0000-4000-8000-00000000000d", status="disabled")
        ghost = acct_key("eeeeeeee-0000-4000-8000-00000000000e")
        with pytest.raises(PrincipalPendingError):
            _put(s, principal_key=pending)
        with pytest.raises(PrincipalDisabledError):
            _put(s, principal_key=disabled)
        with pytest.raises(PrincipalMissingError):
            _put(s, principal_key=ghost)
        assert s.count() == 0

    def test_write_tool_switches_need_an_active_account_too(self, tmp_path: pathlib.Path) -> None:
        s = make_store(tmp_path / "t.sqlite3", _ring(("k1", 1)))
        s.initialize()
        pending = make_account(s, "cccccccc-0000-4000-8000-00000000000c", status="pending")
        with pytest.raises(PrincipalPendingError):
            s.set_tool_prefs(pending, ["send_message"])
        assert s.get_tool_prefs(pending) is None

    def test_enrolling_deleting_and_marking_invalid_are_audited(
        self, store: TokenStore, clock: Clock
    ) -> None:
        _put(store, canvas_host=HOST_A)
        clock.now += 5
        _put(store, canvas_host=HOST_A, token=TOKEN_B)
        store.mark_invalid(PK_A, reason="revoked_by_admin", actor=OPERATOR)
        store.delete(PK_A, actor=OPERATOR)
        rows = [(e.action, e.actor, e.target) for e in store.list_audit()]
        assert rows[:4] == [
            ("token_deleted", "operator", PK_A),
            ("token_marked_invalid", "operator", PK_A),
            ("token_replaced", PK_A, PK_A),
            ("token_enrolled", PK_A, PK_A),
        ]
        # The audit trail never holds the token or the ciphertext.
        text = repr([(e.detail, e.reason) for e in store.list_audit()])
        assert TOKEN_A not in text and TOKEN_B not in text


class TestAadBinding:
    def test_the_ciphertext_is_bound_to_principal_host_and_key_id(self, store: TokenStore) -> None:
        """Decrypt the raw row with the documented layout, and with nothing else."""
        _put(store, canvas_host=HOST_A)
        with _raw(store) as conn:
            kid, nonce, ct = conn.execute("SELECT key_id, nonce, ciphertext FROM canvas_tokens").fetchone()
        aead = AESGCM(_key(1))
        documented = (
            b"canvas-mcp/canvas-token/v2\x1f"
            + PK_A.encode()
            + b"\x1f"
            + HOST_A.encode()
            + b"\x1f"
            + kid.encode()
        )
        assert aead.decrypt(bytes(nonce), bytes(ct), documented) == TOKEN_A.encode()
        for wrong in (
            documented.replace(PK_A.encode(), PK_B.encode()),
            documented.replace(HOST_A.encode(), HOST_B.encode()),
            documented.replace(b"v2", b"v1"),
            documented.replace(b"v2", b"v3"),
            documented + b"\x1f",
        ):
            with pytest.raises(InvalidTag):
                aead.decrypt(bytes(nonce), bytes(ct), wrong)

    def test_a_default_school_row_is_bound_to_principal_and_key_id(self, store: TokenStore) -> None:
        _put(store)
        with _raw(store) as conn:
            kid, nonce, ct = conn.execute("SELECT key_id, nonce, ciphertext FROM canvas_tokens").fetchone()
        aead = AESGCM(_key(1))
        documented = b"canvas-mcp/canvas-token/v3\x1f" + PK_A.encode() + b"\x1f" + kid.encode()
        assert aead.decrypt(bytes(nonce), bytes(ct), documented) == TOKEN_A.encode()
        for wrong in (
            documented.replace(PK_A.encode(), PK_B.encode()),
            documented.replace(b"v3", b"v2"),
            documented.replace(b"v3", b"v1"),
            documented + b"\x1f",
            documented.replace(b"\x1f" + kid.encode(), b"\x1fk2"),
        ):
            with pytest.raises(InvalidTag):
                aead.decrypt(bytes(nonce), bytes(ct), wrong)

    def test_moving_a_row_to_another_principal_fails(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        _put(store, principal_key=PK_B, token=TOKEN_B, canvas_host=HOST_A)
        with _raw(store) as conn:
            # Swap the two principals' keys (through a placeholder: the key is unique).
            conn.execute("UPDATE canvas_tokens SET principal_key = 'tmp' WHERE principal_key = ?", (PK_A,))
            conn.execute("UPDATE canvas_tokens SET principal_key = ? WHERE principal_key = ?", (PK_A, PK_B))
            conn.execute("UPDATE canvas_tokens SET principal_key = ? WHERE principal_key = 'tmp'", (PK_B,))
        for key in (PK_A, PK_B):
            with pytest.raises(TokenDecryptionError):
                store.get(key)

    def test_renaming_the_principal_of_a_v2_row_fails(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        other = PK_B
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET principal_key = ?", (other,))
        assert store.get(PK_A) is None
        with pytest.raises(TokenDecryptionError):
            store.get(other)

    def test_renaming_the_principal_of_a_default_school_row_fails(self, store: TokenStore) -> None:
        _put(store)
        other = PK_B
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET principal_key = ?", (other,))
        with pytest.raises(TokenDecryptionError):
            store.get(other)

    def test_swapping_principal_and_host_together_fails(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        other = PK_B
        with _raw(store) as conn:
            conn.execute(
                "UPDATE canvas_tokens SET principal_key = ?, canvas_host = ?", (other, HOST_B)
            )
        with pytest.raises(TokenDecryptionError):
            store.get(other)

    def test_a_tampered_principal_key_is_a_keyring_error_at_open(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        s = make_store(path, _ring(("k1", 1)))
        s.initialize()
        make_account(s, OID_A)
        _put(s, canvas_host=HOST_A)
        with _raw(s) as conn:
            conn.execute("UPDATE canvas_tokens SET principal_key = ?", (PK_B,))
        with pytest.raises(KeyringError):
            make_store(path, _ring(("k1", 1))).initialize()


class TestStatusColumns:
    NEW_COLUMNS = (
        "canvas_host",
        "principal_key",
        "status",
        "invalid_reason",
        "invalid_since",
        "last_verified_at",
        "expires_hint_at",
    )

    def _status_row(self, store: TokenStore) -> tuple[object, ...]:
        with _raw(store) as conn:
            return conn.execute(
                "SELECT status, invalid_reason, invalid_since, last_verified_at, expires_hint_at"
                " FROM canvas_tokens"
            ).fetchone()

    @pytest.mark.sqlite_only

    def test_a_new_database_has_every_column(self, store: TokenStore) -> None:
        columns = _columns(store._path)
        for name in self.NEW_COLUMNS:
            assert columns.count(name) == 1
        # The Entra tenant, object id and display snapshot are gone: names live in accounts.
        for name in ("tenant_id", "object_id", "entra_display_name", "entra_upn"):
            assert name not in columns

    def test_a_saved_row_is_active_and_verified_now(self, store: TokenStore, clock: Clock) -> None:
        _put(store, canvas_host=HOST_A)
        assert self._status_row(store) == ("active", None, None, int(clock.now), None)

    def test_saving_again_clears_an_invalid_mark(self, store: TokenStore, clock: Clock) -> None:
        _put(store, canvas_host=HOST_A)
        with _raw(store) as conn:
            conn.execute(
                "UPDATE canvas_tokens SET status = 'invalid', invalid_reason = 'canvas_token_rejected',"
                " invalid_since = 5, last_verified_at = 4, expires_hint_at = 99"
            )
        clock.now += 60
        _put(store, token=TOKEN_B, canvas_host=HOST_A)
        # The user's own hint about the expiry date survives a re-save.
        assert self._status_row(store) == ("active", None, None, int(clock.now), 99)
        assert store.get(PK_A).api_token == TOKEN_B  # type: ignore[union-attr]

    def test_the_status_columns_do_not_change_reads(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET status = 'invalid', invalid_reason = 'x'")
        got = store.get(PK_A)
        assert got is not None and got.api_token == TOKEN_A
