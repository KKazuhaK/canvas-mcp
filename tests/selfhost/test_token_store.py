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
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dbbackend import make_store, raw_connection

from canvas_mcp.core.selfhost import token_store as token_store_module
from canvas_mcp.core.selfhost.token_store import (
    SCHEMA_VERSION,
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
    s = make_store(tmp_path / "data" / "tokens.sqlite3", _ring(("k1", 1)), clock=clock)
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


def _raw(store: TokenStore):  # type: ignore[no-untyped-def]
    return raw_connection(store)


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

    def test_a_decryption_failure_carries_the_version_of_the_row_that_failed(
        self, store: TokenStore
    ) -> None:
        info = _put(store)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET ciphertext = x'00'")
        with pytest.raises(TokenDecryptionError) as exc:
            store.get(TID, OID_A)
        assert exc.value.updated_at == info.updated_at

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
        store = make_store(tmp_path / "t.sqlite3", ring)
        store.initialize()
        _put(store)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET key_id = 'k2'")
        with pytest.raises(TokenDecryptionError):
            store.get(TID, OID_A)


class TestInitialize:
    def test_missing_kid_refused(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        old = make_store(path, _ring(("k1", 1)))
        old.initialize()
        _put(old)
        with pytest.raises(KeyringError) as exc:
            make_store(path, _ring(("k2", 2))).initialize()
        assert str(exc.value) == "CANVAS_TOKEN_KEYS is missing key id(s): k1"

    def test_wrong_key_under_same_kid_refused(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        old = make_store(path, _ring(("k1", 1)))
        old.initialize()
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
            conn.execute("UPDATE meta SET value = '5' WHERE key = 'schema_version'")
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

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    def test_posix_permissions(self, tmp_path: pathlib.Path) -> None:
        path = token_db_path(tmp_path / "state")
        s = make_store(path, _ring(("k1", 1)))
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
        old = make_store(path, _ring(("k1", 1)))
        old.initialize()
        _put(old, oid=OID_A, token=TOKEN_A)
        _put(old, oid=OID_B, token=TOKEN_B)
        both = make_store(path, _ring(("k2", 2), ("k1", 1)))
        both.initialize()
        assert both.rotate() == 2
        assert both.rotate() == 0
        with _raw(both) as conn:
            kids = {r[0] for r in conn.execute("SELECT key_id FROM canvas_tokens")}
        assert kids == {"k2"}
        only_new = make_store(path, _ring(("k2", 2)))
        only_new.initialize()  # proves no row needs k1
        got = only_new.get(TID, OID_B)
        assert got is not None and got.api_token == TOKEN_B
        with pytest.raises(KeyringError):
            make_store(path, _ring(("k1", 1))).initialize()

    def test_rotate_rolls_back_when_a_row_is_corrupt(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "t.sqlite3"
        old = make_store(path, _ring(("k1", 1)))
        old.initialize()
        _put(old, oid=OID_A)
        _put(old, oid=OID_B)
        with _raw(old) as conn:
            conn.execute(
                "UPDATE canvas_tokens SET ciphertext = X'00' WHERE object_id = ?",
                (OID_B,),
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
        s = make_store(tmp_path / "missing" / "t.sqlite3", _ring(("k1", 1)))
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


HOST_A = "canvas.school-a.edu"
HOST_B = "canvas.school-b.edu"


def pk(oid: str, tid: str = TID) -> str:
    return f"entra:{tid}:{oid}"


def _seal_v1(store: TokenStore, oid: str, token: str, kid: str = "k1") -> None:
    """Write a row exactly as the pre-school (schema v1) server did."""
    aad = (
        b"canvas-mcp/canvas-token/v1\x1f"
        + TID.encode()
        + b"\x1f"
        + oid.encode()
        + b"\x1f"
        + kid.encode()
    )
    _, nonce, ct = store._keyring.encrypt(token.encode(), aad)
    with _raw(store) as conn:
        conn.execute(
            "INSERT INTO canvas_tokens (tenant_id, object_id, key_id, nonce, ciphertext,"
            " canvas_user_id, canvas_user_name, entra_display_name, entra_upn,"
            " created_at, updated_at, last_used_at, principal_key)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL,?)",
            (TID, oid, kid, nonce, ct, "7", "Legacy", "L", "l@example.test", 1, 1, pk(oid)),
        )


def _make_v1_database(path: pathlib.Path, ring: Keyring, oid: str, token: str) -> None:
    """A database as the previous release left it: version '1', no canvas_host column."""
    old_schema = (
        "CREATE TABLE canvas_tokens ("
        " tenant_id TEXT NOT NULL, object_id TEXT NOT NULL, key_id TEXT NOT NULL,"
        " nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, canvas_user_id TEXT NOT NULL,"
        " canvas_user_name TEXT NOT NULL, entra_display_name TEXT NOT NULL DEFAULT '',"
        " entra_upn TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL, last_used_at INTEGER,"
        " PRIMARY KEY (tenant_id, object_id)) WITHOUT ROWID"
    )
    aad = b"canvas-mcp/canvas-token/v1\x1f" + f"{TID}\x1f{oid}\x1fk1".encode()
    kid, nonce, ct = ring.encrypt(token.encode(), aad)
    conn = sqlite3.connect(str(path), isolation_level=None)
    try:
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID")
        conn.execute(old_schema)
        conn.execute("INSERT INTO meta VALUES ('schema_version', '1')")
        conn.execute(
            "INSERT INTO canvas_tokens VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL)",
            (TID, oid, kid, nonce, ct, "7", "Legacy", "L", "l@example.test", 1, 1),
        )
    finally:
        conn.close()


class TestCanvasHost:
    def test_host_roundtrip_in_get_info_and_list(self, store: TokenStore) -> None:
        info = _put(store, canvas_host=HOST_A)
        assert info.canvas_host == HOST_A
        got = store.get(TID, OID_A)
        assert got is not None and got.canvas_host == HOST_A and got.api_token == TOKEN_A
        assert store.info(TID, OID_A).canvas_host == HOST_A  # type: ignore[union-attr]
        assert [r.canvas_host for r in store.list_enrollments()] == [HOST_A]

    def test_no_host_means_legacy_none(self, store: TokenStore) -> None:
        assert _put(store).canvas_host is None
        got = store.get(TID, OID_A)
        assert got is not None and got.canvas_host is None

    @pytest.mark.parametrize(
        "bad", ["", "Canvas.School.EDU", "canvas.school.edu\n", "caf\u00e9.edu", "a" * 254, "a\x1fb.edu", 5]
    )
    def test_put_validates_the_host(self, store: TokenStore, bad: object) -> None:
        with pytest.raises(ValueError):
            _put(store, canvas_host=bad)
        assert store.count() == 0

    def test_default_hosts_that_are_not_school_names_are_storable(self, store: TokenStore) -> None:
        for host in ("127.0.0.1", "canvas.lan", "localhost"):
            _put(store, canvas_host=host)
            assert store.get(TID, OID_A).canvas_host == host  # type: ignore[union-attr]

    def test_replacing_a_row_can_change_the_school(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        _put(store, token=TOKEN_B, canvas_host=HOST_B)
        got = store.get(TID, OID_A)
        assert got is not None and (got.canvas_host, got.api_token) == (HOST_B, TOKEN_B)

    def test_aad_layouts(self) -> None:
        v1 = token_store_module._aad_v1
        v2 = token_store_module._aad_v2
        legacy = v1(TID, OID_A, "k1")
        with_host = v2(pk(OID_A), HOST_A, "k1")
        assert legacy.startswith(b"canvas-mcp/canvas-token/v1\x1f")
        assert with_host.startswith(b"canvas-mcp/canvas-token/v2\x1f")
        assert with_host == (
            b"canvas-mcp/canvas-token/v2\x1f"
            + pk(OID_A).encode()
            + b"\x1f"
            + HOST_A.encode()
            + b"\x1f"
            + b"k1"
        )
        assert legacy != with_host
        assert v2(pk(OID_A), HOST_A, "k1") != v2(pk(OID_A), HOST_B, "k1")
        assert v2(pk(OID_A), HOST_A, "k1") != v2(pk(OID_B), HOST_A, "k1")
        assert v2(pk(OID_A), HOST_A, "k1") != v2(pk(OID_A), HOST_A, "k2")
        # The field boundaries cannot be shifted into one another.
        assert v2("a", "b.edu", "k1") != v2("a\x1fb", ".edu", "k1")

    def test_aad_for_a_principal_picks_the_layout_from_the_host(self) -> None:
        aad = token_store_module._aad_for_principal
        assert aad(pk(OID_A), HOST_A, "k1") == token_store_module._aad_v2(pk(OID_A), HOST_A, "k1")
        assert aad(pk(OID_A), None, "k1") == token_store_module._aad_v1(TID, OID_A, "k1")
        with pytest.raises(ValueError):
            aad("google:12345", None, "k1")

    def test_the_database_value_is_used_exactly_as_read(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET canvas_host = ?", (HOST_A.upper(),))
        with pytest.raises(TokenDecryptionError):
            store.get(TID, OID_A)


class TestHostTamper:
    def test_swapping_the_host_fails_and_never_decrypts(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        _put(store, oid=OID_B, token=TOKEN_B, canvas_host=HOST_B)
        with _raw(store) as conn:
            conn.execute(
                "UPDATE canvas_tokens SET canvas_host = ? WHERE object_id = ?", (HOST_B, OID_A)
            )
        with pytest.raises(TokenDecryptionError):
            store.get(TID, OID_A)
        other = store.get(TID, OID_B)
        assert other is not None and other.api_token == TOKEN_B

    def test_nulling_a_host_fails(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET canvas_host = NULL")
        with pytest.raises(TokenDecryptionError):
            store.get(TID, OID_A)

    def test_adding_a_host_to_a_legacy_row_fails(self, store: TokenStore) -> None:
        _seal_v1(store, OID_A, TOKEN_A)
        assert store.get(TID, OID_A).api_token == TOKEN_A  # type: ignore[union-attr]
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET canvas_host = ?", (HOST_A,))
        with pytest.raises(TokenDecryptionError):
            store.get(TID, OID_A)

    def test_a_tampered_probe_row_is_a_keyring_error_at_open(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        s = make_store(path, _ring(("k1", 1)))
        s.initialize()
        _put(s, canvas_host=HOST_A)
        with _raw(s) as conn:
            conn.execute("UPDATE canvas_tokens SET canvas_host = ?", (HOST_B,))
        with pytest.raises(KeyringError):
            make_store(path, _ring(("k1", 1))).initialize()

    def test_wrong_key_with_v2_rows_is_a_keyring_error(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        s = make_store(path, _ring(("k1", 1)))
        s.initialize()
        _put(s, canvas_host=HOST_A)
        make_store(path, _ring(("k1", 1))).initialize()
        with pytest.raises(KeyringError):
            make_store(path, _ring(("k1", 9))).initialize()


class TestMigration:
    @pytest.mark.sqlite_only
    def test_version_1_database_is_migrated_in_place(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        ring = _ring(("k1", 1))
        _make_v1_database(path, ring, OID_A, TOKEN_A)
        s = make_store(path, ring, clock=lambda: 1_700_000_000)
        s.initialize()
        with _raw(s) as conn:
            assert conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone() == (str(SCHEMA_VERSION),)
            columns = [r[1] for r in conn.execute("PRAGMA table_info(canvas_tokens)")]
        assert columns.count("canvas_host") == 1
        got = s.get(TID, OID_A)
        assert got is not None and got.api_token == TOKEN_A and got.canvas_host is None
        assert s.info(TID, OID_A).canvas_host is None  # type: ignore[union-attr]

    @pytest.mark.sqlite_only

    def test_migration_is_idempotent(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        ring = _ring(("k1", 1))
        _make_v1_database(path, ring, OID_A, TOKEN_A)
        for _ in range(3):
            make_store(path, ring).initialize()
        s = make_store(path, ring)
        s.initialize()
        with _raw(s) as conn:
            columns = [r[1] for r in conn.execute("PRAGMA table_info(canvas_tokens)")]
        assert columns.count("canvas_host") == 1
        assert s.get(TID, OID_A).api_token == TOKEN_A  # type: ignore[union-attr]

    @pytest.mark.sqlite_only

    def test_a_half_migrated_database_is_completed(self, tmp_path: pathlib.Path) -> None:
        """Column present but version still 1 (e.g. an interrupted manual step)."""
        path = tmp_path / "t.sqlite3"
        ring = _ring(("k1", 1))
        _make_v1_database(path, ring, OID_A, TOKEN_A)
        with sqlite3.connect(str(path)) as conn:
            conn.execute("ALTER TABLE canvas_tokens ADD COLUMN canvas_host TEXT")
        s = make_store(path, ring)
        s.initialize()
        assert s.get(TID, OID_A).api_token == TOKEN_A  # type: ignore[union-attr]

    def test_saving_reseals_a_legacy_row_with_the_host(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        ring = _ring(("k1", 1))
        _make_v1_database(path, ring, OID_A, TOKEN_A)
        s = make_store(path, ring)
        s.initialize()
        s.put(
            tenant_id=TID, object_id=OID_A, api_token=TOKEN_A, canvas_user_id="7",
            canvas_user_name="Legacy", entra_display_name="L", entra_upn="l@example.test",
            canvas_host=HOST_A,
        )
        assert s.get(TID, OID_A).canvas_host == HOST_A  # type: ignore[union-attr]
        # Now sealed as v2: dropping the host breaks it.
        with _raw(s) as conn:
            conn.execute("UPDATE canvas_tokens SET canvas_host = NULL")
        with pytest.raises(TokenDecryptionError):
            s.get(TID, OID_A)

    def test_future_versions_are_still_refused(self, store: TokenStore) -> None:
        with _raw(store) as conn:
            conn.execute("UPDATE meta SET value = '5' WHERE key = 'schema_version'")
        with pytest.raises(TokenStoreError, match="newer"):
            store.initialize()


class TestMixedRotation:
    def test_rotation_keeps_hosts_and_both_aad_kinds(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        old = make_store(path, _ring(("k1", 1)))
        old.initialize()
        _seal_v1(old, OID_A, TOKEN_A)
        _put(old, oid=OID_B, token=TOKEN_B, canvas_host=HOST_B)
        both = make_store(path, _ring(("k2", 2), ("k1", 1)))
        both.initialize()
        assert both.rotate() == 2
        assert both.rotate() == 0
        only_new = make_store(path, _ring(("k2", 2)))
        only_new.initialize()
        a = only_new.get(TID, OID_A)
        b = only_new.get(TID, OID_B)
        assert a is not None and (a.api_token, a.canvas_host, a.key_id) == (TOKEN_A, None, "k2")
        assert b is not None and (b.api_token, b.canvas_host, b.key_id) == (TOKEN_B, HOST_B, "k2")
        with pytest.raises(KeyringError):
            make_store(path, _ring(("k1", 1))).initialize()


# -- principal keys, AAD v2 layout, status columns (identity-ready store) -------------------

PK_A = pk(OID_A)
PK_B = pk(OID_B)


def _put_pk(store: TokenStore, principal_key: str, token: str = TOKEN_A, **kw):
    args: dict[str, object] = {
        "principal_key": principal_key,
        "api_token": token,
        "canvas_user_id": "42",
        "canvas_user_name": "Ada Lovelace",
        "entra_display_name": "Ada",
        "entra_upn": "ada@example.test",
        "canvas_host": HOST_A,
    }
    args.update(kw)
    return store.put(**args)  # type: ignore[arg-type]


def _columns(path: pathlib.Path) -> list[str]:
    conn = sqlite3.connect(str(path))
    try:
        return [r[1] for r in conn.execute("PRAGMA table_info(canvas_tokens)")]
    finally:
        conn.close()


class TestPrincipalKey:
    def test_methods_take_the_principal_key(self, store: TokenStore) -> None:
        info = _put_pk(store, PK_A)
        assert info.principal_key == PK_A
        assert (info.tenant_id, info.object_id) == (TID, OID_A)
        got = store.get(PK_A)
        assert got is not None and got.api_token == TOKEN_A and got.principal_key == PK_A
        assert store.info(PK_A).principal_key == PK_A  # type: ignore[union-attr]
        assert [r.principal_key for r in store.list_enrollments()] == [PK_A]
        store.touch(PK_A, min_interval_seconds=0)
        assert store.info(PK_A).last_used_at is not None  # type: ignore[union-attr]
        assert store.delete(PK_A) is True
        assert store.get(PK_A) is None and store.delete(PK_A) is False

    def test_the_tenant_object_adapter_is_the_same_row(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        assert store.get(PK_A).api_token == TOKEN_A  # type: ignore[union-attr]
        assert store.get(TID, OID_A).principal_key == PK_A  # type: ignore[union-attr]
        # Either spelling replaces the same row.
        _put_pk(store, PK_A, token=TOKEN_B)
        assert store.count() == 1
        assert store.get(TID, OID_A).api_token == TOKEN_B  # type: ignore[union-attr]
        assert store.delete(TID, OID_A) is True
        assert store.get(PK_A) is None

    def test_adapter_ids_are_lowercased_into_the_key(self, store: TokenStore) -> None:
        _put(store, tenant_id=TID.upper(), object_id=OID_A.upper(), canvas_host=HOST_A)
        assert store.info(PK_A).principal_key == PK_A  # type: ignore[union-attr]
        assert token_store_module.entra_principal_key(TID.upper(), OID_A.upper()) == PK_A

    def test_the_key_matches_the_identity_module(self) -> None:
        from canvas_mcp.core.selfhost.identity import principal_key

        assert token_store_module.entra_principal_key(TID, OID_A) == principal_key(TID, OID_A)

    def test_put_needs_exactly_one_way_to_name_the_principal(self, store: TokenStore) -> None:
        with pytest.raises(ValueError):
            _put_pk(store, PK_A, tenant_id=TID, object_id=OID_A)
        with pytest.raises(ValueError):
            store.put(
                api_token=TOKEN_A, canvas_user_id="1", canvas_user_name="x",
                entra_display_name="", entra_upn="", canvas_host=HOST_A,
            )
        with pytest.raises(ValueError):
            store.put(
                tenant_id=TID, api_token=TOKEN_A, canvas_user_id="1", canvas_user_name="x",
                entra_display_name="", entra_upn="", canvas_host=HOST_A,
            )
        assert store.count() == 0

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "Entra:" + TID + ":" + OID_A,
            "entra:" + TID + ":" + OID_A.upper(),
            "entra:not-a-guid:" + OID_A,
            "entra:" + TID,
            "google:abc\x1fdef",
            "google:caf\u00e9",
            "x" * 257,
            5,
        ],
    )
    def test_bad_principal_keys_are_refused(self, store: TokenStore, bad: object) -> None:
        with pytest.raises(ValueError):
            _put_pk(store, bad)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            store.get(bad)  # type: ignore[arg-type]
        assert store.count() == 0

    def test_other_identity_providers_get_a_sealed_row_too(self, store: TokenStore) -> None:
        _put_pk(store, "google:1234567890", token=TOKEN_B)
        got = store.get("google:1234567890")
        assert got is not None and got.api_token == TOKEN_B and got.canvas_host == HOST_A
        # The legacy (tenant, object) columns are only a unique placeholder for these.
        assert (got.tenant_id, got.object_id) == ("", "google:1234567890")
        assert store.get(PK_A) is None

    def test_a_host_less_row_needs_an_entra_principal(self, store: TokenStore) -> None:
        with pytest.raises(ValueError):
            _put_pk(store, "google:1234567890", canvas_host=None)
        assert store.count() == 0

    def test_the_principal_key_is_stored_in_the_row(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        with _raw(store) as conn:
            assert conn.execute("SELECT principal_key FROM canvas_tokens").fetchall() == [(PK_A,)]


class TestAadV2Binding:
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
            documented + b"\x1f",
        ):
            with pytest.raises(InvalidTag):
                aead.decrypt(bytes(nonce), bytes(ct), wrong)

    def test_moving_a_row_to_another_principal_fails(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        _put(store, oid=OID_B, token=TOKEN_B, canvas_host=HOST_A)
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
        other = pk(OID_B)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET principal_key = ?", (other,))
        assert store.get(PK_A) is None
        with pytest.raises(TokenDecryptionError):
            store.get(other)

    def test_renaming_the_principal_of_a_legacy_row_fails(self, store: TokenStore) -> None:
        _seal_v1(store, OID_A, TOKEN_A)
        other = pk(OID_B)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET principal_key = ?", (other,))
        # Even though the old tenant and object columns still name the original user,
        # the key the caller asks for is what is authenticated.
        with pytest.raises(TokenDecryptionError):
            store.get(other)

    def test_swapping_principal_and_host_together_fails(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        other = pk(OID_B)
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
        _put(s, canvas_host=HOST_A)
        with _raw(s) as conn:
            conn.execute("UPDATE canvas_tokens SET principal_key = ?", (pk(OID_B),))
        with pytest.raises(KeyringError):
            make_store(path, _ring(("k1", 1))).initialize()

    def test_a_non_entra_principal_roundtrips_and_is_bound(self, store: TokenStore) -> None:
        _put_pk(store, "google:111", token=TOKEN_A)
        _put_pk(store, "google:222", token=TOKEN_B)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET principal_key = 'tmp' WHERE principal_key = 'google:111'")
            conn.execute("UPDATE canvas_tokens SET principal_key = 'google:111' WHERE principal_key = 'google:222'")
            conn.execute("UPDATE canvas_tokens SET principal_key = 'google:222' WHERE principal_key = 'tmp'")
        for key in ("google:111", "google:222"):
            with pytest.raises(TokenDecryptionError):
                store.get(key)


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
        assert store.get(TID, OID_A).api_token == TOKEN_B  # type: ignore[union-attr]

    def test_the_status_columns_do_not_change_reads(self, store: TokenStore) -> None:
        _put(store, canvas_host=HOST_A)
        with _raw(store) as conn:
            conn.execute("UPDATE canvas_tokens SET status = 'invalid', invalid_reason = 'x'")
        got = store.get(PK_A)
        assert got is not None and got.api_token == TOKEN_A


class TestPrincipalMigration:
    @pytest.mark.sqlite_only
    def test_a_version_1_database_gets_keys_and_status_columns(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        ring = _ring(("k1", 1))
        _make_v1_database(path, ring, OID_A, TOKEN_A)
        s = make_store(path, ring)
        s.initialize()
        columns = _columns(path)
        for name in TestStatusColumns.NEW_COLUMNS:
            assert columns.count(name) == 1
        with _raw(s) as conn:
            row = conn.execute(
                "SELECT principal_key, status, invalid_reason, invalid_since,"
                " last_verified_at, expires_hint_at, canvas_host FROM canvas_tokens"
            ).fetchone()
        assert row == (PK_A, "active", None, None, None, None, None)
        got = s.get(PK_A)
        assert got is not None and got.api_token == TOKEN_A and got.canvas_host is None
        assert s.get(TID, OID_A).api_token == TOKEN_A  # type: ignore[union-attr]

    @pytest.mark.sqlite_only

    def test_a_migrated_database_has_the_same_columns_as_a_new_one(self, tmp_path: pathlib.Path) -> None:
        ring = _ring(("k1", 1))
        _make_v1_database(tmp_path / "old.sqlite3", ring, OID_A, TOKEN_A)
        make_store(tmp_path / "old.sqlite3", ring).initialize()
        make_store(tmp_path / "new.sqlite3", ring).initialize()
        assert sorted(_columns(tmp_path / "old.sqlite3")) == sorted(_columns(tmp_path / "new.sqlite3"))

    @pytest.mark.sqlite_only

    def test_the_migration_is_idempotent(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        ring = _ring(("k1", 1))
        _make_v1_database(path, ring, OID_A, TOKEN_A)
        for _ in range(3):
            make_store(path, ring).initialize()
        columns = _columns(path)
        assert len(columns) == len(set(columns))
        s = make_store(path, ring)
        s.initialize()
        assert s.count() == 1 and s.get(PK_A).api_token == TOKEN_A  # type: ignore[union-attr]
        with _raw(s) as conn:
            assert conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone() == (str(SCHEMA_VERSION),)
            index = conn.execute(
                "SELECT sql FROM sqlite_master WHERE name = 'canvas_tokens_principal_key'"
            ).fetchone()
        assert index is not None and "UNIQUE" in index[0]

    @pytest.mark.sqlite_only

    def test_a_database_with_only_the_host_column_is_completed(self, tmp_path: pathlib.Path) -> None:
        """The shape the previous, unreleased schema left: host column, no principal key."""
        path = tmp_path / "t.sqlite3"
        ring = _ring(("k1", 1))
        _make_v1_database(path, ring, OID_A, TOKEN_A)
        with sqlite3.connect(str(path)) as conn:
            conn.execute("ALTER TABLE canvas_tokens ADD COLUMN canvas_host TEXT")
            conn.execute("UPDATE meta SET value = '2'")
        s = make_store(path, ring)
        s.initialize()
        assert s.get(PK_A).api_token == TOKEN_A  # type: ignore[union-attr]
        assert "principal_key" in _columns(path)

    @pytest.mark.sqlite_only

    def test_every_existing_row_is_backfilled_and_stays_unique(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        ring = _ring(("k1", 1))
        _make_v1_database(path, ring, OID_A, TOKEN_A)
        aad = b"canvas-mcp/canvas-token/v1\x1f" + f"{TID}\x1f{OID_B}\x1fk1".encode()
        kid, nonce, ct = ring.encrypt(TOKEN_B.encode(), aad)
        with sqlite3.connect(str(path)) as conn:
            conn.execute(
                "INSERT INTO canvas_tokens VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL)",
                (TID, OID_B, kid, nonce, ct, "8", "Other", "O", "o@example.test", 2, 2),
            )
        s = make_store(path, ring)
        s.initialize()
        assert sorted(r.principal_key for r in s.list_enrollments()) == sorted([PK_A, PK_B])
        with _raw(s) as conn, pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE canvas_tokens SET principal_key = ?", (PK_A,))

    @pytest.mark.sqlite_only

    def test_saving_reseals_a_legacy_row_as_v2_under_its_principal(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        ring = _ring(("k1", 1))
        _make_v1_database(path, ring, OID_A, TOKEN_A)
        s = make_store(path, ring)
        s.initialize()
        before = s.get(PK_A)
        assert before is not None and before.canvas_host is None
        s.put(
            principal_key=PK_A, api_token=TOKEN_A, canvas_user_id="7", canvas_user_name="Legacy",
            entra_display_name="L", entra_upn="l@example.test", canvas_host=HOST_A,
        )
        assert s.count() == 1
        with _raw(s) as conn:
            kid, nonce, ct = conn.execute("SELECT key_id, nonce, ciphertext FROM canvas_tokens").fetchone()
        v2 = token_store_module._aad_v2(PK_A, HOST_A, kid)
        assert AESGCM(_key(1)).decrypt(bytes(nonce), bytes(ct), v2) == TOKEN_A.encode()

    def test_rotation_keeps_v1_and_v2_rows_and_a_non_entra_row(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        old = make_store(path, _ring(("k1", 1)))
        old.initialize()
        _seal_v1(old, OID_A, TOKEN_A)
        _put(old, oid=OID_B, token=TOKEN_B, canvas_host=HOST_B)
        _put_pk(old, "google:777", token="G" * 30)
        both = make_store(path, _ring(("k2", 2), ("k1", 1)))
        both.initialize()
        assert both.rotate() == 3
        only_new = make_store(path, _ring(("k2", 2)))
        only_new.initialize()
        assert only_new.get(PK_A).api_token == TOKEN_A  # type: ignore[union-attr]
        assert only_new.get(PK_A).canvas_host is None  # type: ignore[union-attr]
        assert only_new.get(PK_B).api_token == TOKEN_B  # type: ignore[union-attr]
        assert only_new.get("google:777").api_token == "G" * 30  # type: ignore[union-attr]
        with _raw(only_new) as conn:
            assert {r[0] for r in conn.execute("SELECT key_id FROM canvas_tokens")} == {"k2"}
