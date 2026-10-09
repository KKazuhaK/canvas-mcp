"""Encrypted per-user Canvas token store for the self-hosted multi-user mode.

One SQLite file holds one row per Entra principal ``(tenant_id, object_id)``.
The Canvas personal access token is encrypted with AES-256-GCM; the associated
data binds each ciphertext to its row, key id and (when recorded) Canvas host,
so a copied or swapped row, or a row whose host was edited in the database,
fails to decrypt instead of sending the token to another school. Metadata columns (Canvas name and id, timestamps) are
plaintext on purpose: the admin page and the operator CLI never need to decrypt.

Associated data (AAD) layouts, joined by ``0x1f``:

* v1 (rows without a host, written before schools existed):
  ``"canvas-mcp/canvas-token/v1" tenant object key_id``
* v2 (rows with a host): ``"canvas-mcp/canvas-token/v2" tenant object key_id host``

Whether a row has a host decides which layout is used, so no version column is
needed. The host is used exactly as stored, never normalised on read; removing
or changing it, or adding one to a v1 row, makes decryption fail. Saving a row
always goes through the account page with a host, which re-seals a v1 row as v2.

Schema version 2 adds the nullable ``canvas_host`` column; opening a version 1
database migrates it in place (idempotently). A version 2 database is refused by
older servers, so roll back only together with a backup taken before the upgrade.

Keys come from ``CANVAS_TOKEN_KEYS`` (``kid:base64key[,kid:base64key...]``).
The first entry encrypts new rows; every entry decrypts. Error messages never
contain key or token material.

All methods are synchronous and thread-safe (one SQLite connection per call).
Async callers use ``anyio.to_thread.run_sync``.
"""

from __future__ import annotations

import base64
import binascii
import os
import pathlib
import re
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCHEMA_VERSION = 2

_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_AAD_PREFIX_V1 = b"canvas-mcp/canvas-token/v1\x1f"
_AAD_PREFIX_V2 = b"canvas-mcp/canvas-token/v2\x1f"
_MAX_HOST = 253
_KEY_BYTES = 32
_NONCE_BYTES = 12

_MAX_CANVAS_NAME = 200
_MAX_ENTRA_NAME = 200
_MAX_UPN = 254

_SCHEMA_META = (
    "CREATE TABLE IF NOT EXISTS meta ("
    " key TEXT PRIMARY KEY,"
    " value TEXT NOT NULL"
    ") WITHOUT ROWID"
)
_SCHEMA_TOKENS = (
    "CREATE TABLE IF NOT EXISTS canvas_tokens ("
    " tenant_id TEXT NOT NULL,"
    " object_id TEXT NOT NULL,"
    " key_id TEXT NOT NULL,"
    " nonce BLOB NOT NULL,"
    " ciphertext BLOB NOT NULL,"
    " canvas_user_id TEXT NOT NULL,"
    " canvas_user_name TEXT NOT NULL,"
    " entra_display_name TEXT NOT NULL DEFAULT '',"
    " entra_upn TEXT NOT NULL DEFAULT '',"
    " created_at INTEGER NOT NULL,"
    " updated_at INTEGER NOT NULL,"
    " last_used_at INTEGER,"
    " canvas_host TEXT,"
    " PRIMARY KEY (tenant_id, object_id)"
    ") WITHOUT ROWID"
)

_INFO_COLUMNS = (
    "tenant_id, object_id, canvas_user_id, canvas_user_name, entra_display_name,"
    " entra_upn, key_id, created_at, updated_at, last_used_at, canvas_host"
)


class TokenStoreError(Exception):
    """Base class for token store failures. Messages carry no secrets."""


class KeyringError(TokenStoreError):
    """The keyring is malformed, or does not match the stored data."""


class TokenDecryptionError(TokenStoreError):
    """A stored token could not be decrypted."""


@dataclass(frozen=True)
class StoredToken:
    """A decrypted enrollment. ``api_token`` is excluded from ``repr``."""

    tenant_id: str
    object_id: str
    api_token: str = field(repr=False)
    canvas_user_id: str
    canvas_user_name: str
    entra_display_name: str
    entra_upn: str
    key_id: str
    created_at: int
    updated_at: int
    last_used_at: int | None
    canvas_host: str | None = None


@dataclass(frozen=True)
class EnrollmentInfo:
    """Enrollment metadata. Carries no token and never needs decryption."""

    tenant_id: str
    object_id: str
    canvas_user_id: str
    canvas_user_name: str
    entra_display_name: str
    entra_upn: str
    key_id: str
    created_at: int
    updated_at: int
    last_used_at: int | None
    canvas_host: str | None = None


def _decode_key(text: str) -> bytes | None:
    """Decode a std or url-safe base64 key (padding optional); None if invalid."""
    body = text.rstrip("=")
    has_url = "-" in body or "_" in body
    has_std = "+" in body or "/" in body
    if has_url and has_std:
        return None
    if len(body) % 4 == 1:
        return None
    padded = body + "=" * (-len(body) % 4)
    try:
        if has_url:
            return base64.urlsafe_b64decode(padded.encode("ascii"))
        return base64.b64decode(padded.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None


class Keyring:
    """AES-256-GCM keys by id. The first key encrypts; all keys decrypt."""

    def __init__(self, keys: list[tuple[str, bytes]]) -> None:
        if not keys:
            raise KeyringError("CANVAS_TOKEN_KEYS is empty")
        self._ids: tuple[str, ...] = tuple(kid for kid, _ in keys)
        self._aead = {kid: AESGCM(key) for kid, key in keys}

    def __repr__(self) -> str:
        return f"Keyring(active={self._ids[0]!r}, ids={self._ids!r})"

    @classmethod
    def parse(cls, raw: str) -> Keyring:
        """Parse ``kid:base64[,kid:base64...]``. Raises :class:`KeyringError`."""
        if not raw or not raw.strip():
            raise KeyringError("CANVAS_TOKEN_KEYS is empty")
        keys: list[tuple[str, bytes]] = []
        seen: set[str] = set()
        for index, entry in enumerate(raw.split(","), start=1):
            entry = entry.strip()
            if not entry:
                raise KeyringError(f"CANVAS_TOKEN_KEYS entry {index} is empty")
            kid, sep, b64 = entry.partition(":")
            kid = kid.strip()
            b64 = b64.strip()
            if not sep or not _KEY_ID_RE.fullmatch(kid):
                raise KeyringError(
                    f"CANVAS_TOKEN_KEYS entry {index} must look like "
                    "'<key id>:<base64 key>' with a key id of 1-32 characters "
                    "from A-Z a-z 0-9 _ -"
                )
            key = _decode_key(b64)
            if key is None:
                raise KeyringError(
                    f"CANVAS_TOKEN_KEYS key {kid} is not valid base64"
                )
            if len(key) != _KEY_BYTES:
                raise KeyringError(
                    f"CANVAS_TOKEN_KEYS key {kid} must decode to exactly "
                    f"{_KEY_BYTES} bytes"
                )
            if kid in seen:
                raise KeyringError(f"CANVAS_TOKEN_KEYS repeats key id {kid}")
            seen.add(kid)
            keys.append((kid, key))
        return cls(keys)

    @property
    def active_key_id(self) -> str:
        return self._ids[0]

    @property
    def key_ids(self) -> tuple[str, ...]:
        return self._ids

    def encrypt(self, plaintext: bytes, aad: bytes) -> tuple[str, bytes, bytes]:
        """Encrypt under the active key; returns ``(key_id, nonce, ciphertext)``."""
        kid = self._ids[0]
        nonce = os.urandom(_NONCE_BYTES)
        return kid, nonce, self._aead[kid].encrypt(nonce, plaintext, aad)

    def decrypt(
        self, key_id: str, nonce: bytes, ciphertext: bytes, aad: bytes
    ) -> bytes:
        """Decrypt; unknown key ids and failed authentication both raise."""
        aead = self._aead.get(key_id)
        if aead is None:
            raise TokenDecryptionError("stored token could not be decrypted")
        try:
            return aead.decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError):
            raise TokenDecryptionError("stored token could not be decrypted") from None


def token_db_path(data_dir: pathlib.Path) -> pathlib.Path:
    """Location of the token database below the persistent data directory."""
    return data_dir / "canvas-mcp" / "tokens.sqlite3"


def _normalize_guid(value: str, label: str) -> str:
    if not isinstance(value, str) or not _GUID_RE.fullmatch(value):
        raise ValueError(f"{label} must be a GUID")
    return value.lower()


def _validate_host_value(host: str | None) -> str | None:
    """A host to store: None (legacy / default school) or a lowercase ASCII name.

    Deliberately generic: the operator's default school may be an IP or a
    ``.test`` name. The account page applies the strict school rules.
    """
    if host is None:
        return None
    if (
        not isinstance(host, str)
        or not 1 <= len(host) <= _MAX_HOST
        or not host.isascii()
        or host != host.lower()
        or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in host)
    ):
        raise ValueError("canvas_host must be a lowercase ASCII host name")
    return host


def _aad(tenant_id: str, object_id: str, key_id: str, canvas_host: str | None = None) -> bytes:
    """Associated data of one row; a host selects the v2 layout and is bound."""
    base = tenant_id.encode() + b"\x1f" + object_id.encode() + b"\x1f" + key_id.encode()
    if canvas_host is None:
        return _AAD_PREFIX_V1 + base
    return _AAD_PREFIX_V2 + base + b"\x1f" + canvas_host.encode("utf-8", "surrogatepass")


def _info_from_row(row: tuple[Any, ...]) -> EnrollmentInfo:
    return EnrollmentInfo(
        tenant_id=row[0],
        object_id=row[1],
        canvas_user_id=row[2],
        canvas_user_name=row[3],
        entra_display_name=row[4],
        entra_upn=row[5],
        key_id=row[6],
        created_at=row[7],
        updated_at=row[8],
        last_used_at=row[9],
        canvas_host=row[10],
    )


class TokenStore:
    """SQLite-backed store of AES-GCM encrypted Canvas tokens."""

    def __init__(
        self,
        db_path: pathlib.Path,
        keyring: Keyring,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._path = pathlib.Path(db_path)
        self._keyring = keyring
        self._clock = clock
        # Serialises writers inside this process; SQLite's own lock (BEGIN
        # IMMEDIATE plus busy_timeout) covers other processes such as the CLI.
        self._write_lock = threading.Lock()

    # -- plumbing ----------------------------------------------------------

    def _now(self) -> int:
        return int(self._clock())

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self._path), timeout=5.0, isolation_level=None)
        try:
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        with self._write_lock, self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")

    # -- lifecycle ---------------------------------------------------------

    def initialize(self) -> None:
        """Create or open the database and prove the keyring matches its data."""
        parent = self._path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            os.chmod(parent, 0o700)
            # Create the file private from the start instead of chmod-after.
            os.close(os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600))

        with self._write_lock, self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(_SCHEMA_META)
                row = conn.execute(
                    "SELECT value FROM meta WHERE key = 'schema_version'"
                ).fetchone()
                if row is None:
                    conn.execute(_SCHEMA_TOKENS)
                    self._ensure_host_column(conn)
                    conn.execute(
                        "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                        (str(SCHEMA_VERSION),),
                    )
                else:
                    try:
                        version = int(row[0])
                    except ValueError:
                        raise TokenStoreError(
                            "token database has an unreadable schema version"
                        ) from None
                    if version > SCHEMA_VERSION:
                        raise TokenStoreError(
                            f"token database schema version {version} is newer "
                            f"than this server supports ({SCHEMA_VERSION})"
                        )
                    conn.execute(_SCHEMA_TOKENS)
                    self._ensure_host_column(conn)
                    if version < SCHEMA_VERSION:
                        conn.execute(
                            "UPDATE meta SET value = ? WHERE key = 'schema_version'",
                            (str(SCHEMA_VERSION),),
                        )
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")

        if os.name == "posix":
            os.chmod(self._path, 0o600)

        self._verify_keyring()

    @staticmethod
    def _ensure_host_column(conn: sqlite3.Connection) -> None:
        """Version 1 -> 2: add the nullable ``canvas_host`` column once."""
        columns = {r[1] for r in conn.execute("PRAGMA table_info(canvas_tokens)")}
        if "canvas_host" not in columns:
            conn.execute("ALTER TABLE canvas_tokens ADD COLUMN canvas_host TEXT")

    def _verify_keyring(self) -> None:
        with self._connection() as conn:
            used = [
                r[0]
                for r in conn.execute(
                    "SELECT DISTINCT key_id FROM canvas_tokens ORDER BY key_id"
                )
            ]
            missing = [kid for kid in used if kid not in self._keyring.key_ids]
            if missing:
                raise KeyringError(
                    "CANVAS_TOKEN_KEYS is missing key id(s): " + ", ".join(missing)
                )
            for kid in used:
                probe = conn.execute(
                    "SELECT tenant_id, object_id, nonce, ciphertext, canvas_host"
                    " FROM canvas_tokens WHERE key_id = ? LIMIT 1",
                    (kid,),
                ).fetchone()
                if probe is None:
                    continue
                try:
                    self._keyring.decrypt(
                        kid,
                        probe[2],
                        probe[3],
                        _aad(probe[0], probe[1], kid, probe[4]),
                    )
                except TokenDecryptionError:
                    raise KeyringError(
                        f"CANVAS_TOKEN_KEYS key {kid} does not match the stored data"
                    ) from None

    # -- reads -------------------------------------------------------------

    def get(self, tenant_id: str, object_id: str) -> StoredToken | None:
        """Return the decrypted enrollment, or None. Raises TokenDecryptionError."""
        tid = _normalize_guid(tenant_id, "tenant_id")
        oid = _normalize_guid(object_id, "object_id")
        with self._connection() as conn:
            row = conn.execute(
                "SELECT key_id, nonce, ciphertext, canvas_user_id,"
                " canvas_user_name, entra_display_name, entra_upn,"
                " created_at, updated_at, last_used_at, canvas_host"
                " FROM canvas_tokens WHERE tenant_id = ? AND object_id = ?",
                (tid, oid),
            ).fetchone()
        if row is None:
            return None
        plaintext = self._keyring.decrypt(
            row[0], bytes(row[1]), bytes(row[2]), _aad(tid, oid, row[0], row[10])
        )
        try:
            api_token = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            raise TokenDecryptionError("stored token could not be decrypted") from None
        return StoredToken(
            tenant_id=tid,
            object_id=oid,
            api_token=api_token,
            canvas_user_id=row[3],
            canvas_user_name=row[4],
            entra_display_name=row[5],
            entra_upn=row[6],
            key_id=row[0],
            created_at=row[7],
            updated_at=row[8],
            last_used_at=row[9],
            canvas_host=row[10],
        )

    def info(self, tenant_id: str, object_id: str) -> EnrollmentInfo | None:
        tid = _normalize_guid(tenant_id, "tenant_id")
        oid = _normalize_guid(object_id, "object_id")
        with self._connection() as conn:
            row = conn.execute(
                f"SELECT {_INFO_COLUMNS} FROM canvas_tokens"
                " WHERE tenant_id = ? AND object_id = ?",
                (tid, oid),
            ).fetchone()
        return None if row is None else _info_from_row(row)

    def list_enrollments(self) -> list[EnrollmentInfo]:
        with self._connection() as conn:
            rows = conn.execute(
                f"SELECT {_INFO_COLUMNS} FROM canvas_tokens"
                " ORDER BY created_at, tenant_id, object_id"
            ).fetchall()
        return [_info_from_row(r) for r in rows]

    def count(self) -> int:
        with self._connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM canvas_tokens").fetchone()
        return int(row[0])

    # -- writes ------------------------------------------------------------

    def put(
        self,
        *,
        tenant_id: str,
        object_id: str,
        api_token: str,
        canvas_user_id: str,
        canvas_user_name: str,
        entra_display_name: str,
        entra_upn: str,
        canvas_host: str | None = None,
    ) -> EnrollmentInfo:
        """Insert or replace an enrollment, preserving ``created_at``.

        ``canvas_host`` is the school the token belongs to (None only for the
        legacy single-school layout); it is bound into the encryption.
        """
        tid = _normalize_guid(tenant_id, "tenant_id")
        oid = _normalize_guid(object_id, "object_id")
        host = _validate_host_value(canvas_host)
        if not isinstance(api_token, str) or not api_token:
            raise ValueError("api_token must be a non-empty string")
        kid, nonce, ciphertext = self._keyring.encrypt(
            api_token.encode("utf-8"), _aad(tid, oid, self._keyring.active_key_id, host)
        )
        now = self._now()
        with self._write() as conn:
            conn.execute(
                "INSERT INTO canvas_tokens (tenant_id, object_id, key_id, nonce,"
                " ciphertext, canvas_user_id, canvas_user_name,"
                " entra_display_name, entra_upn, created_at, updated_at,"
                " last_used_at, canvas_host)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)"
                " ON CONFLICT (tenant_id, object_id) DO UPDATE SET"
                " key_id = excluded.key_id, nonce = excluded.nonce,"
                " ciphertext = excluded.ciphertext,"
                " canvas_user_id = excluded.canvas_user_id,"
                " canvas_user_name = excluded.canvas_user_name,"
                " entra_display_name = excluded.entra_display_name,"
                " entra_upn = excluded.entra_upn,"
                " canvas_host = excluded.canvas_host,"
                " updated_at = excluded.updated_at",
                (
                    tid,
                    oid,
                    kid,
                    nonce,
                    ciphertext,
                    str(canvas_user_id),
                    str(canvas_user_name)[:_MAX_CANVAS_NAME],
                    str(entra_display_name)[:_MAX_ENTRA_NAME],
                    str(entra_upn)[:_MAX_UPN],
                    now,
                    now,
                    host,
                ),
            )
            row = conn.execute(
                f"SELECT {_INFO_COLUMNS} FROM canvas_tokens"
                " WHERE tenant_id = ? AND object_id = ?",
                (tid, oid),
            ).fetchone()
        return _info_from_row(row)

    def delete(self, tenant_id: str, object_id: str) -> bool:
        tid = _normalize_guid(tenant_id, "tenant_id")
        oid = _normalize_guid(object_id, "object_id")
        with self._write() as conn:
            cur = conn.execute(
                "DELETE FROM canvas_tokens WHERE tenant_id = ? AND object_id = ?",
                (tid, oid),
            )
            return cur.rowcount > 0

    def touch(
        self, tenant_id: str, object_id: str, *, min_interval_seconds: int = 300
    ) -> None:
        """Record use, at most once per interval. Never raises."""
        try:
            tid = _normalize_guid(tenant_id, "tenant_id")
            oid = _normalize_guid(object_id, "object_id")
            now = self._now()
            with self._connection() as conn:
                conn.execute(
                    "UPDATE canvas_tokens SET last_used_at = ?"
                    " WHERE tenant_id = ? AND object_id = ?"
                    " AND (last_used_at IS NULL OR last_used_at < ?)",
                    (now, tid, oid, now - max(0, min_interval_seconds)),
                )
        except (sqlite3.Error, ValueError, OSError):
            return

    def rotate(self) -> int:
        """Re-encrypt every row not under the active key; returns rows changed."""
        active = self._keyring.active_key_id
        changed = 0
        with self._write() as conn:
            rows = conn.execute(
                "SELECT tenant_id, object_id, key_id, nonce, ciphertext, canvas_host"
                " FROM canvas_tokens WHERE key_id != ?",
                (active,),
            ).fetchall()
            for tid, oid, kid, nonce, ciphertext, host in rows:
                # Each row keeps its own host, so its AAD layout is preserved.
                plaintext = self._keyring.decrypt(
                    kid, bytes(nonce), bytes(ciphertext), _aad(tid, oid, kid, host)
                )
                new_kid, new_nonce, new_ct = self._keyring.encrypt(
                    plaintext, _aad(tid, oid, active, host)
                )
                conn.execute(
                    "UPDATE canvas_tokens SET key_id = ?, nonce = ?,"
                    " ciphertext = ? WHERE tenant_id = ? AND object_id = ?",
                    (new_kid, new_nonce, new_ct, tid, oid),
                )
                changed += 1
        return changed
