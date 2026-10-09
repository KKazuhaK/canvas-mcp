"""Encrypted per-user Canvas token store for the self-hosted multi-user mode.

One SQLite file holds one row per principal. A principal is named by one opaque,
lower-case ``principal_key`` string; today that is ``entra:<tenant id>:<object id>``.
The Canvas personal access token is encrypted with AES-256-GCM; the associated
data binds each ciphertext to its principal, Canvas host and key id, so a copied
or swapped row, or a row whose principal or host was edited in the database,
fails to decrypt instead of sending the token to another user or school.
Metadata columns (Canvas name and id, timestamps) are plaintext on purpose: the
admin page and the operator CLI never need to decrypt.

Associated data (AAD) layouts, joined by ``0x1f``:

* v2 (every row that records a host, written by the account page):
  ``"canvas-mcp/canvas-token/v2" principal_key host key_id``
* v1 (legacy rows without a host, written before schools existed):
  ``"canvas-mcp/canvas-token/v1" tenant object key_id``

The principal key is an opaque string to the v2 layout, so moving an account to
another identity only means re-encrypting under the new string; the layout does
not change. Whether a row has a host decides which layout is used, so no version
column is needed. The principal and host are used exactly as given (the lookup
key and the stored host), never normalised on read; changing either, removing the
host, or adding one to a v1 row makes decryption fail. Saving a row through the
account page always passes a host, which re-seals a v1 row as v2.

Public methods take the ``principal_key``. For callers that still hold an Entra
tenant and object id, each method also accepts ``(tenant_id, object_id)`` and
turns the pair into ``entra:<tenant>:<object>``.

Schema version 2 adds the ``canvas_host`` and ``principal_key`` columns (the key
is unique and backfilled for existing rows) and the status columns ``status``
(``active`` or ``invalid``, default ``active``), ``invalid_reason``,
``invalid_since``, ``last_verified_at`` and ``expires_hint_at``. They track the
health of the stored token: saving a token marks the row ``active`` and verified,
:meth:`TokenStore.mark_invalid` and :meth:`TokenStore.restore_active` move it
between the two states, and an invalid row keeps its ciphertext so a successful
re-check can restore it. Opening an older database migrates it in place,
idempotently. A version 2 database is refused by older
servers, so roll back only together with a backup taken before the upgrade.

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
from enum import Enum
from typing import Any, Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCHEMA_VERSION = 2

STATUS_ACTIVE = "active"
STATUS_INVALID = "invalid"

# Why a row is invalid: a closed set, stored in ``invalid_reason``.
REASON_CANVAS_TOKEN_REJECTED = "canvas_token_rejected"
REASON_DECRYPT_FAILED = "decrypt_failed"
REASON_REVOKED_BY_ADMIN = "revoked_by_admin"
INVALID_REASONS = frozenset(
    {REASON_CANVAS_TOKEN_REJECTED, REASON_DECRYPT_FAILED, REASON_REVOKED_BY_ADMIN}
)

_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_AAD_PREFIX_V1 = b"canvas-mcp/canvas-token/v1\x1f"
_AAD_PREFIX_V2 = b"canvas-mcp/canvas-token/v2\x1f"
_AAD_SEP = b"\x1f"
_ENTRA_PREFIX = "entra:"
_MAX_HOST = 253
_MAX_PRINCIPAL_KEY = 256
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
    " principal_key TEXT,"
    " status TEXT NOT NULL DEFAULT 'active',"
    " invalid_reason TEXT,"
    " invalid_since INTEGER,"
    " last_verified_at INTEGER,"
    " expires_hint_at INTEGER,"
    " PRIMARY KEY (tenant_id, object_id)"
    ") WITHOUT ROWID"
)
_SCHEMA_PRINCIPAL_INDEX = (
    "CREATE UNIQUE INDEX IF NOT EXISTS canvas_tokens_principal_key"
    " ON canvas_tokens (principal_key)"
)
# Columns added after version 1, as (name, definition). A database that lacks one
# gets it with ALTER TABLE; a freshly created table already has them all.
_ADDED_COLUMNS = (
    ("canvas_host", "TEXT"),
    ("principal_key", "TEXT"),
    ("status", "TEXT NOT NULL DEFAULT 'active'"),
    ("invalid_reason", "TEXT"),
    ("invalid_since", "INTEGER"),
    ("last_verified_at", "INTEGER"),
    ("expires_hint_at", "INTEGER"),
)

_INFO_COLUMNS = (
    "tenant_id, object_id, canvas_user_id, canvas_user_name, entra_display_name,"
    " entra_upn, key_id, created_at, updated_at, last_used_at, canvas_host,"
    " principal_key, status, invalid_reason, invalid_since, last_verified_at,"
    " expires_hint_at"
)
_MAX_EXPIRES_HINT = 4_102_444_800  # 2100-01-01 UTC: a sanity bound, not a policy


class _Unset(Enum):
    UNSET = "unset"


#: Pass as ``expires_hint_at`` to keep the stored hint when a row is saved again.
KEEP_EXPIRY_HINT: Literal[_Unset.UNSET] = _Unset.UNSET


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
    principal_key: str = ""
    status: str = STATUS_ACTIVE
    invalid_reason: str | None = None
    invalid_since: int | None = None
    last_verified_at: int | None = None
    expires_hint_at: int | None = None


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
    principal_key: str = ""
    status: str = STATUS_ACTIVE
    invalid_reason: str | None = None
    invalid_since: int | None = None
    last_verified_at: int | None = None
    expires_hint_at: int | None = None


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


def entra_principal_key(tenant_id: str, object_id: str) -> str:
    """The principal key of an Entra user, ``entra:<tenant id>:<object id>`` in lower case.

    Raises ValueError unless both ids are GUIDs.
    """
    tid = _normalize_guid(tenant_id, "tenant_id")
    oid = _normalize_guid(object_id, "object_id")
    return f"{_ENTRA_PREFIX}{tid}:{oid}"


def _split_entra_key(principal_key: str) -> tuple[str, str] | None:
    """``(tenant id, object id)`` of an ``entra:`` key, or None for any other key."""
    if not principal_key.startswith(_ENTRA_PREFIX):
        return None
    tid, sep, oid = principal_key[len(_ENTRA_PREFIX) :].partition(":")
    if not sep or not _GUID_RE.fullmatch(tid) or not _GUID_RE.fullmatch(oid):
        return None
    return tid, oid


def _validate_principal_key(principal_key: str) -> str:
    """A principal key to store or look up: lower-case printable ASCII, otherwise opaque.

    An ``entra:`` key must carry two GUIDs, because the legacy tenant and object
    columns and the v1 layout are derived from it.
    """
    if (
        not isinstance(principal_key, str)
        or not 1 <= len(principal_key) <= _MAX_PRINCIPAL_KEY
        or not principal_key.isascii()
        or principal_key != principal_key.lower()
        or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in principal_key)
    ):
        raise ValueError("principal_key must be a lower-case printable ASCII string")
    if principal_key.startswith(_ENTRA_PREFIX) and _split_entra_key(principal_key) is None:
        raise ValueError("an entra principal_key must be entra:<tenant GUID>:<object GUID>")
    return principal_key


def _resolve_principal(principal_key: str, object_id: str | None) -> str:
    """The key to use: ``principal_key`` itself, or the adapter's ``(tenant, object)`` pair."""
    if object_id is None:
        return _validate_principal_key(principal_key)
    return entra_principal_key(principal_key, object_id)


def _legacy_columns(principal_key: str) -> tuple[str, str]:
    """Values of the old ``tenant_id`` / ``object_id`` primary-key columns for a principal."""
    parts = _split_entra_key(principal_key)
    return parts if parts is not None else ("", principal_key)


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


def _aad_v2(principal_key: str, canvas_host: str, key_id: str) -> bytes:
    """Associated data of a row that records a host (the current layout)."""
    return (
        _AAD_PREFIX_V2
        + principal_key.encode("utf-8", "surrogatepass")
        + _AAD_SEP
        + canvas_host.encode("utf-8", "surrogatepass")
        + _AAD_SEP
        + key_id.encode("utf-8", "surrogatepass")
    )


def _aad_v1(tenant_id: str, object_id: str, key_id: str) -> bytes:
    """Associated data of a legacy row (no host), as the pre-school server sealed it."""
    return (
        _AAD_PREFIX_V1
        + tenant_id.encode()
        + _AAD_SEP
        + object_id.encode()
        + _AAD_SEP
        + key_id.encode()
    )


def _aad_for_principal(principal_key: str, canvas_host: str | None, key_id: str) -> bytes:
    """AAD of the row stored under ``principal_key``; the host selects the layout.

    Raises ValueError for a host-less (v1) row of a principal that has no tenant
    and object id: such a row cannot exist.
    """
    if canvas_host is not None:
        return _aad_v2(principal_key, canvas_host, key_id)
    parts = _split_entra_key(principal_key)
    if parts is None:
        raise ValueError("a row without a host needs an entra principal")
    return _aad_v1(parts[0], parts[1], key_id)


def _row_aad(
    tenant_id: str,
    object_id: str,
    canvas_host: str | None,
    principal_key: str | None,
    key_id: str,
) -> bytes:
    """AAD of a stored row read from its own columns (rotation and the open-time check)."""
    if canvas_host is None:
        return _aad_v1(tenant_id, object_id, key_id)
    return _aad_v2(principal_key or "", canvas_host, key_id)


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
        principal_key=row[11] or "",
        status=row[12] or STATUS_ACTIVE,
        invalid_reason=row[13],
        invalid_since=row[14],
        last_verified_at=row[15],
        expires_hint_at=row[16],
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
                    self._migrate_columns(conn)
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
                    self._migrate_columns(conn)
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
    def _migrate_columns(conn: sqlite3.Connection) -> None:
        """Bring an older table up to date; a current one is left unchanged.

        Adds each missing column, gives every row without a principal key the key
        ``entra:<tenant>:<object>`` (both ids are stored lower-case) and makes the
        key unique. Safe to run again at any point.
        """
        columns = {r[1] for r in conn.execute("PRAGMA table_info(canvas_tokens)")}
        for name, definition in _ADDED_COLUMNS:
            if name not in columns:
                conn.execute(f"ALTER TABLE canvas_tokens ADD COLUMN {name} {definition}")
        conn.execute(
            "UPDATE canvas_tokens"
            " SET principal_key = 'entra:' || tenant_id || ':' || object_id"
            " WHERE principal_key IS NULL"
        )
        conn.execute(_SCHEMA_PRINCIPAL_INDEX)

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
                    "SELECT tenant_id, object_id, nonce, ciphertext, canvas_host,"
                    " principal_key FROM canvas_tokens WHERE key_id = ? LIMIT 1",
                    (kid,),
                ).fetchone()
                if probe is None:
                    continue
                try:
                    self._keyring.decrypt(
                        kid,
                        bytes(probe[2]),
                        bytes(probe[3]),
                        _row_aad(probe[0], probe[1], probe[4], probe[5], kid),
                    )
                except TokenDecryptionError:
                    raise KeyringError(
                        f"CANVAS_TOKEN_KEYS key {kid} does not match the stored data"
                    ) from None

    # -- reads -------------------------------------------------------------

    def get(self, principal_key: str, object_id: str | None = None) -> StoredToken | None:
        """Return the decrypted enrollment of a principal, or None.

        ``get(principal_key)``; the adapter form ``get(tenant_id, object_id)``
        means the Entra principal. Raises TokenDecryptionError.
        """
        key = _resolve_principal(principal_key, object_id)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT key_id, nonce, ciphertext, canvas_user_id,"
                " canvas_user_name, entra_display_name, entra_upn,"
                " created_at, updated_at, last_used_at, canvas_host,"
                " tenant_id, object_id, status, invalid_reason, invalid_since,"
                " last_verified_at, expires_hint_at"
                " FROM canvas_tokens WHERE principal_key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        # The AAD is built from the key the caller asked for, not from anything
        # stored next to the row, so a row that was moved to another principal
        # fails to decrypt.
        try:
            aad = _aad_for_principal(key, row[10], row[0])
        except ValueError:
            raise TokenDecryptionError("stored token could not be decrypted") from None
        plaintext = self._keyring.decrypt(row[0], bytes(row[1]), bytes(row[2]), aad)
        try:
            api_token = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            raise TokenDecryptionError("stored token could not be decrypted") from None
        return StoredToken(
            tenant_id=row[11],
            object_id=row[12],
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
            principal_key=key,
            status=row[13] or STATUS_ACTIVE,
            invalid_reason=row[14],
            invalid_since=row[15],
            last_verified_at=row[16],
            expires_hint_at=row[17],
        )

    def info(self, principal_key: str, object_id: str | None = None) -> EnrollmentInfo | None:
        key = _resolve_principal(principal_key, object_id)
        with self._connection() as conn:
            row = conn.execute(
                f"SELECT {_INFO_COLUMNS} FROM canvas_tokens WHERE principal_key = ?",
                (key,),
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
        api_token: str,
        canvas_user_id: str,
        canvas_user_name: str,
        entra_display_name: str,
        entra_upn: str,
        principal_key: str | None = None,
        tenant_id: str | None = None,
        object_id: str | None = None,
        canvas_host: str | None = None,
        expires_hint_at: int | None | Literal[_Unset.UNSET] = KEEP_EXPIRY_HINT,
    ) -> EnrollmentInfo:
        """Insert or replace a principal's enrollment, preserving ``created_at``.

        Name the principal with ``principal_key`` or, as the Entra adapter, with
        ``tenant_id`` and ``object_id``. ``canvas_host`` is the school the token
        belongs to (None only for the legacy single-school layout, which needs an
        ``entra:`` principal); it is bound into the encryption together with the
        principal. Saving marks the row ``active`` and verified now, and clears any
        invalid reason. ``expires_hint_at`` is the optional expiry date the user
        gave for the token (epoch seconds, used only for a reminder): an integer
        sets it, ``None`` clears it, and leaving it out keeps the stored value (the
        account page always passes it, so replacing a token replaces the hint).
        """
        if principal_key is not None:
            if tenant_id is not None or object_id is not None:
                raise ValueError("give either principal_key or tenant_id and object_id")
            key = _validate_principal_key(principal_key)
        elif tenant_id is not None and object_id is not None:
            key = entra_principal_key(tenant_id, object_id)
        else:
            raise ValueError("give a principal_key, or both tenant_id and object_id")
        host = _validate_host_value(canvas_host)
        if not isinstance(api_token, str) or not api_token:
            raise ValueError("api_token must be a non-empty string")
        keep_hint = isinstance(expires_hint_at, _Unset)
        hint: int | None = None if isinstance(expires_hint_at, _Unset) else expires_hint_at
        if hint is not None and (
            not isinstance(hint, int)
            or isinstance(hint, bool)
            or not 0 < hint <= _MAX_EXPIRES_HINT
        ):
            raise ValueError("expires_hint_at must be a positive epoch time")
        tid, oid = _legacy_columns(key)
        kid, nonce, ciphertext = self._keyring.encrypt(
            api_token.encode("utf-8"),
            _aad_for_principal(key, host, self._keyring.active_key_id),
        )
        now = self._now()
        with self._write() as conn:
            conn.execute(
                "INSERT INTO canvas_tokens (tenant_id, object_id, key_id, nonce,"
                " ciphertext, canvas_user_id, canvas_user_name,"
                " entra_display_name, entra_upn, created_at, updated_at,"
                " last_used_at, canvas_host, principal_key, status,"
                " last_verified_at, expires_hint_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)"
                " ON CONFLICT (principal_key) DO UPDATE SET"
                " key_id = excluded.key_id, nonce = excluded.nonce,"
                " ciphertext = excluded.ciphertext,"
                " canvas_user_id = excluded.canvas_user_id,"
                " canvas_user_name = excluded.canvas_user_name,"
                " entra_display_name = excluded.entra_display_name,"
                " entra_upn = excluded.entra_upn,"
                " canvas_host = excluded.canvas_host,"
                " status = excluded.status,"
                " invalid_reason = NULL, invalid_since = NULL,"
                " last_verified_at = excluded.last_verified_at,"
                " expires_hint_at = CASE WHEN ? THEN canvas_tokens.expires_hint_at"
                " ELSE excluded.expires_hint_at END,"
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
                    key,
                    STATUS_ACTIVE,
                    now,
                    hint,
                    1 if keep_hint else 0,
                ),
            )
            row = conn.execute(
                f"SELECT {_INFO_COLUMNS} FROM canvas_tokens WHERE principal_key = ?",
                (key,),
            ).fetchone()
        return _info_from_row(row)

    def delete(self, principal_key: str, object_id: str | None = None) -> bool:
        key = _resolve_principal(principal_key, object_id)
        with self._write() as conn:
            cur = conn.execute(
                "DELETE FROM canvas_tokens WHERE principal_key = ?", (key,)
            )
            return cur.rowcount > 0

    def touch(
        self,
        principal_key: str,
        object_id: str | None = None,
        *,
        min_interval_seconds: int = 300,
    ) -> None:
        """Record use, at most once per interval. Never raises."""
        try:
            key = _resolve_principal(principal_key, object_id)
            now = self._now()
            with self._connection() as conn:
                conn.execute(
                    "UPDATE canvas_tokens SET last_used_at = ?"
                    " WHERE principal_key = ?"
                    " AND (last_used_at IS NULL OR last_used_at < ?)",
                    (now, key, now - max(0, min_interval_seconds)),
                )
        except (sqlite3.Error, ValueError, OSError):
            return

    def mark_invalid(
        self,
        principal_key: str,
        object_id: str | None = None,
        *,
        reason: str,
        expected_updated_at: int | None = None,
    ) -> bool:
        """Mark an active row invalid; True only if this call changed it.

        An already invalid row is left as it is (the first reason wins). With
        ``expected_updated_at`` the row is changed only if it still has that
        ``updated_at``, so a token that Canvas rejected cannot invalidate the
        replacement the user enrolled in the meantime.
        """
        if reason not in INVALID_REASONS:
            raise ValueError("unknown invalid reason")
        key = _resolve_principal(principal_key, object_id)
        sql = (
            "UPDATE canvas_tokens SET status = ?, invalid_reason = ?, invalid_since = ?"
            " WHERE principal_key = ? AND status = ?"
        )
        args: list[Any] = [STATUS_INVALID, reason, self._now(), key, STATUS_ACTIVE]
        if expected_updated_at is not None:
            sql += " AND updated_at = ?"
            args.append(expected_updated_at)
        with self._write() as conn:
            return conn.execute(sql, args).rowcount > 0

    def restore_active(
        self,
        principal_key: str,
        object_id: str | None = None,
        *,
        expected_updated_at: int | None = None,
    ) -> bool:
        """Mark an invalid row active again after a successful check; True if changed.

        The stored token is untouched. ``expected_updated_at`` works as in
        :meth:`mark_invalid`.
        """
        key = _resolve_principal(principal_key, object_id)
        now = self._now()
        sql = (
            "UPDATE canvas_tokens SET status = ?, invalid_reason = NULL,"
            " invalid_since = NULL, last_verified_at = ?"
            " WHERE principal_key = ? AND status = ?"
        )
        args: list[Any] = [STATUS_ACTIVE, now, key, STATUS_INVALID]
        if expected_updated_at is not None:
            sql += " AND updated_at = ?"
            args.append(expected_updated_at)
        with self._write() as conn:
            return conn.execute(sql, args).rowcount > 0

    def mark_verified(
        self,
        principal_key: str,
        object_id: str | None = None,
        *,
        min_interval_seconds: int = 600,
    ) -> None:
        """Record a successful Canvas call on an active row, at most once per interval.

        Never raises, and never touches an invalid row.
        """
        try:
            key = _resolve_principal(principal_key, object_id)
            now = self._now()
            with self._connection() as conn:
                conn.execute(
                    "UPDATE canvas_tokens SET last_verified_at = ?"
                    " WHERE principal_key = ? AND status = ?"
                    " AND (last_verified_at IS NULL OR last_verified_at < ?)",
                    (now, key, STATUS_ACTIVE, now - max(0, min_interval_seconds)),
                )
        except (sqlite3.Error, ValueError, OSError):
            return

    def rotate(self) -> int:
        """Re-encrypt every row not under the active key; returns rows changed."""
        active = self._keyring.active_key_id
        changed = 0
        with self._write() as conn:
            rows = conn.execute(
                "SELECT tenant_id, object_id, key_id, nonce, ciphertext,"
                " canvas_host, principal_key"
                " FROM canvas_tokens WHERE key_id != ?",
                (active,),
            ).fetchall()
            for tid, oid, kid, nonce, ciphertext, host, pkey in rows:
                # Each row keeps its own principal and host, so its AAD layout
                # (v1 or v2) is preserved.
                plaintext = self._keyring.decrypt(
                    kid, bytes(nonce), bytes(ciphertext), _row_aad(tid, oid, host, pkey, kid)
                )
                new_kid, new_nonce, new_ct = self._keyring.encrypt(
                    plaintext, _row_aad(tid, oid, host, pkey, active)
                )
                conn.execute(
                    "UPDATE canvas_tokens SET key_id = ?, nonce = ?,"
                    " ciphertext = ? WHERE tenant_id = ? AND object_id = ?",
                    (new_kid, new_nonce, new_ct, tid, oid),
                )
                changed += 1
        return changed
