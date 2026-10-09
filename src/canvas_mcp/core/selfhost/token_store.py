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
idempotently.

The same database holds more tables, all keyed by ``principal_key`` and created
idempotently when the store opens:

* ``user_tool_prefs``: the write tools each principal has switched on at
  ``/account`` (see :mod:`.tool_prefs`). Independent of the token row: replacing,
  deleting or invalidating a token does not touch it.
* ``principal_status``: whether the principal may use the server at all. This is
  the authorization decision, kept apart from the token row on purpose. An
  administrator *disables* a principal (``status = 'disabled'``); deleting the
  enrollment row never changes that, so a user cannot re-enroll their way back in,
  and a sealed ``/account`` session cannot restore a deleted row. Disabling and
  enabling also bump ``session_epoch``, which every ``/account`` session carries and
  which invalidates every session issued before the change. The row also keeps the
  last owner status seen at a sign-in (``is_owner``), which the "never disable the
  last active owner" rule counts. A principal without a row is active. Because the
  key is an opaque string, a later account model (``acct:<uuid>`` principals) can
  absorb the table without a change.
* ``principal_status_events``: append-only history of every status transition
  (disabled, enabled, owner gained or lost) with the actor, written in the same
  transaction as the change, so it also covers the operator CLI.

Schema version 3 adds ``principal_status`` and ``principal_status_events``. A
version 2 server would ignore them and serve a disabled user, so it refuses a
version 3 database: roll back only together with a backup taken before the upgrade.

Keys come from ``CANVAS_TOKEN_KEYS`` (``kid:base64key[,kid:base64key...]``).
The first entry encrypts new rows; every entry decrypts. Error messages never
contain key or token material.

All methods are synchronous and thread-safe (one SQLite connection per call).
Async callers use ``anyio.to_thread.run_sync``.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import pathlib
import re
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCHEMA_VERSION = 3

STATUS_ACTIVE = "active"
STATUS_INVALID = "invalid"

# Why a row is invalid: a closed set, stored in ``invalid_reason``.
REASON_CANVAS_TOKEN_REJECTED = "canvas_token_rejected"
REASON_DECRYPT_FAILED = "decrypt_failed"
REASON_REVOKED_BY_ADMIN = "revoked_by_admin"
INVALID_REASONS = frozenset(
    {REASON_CANVAS_TOKEN_REJECTED, REASON_DECRYPT_FAILED, REASON_REVOKED_BY_ADMIN}
)

# Whether a principal may use the server (``principal_status.status``). Not to be
# confused with the health of a token row above, which reuses STATUS_ACTIVE.
STATUS_DISABLED = "disabled"

# Why a principal is disabled: a closed set, stored in ``disabled_reason``.
DISABLE_REASON_ADMIN = "admin_disabled"
DISABLE_REASON_OPERATOR = "operator_disabled"
DISABLE_REASONS = frozenset({DISABLE_REASON_ADMIN, DISABLE_REASON_OPERATOR})

# The ``actor`` of a change made by the operator CLI (no Entra identity).
OPERATOR_ACTOR = "operator"


class _Operator:
    """The operator at the host (the CLI): authorized by file access, not by an identity."""

    def __repr__(self) -> str:
        return "OPERATOR"


#: Pass as ``actor`` for a change made through the operator CLI.
OPERATOR = _Operator()
Actor = str | _Operator

EVENT_DISABLED = "disabled"
EVENT_ENABLED = "enabled"
EVENT_OWNER_GAINED = "owner_gained"
EVENT_OWNER_LOST = "owner_lost"

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
_SCHEMA_TOOL_PREFS = (
    "CREATE TABLE IF NOT EXISTS user_tool_prefs ("
    " principal_key TEXT PRIMARY KEY,"
    " enabled_write_tools TEXT NOT NULL DEFAULT '[]',"
    " enabled_at TEXT NOT NULL DEFAULT '{}',"
    " updated_at INTEGER NOT NULL,"
    " updated_via TEXT NOT NULL DEFAULT 'account_web'"
    ") WITHOUT ROWID"
)
_SCHEMA_PRINCIPAL_STATUS = (
    "CREATE TABLE IF NOT EXISTS principal_status ("
    " principal_key TEXT PRIMARY KEY,"
    " status TEXT NOT NULL DEFAULT 'active',"
    " disabled_reason TEXT,"
    " disabled_at INTEGER,"
    " disabled_by TEXT,"
    " display_name TEXT NOT NULL DEFAULT '',"
    " upn TEXT NOT NULL DEFAULT '',"
    " session_epoch INTEGER NOT NULL DEFAULT 0,"
    " is_owner INTEGER NOT NULL DEFAULT 0,"
    " owner_seen_at INTEGER,"
    " updated_at INTEGER NOT NULL"
    ") WITHOUT ROWID"
)
_SCHEMA_STATUS_EVENTS = (
    "CREATE TABLE IF NOT EXISTS principal_status_events ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " principal_key TEXT NOT NULL,"
    " action TEXT NOT NULL,"
    " actor TEXT,"
    " reason TEXT,"
    " session_epoch INTEGER NOT NULL,"
    " at INTEGER NOT NULL"
    ")"
)
_SCHEMA_STATUS_EVENTS_INDEX = (
    "CREATE INDEX IF NOT EXISTS principal_status_events_principal"
    " ON principal_status_events (principal_key, id)"
)
_PRINCIPAL_STATUS_COLUMNS = (
    "principal_key, status, disabled_reason, disabled_at, disabled_by,"
    " display_name, upn, session_epoch, is_owner, owner_seen_at, updated_at"
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
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_PREF_TOOLS = 256
_MAX_PREF_VIA = 32
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
    """A stored token could not be decrypted.

    ``updated_at`` is the version of the row that failed, when the store read
    one; callers use it to invalidate exactly that row and not a replacement
    saved a moment later.
    """

    updated_at: int | None = None


class PrincipalDisabledError(TokenStoreError):
    """The principal is administratively disabled, so nothing may be saved for it."""


class AccessActionRefused(TokenStoreError):
    """An administrative access change was refused. ``code`` says why (a closed set)."""

    NOT_OWNER = "not_owner"
    LAST_OWNER = "last_owner"
    SELF = "self"

    def __init__(self, code: str) -> None:
        super().__init__(f"access change refused: {code}")
        self.code = code


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


@dataclass(frozen=True)
class ToolPrefs:
    """The write tools a principal has switched on, by explicit name.

    ``enabled_write_tools`` may name tools the server no longer offers: they are
    kept (so they come back if the operator offers them again) and ignored when
    the effective set is worked out. ``enabled_at`` maps a name to the epoch time
    it was switched on.
    """

    principal_key: str
    enabled_write_tools: frozenset[str]
    enabled_at: dict[str, int]
    updated_at: int
    updated_via: str


@dataclass(frozen=True)
class PrincipalStatus:
    """Whether a principal may use the server, as last decided by an administrator.

    A principal with no stored row is active at epoch 0 (``stored`` is False).
    ``session_epoch`` changes whenever the principal is disabled or enabled; an
    ``/account`` session is valid only while its epoch equals this one.
    ``is_owner`` is the owner role as last seen at a sign-in; it is a record, not
    the authority (the Entra role in a fresh sign-in is).
    """

    principal_key: str
    status: str = STATUS_ACTIVE
    disabled_reason: str | None = None
    disabled_at: int | None = None
    disabled_by: str | None = None
    display_name: str = ""
    upn: str = ""
    session_epoch: int = 0
    is_owner: bool = False
    owner_seen_at: int | None = None
    updated_at: int = 0
    stored: bool = False
    # Set only on the value returned by ``record_sign_in`` when that call changed the
    # owner flag: ``EVENT_OWNER_GAINED`` or ``EVENT_OWNER_LOST``. Not stored.
    owner_change: str | None = None

    @property
    def disabled(self) -> bool:
        return self.status == STATUS_DISABLED


@dataclass(frozen=True)
class StatusEvent:
    """One entry of the status history of a principal."""

    id: int
    principal_key: str
    action: str
    actor: str | None
    reason: str | None
    session_epoch: int
    at: int


def _status_from_row(row: tuple[Any, ...]) -> PrincipalStatus:
    return PrincipalStatus(
        principal_key=row[0],
        status=STATUS_DISABLED if row[1] == STATUS_DISABLED else STATUS_ACTIVE,
        disabled_reason=row[2],
        disabled_at=row[3],
        disabled_by=row[4],
        display_name=row[5] or "",
        upn=row[6] or "",
        session_epoch=int(row[7]),
        is_owner=bool(row[8]),
        owner_seen_at=row[9],
        updated_at=int(row[10]),
        stored=True,
    )


def _validate_tool_names(names: Iterable[str]) -> frozenset[str]:
    """Explicit, well-formed tool names only; raises ValueError otherwise."""
    result: set[str] = set()
    for name in names:
        if not isinstance(name, str) or not _TOOL_NAME_RE.fullmatch(name):
            raise ValueError("tool names must be lower-case identifiers")
        result.add(name)
    if len(result) > _MAX_PREF_TOOLS:
        raise ValueError("too many tool names")
    return frozenset(result)


def _decode_tool_prefs(
    principal_key: str, names_json: str, at_json: str, updated_at: int, via: str
) -> ToolPrefs:
    """Read a stored row; anything unreadable counts as "nothing enabled" (fail closed)."""
    names: frozenset[str] = frozenset()
    stamps: dict[str, int] = {}
    try:
        raw_names = json.loads(names_json)
        if isinstance(raw_names, list):
            names = _validate_tool_names(raw_names)
        raw_at = json.loads(at_json)
        if isinstance(raw_at, dict):
            stamps = {
                key: value
                for key, value in raw_at.items()
                if key in names and isinstance(value, int) and not isinstance(value, bool)
            }
    except (ValueError, TypeError):
        names = frozenset()
        stamps = {}
    return ToolPrefs(principal_key, names, stamps, int(updated_at), str(via))


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


def valid_principal_key(value: object) -> str | None:
    """``value`` if it is a well-formed principal key, else None (never raises)."""
    if not isinstance(value, str):
        return None
    try:
        return _validate_principal_key(value)
    except ValueError:
        return None


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
                    self._create_side_tables(conn)
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
                    self._create_side_tables(conn)
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
    def _create_side_tables(conn: sqlite3.Connection) -> None:
        """The tables keyed by principal: tool switches, access status and its history."""
        conn.execute(_SCHEMA_TOOL_PREFS)
        conn.execute(_SCHEMA_PRINCIPAL_STATUS)
        conn.execute(_SCHEMA_STATUS_EVENTS)
        conn.execute(_SCHEMA_STATUS_EVENTS_INDEX)

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
            try:
                aad = _aad_for_principal(key, row[10], row[0])
            except ValueError:
                raise TokenDecryptionError("stored token could not be decrypted") from None
            plaintext = self._keyring.decrypt(row[0], bytes(row[1]), bytes(row[2]), aad)
            try:
                api_token = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                raise TokenDecryptionError("stored token could not be decrypted") from None
        except TokenDecryptionError as exc:
            exc.updated_at = row[8] if isinstance(row[8], int) else None
            raise
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

        A disabled principal (see :meth:`disable_principal`) cannot be enrolled:
        :class:`PrincipalDisabledError` is raised, checked in the same transaction
        as the write.
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
            # Checked in the same transaction as the write, so an enrollment that
            # races an administrator's disable either lands first (and the principal
            # is disabled right after) or is refused; it can never be saved for a
            # principal that is already disabled.
            gate = conn.execute(
                "SELECT status FROM principal_status WHERE principal_key = ?", (key,)
            ).fetchone()
            if gate is not None and gate[0] == STATUS_DISABLED:
                raise PrincipalDisabledError("this principal is disabled")
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
        """Remove the enrollment row.

        This is housekeeping or a self-disconnect, never an authorization decision:
        it does not touch ``principal_status``, so a disabled principal stays
        disabled and an active one may enroll again.
        """
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

    # -- access status: the authorization decision ------------------------------

    @staticmethod
    def _fetch_status(conn: sqlite3.Connection, key: str) -> PrincipalStatus | None:
        row = conn.execute(
            f"SELECT {_PRINCIPAL_STATUS_COLUMNS} FROM principal_status WHERE principal_key = ?",
            (key,),
        ).fetchone()
        return None if row is None else _status_from_row(row)

    @staticmethod
    def _record_event(
        conn: sqlite3.Connection,
        key: str,
        action: str,
        actor: str | None,
        reason: str | None,
        epoch: int,
        now: int,
    ) -> None:
        conn.execute(
            "INSERT INTO principal_status_events"
            " (principal_key, action, actor, reason, session_epoch, at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (key, action, actor, reason, epoch, now),
        )

    @staticmethod
    def _actor_name(actor: Actor) -> str:
        """The recorded name of an actor; a non-operator actor must be a principal key."""
        if isinstance(actor, _Operator):
            return OPERATOR_ACTOR
        return _validate_principal_key(actor)

    def _require_owner_actor(self, conn: sqlite3.Connection, actor: Actor) -> None:
        """Re-evaluate, inside the transaction, that the actor is an active owner now.

        The operator at the host needs no identity. Anyone else must have a stored
        row that is active and flagged owner: an owner who was disabled, or whose
        owner role a later sign-in no longer showed, cannot act, whatever their
        browser session still says.
        """
        if isinstance(actor, _Operator):
            return
        current = self._fetch_status(conn, _validate_principal_key(actor))
        if current is None or current.disabled or not current.is_owner:
            raise AccessActionRefused(AccessActionRefused.NOT_OWNER)

    def get_principal_status(
        self, principal_key: str, object_id: str | None = None
    ) -> PrincipalStatus:
        """The access status of a principal; active at epoch 0 when nothing is stored."""
        key = _resolve_principal(principal_key, object_id)
        with self._connection() as conn:
            found = self._fetch_status(conn, key)
        return found if found is not None else PrincipalStatus(key)

    def list_principal_statuses(self) -> list[PrincipalStatus]:
        """Every stored status row (disabled principals and known owners)."""
        with self._connection() as conn:
            rows = conn.execute(
                f"SELECT {_PRINCIPAL_STATUS_COLUMNS} FROM principal_status"
                " ORDER BY principal_key"
            ).fetchall()
        return [_status_from_row(r) for r in rows]

    def count_active_owners(self) -> int:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM principal_status WHERE is_owner = 1 AND status = ?",
                (STATUS_ACTIVE,),
            ).fetchone()
        return int(row[0])

    def record_sign_in(
        self, principal_key: str, object_id: str | None = None, *, is_owner: bool
    ) -> PrincipalStatus:
        """Record a verified ``/account`` sign-in; returns the status to apply to it.

        Notes whether the fresh id_token showed the owner role (a change is written
        to the history). Never changes the status or the epoch: a disabled principal
        comes back disabled and the caller refuses the sign-in. A non-owner without a
        row leaves no row.
        """
        key = _resolve_principal(principal_key, object_id)
        now = self._now()
        with self._write() as conn:
            row = self._fetch_status(conn, key)
            if row is None:
                if not is_owner:
                    return PrincipalStatus(key)
                conn.execute(
                    "INSERT INTO principal_status (principal_key, is_owner, owner_seen_at,"
                    " updated_at) VALUES (?, 1, ?, ?)",
                    (key, now, now),
                )
                self._record_event(conn, key, EVENT_OWNER_GAINED, None, "sign_in", 0, now)
            else:
                conn.execute(
                    "UPDATE principal_status SET is_owner = ?, owner_seen_at = ?,"
                    " updated_at = ? WHERE principal_key = ?",
                    (1 if is_owner else 0, now, now, key),
                )
                if row.is_owner != is_owner:
                    self._record_event(
                        conn,
                        key,
                        EVENT_OWNER_GAINED if is_owner else EVENT_OWNER_LOST,
                        None,
                        "sign_in",
                        row.session_epoch,
                        now,
                    )
            found = self._fetch_status(conn, key)
        assert found is not None
        change = None
        if row is None or row.is_owner != is_owner:
            change = EVENT_OWNER_GAINED if is_owner else EVENT_OWNER_LOST
        return replace(found, owner_change=change)

    def demote_owner(
        self, principal_key: str, object_id: str | None = None, *, evidence_issued_at: int
    ) -> bool:
        """Clear the stored owner flag on evidence from a request token; True if cleared.

        The evidence is the issue time of a verified access token that carries no
        owner role. It counts only if it is newer than the last sign-in that was
        recorded, so a token issued before a promotion cannot undo it. This path can
        only ever lower the flag; raising it needs a fresh sign-in.
        """
        key = _resolve_principal(principal_key, object_id)
        now = self._now()
        with self._write() as conn:
            row = self._fetch_status(conn, key)
            if row is None or not row.is_owner:
                return False
            if evidence_issued_at <= (row.owner_seen_at or 0):
                return False
            conn.execute(
                "UPDATE principal_status SET is_owner = 0, updated_at = ?"
                " WHERE principal_key = ?",
                (now, key),
            )
            self._record_event(
                conn, key, EVENT_OWNER_LOST, None, "access_token_roles", row.session_epoch, now
            )
        return True

    def disable_principal(
        self,
        principal_key: str,
        object_id: str | None = None,
        *,
        actor: Actor,
        reason: str,
        allow_last_owner: bool = False,
    ) -> bool:
        """Administratively disable a principal; True if this call changed it.

        The principal cannot sign in to ``/account``, cannot enroll, and every MCP
        request is refused, until an owner (or the operator) enables it again.
        Every ``/account`` session issued before is invalidated (``session_epoch``
        is bumped). The enrollment row, if any, is kept untouched.

        ``actor`` is the acting owner's principal key or :data:`OPERATOR`. An owner
        actor is re-checked inside the transaction (still active and an owner) and
        cannot disable themselves. Disabling the last active owner is refused unless
        ``allow_last_owner``; the check and the write are one transaction, so two
        owners cannot disable each other concurrently. Already disabled: returns
        False and changes nothing.
        """
        key = _resolve_principal(principal_key, object_id)
        if reason not in DISABLE_REASONS:
            raise ValueError("unknown disable reason")
        by = self._actor_name(actor)
        now = self._now()
        with self._write() as conn:
            self._require_owner_actor(conn, actor)
            if not isinstance(actor, _Operator) and by == key:
                raise AccessActionRefused(AccessActionRefused.SELF)
            row = self._fetch_status(conn, key)
            if row is not None and row.disabled:
                return False
            if row is not None and row.is_owner and not allow_last_owner:
                others = conn.execute(
                    "SELECT COUNT(*) FROM principal_status"
                    " WHERE is_owner = 1 AND status = ? AND principal_key != ?",
                    (STATUS_ACTIVE, key),
                ).fetchone()[0]
                if others == 0:
                    raise AccessActionRefused(AccessActionRefused.LAST_OWNER)
            names = conn.execute(
                "SELECT entra_display_name, entra_upn FROM canvas_tokens"
                " WHERE principal_key = ?",
                (key,),
            ).fetchone()
            display_name, upn = (names[0], names[1]) if names is not None else ("", "")
            conn.execute(
                "INSERT INTO principal_status (principal_key, status, disabled_reason,"
                " disabled_at, disabled_by, display_name, upn, session_epoch, is_owner,"
                " owner_seen_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, NULL, ?)"
                " ON CONFLICT (principal_key) DO UPDATE SET"
                " status = excluded.status, disabled_reason = excluded.disabled_reason,"
                " disabled_at = excluded.disabled_at, disabled_by = excluded.disabled_by,"
                " display_name = excluded.display_name, upn = excluded.upn,"
                " session_epoch = principal_status.session_epoch + 1,"
                " updated_at = excluded.updated_at",
                (key, STATUS_DISABLED, reason, now, by, display_name, upn, now),
            )
            epoch = int(
                conn.execute(
                    "SELECT session_epoch FROM principal_status WHERE principal_key = ?",
                    (key,),
                ).fetchone()[0]
            )
            self._record_event(conn, key, EVENT_DISABLED, by, reason, epoch, now)
        return True

    def enable_principal(
        self, principal_key: str, object_id: str | None = None, *, actor: Actor
    ) -> bool:
        """Lift a disablement; True if this call changed it.

        Only an active owner (re-checked inside the transaction) or the operator.
        Bumps ``session_epoch`` again, so no session from before or during the
        disablement comes back. The user's enrollment, if kept, is used again as it
        is; a removed one has to be enrolled again.
        """
        key = _resolve_principal(principal_key, object_id)
        by = self._actor_name(actor)
        now = self._now()
        with self._write() as conn:
            self._require_owner_actor(conn, actor)
            row = self._fetch_status(conn, key)
            if row is None or not row.disabled:
                return False
            conn.execute(
                "UPDATE principal_status SET status = ?, disabled_reason = NULL,"
                " disabled_at = NULL, disabled_by = NULL, display_name = '', upn = '',"
                " session_epoch = session_epoch + 1, updated_at = ?"
                " WHERE principal_key = ?",
                (STATUS_ACTIVE, now, key),
            )
            self._record_event(conn, key, EVENT_ENABLED, by, None, row.session_epoch + 1, now)
        return True

    def list_status_events(
        self,
        principal_key: str | None = None,
        object_id: str | None = None,
        *,
        limit: int = 50,
    ) -> list[StatusEvent]:
        """The newest status transitions first, for one principal or for all."""
        sql = (
            "SELECT id, principal_key, action, actor, reason, session_epoch, at"
            " FROM principal_status_events"
        )
        args: list[Any] = []
        if principal_key is not None:
            sql += " WHERE principal_key = ?"
            args.append(_resolve_principal(principal_key, object_id))
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 1000)))
        with self._connection() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [StatusEvent(*r) for r in rows]

    # -- per-user write-tool preferences -------------------------------------

    def get_tool_prefs(self, principal_key: str) -> ToolPrefs | None:
        """The stored write-tool preferences of a principal, or None if never saved."""
        key = _validate_principal_key(principal_key)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT enabled_write_tools, enabled_at, updated_at, updated_via"
                " FROM user_tool_prefs WHERE principal_key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        return _decode_tool_prefs(key, row[0], row[1], row[2], row[3])

    def set_tool_prefs(
        self,
        principal_key: str,
        enabled_write_tools: Iterable[str],
        *,
        via: str = "account_web",
    ) -> ToolPrefs:
        """Replace a principal's switched-on write tools with exactly these names.

        Only explicit names are stored. A name that was already on keeps its
        ``enabled_at``; a new one gets the current time. Raises ValueError for a
        malformed name or an oversized list.
        """
        key = _validate_principal_key(principal_key)
        names = _validate_tool_names(enabled_write_tools)
        if not isinstance(via, str) or not 1 <= len(via) <= _MAX_PREF_VIA or not via.isascii():
            raise ValueError("via must be a short ASCII label")
        now = self._now()
        with self._write() as conn:
            row = conn.execute(
                "SELECT enabled_write_tools, enabled_at, updated_at, updated_via"
                " FROM user_tool_prefs WHERE principal_key = ?",
                (key,),
            ).fetchone()
            previous = (
                _decode_tool_prefs(key, row[0], row[1], row[2], row[3]).enabled_at
                if row is not None
                else {}
            )
            stamps = {name: previous.get(name, now) for name in names}
            conn.execute(
                "INSERT INTO user_tool_prefs"
                " (principal_key, enabled_write_tools, enabled_at, updated_at, updated_via)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT (principal_key) DO UPDATE SET"
                " enabled_write_tools = excluded.enabled_write_tools,"
                " enabled_at = excluded.enabled_at,"
                " updated_at = excluded.updated_at,"
                " updated_via = excluded.updated_via",
                (
                    key,
                    json.dumps(sorted(names)),
                    json.dumps(stamps, sort_keys=True),
                    now,
                    via,
                ),
            )
        return ToolPrefs(key, names, stamps, now, via)

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
