"""Accounts and encrypted per-user Canvas tokens for the self-hosted multi-user mode.

One database holds the whole state (a SQLite file by default, PostgreSQL when
``DATABASE_URL`` asks for it; see :mod:`.db`). A principal is an **account**,
named by one opaque, lower-case key ``acct:<uuid>``; every row of the server that
belongs to a person is keyed by it. How a person logs in is separate: an account has
one or more external identities (``provider_id``, ``issuer``, ``subject``), and the
only login provider today is Entra (issuer ``https://login.microsoftonline.com/<tid>/v2.0``,
subject = the ``oid`` claim). Who is admitted, and who is an owner, is decided by
:mod:`.accounts` and applied here, in one transaction.

The Canvas personal access token is encrypted with AES-256-GCM; the associated
data binds each ciphertext to its account, Canvas host and key id, so a copied or
swapped row, or a row whose principal or host was edited in the database, fails to
decrypt instead of sending the token to another user or school. Metadata columns
(Canvas name and id, timestamps) are plaintext on purpose: the admin page and the
operator CLI never need to decrypt.

Associated data (AAD) layouts, joined by ``0x1f``:

* v2 (every row that records a host, written by the account page):
  ``"canvas-mcp/canvas-token/v2" principal_key host key_id``
* v3 (a row without a host: it belongs to the operator's default school
  ``CANVAS_API_URL``): ``"canvas-mcp/canvas-token/v3" principal_key key_id``

Whether a row has a host decides which layout is used, so no version column is
needed. The principal and host are used exactly as given (the lookup key and the
stored host), never normalised on read; changing either, removing the host, or
adding one to a v3 row makes decryption fail. Saving a row through the account page
always passes a host. The layout v1 of the first releases (bound to the Entra tenant
and object id) is no longer produced or read at run time: schema 5 re-encrypted
every such row (see :mod:`.db.accounts_v5`).

Tables, all keyed by ``acct:<uuid>`` (no foreign keys; integrity comes from
single-transaction writes):

* ``accounts`` and ``external_identities``: who the person is, whether they may use
  the server (``status``: ``pending``, ``active`` or ``disabled``), their ``role``
  (``user`` or ``owner``) and the ``session_epoch`` that every ``/account`` session
  carries. An administrator *disables* an account; deleting the enrollment row never
  changes that, so a user cannot re-enroll their way back in. Disabling, enabling and
  denying bump ``session_epoch``, which invalidates every session issued before. A
  principal with no account row is not provisioned and is refused (fail closed).
* ``canvas_tokens``: the encrypted enrollments and their health. Saving needs an
  account that is active at that moment (checked in the same transaction).
* ``user_tool_prefs``: the write tools each account has switched on (see
  :mod:`.tool_prefs`).
* ``principal_status_events``: append-only history of every status transition with
  the actor, written in the same transaction as the change.
* ``credential_generations``: a counter raised on every change of the credential
  lifecycle.
* ``auth_events``: the sign-in history (90 days), ``audit_log``: administrative and
  security actions.

Keys come from ``CANVAS_TOKEN_KEYS`` (``kid:base64key[,kid:base64key...]``).
The first entry encrypts new rows; every entry decrypts. Error messages never
contain key or token material.

All methods are synchronous and thread-safe (one connection per call). Async
callers use ``anyio.to_thread.run_sync``.

Persistence is behind the repository interfaces of :mod:`.db.ports`
(SQLAlchemy Core implementations in :mod:`.db.repos`). Each public method is one
transaction, opened here and nowhere else, so the race-sensitive reasoning stays
in this file: a write takes the database's writer serialisation first (SQLite:
``BEGIN IMMEDIATE``; PostgreSQL: a transaction-scoped advisory lock at
``READ COMMITTED``), then runs the same checks and conditional updates in the
same order on both backends. SQLAlchemy is imported lazily, when a store is
built, so the upstream modes never need it.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import pathlib
import re
import time
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..credentials import note_credential_generation
from . import accounts as acc
from .accounts import (
    AUTH_EVENT_RETENTION_SECONDS,
    PENDING_RETENTION_SECONDS,
    AccessPolicy,
    AccountFacts,
    Decision,
    DecisionFacts,
    Denied,
    ExternalClaims,
    Verdict,
)
from .db.errors import StoreUnavailable, TokenStoreError  # noqa: F401 - re-exported

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

    from .db.accounts_v5 import AccountMigrationReport, MigrationOptions
    from .db.engine import Database
    from .db.repos import Repositories
    from .db.url import DatabaseTarget

SCHEMA_VERSION = 5

# Health of a stored token (``canvas_tokens.status``).
STATUS_ACTIVE = "active"
STATUS_INVALID = "invalid"

# Why a row is invalid: a closed set, stored in ``invalid_reason``.
REASON_CANVAS_TOKEN_REJECTED = "canvas_token_rejected"
REASON_DECRYPT_FAILED = "decrypt_failed"
REASON_REVOKED_BY_ADMIN = "revoked_by_admin"
INVALID_REASONS = frozenset(
    {REASON_CANVAS_TOKEN_REJECTED, REASON_DECRYPT_FAILED, REASON_REVOKED_BY_ADMIN}
)

# Whether an account may use the server (``accounts.status``). The token statuses
# above reuse STATUS_ACTIVE; ``missing`` is only ever a read result (no row).
STATUS_PENDING = acc.STATUS_PENDING
STATUS_DISABLED = acc.STATUS_DISABLED
STATUS_MISSING = "missing"
ROLE_USER = acc.ROLE_USER
ROLE_OWNER = acc.ROLE_OWNER

# Why an account is disabled: a closed set, stored in ``disabled_reason``.
DISABLE_REASON_ADMIN = "admin_disabled"
DISABLE_REASON_OPERATOR = "operator_disabled"
DISABLE_REASON_DENIED = "approval_denied"
DISABLE_REASONS = frozenset({DISABLE_REASON_ADMIN, DISABLE_REASON_OPERATOR})

# The ``actor`` of a change made by the operator CLI (no identity).
OPERATOR_ACTOR = "operator"
SYSTEM_ACTOR = "system"


class _Operator:
    """The operator at the host (the CLI): authorized by file access, not by an identity."""

    def __repr__(self) -> str:
        return "OPERATOR"


#: Pass as ``actor`` for a change made through the operator CLI.
OPERATOR = _Operator()
Actor = str | _Operator

# Why a credential generation was raised: a closed set, stored in ``reason``.
GENERATION_ENROLLED = "enrolled"
GENERATION_REMOVED = "removed"
GENERATION_INVALIDATED = "invalidated"
GENERATION_RESTORED = "restored"
GENERATION_DISABLED = "disabled"
GENERATION_ENABLED = "enabled"

EVENT_DISABLED = "disabled"
EVENT_ENABLED = "enabled"
EVENT_APPROVED = "approved"
EVENT_DENIED = "denied"
EVENT_OWNER_GAINED = acc.EVENT_OWNER_GAINED
EVENT_OWNER_LOST = acc.EVENT_OWNER_LOST
EVENT_ACCOUNT_CREATED = acc.EVENT_ACCOUNT_CREATED
EVENT_ACTIVATED = acc.EVENT_ACTIVATED
EVENT_OWNER_LOSS_REFUSED = acc.EVENT_OWNER_LOSS_REFUSED

# The actions of ``audit_log``: a closed set.
AUDIT_ACCOUNT_CREATED = "account_created"
AUDIT_ACCOUNT_CREATED_BY_OPERATOR = "account_created_by_operator"
AUDIT_ACCOUNT_ACTIVATED = "account_activated"
AUDIT_ACCOUNT_APPROVED = "account_approved"
AUDIT_ACCOUNT_DENIED = "account_denied"
AUDIT_ACCOUNT_DISABLED = "account_disabled"
AUDIT_ACCOUNT_ENABLED = "account_enabled"
AUDIT_ROLE_CHANGED = "role_changed"
AUDIT_TOKEN_ENROLLED = "token_enrolled"
AUDIT_TOKEN_REPLACED = "token_replaced"
AUDIT_TOKEN_DELETED = "token_deleted"
AUDIT_TOKEN_MARKED_INVALID = "token_marked_invalid"
AUDIT_WRITE_TOOLS_CHANGED = "write_tools_changed"
AUDIT_SCHEMA_MIGRATED = "schema_migrated"
AUDIT_PENDING_PURGED = "pending_purged"
# The local authorization server (SELFHOST_AUTH_MODE=local).
AUDIT_GRANT_REVOKED = "grant_revoked"
AUDIT_GRANTS_REVOKED_FOR_ACCOUNT = "grants_revoked_for_account"
AUDIT_JWT_KEY_ROTATED = "jwt_key_rotated"
AUDIT_ACTIONS = frozenset(
    {
        AUDIT_GRANT_REVOKED,
        AUDIT_GRANTS_REVOKED_FOR_ACCOUNT,
        AUDIT_JWT_KEY_ROTATED,
        AUDIT_ACCOUNT_CREATED,
        AUDIT_ACCOUNT_CREATED_BY_OPERATOR,
        AUDIT_ACCOUNT_ACTIVATED,
        AUDIT_ACCOUNT_APPROVED,
        AUDIT_ACCOUNT_DENIED,
        AUDIT_ACCOUNT_DISABLED,
        AUDIT_ACCOUNT_ENABLED,
        AUDIT_ROLE_CHANGED,
        AUDIT_TOKEN_ENROLLED,
        AUDIT_TOKEN_REPLACED,
        AUDIT_TOKEN_DELETED,
        AUDIT_TOKEN_MARKED_INVALID,
        AUDIT_WRITE_TOOLS_CHANGED,
        AUDIT_SCHEMA_MIGRATED,
        AUDIT_PENDING_PURGED,
    }
)

_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_AAD_PREFIX_V2 = b"canvas-mcp/canvas-token/v2\x1f"
_AAD_PREFIX_V3 = b"canvas-mcp/canvas-token/v3\x1f"
_AAD_SEP = b"\x1f"
_DERIVE_SALT = b"canvas-mcp/keyring-derive/v1"
_ENTRA_PREFIX = "entra:"
_MAX_HOST = 253
_MAX_PRINCIPAL_KEY = 256
_KEY_BYTES = 32
_NONCE_BYTES = 12

_MAX_CANVAS_NAME = 200
_MAX_DISPLAY_NAME = 200
_MAX_USERNAME = 254

_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_PREF_TOOLS = 256
_MAX_PREF_VIA = 32
_MAX_EXPIRES_HINT = 4_102_444_800  # 2100-01-01 UTC: a sanity bound, not a policy


class _Unset(Enum):
    UNSET = "unset"


#: Pass as ``expires_hint_at`` to keep the stored hint when a row is saved again.
KEEP_EXPIRY_HINT: Literal[_Unset.UNSET] = _Unset.UNSET


class KeyringError(TokenStoreError):
    """The keyring is malformed, or does not match the stored data."""


class TokenDecryptionError(TokenStoreError):
    """A stored token could not be decrypted.

    ``updated_at`` is the version of the row that failed, when the store read
    one; callers use it to invalidate exactly that row and not a replacement
    saved a moment later.
    """

    updated_at: int | None = None
    credential_generation: int | None = None


class PrincipalDisabledError(TokenStoreError):
    """The account is administratively disabled, so nothing may be saved for it."""


class PrincipalPendingError(TokenStoreError):
    """The account is waiting for approval, so no Canvas token may be saved for it."""


class PrincipalMissingError(TokenStoreError):
    """There is no account for this principal, so nothing may be saved for it."""


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

    api_token: str = field(repr=False)
    canvas_user_id: str
    canvas_user_name: str
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
    # Raised every time this principal's credential lifecycle changes (token
    # saved or replaced, removed, found dead, restored, principal disabled or
    # enabled). Read in the same statement as the row, so it describes this token.
    credential_generation: int = 0


@dataclass(frozen=True)
class EnrollmentInfo:
    """Enrollment metadata. Carries no token and never needs decryption."""

    canvas_user_id: str
    canvas_user_name: str
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
    credential_generation: int = 0


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
    """Whether an account may use the server, as last decided.

    ``status`` is ``pending``, ``active``, ``disabled`` or ``missing`` (no account
    row: ``stored`` is False and nothing is allowed). ``session_epoch`` changes
    whenever the account is disabled, enabled or denied; an ``/account`` session is
    valid only while its epoch equals this one. ``role`` is the stored role and
    ``role_source`` says who granted it (``rules`` is re-evaluated at each sign-in).
    """

    principal_key: str
    status: str = STATUS_ACTIVE
    role: str = ROLE_USER
    role_source: str | None = None
    role_seen_at: int | None = None
    admitted_via: str = acc.ADMITTED_RULES
    display_name: str = ""
    created_at: int = 0
    approved_at: int | None = None
    approved_by: str | None = None
    disabled_reason: str | None = None
    disabled_at: int | None = None
    disabled_by: str | None = None
    last_login_at: int | None = None
    session_epoch: int = 0
    updated_at: int = 0
    stored: bool = False
    # The newest credential generation of the principal (0 until the credential
    # has changed once). Read with the status, in one snapshot.
    credential_generation: int = 0
    # Set only on a value returned after a sign-in that changed the role.
    owner_change: str | None = None

    @property
    def disabled(self) -> bool:
        return self.status == STATUS_DISABLED

    @property
    def pending(self) -> bool:
        return self.status == STATUS_PENDING

    @property
    def active(self) -> bool:
        return self.status == STATUS_ACTIVE

    @property
    def missing(self) -> bool:
        return self.status == STATUS_MISSING

    @property
    def is_owner(self) -> bool:
        return self.role == ROLE_OWNER

    @property
    def owner_seen_at(self) -> int | None:
        return self.role_seen_at

    @property
    def facts(self) -> AccountFacts:
        return AccountFacts(self.status, self.role, self.role_source, self.admitted_via)


@dataclass(frozen=True)
class IdentityInfo:
    """One external identity of an account."""

    provider_id: str
    issuer: str
    subject: str
    username: str
    email: str | None
    email_verified: bool
    linked_at: int
    last_login_at: int | None

    @property
    def legacy_key(self) -> str | None:
        """``entra:<tid>:<oid>`` for an Entra identity (the pre-account-model key), else None."""
        if self.provider_id != acc.PROVIDER_ENTRA:
            return None
        prefix, suffix = acc.ENTRA_ISSUER_PREFIX, "/v2.0"
        if not (self.issuer.startswith(prefix) and self.issuer.endswith(suffix)):
            return None
        tid = self.issuer[len(prefix) : -len(suffix)]
        return f"{_ENTRA_PREFIX}{tid}:{self.subject}"

    @property
    def tenant_id(self) -> str:
        legacy = self.legacy_key
        return legacy.split(":")[1] if legacy else ""


@dataclass(frozen=True)
class AccountInfo:
    """An account with its identities, for the admin page and the operator CLI."""

    status: PrincipalStatus
    identities: tuple[IdentityInfo, ...]

    @property
    def principal_key(self) -> str:
        return self.status.principal_key

    @property
    def username(self) -> str:
        return self.identities[0].username if self.identities else ""

    @property
    def legacy_key(self) -> str | None:
        return next((i.legacy_key for i in self.identities if i.legacy_key), None)


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


@dataclass(frozen=True)
class AuthEvent:
    """One sign-in attempt (see ``auth_events``)."""

    id: int
    at: int
    provider_id: str
    surface: str
    outcome: str
    reason: str
    ip: str
    ua_hash: str | None


@dataclass(frozen=True)
class AuditEntry:
    """One administrative or security action (see ``audit_log``)."""

    id: int
    at: int
    actor: str
    action: str
    target: str | None
    reason: str | None
    detail: dict[str, Any]


@dataclass(frozen=True)
class Resolution:
    """The outcome of resolving an external identity (see :meth:`TokenStore.resolve_identity`).

    ``status`` is the account after the decision (None when nothing exists, for
    example a refusal that wrote no account). ``denied`` is set for a refusal.
    """

    outcome: str
    reason: str
    status: PrincipalStatus | None
    denied: Denied | None = None
    created: bool = False
    activated: bool = False
    session_owner: bool = False
    owner_change: str | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"

    @property
    def principal_key(self) -> str | None:
        return None if self.status is None else self.status.principal_key


def _status_from_row(row: Sequence[Any]) -> PrincipalStatus:
    return PrincipalStatus(
        principal_key=acc.account_key_of(row[0]),
        status=row[1],
        role=row[2],
        role_source=row[3],
        role_seen_at=row[4],
        admitted_via=row[5],
        display_name=row[6] or "",
        created_at=int(row[9]),
        approved_at=row[10],
        approved_by=row[11],
        disabled_reason=row[12],
        disabled_at=row[13],
        disabled_by=row[14],
        last_login_at=row[15],
        session_epoch=int(row[16]),
        updated_at=int(row[17]),
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
        # The raw keys stay private to this object: only encrypt, decrypt and derive use them.
        self._raw = dict(keys)

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

    def derive(self, key_id: str, info: str, length: int = 32) -> bytes:
        """A key for another purpose, derived from one of the keys (HKDF-SHA256).

        ``info`` names the purpose (and should include the key id), so two purposes
        never share a key and none of them is the encryption key. The result is
        deterministic: every process with the same ``CANVAS_TOKEN_KEYS`` derives the same
        bytes. Raises :class:`KeyringError` for an unknown key id.
        """
        raw = self._raw.get(key_id)
        if raw is None:
            raise KeyringError("unknown key id")
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=_DERIVE_SALT,
            info=info.encode("utf-8"),
        ).derive(raw)

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
    """The legacy identity key of an Entra user, ``entra:<tenant id>:<object id>`` in lower case.

    This is not a principal key any more (see :func:`_validate_principal_key`); it is
    the form the operator CLI still accepts and the form of audit lines written
    before the account model. Raises ValueError unless both ids are GUIDs.
    """
    tid = _normalize_guid(tenant_id, "tenant_id")
    oid = _normalize_guid(object_id, "object_id")
    return f"{_ENTRA_PREFIX}{tid}:{oid}"


def split_entra_key(principal_key: str) -> tuple[str, str] | None:
    """``(tenant id, object id)`` of an ``entra:`` identity key, or None for any other string."""
    if not principal_key.startswith(_ENTRA_PREFIX):
        return None
    tid, sep, oid = principal_key[len(_ENTRA_PREFIX) :].partition(":")
    if not sep or not _GUID_RE.fullmatch(tid) or not _GUID_RE.fullmatch(oid):
        return None
    return tid.lower(), oid.lower()


def _validate_principal_key(principal_key: str) -> str:
    """A principal key to store or look up: lower-case printable ASCII, otherwise opaque.

    An ``entra:`` string is refused: since the account model every row is keyed by
    ``acct:<uuid>``, and a missed call site must fail loudly rather than read an empty
    row for an old key (which would mean "no restriction").
    """
    if (
        not isinstance(principal_key, str)
        or not 1 <= len(principal_key) <= _MAX_PRINCIPAL_KEY
        or not principal_key.isascii()
        or principal_key != principal_key.lower()
        or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in principal_key)
    ):
        raise ValueError("principal_key must be a lower-case printable ASCII string")
    if principal_key.startswith(_ENTRA_PREFIX):
        raise ValueError(
            "an entra: key is not a principal key; use the account key acct:<uuid> "
            "(TokenStore.resolve_legacy_key maps the old form)"
        )
    return principal_key


def _require_account_key(principal_key: str) -> str:
    """A principal key that names an account (``acct:<uuid>``); raises ValueError otherwise."""
    key = _validate_principal_key(principal_key)
    if not acc.valid_account_key(key):
        raise ValueError("principal_key must be an account key (acct:<uuid>)")
    return key


def valid_principal_key(value: object) -> str | None:
    """``value`` if it is a well-formed account key, else None (never raises)."""
    if not isinstance(value, str):
        return None
    try:
        return _require_account_key(value)
    except ValueError:
        return None


def _account_id(principal_key: str) -> str | None:
    """The account id of a key, or None for an opaque key that cannot name an account."""
    return principal_key[len(acc.ACCOUNT_KEY_PREFIX) :] if acc.valid_account_key(principal_key) else None


def _validate_host_value(host: str | None) -> str | None:
    """A host to store: None (default school) or a lowercase ASCII name.

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
    """Associated data of a row that records a host."""
    return (
        _AAD_PREFIX_V2
        + principal_key.encode("utf-8", "surrogatepass")
        + _AAD_SEP
        + canvas_host.encode("utf-8", "surrogatepass")
        + _AAD_SEP
        + key_id.encode("utf-8", "surrogatepass")
    )


def _aad_v3(principal_key: str, key_id: str) -> bytes:
    """Associated data of a row without a host (it belongs to the default school)."""
    return (
        _AAD_PREFIX_V3
        + principal_key.encode("utf-8", "surrogatepass")
        + _AAD_SEP
        + key_id.encode("utf-8", "surrogatepass")
    )


def _aad_for_principal(principal_key: str, canvas_host: str | None, key_id: str) -> bytes:
    """AAD of the row stored under ``principal_key``; the host selects the layout.

    Raises ValueError for a host-less row of a principal that is not an account:
    such a row cannot exist.
    """
    if canvas_host is not None:
        return _aad_v2(principal_key, canvas_host, key_id)
    if not acc.valid_account_key(principal_key):
        raise ValueError("a row without a host needs an account principal")
    return _aad_v3(principal_key, key_id)


def _info_from_row(row: Sequence[Any]) -> EnrollmentInfo:
    return EnrollmentInfo(
        canvas_user_id=row[0],
        canvas_user_name=row[1],
        key_id=row[2],
        created_at=row[3],
        updated_at=row[4],
        last_used_at=row[5],
        canvas_host=row[6],
        principal_key=row[7] or "",
        status=row[8] or STATUS_ACTIVE,
        invalid_reason=row[9],
        invalid_since=row[10],
        last_verified_at=row[11],
        expires_hint_at=row[12],
        credential_generation=int(row[13]),
    )


def _json(detail: dict[str, Any] | None) -> str:
    return json.dumps(detail or {}, sort_keys=True, separators=(",", ":"))


class TokenStore:
    """Store of accounts, AES-GCM encrypted Canvas tokens and the access state around them.

    ``db`` is a :class:`~.db.engine.Database`, or a file path, which means a
    SQLite file (what every test and the operator CLI have always passed).
    """

    def __init__(
        self,
        db: pathlib.Path | Database,
        keyring: Keyring,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        # Imported here, not at module level: SQLAlchemy is an optional extra that
        # the upstream modes never load (this module is imported in every mode).
        try:
            from .db.engine import Database as _Database
            from .db.repos import Repositories
        except ImportError:  # pragma: no cover - exercised by the isolation tests
            raise TokenStoreError(
                "the self-hosted mode needs SQLAlchemy and Alembic: "
                "pip install 'canvas-mcp[selfhost]'"
            ) from None

        self._db: Database = db if isinstance(db, _Database) else _Database.sqlite(pathlib.Path(db))
        #: The SQLite file, or None on PostgreSQL.
        self._path: pathlib.Path | None = self._db.sqlite_path
        self._repos: Repositories = Repositories(self._db.kind)
        self._keyring = keyring
        self._clock = clock
        # Test seam for deterministic race tests: called with a name at fixed points
        # inside a transaction. None in production.
        self._pause_hook: Callable[[str], None] | None = None
        # Test seam: the id of a newly created account (a random UUID in production).
        self._new_account_id: Callable[[ExternalClaims], str] = lambda _ext: str(uuid.uuid4())

    @classmethod
    def for_target(
        cls,
        target: DatabaseTarget,
        keyring: Keyring,
        *,
        clock: Callable[[], float] = time.time,
    ) -> TokenStore:
        """A store for a validated ``DATABASE_URL`` target (SQLite or PostgreSQL)."""
        from .db.engine import Database as _Database

        return cls(_Database(target), keyring, clock=clock)

    # -- plumbing ----------------------------------------------------------

    def _now(self) -> int:
        return int(self._clock())

    def _pause(self, name: str) -> None:
        if self._pause_hook is not None:
            self._pause_hook(name)

    @property
    def database(self) -> Database:
        return self._db

    @property
    def description(self) -> str:
        """The backend, without credentials (``postgresql+psycopg://host:port/db`` or a path)."""
        return self._db.description

    def close(self) -> None:
        """Release the connection pool (a no-op for SQLite, which opens one per call)."""
        self._db.dispose()

    # -- lifecycle ---------------------------------------------------------

    def initialize(
        self,
        *,
        auto_migrate: bool = True,
        options: MigrationOptions | None = None,
        report: AccountMigrationReport | None = None,
    ) -> None:
        """Create or open the database and prove the keyring matches its data.

        Applies pending schema revisions when ``auto_migrate`` is true (schema 4 -> 5
        re-encrypts every stored token with this store's keyring); otherwise refuses a
        database that is not current (run ``token_admin db upgrade``). Refuses, changing
        nothing, a database written by a newer server.
        """
        from .db import migrate

        self._db.prepare_storage()
        migrate.ensure_ready(
            self._db,
            auto=auto_migrate,
            keyring=self._keyring,
            options=options,
            report=report,
        )
        self._db.tighten_storage()

        self._verify_keyring()

    def _verify_keyring(self) -> None:
        tokens = self._repos.tokens
        with self._db.read() as conn:
            used = tokens.key_ids_in_use(conn)
            missing = [kid for kid in used if kid not in self._keyring.key_ids]
            if missing:
                raise KeyringError(
                    "CANVAS_TOKEN_KEYS is missing key id(s): " + ", ".join(missing)
                )
            for kid in used:
                probe = tokens.probe_row(conn, kid)
                if probe is None:
                    continue
                try:
                    self._keyring.decrypt(
                        kid,
                        bytes(probe[1]),
                        bytes(probe[2]),
                        _aad_for_principal(probe[0], probe[3], kid),
                    )
                except (TokenDecryptionError, ValueError):
                    raise KeyringError(
                        f"CANVAS_TOKEN_KEYS key {kid} does not match the stored data"
                    ) from None

    # -- reads -------------------------------------------------------------

    def get(self, principal_key: str) -> StoredToken | None:
        """Return the decrypted enrollment of a principal, or None.

        Raises TokenDecryptionError.
        """
        key = _validate_principal_key(principal_key)
        with self._db.read() as conn:
            row = self._repos.tokens.row_for_get(conn, key)
        if row is None:
            return None
        # The AAD is built from the key the caller asked for, not from anything
        # stored next to the row, so a row that was moved to another principal
        # fails to decrypt.
        try:
            try:
                aad = _aad_for_principal(key, row[8], row[0])
            except ValueError:
                raise TokenDecryptionError("stored token could not be decrypted") from None
            plaintext = self._keyring.decrypt(row[0], bytes(row[1]), bytes(row[2]), aad)
            try:
                api_token = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                raise TokenDecryptionError("stored token could not be decrypted") from None
        except TokenDecryptionError as exc:
            exc.updated_at = row[6] if isinstance(row[6], int) else None
            exc.credential_generation = int(row[14])
            raise
        return StoredToken(
            api_token=api_token,
            canvas_user_id=row[3],
            canvas_user_name=row[4],
            key_id=row[0],
            created_at=row[5],
            updated_at=row[6],
            last_used_at=row[7],
            canvas_host=row[8],
            principal_key=key,
            status=row[9] or STATUS_ACTIVE,
            invalid_reason=row[10],
            invalid_since=row[11],
            last_verified_at=row[12],
            expires_hint_at=row[13],
            credential_generation=int(row[14]),
        )

    def info(self, principal_key: str) -> EnrollmentInfo | None:
        key = _validate_principal_key(principal_key)
        with self._db.read() as conn:
            row = self._repos.tokens.info(conn, key)
        return None if row is None else _info_from_row(row)

    def list_enrollments(self) -> list[EnrollmentInfo]:
        with self._db.read() as conn:
            rows = self._repos.tokens.list_all(conn)
        return [_info_from_row(r) for r in rows]

    def count(self) -> int:
        with self._db.read() as conn:
            return self._repos.tokens.count(conn)

    # -- writes ------------------------------------------------------------

    def put(
        self,
        *,
        principal_key: str,
        api_token: str,
        canvas_user_id: str,
        canvas_user_name: str,
        canvas_host: str | None = None,
        expires_hint_at: int | None | Literal[_Unset.UNSET] = KEEP_EXPIRY_HINT,
    ) -> EnrollmentInfo:
        """Insert or replace an account's enrollment, preserving ``created_at``.

        ``principal_key`` must be an account key. ``canvas_host`` is the school the
        token belongs to (None only for the default school ``CANVAS_API_URL``); it is
        bound into the encryption together with the principal. Saving marks the row
        ``active`` and verified now, clears any invalid reason, and raises the
        principal's credential generation. ``expires_hint_at`` is the optional expiry
        date the user gave for the token (epoch seconds, used only for a reminder): an
        integer sets it, ``None`` clears it, and leaving it out keeps the stored value
        (the account page always passes it, so replacing a token replaces the hint).

        Only an **active** account can enroll: a disabled one raises
        :class:`PrincipalDisabledError`, one waiting for approval
        :class:`PrincipalPendingError` and an unknown one :class:`PrincipalMissingError`,
        all checked in the same transaction as the write.
        """
        key = _require_account_key(principal_key)
        account_id = acc.account_id_of(key)
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
        kid, nonce, ciphertext = self._keyring.encrypt(
            api_token.encode("utf-8"),
            _aad_for_principal(key, host, self._keyring.active_key_id),
        )
        now = self._now()
        repos = self._repos
        with self._db.write() as conn:
            # Checked in the same transaction as the write, so an enrollment that
            # races an administrator's disable (or an approval) either lands first
            # (and the account is disabled right after) or is refused; it can never
            # be saved for an account that is not active.
            account = repos.accounts.get(conn, account_id, for_update=True)
            self._pause("after_gate_read")
            if account is None:
                raise PrincipalMissingError("there is no account for this principal")
            if account[1] == STATUS_DISABLED:
                raise PrincipalDisabledError("this principal is disabled")
            if account[1] != STATUS_ACTIVE:
                raise PrincipalPendingError("this account is waiting for approval")
            replaced = repos.tokens.exists(conn, key)
            repos.tokens.upsert(
                conn,
                principal_key=key,
                key_id=kid,
                nonce=nonce,
                ciphertext=ciphertext,
                canvas_user_id=str(canvas_user_id),
                canvas_user_name=str(canvas_user_name)[:_MAX_CANVAS_NAME],
                canvas_host=host,
                status=STATUS_ACTIVE,
                now=now,
                expires_hint_at=hint,
                keep_expiry_hint=keep_hint,
            )
            # Saving a token is always a new credential lifecycle, even for the
            # same token text: state learned under the old one is not reused.
            generation = repos.generations.bump(conn, key, GENERATION_ENROLLED, now)
            self._audit(
                conn,
                key,
                AUDIT_TOKEN_REPLACED if replaced else AUDIT_TOKEN_ENROLLED,
                target=key,
                detail={"canvas_host": host or ""},
                now=now,
            )
            row = repos.tokens.info(conn, key)
        assert row is not None
        self._publish_generation(key, generation)
        return _info_from_row(row)

    def delete(self, principal_key: str, *, actor: Actor | None = None) -> bool:
        """Remove the enrollment row.

        This is housekeeping or a self-disconnect, never an authorization decision:
        it does not touch the account, so a disabled principal stays disabled and an
        active one may enroll again. It does raise the credential generation, so
        nothing remembered for the deleted token is served for a later one. ``actor``
        (an administrator or the operator) is recorded in the audit log; without one
        the account itself is the actor. An administrator account is re-checked inside
        the transaction (still an active owner), as for every other administrative
        change; the operator needs no identity.
        """
        key = _validate_principal_key(principal_key)
        by = key if actor is None else self._actor_name(actor)
        generation: int | None = None
        with self._db.write() as conn:
            if actor is not None:
                self._require_owner_actor(conn, actor)
            removed = self._repos.tokens.delete(conn, key)
            if removed:
                now = self._now()
                # The generation outlives the row: a token enrolled afterwards
                # is a later one, never a reuse of the deleted one's number.
                generation = self._repos.generations.bump(conn, key, GENERATION_REMOVED, now)
                self._audit(conn, by, AUDIT_TOKEN_DELETED, target=key, now=now)
        if generation is not None:
            self._publish_generation(key, generation)
        return removed

    def touch(self, principal_key: str, *, min_interval_seconds: int = 300) -> None:
        """Record use, at most once per interval. Never raises."""
        try:
            key = _validate_principal_key(principal_key)
            now = self._now()
            # No writer lock on PostgreSQL: the update only sets a timestamp, and
            # nothing else depends on it.
            with self._db.best_effort_write(lock=False) as conn:
                self._repos.tokens.touch(conn, key, now, now - max(0, min_interval_seconds))
        except (TokenStoreError, ValueError, OSError):
            return

    def mark_invalid(
        self,
        principal_key: str,
        *,
        reason: str,
        expected_updated_at: int | None = None,
        expected_generation: int | None = None,
        actor: Actor | None = None,
    ) -> bool:
        """Mark an active row invalid; True only if this call changed it.

        An already invalid row is left as it is (the first reason wins). With
        ``expected_updated_at`` the row is changed only if it still has that
        ``updated_at``, and with ``expected_generation`` only if the credential
        generation is still that one, so a token that Canvas rejected cannot
        invalidate the replacement the user enrolled in the meantime (the
        generation also catches a replacement within the same second). ``actor``
        (an administrator) is recorded in the audit log, and an administrator account
        is re-checked inside the transaction (still an active owner).
        """
        if reason not in INVALID_REASONS:
            raise ValueError("unknown invalid reason")
        key = _validate_principal_key(principal_key)
        by = None if actor is None else self._actor_name(actor)
        now = self._now()
        generation: int | None = None
        with self._db.write() as conn:
            if actor is not None:
                self._require_owner_actor(conn, actor)
            changed = self._repos.tokens.mark_invalid(
                conn,
                key,
                reason=reason,
                now=now,
                expected_updated_at=expected_updated_at,
                expected_generation=expected_generation,
            )
            self._pause("after_conditional_update")
            if changed:
                generation = self._repos.generations.bump(conn, key, GENERATION_INVALIDATED, now)
                if by is not None:
                    self._audit(
                        conn, by, AUDIT_TOKEN_MARKED_INVALID, target=key, reason=reason, now=now
                    )
        if generation is not None:
            self._publish_generation(key, generation)
        return changed

    def restore_active(
        self,
        principal_key: str,
        *,
        expected_updated_at: int | None = None,
        expected_generation: int | None = None,
    ) -> bool:
        """Mark an invalid row active again after a successful check; True if changed.

        The stored token is untouched. ``expected_updated_at`` and
        ``expected_generation`` work as in :meth:`mark_invalid`.
        """
        key = _validate_principal_key(principal_key)
        now = self._now()
        generation: int | None = None
        with self._db.write() as conn:
            changed = self._repos.tokens.restore_active(
                conn,
                key,
                now=now,
                expected_updated_at=expected_updated_at,
                expected_generation=expected_generation,
            )
            self._pause("after_conditional_update")
            if changed:
                generation = self._repos.generations.bump(conn, key, GENERATION_RESTORED, now)
        if generation is not None:
            self._publish_generation(key, generation)
        return changed

    def mark_verified(
        self,
        principal_key: str,
        *,
        min_interval_seconds: int = 600,
        expected_generation: int | None = None,
    ) -> None:
        """Record a successful Canvas call on an active row, at most once per interval.

        Never raises, and never touches an invalid row. With ``expected_generation``
        the success is recorded only while that is still the credential generation:
        a call made with a token that was replaced meanwhile says nothing about the
        replacement.
        """
        try:
            key = _validate_principal_key(principal_key)
            now = self._now()
            # Takes the PostgreSQL writer lock: the generation comparison must see
            # every enrollment that committed before it.
            with self._db.best_effort_write(lock=True) as conn:
                self._repos.tokens.mark_verified(
                    conn,
                    key,
                    now=now,
                    older_than=now - max(0, min_interval_seconds),
                    expected_generation=expected_generation,
                )
        except (TokenStoreError, ValueError, OSError):
            return

    # -- credential generation --------------------------------------------------

    @staticmethod
    def _publish_generation(key: str, generation: int) -> None:
        """Tell this process a change was committed (it only records; see credentials)."""
        try:
            note_credential_generation(key, generation)
        except Exception:  # noqa: BLE001 - bookkeeping must never fail a write
            return

    def credential_generation(self, principal_key: str) -> int:
        """The current credential generation of a principal (0 if it never changed)."""
        key = _validate_principal_key(principal_key)
        with self._db.read() as conn:
            return self._repos.generations.get(conn, key)

    # -- audit and history plumbing ----------------------------------------------

    def _audit(
        self,
        conn: Connection,
        actor: str,
        action: str,
        *,
        target: str | None = None,
        reason: str | None = None,
        detail: dict[str, Any] | None = None,
        now: int | None = None,
    ) -> None:
        assert action in AUDIT_ACTIONS, action
        self._repos.audit.append(
            conn,
            now=self._now() if now is None else now,
            actor=actor,
            action=action,
            target=target,
            reason=reason,
            detail=_json(detail),
        )

    def _record_event(
        self,
        conn: Connection,
        key: str,
        action: str,
        actor: str | None,
        reason: str | None,
        epoch: int,
        now: int,
    ) -> None:
        self._repos.events.append(conn, key, action, actor, reason, epoch, now)

    @staticmethod
    def _actor_name(actor: Actor) -> str:
        """The recorded name of an actor; a non-operator actor must be an account key."""
        if isinstance(actor, _Operator):
            return OPERATOR_ACTOR
        return _require_account_key(actor)

    def _require_owner_actor(self, conn: Connection, actor: Actor) -> None:
        """Re-evaluate, inside the transaction, that the actor is an active owner now.

        The operator at the host needs no identity. Anyone else must have an account
        that is active and an owner: an owner who was disabled, or whose owner role a
        later sign-in no longer showed, cannot act, whatever their browser session still
        says.
        """
        if isinstance(actor, _Operator):
            return
        row = self._repos.accounts.get(conn, acc.account_id_of(self._actor_name(actor)), for_update=True)
        if row is None or row[1] != STATUS_ACTIVE or row[2] != ROLE_OWNER:
            raise AccessActionRefused(AccessActionRefused.NOT_OWNER)

    # -- accounts: reading -------------------------------------------------------

    def get_principal_status(self, principal_key: str) -> PrincipalStatus:
        """The account status of a principal; ``missing`` when there is no account.

        Carries the credential generation, read in the same statement as the status.
        """
        key = _validate_principal_key(principal_key)
        account_id = _account_id(key)
        if account_id is None:
            with self._db.read() as conn:
                generation = self._repos.generations.get(conn, key)
            return PrincipalStatus(key, status=STATUS_MISSING, credential_generation=generation)
        with self._db.read() as conn:
            row, generation = self._repos.accounts.get_with_generation(conn, account_id)
        if row is None:
            return PrincipalStatus(key, status=STATUS_MISSING, credential_generation=generation)
        return replace(_status_from_row(row), credential_generation=generation)

    def list_principal_statuses(self) -> list[PrincipalStatus]:
        """Every account, oldest first."""
        with self._db.read() as conn:
            rows = self._repos.accounts.list_all(conn)
        return [_status_from_row(r) for r in rows]

    def list_accounts(self) -> list[AccountInfo]:
        """Every account with its identities (admin page, operator CLI)."""
        with self._db.read() as conn:
            rows = self._repos.accounts.list_all(conn)
            identities = self._repos.identities.all(conn)
        by_account: dict[str, list[tuple[Any, ...]]] = {}
        for ident in identities:
            by_account.setdefault(ident[0], []).append(tuple(ident))
        result: list[AccountInfo] = []
        for row in rows:
            infos = tuple(
                IdentityInfo(
                    provider_id=i[1],
                    issuer=i[2],
                    subject=i[3],
                    username=i[4] or "",
                    email=None,
                    email_verified=False,
                    linked_at=0,
                    last_login_at=None,
                )
                for i in by_account.get(row[0], [])
            )
            result.append(AccountInfo(_status_from_row(row), infos))
        return result

    def account_identities(self, principal_key: str) -> list[IdentityInfo]:
        account_id = _account_id(_validate_principal_key(principal_key))
        if account_id is None:
            return []
        with self._db.read() as conn:
            rows = self._repos.identities.for_account(conn, account_id)
        return [
            IdentityInfo(r[0], r[1], r[2], r[3] or "", r[4], bool(r[5]), int(r[6]), r[7])
            for r in rows
        ]

    def count_active_owners(self) -> int:
        with self._db.read() as conn:
            return self._repos.accounts.count_active_owners(conn)

    def lookup_identity(self, provider_id: str, issuer: str, subject: str) -> str | None:
        """The account key of an external identity, or None if it is not known."""
        with self._db.read() as conn:
            account_id = self._repos.identities.lookup(conn, provider_id, issuer, subject)
        return None if account_id is None else acc.account_key_of(account_id)

    def resolve_legacy_key(self, legacy_key: str) -> str | None:
        """Map the pre-account form ``entra:<tid>:<oid>`` to the account key, if known."""
        parts = split_entra_key(legacy_key)
        if parts is None:
            return None
        return self.lookup_identity(acc.PROVIDER_ENTRA, acc.entra_issuer(parts[0]), parts[1])

    # -- accounts: sign-in and admission -------------------------------------------

    def resolve_identity(
        self,
        ext: ExternalClaims,
        verdict: Verdict,
        policy: AccessPolicy,
        *,
        purpose: acc.Purpose,
        ip: str = "unknown",
        ua_hash: str | None = None,
    ) -> Resolution:
        """Decide and apply, in one transaction, what an external identity may do.

        Looks the identity up (``provider_id``, ``issuer``, ``subject``), locks its
        account, reads the owner and pending counts, runs :func:`accounts.decide` and
        applies the result: creating the account and its identity, activating a pending
        account, changing the role (with the last-owner guard), refreshing the login time.
        The history, the audit entry and the sign-in event are written in the same
        transaction. ``purpose='sign_in'`` is the ``/account`` login (roles are
        recomputed, an event is always recorded); ``'request'`` is the MCP path (an
        existing account is not written, a role is never raised).
        """
        now = self._now()
        repos = self._repos
        surface = acc.SURFACE_ACCOUNT if purpose == "sign_in" else acc.SURFACE_MCP
        with self._db.write() as conn:
            account_id = repos.identities.lookup(conn, *ext.identity)
            row = repos.accounts.get(conn, account_id, for_update=True) if account_id else None
            existing = None if row is None else _status_from_row(row).facts
            facts = DecisionFacts(
                active_owner_count=repos.accounts.count_active_owners(conn),
                pending_count=repos.accounts.count_pending(conn),
                is_bootstrap_identity=acc.is_bootstrap_identity(ext, policy),
            )
            decision = acc.decide(existing, verdict, policy, facts, purpose)
            self._pause("after_decision")
            created = activated = False
            owner_change: str | None = None
            if decision.create:
                account_id = self._new_account_id(ext)
                self._create_account(conn, account_id, ext, decision, now)
                created = True
            elif row is not None and account_id is not None:
                if decision.activate:
                    repos.accounts.activate(
                        conn,
                        account_id,
                        admitted_via=decision.admitted_via or acc.ADMITTED_RULES,
                        approved_by=None,
                        now=now,
                    )
                    key = acc.account_key_of(account_id)
                    self._record_event(
                        conn, key, EVENT_ACTIVATED, None, decision.admitted_via,
                        int(row[16]), now,
                    )
                    self._audit(
                        conn, SYSTEM_ACTOR, AUDIT_ACCOUNT_ACTIVATED, target=key,
                        detail={"admitted_via": decision.admitted_via or ""}, now=now,
                    )
                    activated = True
                owner_change = self._apply_role(
                    conn, account_id, row, decision, purpose, verdict, now
                )
            if (
                purpose == "sign_in"
                and account_id is not None
                and decision.outcome != "deny"
            ):
                repos.accounts.touch_login(
                    conn, account_id, display_name=ext.display_name[:_MAX_DISPLAY_NAME], now=now
                )
                repos.identities.touch(
                    conn, *ext.identity, username=ext.username[:_MAX_USERNAME], now=now
                )
            if created:
                owner_change = decision.role_event if decision.role == ROLE_OWNER else None
            if purpose == "sign_in" or created or activated:
                self._record_auth_event(
                    conn,
                    now=now,
                    account_id=account_id,
                    provider_id=ext.provider_id,
                    surface=surface,
                    outcome={
                        "allow": acc.OUTCOME_SUCCESS,
                        "pending": acc.OUTCOME_PENDING,
                        "deny": acc.OUTCOME_DENIED,
                    }[decision.outcome],
                    reason=decision.reason,
                    ip=ip,
                    ua_hash=ua_hash,
                )
            final_row = repos.accounts.get(conn, account_id) if account_id else None
        status = None if final_row is None else _status_from_row(final_row)
        if status is not None and owner_change is not None:
            status = replace(status, owner_change=owner_change)
        return Resolution(
            outcome=decision.outcome,
            reason=decision.reason,
            status=status,
            denied=decision.denied,
            created=created,
            activated=activated,
            session_owner=decision.session_owner,
            owner_change=owner_change,
        )

    def _create_account(
        self,
        conn: Connection,
        account_id: str,
        ext: ExternalClaims,
        decision: Decision,
        now: int,
    ) -> None:
        repos = self._repos
        key = acc.account_key_of(account_id)
        is_owner = decision.role == ROLE_OWNER
        repos.accounts.insert(
            conn,
            account_id=account_id,
            status=decision.create_status or STATUS_ACTIVE,
            role=ROLE_OWNER if is_owner else ROLE_USER,
            role_source=decision.role_source if is_owner else None,
            admitted_via=decision.admitted_via or acc.ADMITTED_RULES,
            display_name=ext.display_name[:_MAX_DISPLAY_NAME],
            now=now,
        )
        repos.identities.insert(
            conn,
            account_id=account_id,
            provider_id=ext.provider_id,
            issuer=ext.issuer,
            subject=ext.subject,
            username=ext.username[:_MAX_USERNAME],
            email=None,
            email_verified=False,
            now=now,
        )
        self._record_event(
            conn, key, EVENT_ACCOUNT_CREATED, None, decision.admitted_via, 0, now
        )
        if is_owner:
            self._record_event(conn, key, EVENT_OWNER_GAINED, None, decision.role_source, 0, now)
        self._audit(
            conn,
            SYSTEM_ACTOR,
            AUDIT_ACCOUNT_CREATED,
            target=key,
            detail={
                "status": decision.create_status or STATUS_ACTIVE,
                "admitted_via": decision.admitted_via or "",
                "provider": ext.provider_id,
            },
            now=now,
        )

    def _apply_role(
        self,
        conn: Connection,
        account_id: str,
        row: Sequence[Any],
        decision: Decision,
        purpose: acc.Purpose,
        verdict: Verdict,
        now: int,
    ) -> str | None:
        """Apply the role part of a decision to an existing account; returns the change made."""
        repos = self._repos
        key = acc.account_key_of(account_id)
        epoch = int(row[16])
        if decision.role is not None:
            repos.accounts.set_role(
                conn,
                account_id,
                role=decision.role,
                source=decision.role_source,
                seen_at=now if decision.role == ROLE_OWNER else row[4],
                now=now,
            )
            event = decision.role_event or (
                EVENT_OWNER_GAINED if decision.role == ROLE_OWNER else EVENT_OWNER_LOST
            )
            self._record_event(conn, key, event, None, "sign_in", epoch, now)
            self._audit(
                conn, SYSTEM_ACTOR, AUDIT_ROLE_CHANGED, target=key,
                detail={"role": decision.role, "source": decision.role_source or "", "via": "sign_in"},
                now=now,
            )
            return event
        if decision.role_event == EVENT_OWNER_LOSS_REFUSED:
            self._record_event(conn, key, EVENT_OWNER_LOSS_REFUSED, None, "sign_in", epoch, now)
            return None
        if (
            purpose == "sign_in"
            and row[2] == ROLE_OWNER
            and row[3] == acc.ROLE_SOURCE_RULES
            and verdict.owner_by_rule
        ):
            # Fresh evidence that the rules still make this account an owner.
            repos.accounts.mark_role_seen(conn, account_id, now)
        return None

    def _record_auth_event(
        self,
        conn: Connection,
        *,
        now: int,
        account_id: str | None,
        provider_id: str,
        surface: str,
        outcome: str,
        reason: str,
        ip: str,
        ua_hash: str | None,
    ) -> None:
        if reason not in acc.AUTH_REASONS:
            reason = acc.REASON_PROVIDER_ERROR
        if outcome not in acc.AUTH_OUTCOMES:
            outcome = acc.OUTCOME_ERROR
        self._repos.auth_events.append(
            conn,
            now=now,
            account_id=account_id,
            provider_id=provider_id[:64],
            surface=surface,
            outcome=outcome,
            reason=reason,
            ip=(ip or "unknown")[:64],
            ua_hash=ua_hash[:32] if ua_hash else None,
        )

    def record_auth_event(
        self,
        *,
        account_key: str | None,
        provider_id: str,
        surface: str,
        outcome: str,
        reason: str,
        ip: str = "unknown",
        ua_hash: str | None = None,
    ) -> None:
        """Record a sign-in outcome that did not go through :meth:`resolve_identity`. Never raises."""
        try:
            account_id = None if account_key is None else _account_id(account_key)
            with self._db.best_effort_write(lock=False) as conn:
                self._record_auth_event(
                    conn,
                    now=self._now(),
                    account_id=account_id,
                    provider_id=provider_id,
                    surface=surface,
                    outcome=outcome,
                    reason=reason,
                    ip=ip,
                    ua_hash=ua_hash,
                )
        except (TokenStoreError, ValueError, OSError):
            return

    def list_auth_events(self, principal_key: str, limit: int = 20) -> list[AuthEvent]:
        """The newest sign-ins of an account first (default: the last 20)."""
        account_id = _account_id(_validate_principal_key(principal_key))
        if account_id is None:
            return []
        with self._db.read() as conn:
            rows = self._repos.auth_events.list_for_account(conn, account_id, max(1, min(limit, 200)))
        return [AuthEvent(*tuple(r)) for r in rows]

    def prune_auth_events(self, *, retention_seconds: int = AUTH_EVENT_RETENTION_SECONDS) -> int:
        """Delete sign-in events older than the retention (default 90 days); returns the count."""
        cutoff = self._now() - retention_seconds
        with self._db.write() as conn:
            return self._repos.auth_events.prune_before(conn, cutoff)

    def purge_stale_pending(self, *, retention_seconds: int = PENDING_RETENTION_SECONDS) -> int:
        """Delete accounts that waited for approval longer than the retention (default 30 days)."""
        cutoff = self._now() - retention_seconds
        now = self._now()
        with self._db.write() as conn:
            ids = self._repos.accounts.purge_pending(conn, cutoff)
            if ids:
                self._repos.identities.delete_for_accounts(conn, ids)
                self._audit(
                    conn, SYSTEM_ACTOR, AUDIT_PENDING_PURGED, detail={"count": len(ids)}, now=now
                )
            return len(ids)

    def list_audit(self, limit: int = 100, before_id: int | None = None) -> list[AuditEntry]:
        with self._db.read() as conn:
            rows = self._repos.audit.list(conn, max(1, min(limit, 500)), before_id)
        result: list[AuditEntry] = []
        for r in rows:
            try:
                detail = json.loads(r[6])
            except ValueError:
                detail = {}
            result.append(
                AuditEntry(
                    r[0], r[1], r[2], r[3], r[4], r[5], detail if isinstance(detail, dict) else {}
                )
            )
        return result

    # -- accounts: administrative changes ------------------------------------------

    def demote_owner(self, principal_key: str, *, evidence_issued_at: int) -> bool:
        """Lower the stored owner role on evidence from a request token; True if lowered.

        The evidence is the issue time of a verified access token that carries no
        owner role. It counts only if it is newer than the last sign-in that showed the
        role, so a token issued before a promotion cannot undo it. Only a role that
        rules granted is touched (a bootstrap or operator owner is not), the last
        active owner is never demoted, and this path can only ever lower the role:
        raising it needs a fresh sign-in.
        """
        key = _require_account_key(principal_key)
        account_id = acc.account_id_of(key)
        now = self._now()
        with self._db.write() as conn:
            row = self._repos.accounts.get(conn, account_id, for_update=True)
            if (
                row is None
                or row[2] != ROLE_OWNER
                or row[3] != acc.ROLE_SOURCE_RULES
                or row[1] != STATUS_ACTIVE
            ):
                return False
            if evidence_issued_at <= (row[4] or 0):
                return False
            others = self._repos.accounts.count_active_owners(conn, exclude=account_id)
            self._pause("after_owner_count")
            if others == 0:
                self._record_event(
                    conn, key, EVENT_OWNER_LOSS_REFUSED, None, "access_token_roles", int(row[16]), now
                )
                return False
            self._repos.accounts.set_role(
                conn, account_id, role=ROLE_USER, source=None, seen_at=row[4], now=now
            )
            self._record_event(
                conn, key, EVENT_OWNER_LOST, None, "access_token_roles", int(row[16]), now
            )
            self._audit(
                conn, SYSTEM_ACTOR, AUDIT_ROLE_CHANGED, target=key,
                detail={"role": ROLE_USER, "via": "access_token_roles"}, now=now,
            )
        return True

    def disable_principal(
        self,
        principal_key: str,
        *,
        actor: Actor,
        reason: str,
        allow_last_owner: bool = False,
    ) -> bool:
        """Administratively disable an account; True if this call changed it.

        The account cannot sign in to ``/account``, cannot enroll, and every MCP
        request is refused, until an owner (or the operator) enables it again.
        Every ``/account`` session issued before is invalidated (``session_epoch``
        is bumped), and so is every authorization code those sessions approved: a code is
        redeemable only in the epoch it was approved in, so it stays dead when the account
        is enabled again. The enrollment row, if any, is kept untouched.

        ``actor`` is the acting owner's account key or :data:`OPERATOR`. An owner
        actor is re-checked inside the transaction (still active and an owner) and
        cannot disable themselves. Disabling the last active owner is refused unless
        ``allow_last_owner``; the check and the write are one transaction, so two
        owners cannot disable each other concurrently. Already disabled, or no such
        account: returns False and changes nothing.
        """
        key = _require_account_key(principal_key)
        if reason not in DISABLE_REASONS:
            raise ValueError("unknown disable reason")
        account_id = acc.account_id_of(key)
        by = self._actor_name(actor)
        now = self._now()
        repos = self._repos
        with self._db.write() as conn:
            self._require_owner_actor(conn, actor)
            if not isinstance(actor, _Operator) and by == key:
                raise AccessActionRefused(AccessActionRefused.SELF)
            row = repos.accounts.get(conn, account_id, for_update=True)
            if row is None or row[1] == STATUS_DISABLED:
                return False
            if row[1] == STATUS_ACTIVE and row[2] == ROLE_OWNER and not allow_last_owner:
                others = repos.accounts.count_active_owners(conn, exclude=account_id)
                self._pause("after_owner_count")
                if others == 0:
                    raise AccessActionRefused(AccessActionRefused.LAST_OWNER)
            epoch = repos.accounts.disable(conn, account_id, reason=reason, by=by, now=now)
            self._record_event(conn, key, EVENT_DISABLED, by, reason, epoch, now)
            generation = repos.generations.bump(conn, key, GENERATION_DISABLED, now)
            # The apps this person connected stop working with the account (the table is
            # empty unless SELFHOST_AUTH_MODE=local has ever issued a grant).
            revoked = repos.grants.revoke_for_account(
                conn, account_id, reason="account_disabled", by=by, now=now
            )
            self._audit(
                conn,
                by,
                AUDIT_ACCOUNT_DISABLED,
                target=key,
                reason=reason,
                detail={"grants_revoked": revoked} if revoked else None,
                now=now,
            )
        self._publish_generation(key, generation)
        return True

    def enable_principal(self, principal_key: str, *, actor: Actor) -> bool:
        """Lift a disablement; True if this call changed it.

        Only an active owner (re-checked inside the transaction) or the operator.
        Bumps ``session_epoch`` again, so no session from before or during the
        disablement comes back. The user's enrollment, if kept, is used again as it
        is; a removed one has to be enrolled again.
        """
        key = _require_account_key(principal_key)
        account_id = acc.account_id_of(key)
        by = self._actor_name(actor)
        now = self._now()
        with self._db.write() as conn:
            self._require_owner_actor(conn, actor)
            row = self._repos.accounts.get(conn, account_id, for_update=True)
            if row is None or row[1] != STATUS_DISABLED:
                return False
            epoch = self._repos.accounts.enable(conn, account_id, now)
            self._record_event(conn, key, EVENT_ENABLED, by, None, epoch, now)
            generation = self._repos.generations.bump(conn, key, GENERATION_ENABLED, now)
            self._audit(conn, by, AUDIT_ACCOUNT_ENABLED, target=key, now=now)
        self._publish_generation(key, generation)
        return True

    def approve_account(self, principal_key: str, *, actor: Actor) -> bool:
        """Approve a pending account; True if this call changed it.

        Only an active owner (re-checked inside the transaction) or the operator.
        The status is checked and changed in one transaction, with the same writer
        serialisation as an enrollment, so an enrollment that read ``pending`` is
        refused and one that waits for the approval then succeeds.
        """
        key = _require_account_key(principal_key)
        account_id = acc.account_id_of(key)
        by = self._actor_name(actor)
        now = self._now()
        with self._db.write() as conn:
            self._require_owner_actor(conn, actor)
            row = self._repos.accounts.get(conn, account_id, for_update=True)
            self._pause("after_account_read")
            if row is None or row[1] != STATUS_PENDING:
                return False
            self._repos.accounts.activate(
                conn, account_id, admitted_via=acc.ADMITTED_APPROVAL, approved_by=by, now=now
            )
            self._record_event(conn, key, EVENT_APPROVED, by, None, int(row[16]), now)
            self._audit(conn, by, AUDIT_ACCOUNT_APPROVED, target=key, now=now)
        return True

    def deny_account(self, principal_key: str, *, actor: Actor) -> bool:
        """Deny a pending account (it becomes disabled, ``approval_denied``); True if changed.

        Bumps the session epoch and the credential generation like a disablement, so
        nothing the account held survives. An owner (or the operator) can enable it again.
        """
        key = _require_account_key(principal_key)
        account_id = acc.account_id_of(key)
        by = self._actor_name(actor)
        now = self._now()
        with self._db.write() as conn:
            self._require_owner_actor(conn, actor)
            row = self._repos.accounts.get(conn, account_id, for_update=True)
            self._pause("after_account_read")
            if row is None or row[1] != STATUS_PENDING:
                return False
            epoch = self._repos.accounts.disable(
                conn, account_id, reason=DISABLE_REASON_DENIED, by=by, now=now
            )
            self._record_event(conn, key, EVENT_DENIED, by, DISABLE_REASON_DENIED, epoch, now)
            generation = self._repos.generations.bump(conn, key, GENERATION_DISABLED, now)
            self._audit(
                conn, by, AUDIT_ACCOUNT_DENIED, target=key, reason=DISABLE_REASON_DENIED, now=now
            )
        self._publish_generation(key, generation)
        return True

    def promote_owner(self, principal_key: str, *, actor: Actor = OPERATOR) -> bool:
        """Make an active account an owner (``role_source`` operator); operator only.

        The emergency entrance of the CLI: owners otherwise come from ``OWNER_RULES``
        or the bootstrap owner. Returns False when the account is not active or already
        an owner. A role the operator granted is not taken back by the rules.
        """
        if not isinstance(actor, _Operator):
            raise AccessActionRefused(AccessActionRefused.NOT_OWNER)
        key = _require_account_key(principal_key)
        account_id = acc.account_id_of(key)
        now = self._now()
        with self._db.write() as conn:
            row = self._repos.accounts.get(conn, account_id, for_update=True)
            if row is None or row[1] != STATUS_ACTIVE or row[2] == ROLE_OWNER:
                return False
            self._repos.accounts.set_role(
                conn, account_id, role=ROLE_OWNER, source=acc.ROLE_SOURCE_OPERATOR,
                seen_at=now, now=now,
            )
            self._record_event(
                conn, key, EVENT_OWNER_GAINED, OPERATOR_ACTOR, "operator", int(row[16]), now
            )
            self._audit(
                conn, OPERATOR_ACTOR, AUDIT_ROLE_CHANGED, target=key,
                detail={"role": ROLE_OWNER, "source": acc.ROLE_SOURCE_OPERATOR}, now=now,
            )
        return True

    def create_operator_account(
        self,
        *,
        provider_id: str,
        issuer: str,
        subject: str,
        display_name: str = "",
        username: str = "",
        status: str = STATUS_DISABLED,
        role: str = ROLE_USER,
        reason: str | None = None,
        account_id: str | None = None,
    ) -> str:
        """Create an account on the operator's say-so and return its key.

        The CLI pre-provisions a *disabled* account to block someone before their first
        sign-in; tests and break-glass use create active ones (``admitted_via='operator'``,
        so a later change of the rules does not undo it). Only an active account is a
        personal admission: a disabled or pending one is stored as ``rules`` so that
        enabling it later only lifts the block and the rules keep deciding. An identity that already has an
        account returns that account's key and changes nothing. ``account_id`` (a lower-case
        UUID) chooses the id instead of drawing one; the tests use it to get stable keys.
        """
        if status not in (STATUS_DISABLED, STATUS_ACTIVE, STATUS_PENDING):
            raise ValueError("unknown account status")
        if role not in (ROLE_USER, ROLE_OWNER):
            raise ValueError("unknown role")
        if status == STATUS_DISABLED and reason not in DISABLE_REASONS:
            raise ValueError("a disabled account needs a disable reason")
        now = self._now()
        repos = self._repos
        with self._db.write() as conn:
            existing = repos.identities.lookup(conn, provider_id, issuer, subject)
            if existing is not None:
                return acc.account_key_of(existing)
            account_id = account_id or str(uuid.uuid4())
            key = acc.account_key_of(account_id)
            if not acc.valid_account_key(key):
                raise ValueError("account_id must be a lower-case UUID")
            repos.accounts.insert(
                conn,
                account_id=account_id,
                status=status,
                role=role,
                role_source=acc.ROLE_SOURCE_OPERATOR if role == ROLE_OWNER else None,
                admitted_via=(
                    acc.ADMITTED_OPERATOR if status == STATUS_ACTIVE else acc.ADMITTED_RULES
                ),
                display_name=display_name[:_MAX_DISPLAY_NAME],
                now=now,
                approved_by=OPERATOR_ACTOR if status == STATUS_ACTIVE else None,
                disabled_reason=reason if status == STATUS_DISABLED else None,
                disabled_by=OPERATOR_ACTOR if status == STATUS_DISABLED else None,
            )
            repos.identities.insert(
                conn,
                account_id=account_id,
                provider_id=provider_id,
                issuer=issuer,
                subject=subject,
                username=username[:_MAX_USERNAME],
                email=None,
                email_verified=False,
                now=now,
            )
            epoch = 1 if status == STATUS_DISABLED else 0
            self._record_event(conn, key, EVENT_ACCOUNT_CREATED, OPERATOR_ACTOR, "operator", 0, now)
            if status == STATUS_DISABLED:
                self._record_event(conn, key, EVENT_DISABLED, OPERATOR_ACTOR, reason, epoch, now)
                generation = repos.generations.bump(conn, key, GENERATION_DISABLED, now)
            else:
                generation = 0
            self._audit(
                conn, OPERATOR_ACTOR, AUDIT_ACCOUNT_CREATED_BY_OPERATOR, target=key,
                detail={"status": status, "role": role, "provider": provider_id}, now=now,
            )
        if generation:
            self._publish_generation(key, generation)
        return key

    def list_status_events(
        self,
        principal_key: str | None = None,
        *,
        limit: int = 50,
    ) -> list[StatusEvent]:
        """The newest status transitions first, for one principal or for all."""
        key = None if principal_key is None else _validate_principal_key(principal_key)
        with self._db.read() as conn:
            rows = self._repos.events.list_events(conn, key, max(1, min(int(limit), 1000)))
        return [StatusEvent(*tuple(r)) for r in rows]

    # -- per-user write-tool preferences -------------------------------------

    def get_tool_prefs(self, principal_key: str) -> ToolPrefs | None:
        """The stored write-tool preferences of a principal, or None if never saved."""
        key = _validate_principal_key(principal_key)
        with self._db.read() as conn:
            row = self._repos.prefs.get(conn, key)
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
        """Replace an account's switched-on write tools with exactly these names.

        Only explicit names are stored, and only for an **active** account (checked in
        the same transaction). A name that was already on keeps its ``enabled_at``; a new
        one gets the current time. Raises ValueError for a malformed name or an oversized
        list.
        """
        key = _require_account_key(principal_key)
        names = _validate_tool_names(enabled_write_tools)
        if not isinstance(via, str) or not 1 <= len(via) <= _MAX_PREF_VIA or not via.isascii():
            raise ValueError("via must be a short ASCII label")
        account_id = acc.account_id_of(key)
        now = self._now()
        with self._db.write() as conn:
            account = self._repos.accounts.get(conn, account_id, for_update=True)
            if account is None:
                raise PrincipalMissingError("there is no account for this principal")
            if account[1] == STATUS_DISABLED:
                raise PrincipalDisabledError("this principal is disabled")
            if account[1] != STATUS_ACTIVE:
                raise PrincipalPendingError("this account is waiting for approval")
            row = self._repos.prefs.get(conn, key)
            previous = (
                _decode_tool_prefs(key, row[0], row[1], row[2], row[3])
                if row is not None
                else None
            )
            before = previous.enabled_write_tools if previous is not None else frozenset()
            stamps = {name: (previous.enabled_at.get(name, now) if previous else now) for name in names}
            self._repos.prefs.upsert(
                conn,
                key,
                names_json=json.dumps(sorted(names)),
                stamps_json=json.dumps(stamps, sort_keys=True),
                now=now,
                via=via,
            )
            if names != before:
                self._audit(
                    conn,
                    key,
                    AUDIT_WRITE_TOOLS_CHANGED,
                    target=key,
                    detail={"enabled": sorted(names - before), "disabled": sorted(before - names)},
                    now=now,
                )
        return ToolPrefs(key, names, stamps, now, via)

    def rotate(self) -> int:
        """Re-encrypt every row not under the active key; returns rows changed."""
        active = self._keyring.active_key_id
        changed = 0
        with self._db.write() as conn:
            rows = self._repos.tokens.rows_not_under_key(conn, active)
            for pkey, kid, nonce, ciphertext, host in rows:
                # Each row keeps its own principal and host, so its AAD layout
                # (v2 or v3) is preserved.
                plaintext = self._keyring.decrypt(
                    kid, bytes(nonce), bytes(ciphertext), _aad_for_principal(pkey, host, kid)
                )
                new_kid, new_nonce, new_ct = self._keyring.encrypt(
                    plaintext, _aad_for_principal(pkey, host, active)
                )
                self._repos.tokens.reseal(
                    conn,
                    principal_key=pkey,
                    key_id=new_kid,
                    nonce=new_nonce,
                    ciphertext=new_ct,
                )
                changed += 1
        return changed
