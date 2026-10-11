"""Accounts and sealed Canvas credentials for self-hosted deployments.

Account and credential ownership use canonical bare UUIDs. The current schema
has enforced foreign keys and immutable named repository results. Credential
seals bind account, explicit Canvas host, credential kind and key id. Every
credential put requires the current custody acknowledgement.

Public methods own the transaction boundary. Governance serializes decisions
about owners and sets; row-conditional operations use committed account versions.
Schema upgrades and transfers are isolated in ``db.migrations``.
"""

from __future__ import annotations

import base64
import binascii
import os
import pathlib
import re
import time
from collections.abc import Callable, Collection, Iterable, Iterator, Sequence
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
    AccessPolicy,
    AccountFacts,
    Decision,
    DecisionFacts,
    Denied,
    ExternalClaims,
    Verdict,
)
from .custody import CustodyAcknowledgement
from .db.errors import StoreUnavailable, TokenStoreError  # noqa: F401 - re-exported
from .pagination import DEFAULT_LIMIT, Page, decode_cursor, make_page, page_limit

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

    from .db.engine import Database
    from .db.repos import Repositories
    from .db.rows import AccountRow, CredentialRow, IdentityRow
    from .db.snapshots import McpSnapshot, SessionSnapshot
    from .db.url import DatabaseTarget


#: ``meta`` key holding the server's listed sign-in providers (see ``record_login_providers``).
_PROVIDER_ID_RE = re.compile(r"[a-z0-9][a-z0-9:_.-]{0,63}")

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
EVENT_IDENTITY_UNLINKED = "identity_unlinked"

# The actions of ``audit_log``: a closed set.
AUDIT_ACCOUNT_CREATED = "account_created"
AUDIT_ACCOUNT_CREATED_BY_OPERATOR = "account_created_by_operator"
AUDIT_ACCOUNT_ACTIVATED = "account_activated"
AUDIT_ACCOUNT_APPROVED = "account_approved"
AUDIT_ACCOUNT_DENIED = "account_denied"
AUDIT_ACCOUNT_DISABLED = "account_disabled"
AUDIT_ACCOUNT_ENABLED = "account_enabled"
AUDIT_ACCOUNT_DELETED = "account_deleted"
AUDIT_ROLE_CHANGED = "role_changed"
AUDIT_ROLE_LOSS_REFUSED = "owner_loss_refused_last_owner"
AUDIT_CUSTODY_ACKNOWLEDGED = "custody_notice_acknowledged"
AUDIT_TOKEN_ENROLLED = "token_enrolled"
AUDIT_TOKEN_REPLACED = "token_replaced"
AUDIT_TOKEN_DELETED = "token_deleted"
AUDIT_TOKEN_MARKED_INVALID = "token_marked_invalid"
AUDIT_WRITE_TOOLS_CHANGED = "write_tools_changed"
AUDIT_SCHEMA_MIGRATED = "schema_migrated"
AUDIT_PENDING_PURGED = "pending_purged"
AUDIT_IDENTITY_LINKED = "identity_linked"
AUDIT_IDENTITY_UNLINKED = "identity_unlinked"
AUDIT_IDENTITY_LINK_REFUSED = "identity_link_refused"
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
        AUDIT_ACCOUNT_DELETED,
        AUDIT_ROLE_CHANGED,
        AUDIT_ROLE_LOSS_REFUSED,
        AUDIT_CUSTODY_ACKNOWLEDGED,
        AUDIT_TOKEN_ENROLLED,
        AUDIT_TOKEN_REPLACED,
        AUDIT_TOKEN_DELETED,
        AUDIT_TOKEN_MARKED_INVALID,
        AUDIT_WRITE_TOOLS_CHANGED,
        AUDIT_SCHEMA_MIGRATED,
        AUDIT_PENDING_PURGED,
        AUDIT_IDENTITY_LINKED,
        AUDIT_IDENTITY_UNLINKED,
        AUDIT_IDENTITY_LINK_REFUSED,
    }
)

# Why a link or an unlink did not happen (``LinkResult.code`` / ``UnlinkResult.code``).
LINK_OK = "linked"
LINK_ALREADY = "already_linked"
LINK_IN_USE = "identity_in_use"
LINK_PROVIDER_TAKEN = "provider_already_linked"
LINK_DENIED = "access_denied"
LINK_SESSION_ENDED = "link_session_ended"
UNLINK_OK = "unlinked"
UNLINK_NOT_FOUND = "not_found"
UNLINK_LAST = "last_identity"
UNLINK_LAST_OWNER = "last_owner"
UNLINK_SESSION_ENDED = "link_session_ended"

_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_DERIVE_SALT = b"canvas-mcp/keyring-derive/v1"
_MAX_HOST = 253
_MAX_PRINCIPAL_KEY = 256
_KEY_BYTES = 32
_NONCE_BYTES = 12

_MAX_CANVAS_NAME = 200
_MAX_DISPLAY_NAME = 200
_MAX_USERNAME = 254
_MAX_EMAIL = 254

_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_PREF_TOOLS = 256
_MAX_PREF_VIA = 32
_MAX_EXPIRES_HINT = 4_102_444_800  # 2100-01-01 UTC: a sanity bound, not a policy


def _listed(provider_ids: Iterable[str] | None) -> list[str] | None:
    """The listed provider ids as a sorted list (None stays None: every provider is listed)."""
    return None if provider_ids is None else sorted(set(provider_ids))


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
    credential_id: str = ""
    kind: str = "pat"
    is_primary: bool = True
    custody_notice_version: int = 0
    custody_ack_at: int = 0


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
    credential_id: str = ""
    kind: str = "pat"
    is_primary: bool = True
    custody_notice_version: int = 0
    custody_ack_at: int = 0


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
    version: int = 0


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
    #: The UUID an unlink names (empty when the reader did not select it).
    id: str = ""

    @property
    def tenant_id(self) -> str:
        """The tenant in a validated Entra issuer; other providers have no tenant."""
        if self.provider_id != acc.PROVIDER_ENTRA:
            return ""
        prefix, suffix = acc.ENTRA_ISSUER_PREFIX, "/v2.0"
        if self.issuer.startswith(prefix) and self.issuer.endswith(suffix):
            return self.issuer[len(prefix) : -len(suffix)]
        return ""


@dataclass(frozen=True)
class LinkedIdentity:
    """One external identity of an account, with the id an unlink names."""

    id: str
    provider_id: str
    issuer: str
    subject: str
    username: str
    email: str | None
    email_verified: bool
    linked_at: int
    last_login_at: int | None


@dataclass(frozen=True)
class LinkResult:
    """The outcome of attaching an identity to an account (see :meth:`TokenStore.link_identity`)."""

    code: str
    provider_id: str = ""

    @property
    def ok(self) -> bool:
        return self.code in (LINK_OK, LINK_ALREADY)


@dataclass(frozen=True)
class UnlinkResult:
    """The outcome of removing an identity (see :meth:`TokenStore.unlink_identity`)."""

    code: str
    provider_id: str = ""
    issuer: str = ""
    subject: str = ""
    session_epoch: int = 0

    @property
    def ok(self) -> bool:
        return self.code == UNLINK_OK


@dataclass(frozen=True)
class AccountInfo:
    """An account with its identities, for the admin page and the operator CLI."""

    status: PrincipalStatus
    identities: tuple[IdentityInfo, ...]
    enrollment: EnrollmentInfo | None = None

    @property
    def principal_key(self) -> str:
        return self.status.principal_key

    @property
    def username(self) -> str:
        return self.identities[0].username if self.identities else ""


@dataclass(frozen=True)
class AuthEvent:
    id: int
    at: int
    provider_id: str
    surface: str
    outcome: str
    reason: str
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


def _status(row: AccountRow) -> PrincipalStatus:
    return PrincipalStatus(
        principal_key=row.id,
        status=row.status,
        role=row.role,
        role_source=row.role_source,
        role_seen_at=row.role_seen_at,
        admitted_via=row.admitted_via,
        display_name=row.display_name,
        created_at=row.created_at,
        approved_at=row.approved_at,
        approved_by=row.approved_by,
        disabled_reason=row.disabled_reason,
        disabled_at=row.disabled_at,
        disabled_by=row.disabled_by,
        last_login_at=row.last_login_at,
        session_epoch=row.session_epoch,
        updated_at=row.updated_at,
        stored=True,
        credential_generation=row.credential_generation,
    )


def _linked(row: IdentityRow) -> LinkedIdentity:
    return LinkedIdentity(
        id=row.id,
        provider_id=row.provider_id,
        issuer=row.issuer,
        subject=row.subject,
        username=row.username or "",
        email=row.email,
        email_verified=row.email_verified,
        linked_at=row.linked_at,
        last_login_at=row.last_login_at,
    )


def _identity_info(row: IdentityRow) -> IdentityInfo:
    return IdentityInfo(
        provider_id=row.provider_id,
        issuer=row.issuer,
        subject=row.subject,
        username=row.username or "",
        email=row.email,
        email_verified=row.email_verified,
        linked_at=row.linked_at,
        last_login_at=row.last_login_at,
        id=row.id,
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
                raise KeyringError(f"CANVAS_TOKEN_KEYS key {kid} is not valid base64")
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


def _validate_principal_key(principal_key: str) -> str:
    return acc.account_id_of(principal_key)


def _require_account_key(principal_key: str) -> str:
    return acc.account_id_of(principal_key)


def valid_principal_key(value: object) -> str | None:
    """``value`` if it is a well-formed account key, else None (never raises)."""
    if not isinstance(value, str):
        return None
    try:
        return _require_account_key(value)
    except ValueError:
        return None


def _account_id(principal_key: str) -> str | None:
    return principal_key if acc.valid_account_key(principal_key) else None


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


def credential_aad(account_id: str, canvas_host: str, kind: str, key_id: str) -> bytes:
    """The reviewed v1 seal binds ownership, explicit school, credential kind and key."""
    _require_account_key(account_id)
    if (
        not canvas_host
        or kind not in ("pat", "oauth")
        or not _KEY_ID_RE.fullmatch(key_id)
    ):
        raise ValueError("invalid credential seal fields")
    fields = ("canvas-mcp/canvas-credential/v1", account_id, canvas_host, kind, key_id)
    if any("\x1f" in value for value in fields):
        raise ValueError("invalid credential seal delimiter")
    return "\x1f".join(fields).encode("utf-8")


def _enrollment(row: CredentialRow) -> EnrollmentInfo:
    return EnrollmentInfo(
        canvas_user_id=row.canvas_user_id,
        canvas_user_name=row.canvas_user_name,
        key_id=row.key_id,
        created_at=row.created_at,
        updated_at=row.updated_at,
        last_used_at=row.last_used_at,
        canvas_host=row.canvas_host,
        principal_key=row.account_id,
        status=row.status,
        invalid_reason=row.invalid_reason,
        invalid_since=row.invalid_since,
        last_verified_at=row.last_verified_at,
        expires_hint_at=row.expires_hint_at,
        credential_generation=row.generation,
        credential_id=row.id,
        kind=row.kind,
        is_primary=row.is_primary,
        custody_notice_version=row.custody_notice_version,
        custody_ack_at=row.custody_ack_at,
    )


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

        self._db: Database = (
            db if isinstance(db, _Database) else _Database.sqlite(pathlib.Path(db))
        )
        #: The SQLite file, or None on PostgreSQL.
        self._path: pathlib.Path | None = self._db.sqlite_path
        self._repos: Repositories = Repositories(self._db.kind)
        self._keyring = keyring
        self._clock = clock
        # Test seam for deterministic race tests: called with a name at fixed points
        # inside a transaction. None in production.
        self._pause_hook: Callable[[str], None] | None = None
        # Test seam: the id of a newly created account (a random UUID in production).
        from .db.types import new_id

        self._new_account_id: Callable[[ExternalClaims], str] = lambda _ext: new_id()

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
    ) -> None:
        """Open a compatible v1 database, upgrading through the isolated runner."""
        from .db.migrations import runner as migrate

        self._db.prepare_storage()
        migrate.ensure_ready(
            self._db,
            auto=auto_migrate,
        )
        self._db.tighten_storage()

        self._verify_keyring()

    def _verify_keyring(self) -> None:
        from .db.sealed import verify

        with self._db.read() as conn:
            verify(conn, self._keyring)

    # -- reads -------------------------------------------------------------

    def get(self, principal_key: str) -> StoredToken | None:
        key = _require_account_key(principal_key)
        with self._db.read() as conn:
            row = self._repos.credentials.primary(conn, key)
        if row is None:
            return None
        try:
            plaintext = self._keyring.decrypt(
                row.key_id,
                row.nonce,
                row.ciphertext,
                credential_aad(key, row.canvas_host, row.kind, row.key_id),
            )
            try:
                api_token = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                raise TokenDecryptionError(
                    "stored token could not be decrypted"
                ) from None
        except TokenDecryptionError as exc:
            exc.updated_at = row.updated_at
            exc.credential_generation = row.generation
            raise
        return StoredToken(
            api_token=api_token,
            canvas_user_id=row.canvas_user_id,
            canvas_user_name=row.canvas_user_name,
            key_id=row.key_id,
            created_at=row.created_at,
            updated_at=row.updated_at,
            last_used_at=row.last_used_at,
            canvas_host=row.canvas_host,
            principal_key=key,
            status=row.status,
            invalid_reason=row.invalid_reason,
            invalid_since=row.invalid_since,
            last_verified_at=row.last_verified_at,
            expires_hint_at=row.expires_hint_at,
            credential_generation=row.generation,
            credential_id=row.id,
            kind=row.kind,
            custody_notice_version=row.custody_notice_version,
            custody_ack_at=row.custody_ack_at,
        )

    def decrypt_snapshot(self, account_id: str, snapshot: McpSnapshot) -> str:
        """Decrypt the already authorized primary credential without another read."""
        if (
            snapshot.key_id is None
            or snapshot.nonce is None
            or snapshot.ciphertext is None
            or snapshot.canvas_host is None
            or snapshot.kind is None
        ):
            raise TokenDecryptionError("stored token could not be decrypted")
        try:
            return self._keyring.decrypt(
                snapshot.key_id,
                snapshot.nonce,
                snapshot.ciphertext,
                credential_aad(
                    account_id, snapshot.canvas_host, snapshot.kind, snapshot.key_id
                ),
            ).decode("utf-8")
        except UnicodeDecodeError:
            raise TokenDecryptionError("stored token could not be decrypted") from None

    def info(self, principal_key: str) -> EnrollmentInfo | None:
        key = _validate_principal_key(principal_key)
        with self._db.read() as conn:
            row = self._repos.credentials.primary(conn, key)
        return None if row is None else _enrollment(row)

    def enrollments_page(
        self,
        *,
        cursor: str | None = None,
        limit: int = DEFAULT_LIMIT,
        invalid_only: bool = False,
    ) -> Page[EnrollmentInfo]:
        from .db import lists

        limit = page_limit(limit)
        scope = "enrollments/" + str(invalid_only)
        before = decode_cursor(cursor, scope)
        assert before is None or isinstance(before, str)
        with self._db.read() as conn:
            rows = lists.credentials(
                conn, before=before, limit=limit + 1, invalid_only=invalid_only
            )
        return make_page(
            [_enrollment(row) for row in rows],
            limit=limit,
            scope=scope,
            key=lambda row: row.credential_id,
        )

    def iter_enrollments(self) -> Iterator[EnrollmentInfo]:
        cursor = None
        while True:
            page = self.enrollments_page(cursor=cursor, limit=200)
            yield from page.items
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    def enrollment_counts(self) -> dict[str, int]:
        from .db import lists

        with self._db.read() as conn:
            return lists.enrollment_counts(conn)

    def count(self) -> int:
        with self._db.read() as conn:
            return self._repos.credentials.count(conn)

    # -- writes ------------------------------------------------------------

    def put(
        self,
        *,
        principal_key: str,
        api_token: str,
        canvas_user_id: str,
        canvas_user_name: str,
        canvas_host: str,
        custody: CustodyAcknowledgement,
        expires_hint_at: int | None | Literal[_Unset.UNSET] = KEEP_EXPIRY_HINT,
    ) -> EnrollmentInfo:
        """Save one acknowledged PAT under an active account in a governance transaction."""
        key = _require_account_key(principal_key)
        host = _validate_host_value(canvas_host)
        if host is None:
            raise ValueError("a credential requires an explicit Canvas host")
        now = self._now()
        if not isinstance(custody, CustodyAcknowledgement):
            raise ValueError("a current custody acknowledgement is required")
        custody.validate(now=now)
        if not isinstance(api_token, str) or not api_token:
            raise ValueError("api_token must be a non-empty string")
        hint = None if isinstance(expires_hint_at, _Unset) else expires_hint_at
        if hint is not None and (
            type(hint) is not int or not 0 < hint <= _MAX_EXPIRES_HINT
        ):
            raise ValueError("expires_hint_at must be a positive epoch time")
        kid, nonce, ciphertext = self._keyring.encrypt(
            api_token.encode("utf-8"),
            credential_aad(key, host, "pat", self._keyring.active_key_id),
        )
        from .db.types import new_id

        with self._db.write() as conn:
            account = self._repos.accounts.get(conn, key, for_update=True)
            self._pause("after_gate_read")
            if account is None:
                raise PrincipalMissingError("there is no account for this principal")
            if account.status == STATUS_DISABLED:
                raise PrincipalDisabledError("this principal is disabled")
            if account.status != STATUS_ACTIVE:
                raise PrincipalPendingError("this account is waiting for approval")
            previous = self._repos.credentials.primary(conn, key)
            same_host = self._repos.credentials.at_host(conn, key, host)
            identifier = same_host.id if same_host is not None else new_id()
            if isinstance(expires_hint_at, _Unset) and same_host is not None:
                hint = same_host.expires_hint_at
            self._repos.credentials.ensure_school(conn, host, account_id=key, now=now)
            self._pause("after_school_upsert")
            generation = self._repos.generations.bump(
                conn, key, GENERATION_ENROLLED, now, writing=identifier
            )
            self._repos.credentials.put(
                conn,
                identifier=identifier,
                account_id=key,
                canvas_host=host,
                generation=generation,
                key_id=kid,
                nonce=nonce,
                ciphertext=ciphertext,
                canvas_user_id=str(canvas_user_id),
                canvas_user_name=str(canvas_user_name)[:_MAX_CANVAS_NAME],
                now=now,
                expires_hint_at=hint,
                custody_notice_version=custody.notice_version,
                custody_ack_at=custody.acked_at,
            )
            self._audit(
                conn,
                key,
                AUDIT_TOKEN_REPLACED if previous is not None else AUDIT_TOKEN_ENROLLED,
                target=key,
                detail={
                    "canvas_host": host,
                    "custody_notice_version": custody.notice_version,
                },
                now=now,
            )
            self._audit(
                conn,
                key,
                AUDIT_CUSTODY_ACKNOWLEDGED,
                target=identifier,
                target_kind="credential",
                subject_account_id=key,
                detail={
                    "old": same_host.custody_notice_version if same_host else None,
                    "new": custody.notice_version,
                },
                now=custody.acked_at,
            )
            row = self._repos.credentials.primary(conn, key)
        assert row is not None
        self._publish_generation(key, generation)
        return _enrollment(row)

    def acknowledge_custody(
        self, principal_key: str, custody: CustodyAcknowledgement
    ) -> EnrollmentInfo | None:
        """Re-acknowledge without decrypting, replacing or changing the generation."""
        key = _require_account_key(principal_key)
        now = self._now()
        custody.validate(now=now)
        with self._db.write() as conn:
            account = self._repos.accounts.get(conn, key, for_update=True)
            if account is None:
                raise PrincipalMissingError("there is no account for this principal")
            if account.status == STATUS_DISABLED:
                raise PrincipalDisabledError("this principal is disabled")
            if account.status != STATUS_ACTIVE:
                raise PrincipalPendingError("this account is waiting for approval")
            row = self._repos.credentials.primary(conn, key)
            if row is None:
                return None
            if row.custody_notice_version == custody.notice_version:
                return _enrollment(row)
            self._repos.credentials.acknowledge(
                conn, key, version=custody.notice_version, now=custody.acked_at
            )
            self._audit(
                conn,
                key,
                AUDIT_CUSTODY_ACKNOWLEDGED,
                target=row.id,
                target_kind="credential",
                subject_account_id=key,
                detail={
                    "old": row.custody_notice_version,
                    "new": custody.notice_version,
                },
                now=now,
            )
            updated = self._repos.credentials.primary(conn, key)
            assert updated is not None
            return _enrollment(updated)

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
            if self._repos.accounts.get(conn, key, for_update=True) is None:
                return False
            removed = self._repos.credentials.delete(conn, key)
            if removed:
                now = self._now()
                # The generation outlives the row: a token enrolled afterwards
                # is a later one, never a reuse of the deleted one's number.
                generation = self._repos.generations.bump(
                    conn, key, GENERATION_REMOVED, now
                )
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
            with self._db.best_effort_write() as conn:
                self._repos.credentials.touch(
                    conn, key, now, now - max(0, min_interval_seconds)
                )
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
        with self._db.write() if actor is not None else self._db.row_write() as conn:
            if actor is not None:
                self._require_owner_actor(conn, actor)
            if self._repos.accounts.get(conn, key, for_update=True) is None:
                return False
            changed = self._repos.credentials.mark_invalid(
                conn,
                key,
                reason=reason,
                now=now,
                expected_updated_at=expected_updated_at,
                expected_generation=expected_generation,
            )
            self._pause("after_conditional_update")
            if changed:
                generation = self._repos.generations.bump(
                    conn, key, GENERATION_INVALIDATED, now
                )
                if by is not None:
                    self._audit(
                        conn,
                        by,
                        AUDIT_TOKEN_MARKED_INVALID,
                        target=key,
                        reason=reason,
                        now=now,
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
        with self._db.row_write() as conn:
            if self._repos.accounts.get(conn, key, for_update=True) is None:
                return False
            changed = self._repos.credentials.restore_active(
                conn,
                key,
                now=now,
                expected_updated_at=expected_updated_at,
                expected_generation=expected_generation,
            )
            self._pause("after_conditional_update")
            if changed:
                generation = self._repos.generations.bump(
                    conn, key, GENERATION_RESTORED, now
                )
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
            with self._db.best_effort_write() as conn:
                self._repos.credentials.mark_verified(
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
        target_kind: str = "account",
        subject_account_id: str | None = None,
    ) -> None:
        assert action in AUDIT_ACTIONS, action
        self._repos.audit.append(
            conn,
            now=self._now() if now is None else now,
            actor=actor,
            action=action,
            target=target,
            reason=reason,
            detail=detail or {},
            target_kind=target_kind,
            subject_account_id=subject_account_id,
        )

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
        row = self._repos.accounts.get(
            conn, acc.account_id_of(self._actor_name(actor)), for_update=True
        )
        if row is None or row.status != STATUS_ACTIVE or row.role != ROLE_OWNER:
            raise AccessActionRefused(AccessActionRefused.NOT_OWNER)

    # -- accounts: reading -------------------------------------------------------

    def get_principal_status(self, principal_key: str) -> PrincipalStatus:
        key = _require_account_key(principal_key)
        with self._db.read() as conn:
            row = self._repos.accounts.get(conn, key)
        return (
            PrincipalStatus(key, status=STATUS_MISSING) if row is None else _status(row)
        )

    def _account_infos(
        self, conn: Connection, rows: Sequence[AccountRow]
    ) -> list[AccountInfo]:
        from .db import lists

        ids = [row.id for row in rows]
        identities: dict[str, list[IdentityInfo]] = {}
        for identity in lists.identities(conn, ids):
            identities.setdefault(identity.account_id, []).append(
                _identity_info(identity)
            )
        primary = {
            row.account_id: _enrollment(row)
            for row in lists.primary_credentials(conn, ids)
        }
        return [
            AccountInfo(
                _status(row), tuple(identities.get(row.id, ())), primary.get(row.id)
            )
            for row in rows
        ]

    def accounts_page(
        self,
        *,
        cursor: str | None = None,
        limit: int = DEFAULT_LIMIT,
        status: str | None = None,
    ) -> Page[AccountInfo]:
        from .db import lists

        limit = page_limit(limit)
        if status is not None and status not in acc.ACCOUNT_STATUSES:
            raise ValueError("invalid account status")
        scope = "accounts/" + str(status)
        before = decode_cursor(cursor, scope)
        assert before is None or isinstance(before, str)
        with self._db.read() as conn:
            rows = lists.accounts(conn, before=before, limit=limit + 1, status=status)
            infos = self._account_infos(conn, rows)
        return make_page(
            infos, limit=limit, scope=scope, key=lambda row: row.principal_key
        )

    def enrollment_accounts(
        self, enrollments: Sequence[EnrollmentInfo]
    ) -> dict[str, AccountInfo]:
        return self.account_infos([row.principal_key for row in enrollments])

    def account_infos(self, ids: Sequence[str]) -> dict[str, AccountInfo]:
        from .db import lists

        if len(ids) > 200:
            raise ValueError("account lookup is bounded to a page")
        ids = [_require_account_key(key) for key in ids]
        with self._db.read() as conn:
            rows = lists.accounts_by_ids(conn, ids)
            return {row.principal_key: row for row in self._account_infos(conn, rows)}

    def iter_accounts(self) -> Iterator[AccountInfo]:
        cursor = None
        while True:
            page = self.accounts_page(cursor=cursor, limit=200)
            yield from page.items
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    def account_counts(self) -> dict[str, int]:
        from .db import lists

        with self._db.read() as conn:
            return lists.account_counts(conn)

    def credential_inventory(self) -> tuple[int, int, tuple[str, ...]]:
        from .db import lists

        with self._db.read() as conn:
            return lists.credential_inventory(conn)

    def account_names(self, account_ids: Collection[str]) -> dict[str, str]:
        from .db import lists

        ids = list(dict.fromkeys(account_ids))
        if len(ids) > 400:
            raise ValueError("account name lookup is bounded to a page")
        with self._db.read() as conn:
            return lists.account_names(conn, ids)

    def account_identities(self, principal_key: str) -> list[IdentityInfo]:
        key = _require_account_key(principal_key)
        with self._db.read() as conn:
            rows = self._repos.identities.for_account(conn, key)
        return [_identity_info(row) for row in rows]

    def list_identities(self, principal_key: str) -> list[LinkedIdentity]:
        """The identities of an account with their ids, oldest first (unknown account: none)."""
        account_id = _account_id(_validate_principal_key(principal_key))
        if account_id is None:
            return []
        with self._db.read() as conn:
            rows = self._repos.identities.for_account(conn, account_id)
        return [_linked(r) for r in rows]

    def identity_account(self, identity_id: str) -> str | None:
        """The account key an identity row belongs to (None for an unknown id)."""
        with self._db.read() as conn:
            account_id = self._repos.identities.account_of(conn, identity_id)
        return None if account_id is None else acc.account_key_of(account_id)

    def count_active_owners(self) -> int:
        with self._db.read() as conn:
            return self._repos.accounts.count_active_owners(conn)

    def count_usable_owners(self, provider_ids: Iterable[str] | None) -> int:
        """Active owners that can still get an owner session under the listed providers.

        ``provider_ids`` are the providers of ``SELFHOST_LOGIN_PROVIDERS`` (None: all of them).
        An owner whose role the Entra owner rules granted counts only while Entra is listed and it
        holds an Entra identity; every other owner needs one identity at a listed provider (see
        :func:`accounts.owner_is_usable`).
        """
        with self._db.read() as conn:
            return self._repos.accounts.count_usable_owners(conn, _listed(provider_ids))

    def read_session_snapshot(self, account_id: str) -> SessionSnapshot | None:
        from .db.snapshots import session_snapshot

        with self._db.read() as conn:
            return session_snapshot(conn, account_id)

    def record_login_providers(self, provider_ids: Iterable[str]) -> None:
        """Reconcile env providers under governance, preserving edited public names."""
        with self._db.write() as conn:
            self._repos.providers.reconcile(
                conn, list(dict.fromkeys(provider_ids)), now=self._now()
            )

    def recorded_login_providers(self) -> frozenset[str]:
        with self._db.read() as conn:
            return self._repos.providers.configured(conn)

    def lookup_identity(
        self, provider_id: str, issuer: str, subject: str
    ) -> str | None:
        """The account key of an external identity, or None if it is not known."""
        with self._db.read() as conn:
            account_id = self._repos.identities.lookup(
                conn, provider_id, issuer, subject
            )
        return None if account_id is None else acc.account_key_of(account_id)

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
        listed_providers: Collection[str] | None = None,
    ) -> Resolution:
        """Decide and apply, in one transaction, what an external identity may do.

        Looks the identity up (``provider_id``, ``issuer``, ``subject``), locks its
        account, reads the owner and pending counts, runs :func:`accounts.decide` and
        applies the result: creating the account and its identity, activating a pending
        account, changing the role (with the last-owner guard), refreshing the login time.
        The history, the audit entry and the sign-in event are written in the same
        transaction. ``purpose='sign_in'`` is the ``/account`` login (roles are
        recomputed, an event is always recorded); ``'request'`` is the MCP path (an
        existing account is not written, a role is never raised). ``listed_providers`` (the
        providers of ``SELFHOST_LOGIN_PROVIDERS``; None: all) decides which owners are usable:
        the bootstrap identity becomes an owner while there is no usable owner, and the number
        of owners it overrides is audited.
        """
        now = self._now()
        repos = self._repos
        surface = acc.SURFACE_ACCOUNT
        with self._db.write() as conn:
            account_id = repos.identities.lookup(conn, *ext.identity)
            row = (
                repos.accounts.get(conn, account_id, for_update=True)
                if account_id
                else None
            )
            existing = None if row is None else _status(row).facts
            active_owners = repos.accounts.count_active_owners(conn)
            listed = _listed(listed_providers)
            usable_owners = repos.accounts.count_usable_owners(conn, listed)
            is_bootstrap = acc.is_bootstrap_identity(ext, policy)
            owner_usable = True
            if (
                is_bootstrap
                and row is not None
                and account_id is not None
                and row.status == STATUS_ACTIVE
                and row.role == ROLE_OWNER
            ):
                # Only the bootstrap identity may re-source an owner: whether this one is usable.
                held = repos.identities.for_account(conn, account_id)
                owner_usable = acc.owner_is_usable(
                    role=row.role,
                    status=row.status,
                    role_source=row.role_source,
                    identity_providers=[r.provider_id for r in held],
                    listed=listed,
                )
            facts = DecisionFacts(
                active_owner_count=active_owners,
                usable_owner_count=usable_owners,
                pending_count=repos.accounts.count_pending(conn),
                is_bootstrap_identity=is_bootstrap,
                existing_owner_usable=owner_usable,
            )
            decision = acc.decide(existing, verdict, policy, facts, purpose)
            self._pause("after_decision")
            created = activated = False
            owner_change: str | None = None
            unusable_owners = (
                # The owners this bootstrap overrides: not the account being re-sourced itself.
                max(0, active_owners - usable_owners - (0 if owner_usable else 1))
                if decision.role == ROLE_OWNER
                and decision.role_source == acc.ROLE_SOURCE_BOOTSTRAP
                else 0
            )
            if decision.create:
                account_id = self._new_account_id(ext)
                self._create_account(conn, account_id, ext, decision, now)
                created = True
                if unusable_owners > 0:
                    self._audit_bootstrap_override(
                        conn, account_id, unusable_owners, now
                    )
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
                    self._audit(
                        conn,
                        SYSTEM_ACTOR,
                        AUDIT_ACCOUNT_ACTIVATED,
                        target=key,
                        detail={"admitted_via": decision.admitted_via or ""},
                        now=now,
                    )
                    activated = True
                owner_change = self._apply_role(
                    conn,
                    account_id,
                    row,
                    decision,
                    purpose,
                    verdict,
                    now,
                    unusable_owners=unusable_owners,
                )
            if account_id is not None and decision.outcome != "deny":
                repos.accounts.touch_login(
                    conn,
                    account_id,
                    display_name=ext.display_name[:_MAX_DISPLAY_NAME],
                    now=now,
                )
                repos.identities.touch(
                    conn,
                    *ext.identity,
                    username=ext.username[:_MAX_USERNAME],
                    now=now,
                    email=(ext.email or None) and ext.email[:_MAX_EMAIL],
                    email_verified=ext.email_verified,
                )
            if created:
                owner_change = (
                    decision.role_event if decision.role == ROLE_OWNER else None
                )
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
        status = None if final_row is None else _status(final_row)
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

    # -- accounts: linking identities --------------------------------------------------

    def link_identity(
        self,
        principal_key: str,
        ext: ExternalClaims,
        verdict: Verdict,
        policy: AccessPolicy,
        *,
        expected_epoch: int,
        ua_hash: str | None = None,
    ) -> LinkResult:
        """Attach an external identity to an existing, active account in one transaction.

        The writer lock is taken first (SQLite ``BEGIN IMMEDIATE`` plus the process lock;
        PostgreSQL the advisory lock), then the account row is locked: it must be active and
        its ``session_epoch`` must still be ``expected_epoch`` (the epoch of the session that
        started the link), else ``link_session_ended``. An identity that already belongs to
        another account is ``identity_in_use`` and nothing changes for either account (there
        is no silent merge); an account holds at most one identity per provider
        (``provider_already_linked``); and an identity the admission rules would refuse at
        sign-in cannot be attached (``access_denied``: see :func:`accounts.link_admissible`).
        A refusal is audited. The unique key on the identity is a second barrier; under the
        writer lock it cannot fire, and if it ever does the error propagates (fail closed).
        """
        key = _require_account_key(principal_key)
        account_id = acc.account_id_of(key)
        now = self._now()
        repos = self._repos
        provider = ext.provider_id
        with self._db.write() as conn:
            row = repos.accounts.get(conn, account_id, for_update=True)
            if (
                row is None
                or row.status != STATUS_ACTIVE
                or int(row.session_epoch) != expected_epoch
            ):
                return LinkResult(LINK_SESSION_ENDED, provider)
            owner = repos.identities.lookup(conn, *ext.identity)
            self._pause("after_identity_lookup")
            if owner == account_id:
                return LinkResult(LINK_ALREADY, provider)
            refusal: str | None = None
            if owner is not None:
                refusal = LINK_IN_USE
            elif repos.identities.count_for_provider(conn, account_id, provider) > 0:
                refusal = LINK_PROVIDER_TAKEN
            elif not acc.link_admissible(_status(row).facts, verdict, policy):
                refusal = LINK_DENIED
            if refusal is not None:
                self._audit(
                    conn,
                    key,
                    AUDIT_IDENTITY_LINK_REFUSED,
                    target=key,
                    reason=refusal,
                    detail={"provider": provider[:64]},
                    now=now,
                )
                return LinkResult(refusal, provider)
            repos.identities.insert(
                conn,
                account_id=account_id,
                provider_id=provider,
                issuer=ext.issuer,
                subject=ext.subject,
                username=ext.username[:_MAX_USERNAME],
                email=(ext.email or None) and ext.email[:_MAX_EMAIL],
                email_verified=bool(ext.email) and ext.email_verified,
                now=now,
            )
            self._audit(
                conn,
                key,
                AUDIT_IDENTITY_LINKED,
                target=key,
                detail={"provider": provider[:64]},
                now=now,
            )
            self._record_auth_event(
                conn,
                now=now,
                account_id=account_id,
                provider_id=provider,
                surface=acc.SURFACE_ACCOUNT,
                outcome=acc.OUTCOME_SUCCESS,
                reason=acc.REASON_IDENTITY_LINKED,
                ip="unknown",
                ua_hash=ua_hash,
            )
        return LinkResult(LINK_OK, provider)

    def unlink_identity(
        self,
        principal_key: str,
        identity_id: str,
        *,
        actor: Actor,
        expected_epoch: int | None = None,
        listed_providers: Collection[str] | None = None,
        additional_provider_lists: Sequence[Collection[str]] = (),
    ) -> UnlinkResult:
        """Remove one identity from an account; every session of the account ends.

        ``actor`` is the account itself (its key), another account that must be an active
        owner (re-checked in this transaction), or :data:`OPERATOR`. An account always keeps
        at least one identity (``last_identity``: to cut a person off, disable the account), and
        the server keeps at least one *usable owner* (``last_owner``): an unlink that would take
        the last usable owner's last way to an owner session is refused. An active owner is usable
        while a sign-in under ``listed_providers`` (the providers of ``SELFHOST_LOGIN_PROVIDERS``;
        None: all) can show its role: one granted by the Entra owner rules needs an Entra identity
        and Entra listed, any other needs one identity at a listed provider
        (:func:`accounts.owner_is_usable`). The unlink is refused only when the account is usable
        before and not after it and no other usable owner exists; the other owners' rows are read
        ``FOR UPDATE`` inside the writer lock, so two owners cannot unlink their way out together.
        The count and the delete are one transaction under the writer lock, so two
        concurrent unlinks of a two-identity account cannot both succeed. A successful unlink
        bumps ``session_epoch`` (every browser session and every authorization code not yet
        redeemed dies with the old epoch; connected apps survive) and writes the status
        history and the audit log. ``expected_epoch`` (an own unlink) ties the call to the
        session that made it.
        """
        key = _require_account_key(principal_key)
        account_id = acc.account_id_of(key)
        by = self._actor_name(actor)
        now = self._now()
        repos = self._repos
        with self._db.write() as conn:
            self_service = not isinstance(actor, _Operator) and by == key
            if not self_service:
                self._require_owner_actor(conn, actor)
            row = repos.accounts.get(conn, account_id, for_update=True)
            if row is None:
                return UnlinkResult(UNLINK_NOT_FOUND)
            if self_service and (
                row.status != STATUS_ACTIVE
                or (
                    expected_epoch is not None
                    and int(row.session_epoch) != expected_epoch
                )
            ):
                return UnlinkResult(UNLINK_SESSION_ENDED)
            ident = repos.identities.get_for_account(
                conn, identity_id, account_id, for_update=True
            )
            if ident is None:
                return UnlinkResult(UNLINK_NOT_FOUND)
            count = repos.identities.count_for_account(conn, account_id)
            self._pause("after_identity_count")
            if count <= 1:
                return UnlinkResult(UNLINK_LAST, ident.provider_id)
            if row.status == STATUS_ACTIVE and row.role == ROLE_OWNER:
                rows = repos.identities.for_account(conn, account_id)
                for provider_list in (listed_providers, *additional_provider_lists):
                    listed = _listed(provider_list)
                    usable_before = acc.owner_is_usable(
                        role=row.role,
                        status=row.status,
                        role_source=row.role_source,
                        identity_providers=[r.provider_id for r in rows],
                        listed=listed,
                    )
                    usable_after = acc.owner_is_usable(
                        role=row.role,
                        status=row.status,
                        role_source=row.role_source,
                        identity_providers=[
                            r.provider_id for r in rows if r.id != identity_id
                        ],
                        listed=listed,
                    )
                    if usable_before and not usable_after:
                        others = repos.accounts.usable_owner_ids(
                            conn, listed, exclude=account_id, for_update=True
                        )
                        self._pause("after_owner_count")
                        if not others:
                            return UnlinkResult(UNLINK_LAST_OWNER, ident.provider_id)
            if not repos.identities.delete_one(conn, identity_id, account_id):
                return UnlinkResult(UNLINK_NOT_FOUND)
            epoch = repos.accounts.end_sessions(conn, account_id, now)
            who = (
                "operator"
                if isinstance(actor, _Operator)
                else ("self" if self_service else "owner")
            )
            self._audit(
                conn,
                by,
                AUDIT_IDENTITY_UNLINKED,
                target=key,
                detail={"provider": ident.provider_id[:64], "by": who},
                now=now,
            )
        return UnlinkResult(
            UNLINK_OK, ident.provider_id, ident.issuer, ident.subject, epoch
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
            email=(ext.email or None) and ext.email[:_MAX_EMAIL],
            email_verified=bool(ext.email) and ext.email_verified,
            now=now,
        )
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

    def _audit_bootstrap_override(
        self, conn: Connection, account_id: str, unusable_owners: int, now: int
    ) -> None:
        """Audit a bootstrap owner made while the owners the database holds were all unusable."""
        self._audit(
            conn,
            SYSTEM_ACTOR,
            AUDIT_ROLE_CHANGED,
            target=acc.account_key_of(account_id),
            detail={
                "role": ROLE_OWNER,
                "source": acc.ROLE_SOURCE_BOOTSTRAP,
                "via": "sign_in",
                "unusable_owners": unusable_owners,
            },
            now=now,
        )

    def _apply_role(
        self,
        conn: Connection,
        account_id: str,
        row: AccountRow,
        decision: Decision,
        purpose: acc.Purpose,
        verdict: Verdict,
        now: int,
        *,
        unusable_owners: int = 0,
    ) -> str | None:
        """Apply the role part of a decision to an existing account; returns the change made."""
        repos = self._repos
        key = acc.account_key_of(account_id)
        if decision.role is not None:
            repos.accounts.set_role(
                conn,
                account_id,
                role=decision.role,
                source=decision.role_source,
                seen_at=now if decision.role == ROLE_OWNER else row.role_seen_at,
                now=now,
            )
            admitted_via = decision.admitted_via
            if (
                admitted_via is not None
                and not decision.activate
                and admitted_via != row.admitted_via
            ):
                # The bootstrap owner is admitted personally, so the rules it overrode cannot
                # refuse it at its next sign-in.
                repos.accounts.set_admitted_via(conn, account_id, admitted_via, now)
            else:
                admitted_via = None
            event = decision.role_event or (
                EVENT_OWNER_GAINED if decision.role == ROLE_OWNER else EVENT_OWNER_LOST
            )
            detail: dict[str, Any] = {
                "role": decision.role,
                "source": decision.role_source or "",
                "via": "sign_in",
            }
            if unusable_owners > 0:
                detail["unusable_owners"] = unusable_owners
            if admitted_via is not None:
                detail["admitted_via"] = admitted_via
            if row.role == ROLE_OWNER and decision.role == ROLE_OWNER:
                # An owner re-sourced at a sign-in (the bootstrap identity took over a role no
                # sign-in could use): say where it came from.
                detail["was"] = (row.role_source or "")[:32]
            self._audit(
                conn,
                SYSTEM_ACTOR,
                AUDIT_ROLE_CHANGED,
                target=key,
                detail=detail,
                now=now,
            )
            return event
        if decision.role_event == EVENT_OWNER_LOSS_REFUSED:
            self._audit(
                conn,
                SYSTEM_ACTOR,
                AUDIT_ROLE_LOSS_REFUSED,
                target=key,
                reason="last_owner",
                detail={"via": "sign_in"},
                now=now,
            )
            return None
        if (
            row.role == ROLE_OWNER
            and row.role_source == acc.ROLE_SOURCE_RULES
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
            ua_hash=bytes.fromhex(ua_hash[:16]) if ua_hash else None,
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
            with self._db.best_effort_write() as conn:
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

    def auth_events_page(
        self,
        principal_key: str,
        *,
        cursor: str | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> Page[AuthEvent]:
        account_id = _require_account_key(principal_key)
        limit = page_limit(limit)
        scope = "auth-events/" + account_id
        before = decode_cursor(cursor, scope, integer=True)
        assert before is None or isinstance(before, int)
        with self._db.read() as conn:
            rows = self._repos.auth_events.list_for_account(
                conn, account_id, limit + 1, before_id=before
            )
        events = [
            AuthEvent(
                row.id,
                row.at,
                row.provider_id,
                row.surface,
                row.outcome,
                row.reason,
                row.ua_hash.hex() if row.ua_hash is not None else None,
            )
            for row in rows
        ]
        return make_page(events, limit=limit, scope=scope, key=lambda row: row.id)

    def audit_page(
        self,
        *,
        cursor: str | None = None,
        limit: int = DEFAULT_LIMIT,
        account_id: str | None = None,
    ) -> Page[AuditEntry]:
        limit = page_limit(limit)
        if account_id is not None:
            account_id = _require_account_key(account_id)
        scope = "audit/" + str(account_id)
        before = decode_cursor(cursor, scope, integer=True)
        assert before is None or isinstance(before, int)
        with self._db.read() as conn:
            rows = self._repos.audit.list(
                conn, limit + 1, before, account_id=account_id
            )
        entries = [
            AuditEntry(
                row.id,
                row.at,
                row.actor_id or row.actor_kind,
                row.action,
                row.target_id,
                row.reason,
                row.detail,
            )
            for row in rows
        ]
        return make_page(entries, limit=limit, scope=scope, key=lambda row: row.id)

    def iter_audit(self, *, account_id: str | None = None) -> Iterator[AuditEntry]:
        cursor = None
        while True:
            page = self.audit_page(cursor=cursor, limit=200, account_id=account_id)
            yield from page.items
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    # -- accounts: administrative changes ------------------------------------------

    def delete_account(
        self,
        account_id: str,
        *,
        actor: Actor = OPERATOR,
        listed_providers: Collection[str] | None = None,
    ) -> bool:
        """Operator-only account deletion, with owner protection and retained history."""
        from sqlalchemy import delete, func, select

        from .db import schema as s

        if not isinstance(actor, _Operator):
            raise AccessActionRefused(AccessActionRefused.NOT_OWNER)
        account_id = _require_account_key(account_id)
        now = self._now()
        with self._db.write() as conn:
            # Include consumed tombstones: account cascades must not take code
            # locks after the account lock held by a first exchange.
            self._repos.codes.delete_for_account(conn, account_id)
            self._pause("after_account_codes_deleted")
            row = self._repos.accounts.get(conn, account_id, for_update=True)
            if row is None:
                return False
            if row.status == STATUS_ACTIVE and row.role == ROLE_OWNER:
                listed = _listed(listed_providers)
                others = self._repos.accounts.usable_owner_ids(
                    conn, listed, exclude=account_id, for_update=True
                )
                if not others:
                    identities = self._repos.identities.for_account(conn, account_id)
                    if (
                        acc.owner_is_usable(
                            role=row.role,
                            status=row.status,
                            role_source=row.role_source,
                            identity_providers=[
                                identity.provider_id for identity in identities
                            ],
                            listed=listed,
                        )
                        or self._repos.accounts.count_active_owners(
                            conn, exclude=account_id
                        )
                        == 0
                    ):
                        raise AccessActionRefused(AccessActionRefused.LAST_OWNER)
            counts = {
                name: conn.execute(
                    select(func.count())
                    .select_from(table)
                    .where(table.c.account_id == account_id)
                ).scalar_one()
                for name, table in (
                    ("credentials_removed", s.canvas_credentials),
                    ("identities_removed", s.external_identities),
                    ("grants_removed", s.oauth_grants),
                )
            }
            conn.execute(delete(s.accounts).where(s.accounts.c.id == account_id))
            self._audit(
                conn,
                OPERATOR_ACTOR,
                AUDIT_ACCOUNT_DELETED,
                target=account_id,
                detail=counts,
                now=now,
            )
        return True

    def disable_principal(
        self,
        principal_key: str,
        *,
        actor: Actor,
        reason: str,
        allow_last_owner: bool = False,
        listed_providers: Collection[str] | None = None,
        additional_provider_lists: Sequence[Collection[str]] = (),
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
        cannot disable themselves. Disabling the last *usable* owner (an active owner that can
        still get an owner session under ``listed_providers``, the providers of
        ``SELFHOST_LOGIN_PROVIDERS``; None: all; see :func:`accounts.owner_is_usable`) is refused
        unless ``allow_last_owner``, and so is disabling the last active owner of any kind; the
        check and the write are one transaction (the other owners' rows are read ``FOR UPDATE``),
        so two owners cannot disable each other concurrently. Already disabled, or no such
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
            current = repos.accounts.get(conn, account_id)
            if current is None or current.status == STATUS_DISABLED:
                self._require_owner_actor(conn, actor)
                return False
            # An exchange consumes its code before it locks the account.
            # Governance must delete codes before taking any account lock.
            self._repos.codes.delete_unconsumed_for_account(conn, account_id)
            self._pause("after_account_codes_deleted")
            self._require_owner_actor(conn, actor)
            if not isinstance(actor, _Operator) and by == key:
                raise AccessActionRefused(AccessActionRefused.SELF)
            row = repos.accounts.get(conn, account_id, for_update=True)
            if row is None or row.status == STATUS_DISABLED:
                return False
            if (
                row.status == STATUS_ACTIVE
                and row.role == ROLE_OWNER
                and not allow_last_owner
            ):
                for provider_list in (listed_providers, *additional_provider_lists):
                    listed = _listed(provider_list)
                    usable_others = repos.accounts.usable_owner_ids(
                        conn, listed, exclude=account_id, for_update=True
                    )
                    self._pause("after_owner_count")
                    if not usable_others:
                        identities = repos.identities.for_account(conn, account_id)
                        target_usable = acc.owner_is_usable(
                            role=row.role,
                            status=row.status,
                            role_source=row.role_source,
                            identity_providers=[r.provider_id for r in identities],
                            listed=listed,
                        )
                        if (
                            target_usable
                            or repos.accounts.count_active_owners(
                                conn, exclude=account_id
                            )
                            == 0
                        ):
                            raise AccessActionRefused(AccessActionRefused.LAST_OWNER)
            repos.accounts.disable(conn, account_id, reason=reason, by=by, now=now)
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
            if row is None or row.status != STATUS_DISABLED:
                return False
            self._repos.accounts.enable(conn, account_id, now)
            generation = self._repos.generations.bump(
                conn, key, GENERATION_ENABLED, now
            )
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
            if row is None or row.status != STATUS_PENDING:
                return False
            self._repos.accounts.activate(
                conn,
                account_id,
                admitted_via=acc.ADMITTED_APPROVAL,
                approved_by=by,
                now=now,
            )
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
            current = self._repos.accounts.get(conn, account_id)
            if current is None or current.status != STATUS_PENDING:
                self._require_owner_actor(conn, actor)
                return False
            # An exchange consumes its code before it locks the account.
            # Governance must delete codes before taking any account lock.
            self._repos.codes.delete_unconsumed_for_account(conn, account_id)
            self._pause("after_account_codes_deleted")
            self._require_owner_actor(conn, actor)
            row = self._repos.accounts.get(conn, account_id, for_update=True)
            self._pause("after_account_read")
            if row is None or row.status != STATUS_PENDING:
                return False
            self._repos.accounts.disable(
                conn, account_id, reason=DISABLE_REASON_DENIED, by=by, now=now
            )
            generation = self._repos.generations.bump(
                conn, key, GENERATION_DISABLED, now
            )
            self._audit(
                conn,
                by,
                AUDIT_ACCOUNT_DENIED,
                target=key,
                reason=DISABLE_REASON_DENIED,
                now=now,
            )
        self._publish_generation(key, generation)
        return True

    def promote_owner(
        self,
        principal_key: str,
        *,
        actor: Actor = OPERATOR,
        listed_providers: Collection[str] | None = None,
    ) -> bool:
        """Make an active account an owner (``role_source`` operator); operator only.

        The emergency entrance of the CLI: owners otherwise come from ``OWNER_RULES``
        or the bootstrap owner. A role the operator granted is not taken back by the rules.

        An account that is already an owner is left alone unless it is not a *usable* owner
        under ``listed_providers`` (the providers of ``SELFHOST_LOGIN_PROVIDERS``; None: all;
        see :func:`accounts.owner_is_usable`) and the operator's say-so would make it one: an
        owner whose role the Entra owner rules granted keeps that source after Entra is
        delisted, and no sign-in can show it, so it is re-sourced to ``operator`` (audited) and,
        when the access rules were what admitted it, becomes a personal admission
        (``admitted_via`` ``operator``) so that the rules cannot refuse it at its next sign-in.
        Returns False when the account is not active, or is already an owner that needs no
        change (a usable owner, or one that no change of source could make usable).
        An ordinary user promotion also records personal admission when needed.
        """
        if not isinstance(actor, _Operator):
            raise AccessActionRefused(AccessActionRefused.NOT_OWNER)
        key = _require_account_key(principal_key)
        account_id = acc.account_id_of(key)
        now = self._now()
        with self._db.write() as conn:
            row = self._repos.accounts.get(conn, account_id, for_update=True)
            if row is None or row.status != STATUS_ACTIVE:
                return False
            previous_source: str | None = None
            admitted: str | None = None
            if row.role == ROLE_OWNER:
                held = [
                    r.provider_id
                    for r in self._repos.identities.for_account(conn, account_id)
                ]
                listed = _listed(listed_providers)
                usable_now = acc.owner_is_usable(
                    role=row.role,
                    status=row.status,
                    role_source=row.role_source,
                    identity_providers=held,
                    listed=listed,
                )
                usable_as_operator = acc.owner_is_usable(
                    role=row.role,
                    status=row.status,
                    role_source=acc.ROLE_SOURCE_OPERATOR,
                    identity_providers=held,
                    listed=listed,
                )
                if usable_now or not usable_as_operator:
                    return False
                previous_source = row.role_source or ""
            # Every operator promotion is a personal admission. The rules must not lock
            # out the resulting owner, including a user promoted for the first time.
            if row.admitted_via not in acc.PERSONAL_ADMISSION:
                admitted = acc.ADMITTED_OPERATOR
            self._repos.accounts.set_role(
                conn,
                account_id,
                role=ROLE_OWNER,
                source=acc.ROLE_SOURCE_OPERATOR,
                seen_at=now,
                now=now,
            )
            if admitted is not None:
                self._repos.accounts.set_admitted_via(conn, account_id, admitted, now)
            self._audit(
                conn,
                OPERATOR_ACTOR,
                AUDIT_ROLE_CHANGED,
                target=key,
                detail={
                    "role": ROLE_OWNER,
                    "source": acc.ROLE_SOURCE_OPERATOR,
                    **(
                        {} if previous_source is None else {"was": previous_source[:32]}
                    ),
                    **({} if admitted is None else {"admitted_via": admitted}),
                },
                now=now,
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
            from .db.types import new_id

            account_id = account_id or new_id()
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
                    acc.ADMITTED_OPERATOR
                    if status == STATUS_ACTIVE
                    else acc.ADMITTED_RULES
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
            if status == STATUS_DISABLED:
                generation = repos.generations.bump(conn, key, GENERATION_DISABLED, now)
            else:
                generation = 0
            self._audit(
                conn,
                OPERATOR_ACTOR,
                AUDIT_ACCOUNT_CREATED_BY_OPERATOR,
                target=key,
                detail={"status": status, "role": role, "provider": provider_id},
                now=now,
            )
        if generation:
            self._publish_generation(key, generation)
        return key

    # -- per-user write-tool preferences -------------------------------------

    def get_tool_prefs(self, principal_key: str) -> ToolPrefs | None:
        from sqlalchemy import select

        from .db import schema as s

        key = _require_account_key(principal_key)
        a, p = s.accounts, s.account_write_tools
        with self._db.read() as conn:
            rows = (
                conn.execute(
                    select(
                        a.c.write_tools_version,
                        a.c.updated_at,
                        p.c.tool_name,
                        p.c.enabled_at,
                        p.c.enabled_via,
                    )
                    .select_from(a.outerjoin(p, p.c.account_id == a.c.id))
                    .where(a.c.id == key)
                    .order_by(p.c.tool_name)
                )
                .mappings()
                .all()
            )
        if not rows or rows[0]["write_tools_version"] == 0:
            return None
        stamps = {
            row["tool_name"]: row["enabled_at"]
            for row in rows
            if row["tool_name"] is not None
        }
        return ToolPrefs(
            key,
            frozenset(stamps),
            stamps,
            rows[0]["updated_at"],
            rows[0]["enabled_via"] or "api",
            rows[0]["write_tools_version"],
        )

    def set_tool_prefs(
        self,
        principal_key: str,
        enabled_write_tools: Iterable[str],
        *,
        via: str = "api",
    ) -> ToolPrefs:
        key = _require_account_key(principal_key)
        names = _validate_tool_names(enabled_write_tools)
        if via not in ("account_web", "api", "operator"):
            raise ValueError("unknown preference writer")
        now = self._now()
        with self._db.write() as conn:
            account = self._repos.accounts.get(conn, key, for_update=True)
            if account is None:
                raise PrincipalMissingError("there is no account for this principal")
            if account.status == STATUS_DISABLED:
                raise PrincipalDisabledError("this principal is disabled")
            if account.status != STATUS_ACTIVE:
                raise PrincipalPendingError("this account is waiting for approval")
            previous = {
                row.tool_name: row.enabled_at
                for row in self._repos.prefs.get(conn, key)
            }
            before = frozenset(previous)
            stamps = {name: previous.get(name, now) for name in names}
            version = self._repos.prefs.replace(
                conn, key, stamps=stamps, now=now, via=via
            )
            if names != before:
                self._audit(
                    conn,
                    key,
                    AUDIT_WRITE_TOOLS_CHANGED,
                    target=key,
                    detail={
                        "enabled": sorted(names - before),
                        "disabled": sorted(before - names),
                    },
                    now=now,
                )
        return ToolPrefs(key, names, stamps, now, via, version)

    def rotate(self) -> int:
        """Re-seal all registered values without changing lifecycle or custody."""
        from .db.sealed import rotate

        return rotate(self._db, self._keyring)
