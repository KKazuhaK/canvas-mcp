"""The repository interfaces behind :class:`~canvas_mcp.core.selfhost.token_store.TokenStore`.

Each repository is a set of statements over one table family. They are stateless
and take a caller-owned ``Connection``: they never open, commit or roll back a
transaction. The transaction boundaries of every public store operation live in
``token_store.py`` so the race-sensitive reasoning (status gate, last-owner
guard, generation bumps, conditional updates) stays in one reviewable place.

Rows are returned as tuples in a documented column order; the store decodes them.
Every principal is named by its key ``acct:<uuid>``; the ``accounts`` table is
keyed by the bare ``<uuid>``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

Row = Sequence[Any]


class CanvasTokenRepo(Protocol):
    """``canvas_tokens``: the encrypted enrollments and their health columns."""

    def row_for_get(self, conn: Connection, key: str) -> Row | None:
        """Sealed columns plus metadata plus the credential generation, one statement.

        ``(key_id, nonce, ciphertext, canvas_user_id, canvas_user_name, created_at,
        updated_at, last_used_at, canvas_host, status, invalid_reason, invalid_since,
        last_verified_at, expires_hint_at, credential_generation)``.
        """

    def info(self, conn: Connection, key: str) -> Row | None:
        """Metadata and the credential generation of one enrollment."""

    def list_all(self, conn: Connection) -> list[Row]:
        """Metadata of every enrollment, oldest first."""

    def count(self, conn: Connection) -> int: ...

    def exists(self, conn: Connection, key: str) -> bool: ...

    def upsert(
        self,
        conn: Connection,
        *,
        principal_key: str,
        key_id: str,
        nonce: bytes,
        ciphertext: bytes,
        canvas_user_id: str,
        canvas_user_name: str,
        canvas_host: str | None,
        status: str,
        now: int,
        expires_hint_at: int | None,
        keep_expiry_hint: bool,
    ) -> None:
        """Insert or replace by ``principal_key``, preserving ``created_at``."""

    def delete(self, conn: Connection, key: str) -> bool: ...

    def touch(self, conn: Connection, key: str, now: int, older_than: int) -> None: ...

    def mark_invalid(
        self,
        conn: Connection,
        key: str,
        *,
        reason: str,
        now: int,
        expected_updated_at: int | None,
        expected_generation: int | None,
    ) -> bool:
        """Conditional update guarded by the expected versions; True if a row changed."""

    def restore_active(
        self,
        conn: Connection,
        key: str,
        *,
        now: int,
        expected_updated_at: int | None,
        expected_generation: int | None,
    ) -> bool: ...

    def mark_verified(
        self,
        conn: Connection,
        key: str,
        *,
        now: int,
        older_than: int,
        expected_generation: int | None,
    ) -> bool: ...

    def rows_not_under_key(self, conn: Connection, key_id: str) -> list[Row]:
        """``(principal_key, key_id, nonce, ciphertext, canvas_host)``."""

    def reseal(
        self,
        conn: Connection,
        *,
        principal_key: str,
        key_id: str,
        nonce: bytes,
        ciphertext: bytes,
    ) -> None: ...

    def key_ids_in_use(self, conn: Connection) -> list[str]: ...

    def probe_row(self, conn: Connection, key_id: str) -> Row | None:
        """``(principal_key, nonce, ciphertext, canvas_host)`` of a row that should decrypt.

        Rows already recorded as unreadable (``decrypt_failed``) prove nothing about
        the keyring and are skipped.
        """


class CredentialGenerationRepo(Protocol):
    """``credential_generations``: a per-principal counter that never goes down."""

    def bump(self, conn: Connection, key: str, reason: str, now: int) -> int:
        """Raise the generation inside the caller's transaction and return the new value."""

    def get(self, conn: Connection, key: str) -> int: ...


class AccountRepo(Protocol):
    """``accounts``: who may use the server, their role and the session epoch.

    Account columns, in order: ``(id, status, role, role_source, role_seen_at,
    admitted_via, display_name, contact_email, ui_locale, created_at, approved_at,
    approved_by, disabled_reason, disabled_at, disabled_by, last_login_at,
    session_epoch, updated_at)``.
    """

    def get(self, conn: Connection, account_id: str, *, for_update: bool = False) -> Row | None: ...

    def get_with_generation(self, conn: Connection, account_id: str) -> tuple[Row | None, int]:
        """The account row (if any) and the credential generation, in one statement."""

    def list_all(self, conn: Connection) -> list[Row]: ...

    def count_active_owners(self, conn: Connection, *, exclude: str | None = None) -> int: ...

    def count_pending(self, conn: Connection) -> int: ...

    def insert(
        self,
        conn: Connection,
        *,
        account_id: str,
        status: str,
        role: str,
        role_source: str | None,
        admitted_via: str,
        display_name: str,
        now: int,
        approved_by: str | None = None,
        disabled_reason: str | None = None,
        disabled_by: str | None = None,
    ) -> None: ...

    def activate(
        self,
        conn: Connection,
        account_id: str,
        *,
        admitted_via: str,
        approved_by: str | None,
        now: int,
    ) -> bool:
        """pending -> active; True only if the account was pending."""

    def disable(
        self, conn: Connection, account_id: str, *, reason: str, by: str, now: int
    ) -> int:
        """Mark disabled, raise ``session_epoch`` by one in place and return the new epoch."""

    def enable(self, conn: Connection, account_id: str, now: int) -> int:
        """Lift a disablement, raise ``session_epoch`` by one in place and return it."""

    def end_sessions(self, conn: Connection, account_id: str, now: int) -> int:
        """Raise ``session_epoch`` by one in place (every ``/account`` session ends); return it."""

    def set_role(
        self,
        conn: Connection,
        account_id: str,
        *,
        role: str,
        source: str | None,
        seen_at: int | None,
        now: int,
    ) -> None: ...

    def mark_role_seen(self, conn: Connection, account_id: str, now: int) -> None:
        """Record fresh evidence of the role (a sign-in)."""

    def touch_login(self, conn: Connection, account_id: str, *, display_name: str, now: int) -> None: ...

    def purge_pending(self, conn: Connection, older_than: int) -> list[str]:
        """Delete pending accounts created before ``older_than``; returns their ids."""


class IdentityRepo(Protocol):
    """``external_identities``: the login identities that belong to accounts."""

    def lookup(
        self, conn: Connection, provider_id: str, issuer: str, subject: str
    ) -> str | None:
        """The account id the identity belongs to, if it is known."""

    def insert(
        self,
        conn: Connection,
        *,
        account_id: str,
        provider_id: str,
        issuer: str,
        subject: str,
        username: str,
        email: str | None,
        email_verified: bool,
        now: int,
    ) -> None: ...

    def touch(
        self,
        conn: Connection,
        provider_id: str,
        issuer: str,
        subject: str,
        *,
        username: str,
        now: int,
    ) -> None: ...

    def for_account(self, conn: Connection, account_id: str) -> list[Row]:
        """``(provider_id, issuer, subject, username, email, email_verified, linked_at,
        last_login_at)``, oldest first."""

    def all(self, conn: Connection) -> list[Row]:
        """``(account_id, provider_id, issuer, subject, username)`` of every identity."""

    def delete_for_accounts(self, conn: Connection, account_ids: Sequence[str]) -> None: ...


class PrincipalEventRepo(Protocol):
    """``principal_status_events``: the append-only history of status transitions."""

    def append(
        self,
        conn: Connection,
        key: str,
        action: str,
        actor: str | None,
        reason: str | None,
        epoch: int,
        now: int,
    ) -> None: ...

    def list_events(self, conn: Connection, key: str | None, limit: int) -> list[Row]:
        """Newest first: ``(id, principal_key, action, actor, reason, session_epoch, at)``."""


class AuthEventRepo(Protocol):
    """``auth_events``: the sign-in history (kept for 90 days)."""

    def append(
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
    ) -> None: ...

    def list_for_account(self, conn: Connection, account_id: str, limit: int) -> list[Row]:
        """Newest first: ``(id, at, provider_id, surface, outcome, reason, ip, ua_hash)``."""

    def prune_before(self, conn: Connection, cutoff: int) -> int: ...


class AuditRepo(Protocol):
    """``audit_log``: administrative and security actions."""

    def append(
        self,
        conn: Connection,
        *,
        now: int,
        actor: str,
        action: str,
        target: str | None,
        reason: str | None,
        detail: str,
    ) -> None: ...

    def list(self, conn: Connection, limit: int, before_id: int | None) -> list[Row]:
        """Newest first: ``(id, at, actor, action, target, reason, detail)``."""


class PrefsRepo(Protocol):
    """``user_tool_prefs``: the write tools each principal switched on."""

    def get(self, conn: Connection, key: str) -> Row | None:
        """``(enabled_write_tools, enabled_at, updated_at, updated_via)``."""

    def upsert(
        self,
        conn: Connection,
        key: str,
        *,
        names_json: str,
        stamps_json: str,
        now: int,
        via: str,
    ) -> None: ...


class MetaRepo(Protocol):
    """``meta``: the cross-release compatibility marker."""

    def schema_version(self, conn: Connection) -> str | None: ...

    def set_schema_version(self, conn: Connection, value: str) -> None: ...


# -- the self-hosted authorization server (revision 0003) ---------------------------------
#
# Statements that consume something (a login state, a code, a refresh token, a
# revocation) are one conditional UPDATE/DELETE each and return whether this call did it;
# the callers act on that, never on a prior read.


class OAuthClientRepo(Protocol):
    """``oauth_clients``: dynamically registered (public) clients."""

    def insert(
        self,
        conn: Connection,
        *,
        client_id: str,
        info_json: str,
        client_name: str,
        now: int,
        expires_at: int,
    ) -> None: ...

    def get(self, conn: Connection, client_id: str) -> Row | None:
        """``(id, info_json, client_name, created_at, expires_at)``."""

    def extend(self, conn: Connection, client_id: str, expires_at: int) -> bool:
        """Raise the expiry (never lowers it)."""

    def delete_expired(self, conn: Connection, now: int) -> int: ...


class CimdRepo(Protocol):
    """``cimd_clients``: the last known good client metadata documents."""

    def get(self, conn: Connection, url: str) -> Row | None:
        """``(url, doc_json, fetched_at, fresh_until, last_error_at, last_error)``."""

    def upsert(
        self, conn: Connection, *, url: str, doc_json: str, fetched_at: int, fresh_until: int
    ) -> bool:
        """Store unless a newer document is stored (monotonic); True if this call wrote."""

    def record_error(self, conn: Connection, url: str, *, now: int, code: str) -> bool: ...

    def delete_fetched_before(self, conn: Connection, cutoff: int) -> int: ...


class GrantRepo(Protocol):
    """``oauth_grants``: one row per connection of an app to an account."""

    def insert(self, conn: Connection, **fields: Any) -> None: ...

    def get(self, conn: Connection, grant_id: str) -> Row | None:
        """Columns in the order of ``authz_repos.GRANT_COLUMNS``."""

    def status_row(self, conn: Connection, grant_id: str) -> Row | None:
        """``(account_id, client_id, revoked_at, expires_at, last_used_at, account_status)``."""

    def lock_live(self, conn: Connection, grant_id: str, now: int) -> bool:
        """Take the row lock if the grant is live (and note the use); True if live."""

    def revoke(self, conn: Connection, grant_id: str, *, reason: str, by: str, now: int) -> bool: ...

    def revoke_own(
        self, conn: Connection, grant_id: str, account_id: str, *, reason: str, by: str, now: int
    ) -> bool: ...

    def revoke_for_account(
        self, conn: Connection, account_id: str, *, reason: str, by: str, now: int
    ) -> int: ...

    def touch_used(self, conn: Connection, grant_id: str, *, now: int, older_than: int) -> bool: ...

    def list_for_account(self, conn: Connection, account_id: str, now: int) -> list[Row]: ...

    def list_all(
        self,
        conn: Connection,
        *,
        include_inactive: bool,
        now: int,
        limit: int,
        account_id: str | None = None,
    ) -> list[Row]:
        """Newest first; with ``account_id`` only that account's rows (filtered in SQL)."""

    def delete_inactive_before(self, conn: Connection, cutoff: int) -> int: ...


class AuthCodeRepo(Protocol):
    """``oauth_codes``: authorization codes, kept as tombstones after use."""

    def insert(self, conn: Connection, **fields: Any) -> None: ...

    def get(self, conn: Connection, code_hash: str) -> Row | None:
        """Columns in the order of ``authz_repos.CODE_COLUMNS``."""

    def consume(
        self, conn: Connection, code_hash: str, client_id: str, *, grant_id: str, now: int
    ) -> bool: ...

    def bump_grace(self, conn: Connection, code_hash: str, cap: int) -> bool: ...

    def delete_unconsumed_for_account(self, conn: Connection, account_id: str) -> int:
        """Delete the codes of an account that nobody has redeemed yet; returns how many."""

    def delete_expired_before(self, conn: Connection, cutoff: int) -> int: ...


class RefreshRepo(Protocol):
    """``oauth_refresh_tokens``: hashes of refresh tokens and their rotation chain."""

    def insert(
        self,
        conn: Connection,
        *,
        token_hash: str,
        grant_id: str,
        parent_hash: str | None,
        now: int,
        expires_at: int,
    ) -> None: ...

    def get(self, conn: Connection, token_hash: str) -> Row | None:
        """Columns in the order of ``authz_repos.REFRESH_COLUMNS``."""

    def get_with_grant(self, conn: Connection, token_hash: str) -> Row | None:
        """The token row, then ``(client_id, scopes, resource, account_id, revoked_at)``."""

    def mark_used(self, conn: Connection, token_hash: str, *, replaced_by: str, now: int) -> bool: ...

    def retire_siblings(
        self, conn: Connection, *, grant_id: str, parent_hash: str | None, keep: str, now: int
    ) -> int: ...

    def has_rotated_child(self, conn: Connection, token_hash: str) -> bool: ...

    def any_used(self, conn: Connection, grant_id: str) -> bool: ...

    def bump_grace(self, conn: Connection, token_hash: str, cap: int) -> bool: ...

    def delete_dead(self, conn: Connection, *, now: int, revoked_before: int) -> int: ...


class LoginStateRepo(Protocol):
    """``login_states``: one-time state that must survive between requests."""

    def insert(
        self,
        conn: Connection,
        *,
        kind: str,
        id_hash: str,
        binding_hash: str | None,
        payload: str,
        now: int,
        expires_at: int,
    ) -> None: ...

    def peek(
        self, conn: Connection, *, kind: str, id_hash: str, binding_hash: str | None, now: int
    ) -> str | None: ...

    def delete_matching(
        self, conn: Connection, *, kind: str, id_hash: str, binding_hash: str | None, now: int
    ) -> bool: ...

    def delete_expired(self, conn: Connection, now: int) -> int: ...


class JwtEpochRepo(Protocol):
    """``meta['mcp_jwt_epoch']``: raised to invalidate every access token at once."""

    def get(self, conn: Connection) -> int: ...

    def bump(self, conn: Connection) -> int: ...

    def set(self, conn: Connection, value: int) -> None:
        """Store ``value`` (an import carries the source's epoch over; never lowers a live one)."""
