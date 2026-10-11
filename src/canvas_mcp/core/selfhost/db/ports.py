"""V1 repository contracts: stateless statements on caller-owned connections.

Results are frozen named records. No driver row, tuple column order or legacy
table interface escapes the SQL layer.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Protocol

from ..authz.models import (
    CimdSnapshot,
    ClientRecord,
    CodeRecord,
    GrantRecord,
    GrantStatus,
    RefreshView,
)
from .rows import (
    AccountRow,
    AuditRow,
    AuthEventRow,
    CanvasOAuthAppRow,
    CredentialRow,
    IdentityRow,
    WriteToolRow,
)

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

    from .authz_repos import RefreshTokenRecord


class CredentialGenerationRepo(Protocol):
    def bump(
        self,
        conn: Connection,
        key: str,
        reason: str,
        now: int,
        *,
        writing: str | None = None,
    ) -> int: ...

    def get(self, conn: Connection, key: str) -> int: ...


class AccountRepo(Protocol):
    def get(
        self, conn: Connection, account_id: str, *, for_update: bool = False
    ) -> AccountRow | None: ...

    def count_active_owners(
        self, conn: Connection, *, exclude: str | None = None
    ) -> int: ...

    def usable_owner_ids(
        self,
        conn: Connection,
        provider_ids: Sequence[str] | None,
        *,
        exclude: str | None = None,
        for_update: bool = False,
    ) -> list[str]: ...

    def count_usable_owners(
        self, conn: Connection, provider_ids: Sequence[str] | None
    ) -> int: ...

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
    ) -> bool: ...

    def disable(
        self, conn: Connection, account_id: str, *, reason: str, by: str, now: int
    ) -> int: ...

    def enable(self, conn: Connection, account_id: str, now: int) -> int: ...

    def end_sessions(self, conn: Connection, account_id: str, now: int) -> int: ...

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

    def set_admitted_via(
        self, conn: Connection, account_id: str, admitted_via: str, now: int
    ) -> None: ...

    def mark_role_seen(self, conn: Connection, account_id: str, now: int) -> None: ...

    def touch_login(
        self, conn: Connection, account_id: str, *, display_name: str, now: int
    ) -> None: ...


class IdentityRepo(Protocol):
    def lookup(
        self, conn: Connection, provider_id: str, issuer: str, subject: str
    ) -> str | None: ...

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
        email: str | None = None,
        email_verified: bool | None = None,
    ) -> None: ...

    def for_account(self, conn: Connection, account_id: str) -> list[IdentityRow]: ...

    def get_for_account(
        self,
        conn: Connection,
        identity_id: str,
        account_id: str,
        *,
        for_update: bool = False,
    ) -> IdentityRow | None: ...

    def account_of(self, conn: Connection, identity_id: str) -> str | None: ...

    def count_for_account(self, conn: Connection, account_id: str) -> int: ...

    def count_for_provider(
        self, conn: Connection, account_id: str, provider_id: str
    ) -> int: ...

    def delete_one(
        self, conn: Connection, identity_id: str, account_id: str
    ) -> bool: ...


class ProviderRepo(Protocol):
    def ensure(self, conn: Connection, identifier: str, *, now: int) -> None: ...

    def reconcile(
        self, conn: Connection, identifiers: Sequence[str], *, now: int
    ) -> bool: ...

    def configured(self, conn: Connection) -> frozenset[str]: ...


class AuthEventRepo(Protocol):
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
        ua_hash: bytes | None,
    ) -> None: ...

    def list_for_account(
        self,
        conn: Connection,
        account_id: str,
        limit: int,
        *,
        before_id: int | None = None,
    ) -> list[AuthEventRow]: ...


class AuditRepo(Protocol):
    def append(
        self,
        conn: Connection,
        *,
        now: int,
        actor: str,
        action: str,
        target: str | None,
        reason: str | None,
        detail: Mapping[str, Any],
    ) -> None: ...

    def list(
        self,
        conn: Connection,
        limit: int,
        before_id: int | None,
        *,
        account_id: str | None = None,
    ) -> list[AuditRow]: ...


class PrefsRepo(Protocol):
    def get(self, conn: Connection, key: str) -> list[WriteToolRow]: ...

    def replace(
        self,
        conn: Connection,
        key: str,
        *,
        stamps: Mapping[str, int],
        now: int,
        via: str,
    ) -> int: ...


class CanvasOAuthAppRepo(Protocol):
    """Reserved Developer Key repository; no implementation is wired in v1."""

    def get(self, conn: Connection, canvas_host: str) -> CanvasOAuthAppRow | None: ...

    def put(self, conn: Connection, row: CanvasOAuthAppRow) -> None: ...

    def delete(self, conn: Connection, identifier: str) -> bool: ...


class CanvasCredentialRepo(Protocol):
    def acknowledge(
        self, conn: Connection, account_id: str, *, version: int, now: int
    ) -> None: ...

    def primary(self, conn: Connection, account_id: str) -> CredentialRow | None: ...

    def at_host(
        self, conn: Connection, account_id: str, host: str
    ) -> CredentialRow | None: ...

    def count(self, conn: Connection) -> int: ...

    def ensure_school(
        self, conn: Connection, host: str, *, account_id: str, now: int
    ) -> None: ...

    def put(
        self,
        conn: Connection,
        *,
        identifier: str,
        account_id: str,
        canvas_host: str,
        generation: int,
        key_id: str,
        nonce: bytes,
        ciphertext: bytes,
        canvas_user_id: str,
        canvas_user_name: str,
        now: int,
        expires_hint_at: int | None,
        custody_notice_version: int,
        custody_ack_at: int,
    ) -> None: ...

    def delete(self, conn: Connection, account_id: str) -> bool: ...

    def mark_invalid(
        self,
        conn: Connection,
        key: str,
        *,
        reason: str,
        now: int,
        expected_updated_at: int | None,
        expected_generation: int | None,
    ) -> bool: ...

    def restore_active(
        self,
        conn: Connection,
        key: str,
        *,
        now: int,
        expected_updated_at: int | None,
        expected_generation: int | None,
    ) -> bool: ...

    def touch(self, conn: Connection, key: str, now: int, older_than: int) -> None: ...

    def mark_verified(
        self,
        conn: Connection,
        key: str,
        *,
        now: int,
        older_than: int,
        expected_generation: int | None,
    ) -> bool: ...

    def rows_not_under_key(
        self, conn: Connection, key_id: str
    ) -> list[CredentialRow]: ...

    def reseal(
        self,
        conn: Connection,
        *,
        identifier: str,
        key_id: str,
        nonce: bytes,
        ciphertext: bytes,
    ) -> None: ...

    def key_ids_in_use(self, conn: Connection) -> list[str]: ...

    def probe_row(self, conn: Connection, key_id: str) -> CredentialRow | None: ...


class OAuthClientRepo(Protocol):
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

    def get(self, conn: Connection, client_id: str) -> ClientRecord | None: ...

    def extend(self, conn: Connection, client_id: str, expires_at: int) -> bool: ...


class CimdRepo(Protocol):
    def get(self, conn: Connection, url: str) -> CimdSnapshot | None: ...

    def upsert(
        self,
        conn: Connection,
        *,
        url: str,
        doc_json: str,
        fetched_at: int,
        fresh_until: int,
    ) -> bool: ...

    def record_error(
        self, conn: Connection, url: str, *, now: int, code: str
    ) -> bool: ...


class GrantRepo(Protocol):
    def insert(self, conn: Connection, **fields: Any) -> None: ...

    def get(self, conn: Connection, grant_id: str) -> GrantRecord | None: ...

    def status_row(self, conn: Connection, grant_id: str) -> GrantStatus: ...

    def lock_live(self, conn: Connection, grant_id: str, now: int) -> bool: ...

    def revoke(
        self, conn: Connection, grant_id: str, *, reason: str, by: str, now: int
    ) -> bool: ...

    def revoke_own(
        self,
        conn: Connection,
        grant_id: str,
        account_id: str,
        *,
        reason: str,
        by: str,
        now: int,
    ) -> bool: ...

    def revoke_for_account(
        self, conn: Connection, account_id: str, *, reason: str, by: str, now: int
    ) -> int: ...

    def touch_used(
        self, conn: Connection, grant_id: str, *, now: int, older_than: int
    ) -> bool: ...

    def list_all(
        self,
        conn: Connection,
        *,
        include_inactive: bool,
        now: int,
        limit: int,
        account_id: str | None = None,
        before_id: str | None = None,
    ) -> list[GrantRecord]: ...


class AuthCodeRepo(Protocol):
    def insert(self, conn: Connection, **fields: Any) -> None: ...

    def get(
        self, conn: Connection, code_hash: str, *, for_update: bool = False
    ) -> CodeRecord | None: ...

    def consume(
        self,
        conn: Connection,
        code_hash: str,
        client_id: str,
        *,
        grant_id: str,
        now: int,
    ) -> bool: ...

    def bump_grace(self, conn: Connection, code_hash: str, cap: int) -> bool: ...

    def delete_unconsumed_for_account(
        self, conn: Connection, account_id: str
    ) -> int: ...

    def delete_for_account(self, conn: Connection, account_id: str) -> int: ...


class RefreshRepo(Protocol):
    def insert(
        self,
        conn: Connection,
        *,
        token_hash: str,
        grant_id: str,
        parent_hash: str | None,
        now: int,
    ) -> None: ...

    def get(self, conn: Connection, token_hash: str) -> RefreshTokenRecord | None: ...

    def get_with_grant(
        self, conn: Connection, token_hash: str
    ) -> RefreshView | None: ...

    def mark_used(
        self, conn: Connection, token_hash: str, *, replaced_by: str, now: int
    ) -> bool: ...

    def retire_siblings(
        self,
        conn: Connection,
        *,
        grant_id: str,
        parent_hash: str | None,
        keep: str,
        now: int,
    ) -> int: ...

    def has_rotated_child(
        self, conn: Connection, grant_id: str, token_hash: str
    ) -> bool: ...

    def any_used(self, conn: Connection, grant_id: str) -> bool: ...

    def bump_grace(self, conn: Connection, token_hash: str, cap: int) -> bool: ...


class LoginStateRepo(Protocol):
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
        self,
        conn: Connection,
        *,
        kind: str,
        id_hash: str,
        binding_hash: str | None,
        now: int,
    ) -> str | None: ...

    def pop(
        self,
        conn: Connection,
        *,
        kind: str,
        id_hash: str,
        binding_hash: str | None,
        now: int,
    ) -> str | None: ...


class JwtEpochRepo(Protocol):
    def get(self, conn: Connection) -> int: ...

    def bump(self, conn: Connection, *, now: int) -> int: ...

    def set(self, conn: Connection, value: int, *, now: int) -> None: ...
