"""The repository interfaces behind :class:`~canvas_mcp.core.selfhost.token_store.TokenStore`.

Each repository is a set of statements over one table family. They are stateless
and take a caller-owned ``Connection``: they never open, commit or roll back a
transaction. The transaction boundaries of every public store operation live in
``token_store.py`` so the race-sensitive reasoning (status gate, last-owner
guard, generation bumps, conditional updates) stays in one reviewable place.

Rows are returned as tuples in a documented column order; the store decodes them.
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
        """Sealed columns plus metadata plus the credential generation, one statement."""

    def info(self, conn: Connection, key: str) -> Row | None:
        """Metadata and the credential generation of one enrollment."""

    def list_all(self, conn: Connection) -> list[Row]:
        """Metadata of every enrollment, oldest first."""

    def count(self, conn: Connection) -> int: ...

    def upsert(
        self,
        conn: Connection,
        *,
        tenant_id: str,
        object_id: str,
        key_id: str,
        nonce: bytes,
        ciphertext: bytes,
        canvas_user_id: str,
        canvas_user_name: str,
        entra_display_name: str,
        entra_upn: str,
        canvas_host: str | None,
        principal_key: str,
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

    def names(self, conn: Connection, key: str) -> tuple[str, str] | None:
        """``(entra_display_name, entra_upn)`` of an enrollment, if there is one."""

    def rows_not_under_key(self, conn: Connection, key_id: str) -> list[Row]:
        """``(tenant_id, object_id, key_id, nonce, ciphertext, canvas_host, principal_key)``."""

    def reseal(
        self,
        conn: Connection,
        *,
        tenant_id: str,
        object_id: str,
        key_id: str,
        nonce: bytes,
        ciphertext: bytes,
    ) -> None: ...

    def key_ids_in_use(self, conn: Connection) -> list[str]: ...

    def probe_row(self, conn: Connection, key_id: str) -> Row | None:
        """``(tenant_id, object_id, nonce, ciphertext, canvas_host, principal_key)``."""


class CredentialGenerationRepo(Protocol):
    """``credential_generations``: a per-principal counter that never goes down."""

    def bump(self, conn: Connection, key: str, reason: str, now: int) -> int:
        """Raise the generation inside the caller's transaction and return the new value."""

    def get(self, conn: Connection, key: str) -> int: ...


class PrincipalStatusRepo(Protocol):
    """``principal_status``: whether a principal may use the server, and the owner flag."""

    def get(self, conn: Connection, key: str, *, for_update: bool = False) -> Row | None: ...

    def get_with_generation(self, conn: Connection, key: str) -> tuple[Row | None, int]:
        """The status row (if any) and the credential generation, in one statement."""

    def list_all(self, conn: Connection) -> list[Row]: ...

    def count_active_owners(self, conn: Connection, *, exclude: str | None = None) -> int: ...

    def gate_status(self, conn: Connection, key: str) -> str | None:
        """The ``status`` value of the row, or None if there is no row."""

    def insert_owner_seen(self, conn: Connection, key: str, now: int) -> None: ...

    def set_owner_flag(self, conn: Connection, key: str, is_owner: bool, now: int) -> None: ...

    def demote(self, conn: Connection, key: str, now: int) -> None: ...

    def upsert_disabled(
        self,
        conn: Connection,
        key: str,
        *,
        reason: str,
        by: str,
        display_name: str,
        upn: str,
        now: int,
    ) -> int:
        """Mark disabled, raise ``session_epoch`` by one and return the new epoch."""

    def enable(self, conn: Connection, key: str, now: int) -> None: ...


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
