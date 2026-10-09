"""SQLAlchemy Core implementations of the repositories (SQLite and PostgreSQL).

Statements are built with the expression language, so one definition serves both
dialects. Upserts use the dialect's ``insert().on_conflict_do_update`` (both
SQLite and PostgreSQL support ``excluded``). Every value is a bound parameter.
Nothing here begins or ends a transaction.
"""

from __future__ import annotations

from typing import Any, Literal

from sqlalchemy import Select, delete, func, insert, literal, or_, select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import Connection

from . import schema as t
from .ports import (
    CanvasTokenRepo,
    CredentialGenerationRepo,
    MetaRepo,
    PrefsRepo,
    PrincipalEventRepo,
    PrincipalStatusRepo,
    Row,
)

Dialect = Literal["sqlite", "postgresql"]

STATUS_ACTIVE = "active"
STATUS_INVALID = "invalid"
STATUS_DISABLED = "disabled"

_ct = t.canvas_tokens
_cg = t.credential_generations
_ps = t.principal_status


def _upsert_insert(dialect: Dialect, table: Any) -> Any:
    return (postgresql.insert if dialect == "postgresql" else sqlite.insert)(table)


def _generation_of_token_row() -> Any:
    """The generation of the credential that belongs to ``canvas_tokens.principal_key``.

    Evaluated in the same statement as the row so a token and its generation always
    match; 0 when the principal has no counter yet.
    """
    return func.coalesce(
        select(_cg.c.generation).where(_cg.c.principal_key == _ct.c.principal_key).scalar_subquery(),
        0,
    )


def _info_columns() -> list[Any]:
    return [
        _ct.c.tenant_id,
        _ct.c.object_id,
        _ct.c.canvas_user_id,
        _ct.c.canvas_user_name,
        _ct.c.entra_display_name,
        _ct.c.entra_upn,
        _ct.c.key_id,
        _ct.c.created_at,
        _ct.c.updated_at,
        _ct.c.last_used_at,
        _ct.c.canvas_host,
        _ct.c.principal_key,
        _ct.c.status,
        _ct.c.invalid_reason,
        _ct.c.invalid_since,
        _ct.c.last_verified_at,
        _ct.c.expires_hint_at,
        _generation_of_token_row().label("credential_generation"),
    ]


def _status_columns() -> list[Any]:
    return [
        _ps.c.principal_key,
        _ps.c.status,
        _ps.c.disabled_reason,
        _ps.c.disabled_at,
        _ps.c.disabled_by,
        _ps.c.display_name,
        _ps.c.upn,
        _ps.c.session_epoch,
        _ps.c.is_owner,
        _ps.c.owner_seen_at,
        _ps.c.updated_at,
    ]


def _for_update(stmt: Select[Any], enabled: bool) -> Select[Any]:
    # SQLite has no row locks and renders nothing for FOR UPDATE; on PostgreSQL
    # the global writer lock already serialises writers, so this is defence in depth.
    return stmt.with_for_update() if enabled else stmt


class SqlCanvasTokenRepo:
    def __init__(self, dialect: Dialect) -> None:
        self._dialect = dialect

    def row_for_get(self, conn: Connection, key: str) -> Row | None:
        stmt = select(
            _ct.c.key_id,
            _ct.c.nonce,
            _ct.c.ciphertext,
            _ct.c.canvas_user_id,
            _ct.c.canvas_user_name,
            _ct.c.entra_display_name,
            _ct.c.entra_upn,
            _ct.c.created_at,
            _ct.c.updated_at,
            _ct.c.last_used_at,
            _ct.c.canvas_host,
            _ct.c.tenant_id,
            _ct.c.object_id,
            _ct.c.status,
            _ct.c.invalid_reason,
            _ct.c.invalid_since,
            _ct.c.last_verified_at,
            _ct.c.expires_hint_at,
            _generation_of_token_row().label("credential_generation"),
        ).where(_ct.c.principal_key == key)
        return conn.execute(stmt).one_or_none()

    def info(self, conn: Connection, key: str) -> Row | None:
        stmt = select(*_info_columns()).where(_ct.c.principal_key == key)
        return conn.execute(stmt).one_or_none()

    def list_all(self, conn: Connection) -> list[Row]:
        stmt = select(*_info_columns()).order_by(_ct.c.created_at, _ct.c.tenant_id, _ct.c.object_id)
        return list(conn.execute(stmt).all())

    def count(self, conn: Connection) -> int:
        return int(conn.execute(select(func.count()).select_from(_ct)).scalar_one())

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
        stmt = _upsert_insert(self._dialect, _ct).values(
            tenant_id=tenant_id,
            object_id=object_id,
            key_id=key_id,
            nonce=nonce,
            ciphertext=ciphertext,
            canvas_user_id=canvas_user_id,
            canvas_user_name=canvas_user_name,
            entra_display_name=entra_display_name,
            entra_upn=entra_upn,
            created_at=now,
            updated_at=now,
            canvas_host=canvas_host,
            principal_key=principal_key,
            status=status,
            last_verified_at=now,
            expires_hint_at=expires_hint_at,
        )
        excluded = stmt.excluded
        changes: dict[str, Any] = {
            "key_id": excluded.key_id,
            "nonce": excluded.nonce,
            "ciphertext": excluded.ciphertext,
            "canvas_user_id": excluded.canvas_user_id,
            "canvas_user_name": excluded.canvas_user_name,
            "entra_display_name": excluded.entra_display_name,
            "entra_upn": excluded.entra_upn,
            "canvas_host": excluded.canvas_host,
            "status": excluded.status,
            "invalid_reason": None,
            "invalid_since": None,
            "last_verified_at": excluded.last_verified_at,
            "updated_at": excluded.updated_at,
        }
        if not keep_expiry_hint:
            # Left out of the update entirely when the stored hint is kept (a
            # CASE over an integer parameter is not portable).
            changes["expires_hint_at"] = excluded.expires_hint_at
        conn.execute(stmt.on_conflict_do_update(index_elements=[_ct.c.principal_key], set_=changes))

    def delete(self, conn: Connection, key: str) -> bool:
        return conn.execute(delete(_ct).where(_ct.c.principal_key == key)).rowcount > 0

    def touch(self, conn: Connection, key: str, now: int, older_than: int) -> None:
        conn.execute(
            update(_ct)
            .where(
                _ct.c.principal_key == key,
                or_(_ct.c.last_used_at.is_(None), _ct.c.last_used_at < older_than),
            )
            .values(last_used_at=now)
        )

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
        stmt = (
            update(_ct)
            .where(_ct.c.principal_key == key, _ct.c.status == STATUS_ACTIVE)
            .values(status=STATUS_INVALID, invalid_reason=reason, invalid_since=now)
        )
        stmt = self._guard(stmt, expected_updated_at, expected_generation)
        return conn.execute(stmt).rowcount > 0

    def restore_active(
        self,
        conn: Connection,
        key: str,
        *,
        now: int,
        expected_updated_at: int | None,
        expected_generation: int | None,
    ) -> bool:
        stmt = (
            update(_ct)
            .where(_ct.c.principal_key == key, _ct.c.status == STATUS_INVALID)
            .values(
                status=STATUS_ACTIVE,
                invalid_reason=None,
                invalid_since=None,
                last_verified_at=now,
            )
        )
        stmt = self._guard(stmt, expected_updated_at, expected_generation)
        return conn.execute(stmt).rowcount > 0

    def mark_verified(
        self,
        conn: Connection,
        key: str,
        *,
        now: int,
        older_than: int,
        expected_generation: int | None,
    ) -> bool:
        stmt = (
            update(_ct)
            .where(
                _ct.c.principal_key == key,
                _ct.c.status == STATUS_ACTIVE,
                or_(_ct.c.last_verified_at.is_(None), _ct.c.last_verified_at < older_than),
            )
            .values(last_verified_at=now)
        )
        stmt = self._guard(stmt, None, expected_generation)
        return conn.execute(stmt).rowcount > 0

    @staticmethod
    def _guard(stmt: Any, expected_updated_at: int | None, expected_generation: int | None) -> Any:
        """Only touch the row version the caller saw (updated_at, and the generation)."""
        if expected_updated_at is not None:
            stmt = stmt.where(_ct.c.updated_at == expected_updated_at)
        if expected_generation is not None:
            stmt = stmt.where(_generation_of_token_row() == expected_generation)
        return stmt

    def names(self, conn: Connection, key: str) -> tuple[str, str] | None:
        row = conn.execute(
            select(_ct.c.entra_display_name, _ct.c.entra_upn).where(_ct.c.principal_key == key)
        ).one_or_none()
        return None if row is None else (row[0], row[1])

    def rows_not_under_key(self, conn: Connection, key_id: str) -> list[Row]:
        stmt = select(
            _ct.c.tenant_id,
            _ct.c.object_id,
            _ct.c.key_id,
            _ct.c.nonce,
            _ct.c.ciphertext,
            _ct.c.canvas_host,
            _ct.c.principal_key,
        ).where(_ct.c.key_id != key_id)
        return list(conn.execute(stmt).all())

    def reseal(
        self,
        conn: Connection,
        *,
        tenant_id: str,
        object_id: str,
        key_id: str,
        nonce: bytes,
        ciphertext: bytes,
    ) -> None:
        conn.execute(
            update(_ct)
            .where(_ct.c.tenant_id == tenant_id, _ct.c.object_id == object_id)
            .values(key_id=key_id, nonce=nonce, ciphertext=ciphertext)
        )

    def key_ids_in_use(self, conn: Connection) -> list[str]:
        stmt = select(_ct.c.key_id).distinct().order_by(_ct.c.key_id)
        return [r[0] for r in conn.execute(stmt)]

    def probe_row(self, conn: Connection, key_id: str) -> Row | None:
        stmt = (
            select(
                _ct.c.tenant_id,
                _ct.c.object_id,
                _ct.c.nonce,
                _ct.c.ciphertext,
                _ct.c.canvas_host,
                _ct.c.principal_key,
            )
            .where(_ct.c.key_id == key_id)
            .limit(1)
        )
        return conn.execute(stmt).first()


class SqlCredentialGenerationRepo:
    def __init__(self, dialect: Dialect) -> None:
        self._dialect = dialect

    def bump(self, conn: Connection, key: str, reason: str, now: int) -> int:
        stmt = _upsert_insert(self._dialect, _cg).values(
            principal_key=key, generation=1, reason=reason, updated_at=now
        )
        conn.execute(
            stmt.on_conflict_do_update(
                index_elements=[_cg.c.principal_key],
                set_={
                    "generation": _cg.c.generation + 1,
                    "reason": stmt.excluded.reason,
                    "updated_at": stmt.excluded.updated_at,
                },
            )
        )
        return self.get(conn, key)

    def get(self, conn: Connection, key: str) -> int:
        value = conn.execute(
            select(_cg.c.generation).where(_cg.c.principal_key == key)
        ).scalar_one_or_none()
        return 0 if value is None else int(value)


class SqlPrincipalStatusRepo:
    def __init__(self, dialect: Dialect) -> None:
        self._dialect = dialect

    def get(self, conn: Connection, key: str, *, for_update: bool = False) -> Row | None:
        stmt = _for_update(select(*_status_columns()).where(_ps.c.principal_key == key), for_update)
        return conn.execute(stmt).one_or_none()

    def get_with_generation(self, conn: Connection, key: str) -> tuple[Row | None, int]:
        """One statement, so the status and the generation come from one snapshot."""
        anchor = select(literal(key, t.canvas_tokens.c.principal_key.type).label("principal_key")).subquery(
            "anchor"
        )
        stmt = select(*_status_columns(), _cg.c.generation.label("credential_generation")).select_from(
            anchor.outerjoin(_ps, _ps.c.principal_key == anchor.c.principal_key).outerjoin(
                _cg, _cg.c.principal_key == anchor.c.principal_key
            )
        )
        row = conn.execute(stmt).one()
        generation = 0 if row[-1] is None else int(row[-1])
        status_row = None if row[0] is None else tuple(row[:-1])
        return status_row, generation

    def list_all(self, conn: Connection) -> list[Row]:
        stmt = select(*_status_columns()).order_by(_ps.c.principal_key)
        return list(conn.execute(stmt).all())

    def count_active_owners(self, conn: Connection, *, exclude: str | None = None) -> int:
        stmt = select(func.count()).select_from(_ps).where(
            _ps.c.is_owner == 1, _ps.c.status == STATUS_ACTIVE
        )
        if exclude is not None:
            stmt = stmt.where(_ps.c.principal_key != exclude)
        return int(conn.execute(stmt).scalar_one())

    def gate_status(self, conn: Connection, key: str) -> str | None:
        stmt = _for_update(select(_ps.c.status).where(_ps.c.principal_key == key), True)
        return conn.execute(stmt).scalar_one_or_none()

    def insert_owner_seen(self, conn: Connection, key: str, now: int) -> None:
        conn.execute(
            insert(_ps).values(principal_key=key, is_owner=1, owner_seen_at=now, updated_at=now)
        )

    def set_owner_flag(self, conn: Connection, key: str, is_owner: bool, now: int) -> None:
        conn.execute(
            update(_ps)
            .where(_ps.c.principal_key == key)
            .values(is_owner=1 if is_owner else 0, owner_seen_at=now, updated_at=now)
        )

    def demote(self, conn: Connection, key: str, now: int) -> None:
        conn.execute(
            update(_ps).where(_ps.c.principal_key == key).values(is_owner=0, updated_at=now)
        )

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
        stmt = _upsert_insert(self._dialect, _ps).values(
            principal_key=key,
            status=STATUS_DISABLED,
            disabled_reason=reason,
            disabled_at=now,
            disabled_by=by,
            display_name=display_name,
            upn=upn,
            session_epoch=1,
            is_owner=0,
            owner_seen_at=None,
            updated_at=now,
        )
        excluded = stmt.excluded
        conn.execute(
            stmt.on_conflict_do_update(
                index_elements=[_ps.c.principal_key],
                set_={
                    "status": excluded.status,
                    "disabled_reason": excluded.disabled_reason,
                    "disabled_at": excluded.disabled_at,
                    "disabled_by": excluded.disabled_by,
                    "display_name": excluded.display_name,
                    "upn": excluded.upn,
                    "session_epoch": _ps.c.session_epoch + 1,
                    "updated_at": excluded.updated_at,
                },
            )
        )
        return int(
            conn.execute(
                select(_ps.c.session_epoch).where(_ps.c.principal_key == key)
            ).scalar_one()
        )

    def enable(self, conn: Connection, key: str, now: int) -> None:
        conn.execute(
            update(_ps)
            .where(_ps.c.principal_key == key)
            .values(
                status=STATUS_ACTIVE,
                disabled_reason=None,
                disabled_at=None,
                disabled_by=None,
                display_name="",
                upn="",
                session_epoch=_ps.c.session_epoch + 1,
                updated_at=now,
            )
        )


class SqlPrincipalEventRepo:
    def append(
        self,
        conn: Connection,
        key: str,
        action: str,
        actor: str | None,
        reason: str | None,
        epoch: int,
        now: int,
    ) -> None:
        conn.execute(
            insert(t.principal_status_events).values(
                principal_key=key,
                action=action,
                actor=actor,
                reason=reason,
                session_epoch=epoch,
                at=now,
            )
        )

    def list_events(self, conn: Connection, key: str | None, limit: int) -> list[Row]:
        ev = t.principal_status_events
        stmt = select(
            ev.c.id, ev.c.principal_key, ev.c.action, ev.c.actor, ev.c.reason, ev.c.session_epoch, ev.c.at
        )
        if key is not None:
            stmt = stmt.where(ev.c.principal_key == key)
        stmt = stmt.order_by(ev.c.id.desc()).limit(limit)
        return list(conn.execute(stmt).all())


class SqlPrefsRepo:
    def __init__(self, dialect: Dialect) -> None:
        self._dialect = dialect

    def get(self, conn: Connection, key: str) -> Row | None:
        p = t.user_tool_prefs
        stmt = select(p.c.enabled_write_tools, p.c.enabled_at, p.c.updated_at, p.c.updated_via).where(
            p.c.principal_key == key
        )
        return conn.execute(stmt).one_or_none()

    def upsert(
        self,
        conn: Connection,
        key: str,
        *,
        names_json: str,
        stamps_json: str,
        now: int,
        via: str,
    ) -> None:
        p = t.user_tool_prefs
        stmt = _upsert_insert(self._dialect, p).values(
            principal_key=key,
            enabled_write_tools=names_json,
            enabled_at=stamps_json,
            updated_at=now,
            updated_via=via,
        )
        excluded = stmt.excluded
        conn.execute(
            stmt.on_conflict_do_update(
                index_elements=[p.c.principal_key],
                set_={
                    "enabled_write_tools": excluded.enabled_write_tools,
                    "enabled_at": excluded.enabled_at,
                    "updated_at": excluded.updated_at,
                    "updated_via": excluded.updated_via,
                },
            )
        )


class SqlMetaRepo:
    def schema_version(self, conn: Connection) -> str | None:
        stmt = select(t.meta.c.value).where(t.meta.c.key == "schema_version")
        value = conn.execute(stmt).scalar_one_or_none()
        return None if value is None else str(value)

    def set_schema_version(self, conn: Connection, value: str) -> None:
        exists = self.schema_version(conn) is not None
        if exists:
            conn.execute(update(t.meta).where(t.meta.c.key == "schema_version").values(value=value))
        else:
            conn.execute(insert(t.meta).values(key="schema_version", value=value))


class Repositories:
    """The repositories of one dialect, bundled for the store.

    The attributes are annotated with the interfaces of :mod:`.ports`, so a type
    checker proves the SQL implementations satisfy them.
    """

    def __init__(self, dialect: Dialect) -> None:
        self.dialect: Dialect = dialect
        self.tokens: CanvasTokenRepo = SqlCanvasTokenRepo(dialect)
        self.generations: CredentialGenerationRepo = SqlCredentialGenerationRepo(dialect)
        self.status: PrincipalStatusRepo = SqlPrincipalStatusRepo(dialect)
        self.events: PrincipalEventRepo = SqlPrincipalEventRepo()
        self.prefs: PrefsRepo = SqlPrefsRepo(dialect)
        self.meta: MetaRepo = SqlMetaRepo()


__all__ = [
    "Repositories",
    "SqlCanvasTokenRepo",
    "SqlCredentialGenerationRepo",
    "SqlMetaRepo",
    "SqlPrefsRepo",
    "SqlPrincipalEventRepo",
    "SqlPrincipalStatusRepo",
]
