"""SQLAlchemy Core implementations of the repositories (SQLite and PostgreSQL).

Statements are built with the expression language, so one definition serves both
dialects. Upserts use the dialect's ``insert().on_conflict_do_update`` (both
SQLite and PostgreSQL support ``excluded``). Every value is a bound parameter.
Nothing here begins or ends a transaction.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

from sqlalchemy import Select, delete, func, insert, literal, or_, select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import Connection

from . import schema as t
from .ports import (
    AccountRepo,
    AuditRepo,
    AuthEventRepo,
    CanvasTokenRepo,
    CredentialGenerationRepo,
    IdentityRepo,
    MetaRepo,
    PrefsRepo,
    PrincipalEventRepo,
    Row,
)

Dialect = Literal["sqlite", "postgresql"]

STATUS_ACTIVE = "active"
STATUS_INVALID = "invalid"
STATUS_DISABLED = "disabled"
STATUS_PENDING = "pending"
ROLE_OWNER = "owner"
ROLE_USER = "user"
REASON_DECRYPT_FAILED = "decrypt_failed"

_ct = t.canvas_tokens
_cg = t.credential_generations
_a = t.accounts
_ei = t.external_identities
_ae = t.auth_events
_al = t.audit_log


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
        _ct.c.canvas_user_id,
        _ct.c.canvas_user_name,
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


def _account_columns() -> list[Any]:
    return [
        _a.c.id,
        _a.c.status,
        _a.c.role,
        _a.c.role_source,
        _a.c.role_seen_at,
        _a.c.admitted_via,
        _a.c.display_name,
        _a.c.contact_email,
        _a.c.ui_locale,
        _a.c.created_at,
        _a.c.approved_at,
        _a.c.approved_by,
        _a.c.disabled_reason,
        _a.c.disabled_at,
        _a.c.disabled_by,
        _a.c.last_login_at,
        _a.c.session_epoch,
        _a.c.updated_at,
    ]


def _for_update(stmt: Select[Any], enabled: bool) -> Select[Any]:
    # SQLite has no row locks and renders nothing for FOR UPDATE; on PostgreSQL the
    # global writer lock already serialises writers, so this is defence in depth.
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
            _ct.c.created_at,
            _ct.c.updated_at,
            _ct.c.last_used_at,
            _ct.c.canvas_host,
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
        stmt = select(*_info_columns()).order_by(_ct.c.created_at, _ct.c.principal_key)
        return list(conn.execute(stmt).all())

    def count(self, conn: Connection) -> int:
        return int(conn.execute(select(func.count()).select_from(_ct)).scalar_one())

    def exists(self, conn: Connection, key: str) -> bool:
        return conn.execute(select(_ct.c.principal_key).where(_ct.c.principal_key == key)).first() is not None

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
        stmt = _upsert_insert(self._dialect, _ct).values(
            principal_key=principal_key,
            key_id=key_id,
            nonce=nonce,
            ciphertext=ciphertext,
            canvas_user_id=canvas_user_id,
            canvas_user_name=canvas_user_name,
            created_at=now,
            updated_at=now,
            canvas_host=canvas_host,
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

    def rows_not_under_key(self, conn: Connection, key_id: str) -> list[Row]:
        stmt = select(
            _ct.c.principal_key,
            _ct.c.key_id,
            _ct.c.nonce,
            _ct.c.ciphertext,
            _ct.c.canvas_host,
        ).where(_ct.c.key_id != key_id)
        return list(conn.execute(stmt).all())

    def reseal(
        self,
        conn: Connection,
        *,
        principal_key: str,
        key_id: str,
        nonce: bytes,
        ciphertext: bytes,
    ) -> None:
        conn.execute(
            update(_ct)
            .where(_ct.c.principal_key == principal_key)
            .values(key_id=key_id, nonce=nonce, ciphertext=ciphertext)
        )

    def key_ids_in_use(self, conn: Connection) -> list[str]:
        stmt = select(_ct.c.key_id).distinct().order_by(_ct.c.key_id)
        return [r[0] for r in conn.execute(stmt)]

    def probe_row(self, conn: Connection, key_id: str) -> Row | None:
        stmt = (
            select(_ct.c.principal_key, _ct.c.nonce, _ct.c.ciphertext, _ct.c.canvas_host)
            .where(
                _ct.c.key_id == key_id,
                or_(
                    _ct.c.status != STATUS_INVALID,
                    _ct.c.invalid_reason.is_(None),
                    _ct.c.invalid_reason != REASON_DECRYPT_FAILED,
                ),
            )
            .order_by(_ct.c.principal_key)
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


class SqlAccountRepo:
    def __init__(self, dialect: Dialect) -> None:
        self._dialect = dialect

    def get(self, conn: Connection, account_id: str, *, for_update: bool = False) -> Row | None:
        stmt = _for_update(select(*_account_columns()).where(_a.c.id == account_id), for_update)
        return conn.execute(stmt).one_or_none()

    def get_with_generation(self, conn: Connection, account_id: str) -> tuple[Row | None, int]:
        """One statement, so the account and the generation come from one snapshot."""
        anchor = select(
            literal(account_id, _a.c.id.type).label("account_id"),
            literal(f"acct:{account_id}", _cg.c.principal_key.type).label("principal_key"),
        ).subquery("anchor")
        stmt = select(*_account_columns(), _cg.c.generation.label("credential_generation")).select_from(
            anchor.outerjoin(_a, _a.c.id == anchor.c.account_id).outerjoin(
                _cg, _cg.c.principal_key == anchor.c.principal_key
            )
        )
        row = conn.execute(stmt).one()
        generation = 0 if row[-1] is None else int(row[-1])
        account_row = None if row[0] is None else tuple(row[:-1])
        return account_row, generation

    def list_all(self, conn: Connection) -> list[Row]:
        return list(conn.execute(select(*_account_columns()).order_by(_a.c.created_at, _a.c.id)).all())

    def count_active_owners(self, conn: Connection, *, exclude: str | None = None) -> int:
        stmt = select(func.count()).select_from(_a).where(
            _a.c.role == ROLE_OWNER, _a.c.status == STATUS_ACTIVE
        )
        if exclude is not None:
            stmt = stmt.where(_a.c.id != exclude)
        return int(conn.execute(stmt).scalar_one())

    def count_pending(self, conn: Connection) -> int:
        stmt = select(func.count()).select_from(_a).where(_a.c.status == STATUS_PENDING)
        return int(conn.execute(stmt).scalar_one())

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
    ) -> None:
        conn.execute(
            insert(_a).values(
                id=account_id,
                status=status,
                role=role,
                role_source=role_source,
                role_seen_at=now if role == ROLE_OWNER else None,
                admitted_via=admitted_via,
                display_name=display_name,
                created_at=now,
                approved_at=now if status == STATUS_ACTIVE and approved_by is not None else None,
                approved_by=approved_by,
                disabled_reason=disabled_reason,
                disabled_at=now if status == STATUS_DISABLED else None,
                disabled_by=disabled_by,
                session_epoch=1 if status == STATUS_DISABLED else 0,
                updated_at=now,
            )
        )

    def activate(
        self,
        conn: Connection,
        account_id: str,
        *,
        admitted_via: str,
        approved_by: str | None,
        now: int,
    ) -> bool:
        result = conn.execute(
            update(_a)
            .where(_a.c.id == account_id, _a.c.status == STATUS_PENDING)
            .values(
                status=STATUS_ACTIVE,
                admitted_via=admitted_via,
                approved_at=now,
                approved_by=approved_by,
                updated_at=now,
            )
        )
        return result.rowcount > 0

    def disable(
        self, conn: Connection, account_id: str, *, reason: str, by: str, now: int
    ) -> int:
        conn.execute(
            update(_a)
            .where(_a.c.id == account_id)
            .values(
                status=STATUS_DISABLED,
                disabled_reason=reason,
                disabled_at=now,
                disabled_by=by,
                session_epoch=_a.c.session_epoch + 1,
                updated_at=now,
            )
        )
        return self._epoch(conn, account_id)

    def enable(self, conn: Connection, account_id: str, now: int) -> int:
        conn.execute(
            update(_a)
            .where(_a.c.id == account_id)
            .values(
                status=STATUS_ACTIVE,
                disabled_reason=None,
                disabled_at=None,
                disabled_by=None,
                session_epoch=_a.c.session_epoch + 1,
                updated_at=now,
            )
        )
        return self._epoch(conn, account_id)

    @staticmethod
    def _epoch(conn: Connection, account_id: str) -> int:
        return int(conn.execute(select(_a.c.session_epoch).where(_a.c.id == account_id)).scalar_one())

    def set_role(
        self,
        conn: Connection,
        account_id: str,
        *,
        role: str,
        source: str | None,
        seen_at: int | None,
        now: int,
    ) -> None:
        conn.execute(
            update(_a)
            .where(_a.c.id == account_id)
            .values(role=role, role_source=source, role_seen_at=seen_at, updated_at=now)
        )

    def mark_role_seen(self, conn: Connection, account_id: str, now: int) -> None:
        conn.execute(
            update(_a).where(_a.c.id == account_id).values(role_seen_at=now, updated_at=now)
        )

    def touch_login(
        self, conn: Connection, account_id: str, *, display_name: str, now: int
    ) -> None:
        values: dict[str, Any] = {"last_login_at": now}
        if display_name:
            values["display_name"] = display_name
        conn.execute(update(_a).where(_a.c.id == account_id).values(**values))

    def purge_pending(self, conn: Connection, older_than: int) -> list[str]:
        ids = [
            r[0]
            for r in conn.execute(
                select(_a.c.id).where(_a.c.status == STATUS_PENDING, _a.c.created_at < older_than)
            )
        ]
        if ids:
            conn.execute(delete(_a).where(_a.c.id.in_(ids), _a.c.status == STATUS_PENDING))
        return ids


class SqlIdentityRepo:
    def lookup(
        self, conn: Connection, provider_id: str, issuer: str, subject: str
    ) -> str | None:
        stmt = select(_ei.c.account_id).where(
            _ei.c.provider_id == provider_id,
            _ei.c.issuer == issuer,
            _ei.c.subject == subject,
        )
        value = conn.execute(stmt).scalar_one_or_none()
        return None if value is None else str(value)

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
    ) -> None:
        conn.execute(
            insert(_ei).values(
                account_id=account_id,
                provider_id=provider_id,
                issuer=issuer,
                subject=subject,
                username=username or None,
                email=email,
                email_verified=1 if email_verified else 0,
                linked_at=now,
            )
        )

    def touch(
        self,
        conn: Connection,
        provider_id: str,
        issuer: str,
        subject: str,
        *,
        username: str,
        now: int,
    ) -> None:
        values: dict[str, Any] = {"last_login_at": now}
        if username:
            values["username"] = username
        conn.execute(
            update(_ei)
            .where(
                _ei.c.provider_id == provider_id,
                _ei.c.issuer == issuer,
                _ei.c.subject == subject,
            )
            .values(**values)
        )

    def for_account(self, conn: Connection, account_id: str) -> list[Row]:
        stmt = (
            select(
                _ei.c.provider_id,
                _ei.c.issuer,
                _ei.c.subject,
                _ei.c.username,
                _ei.c.email,
                _ei.c.email_verified,
                _ei.c.linked_at,
                _ei.c.last_login_at,
            )
            .where(_ei.c.account_id == account_id)
            .order_by(_ei.c.id)
        )
        return list(conn.execute(stmt).all())

    def all(self, conn: Connection) -> list[Row]:
        stmt = select(
            _ei.c.account_id, _ei.c.provider_id, _ei.c.issuer, _ei.c.subject, _ei.c.username
        ).order_by(_ei.c.id)
        return list(conn.execute(stmt).all())

    def delete_for_accounts(self, conn: Connection, account_ids: Sequence[str]) -> None:
        if account_ids:
            conn.execute(delete(_ei).where(_ei.c.account_id.in_(list(account_ids))))


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


class SqlAuthEventRepo:
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
    ) -> None:
        conn.execute(
            insert(_ae).values(
                at=now,
                account_id=account_id,
                provider_id=provider_id,
                surface=surface,
                outcome=outcome,
                reason=reason,
                ip=ip,
                ua_hash=ua_hash,
            )
        )

    def list_for_account(self, conn: Connection, account_id: str, limit: int) -> list[Row]:
        stmt = (
            select(
                _ae.c.id,
                _ae.c.at,
                _ae.c.provider_id,
                _ae.c.surface,
                _ae.c.outcome,
                _ae.c.reason,
                _ae.c.ip,
                _ae.c.ua_hash,
            )
            .where(_ae.c.account_id == account_id)
            .order_by(_ae.c.id.desc())
            .limit(limit)
        )
        return list(conn.execute(stmt).all())

    def prune_before(self, conn: Connection, cutoff: int) -> int:
        return int(conn.execute(delete(_ae).where(_ae.c.at < cutoff)).rowcount or 0)


class SqlAuditRepo:
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
    ) -> None:
        conn.execute(
            insert(_al).values(
                at=now, actor=actor, action=action, target=target, reason=reason, detail=detail
            )
        )

    def list(self, conn: Connection, limit: int, before_id: int | None) -> list[Row]:
        stmt = select(
            _al.c.id, _al.c.at, _al.c.actor, _al.c.action, _al.c.target, _al.c.reason, _al.c.detail
        )
        if before_id is not None:
            stmt = stmt.where(_al.c.id < before_id)
        stmt = stmt.order_by(_al.c.id.desc()).limit(limit)
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
        self.accounts: AccountRepo = SqlAccountRepo(dialect)
        self.identities: IdentityRepo = SqlIdentityRepo()
        self.events: PrincipalEventRepo = SqlPrincipalEventRepo()
        self.auth_events: AuthEventRepo = SqlAuthEventRepo()
        self.audit: AuditRepo = SqlAuditRepo()
        self.prefs: PrefsRepo = SqlPrefsRepo(dialect)
        self.meta: MetaRepo = SqlMetaRepo()


__all__ = [
    "Repositories",
    "SqlAccountRepo",
    "SqlAuditRepo",
    "SqlAuthEventRepo",
    "SqlCanvasTokenRepo",
    "SqlCredentialGenerationRepo",
    "SqlIdentityRepo",
    "SqlMetaRepo",
    "SqlPrefsRepo",
    "SqlPrincipalEventRepo",
]
