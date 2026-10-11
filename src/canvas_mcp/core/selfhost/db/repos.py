"""Portable v1 repositories; every result is a frozen record with named fields.

Repositories never own transaction boundaries. The caller supplies the connection
and chooses the row-conditional or governance tier before calling a statement.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal, cast

from sqlalchemy import Select, and_, delete, false, func, insert, or_, select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import Connection

from . import schema as t
from .authz_repos import (
    SqlAuthCodeRepo,
    SqlCimdRepo,
    SqlGrantRepo,
    SqlJwtEpochRepo,
    SqlLoginStateRepo,
    SqlOAuthClientRepo,
    SqlRefreshRepo,
)
from .rows import (
    AccountRow,
    AuditRow,
    AuthEventRow,
    CredentialRow,
    IdentityRow,
    WriteToolRow,
)
from .types import new_id

Dialect = Literal["sqlite", "postgresql"]
SIGN_IN_SURFACES = ("account",)
STATUS_ACTIVE = "active"
STATUS_INVALID = "invalid"
STATUS_DISABLED = "disabled"
STATUS_PENDING = "pending"
ROLE_OWNER = "owner"
ROLE_SOURCE_RULES = "rules"
PROVIDER_ENTRA = "entra"
REASON_DECRYPT_FAILED = "decrypt_failed"
_a = t.accounts
_ct = t.canvas_credentials
_ei = t.external_identities
_ae = t.auth_events
_al = t.audit_log


def _upsert_insert(dialect: Dialect, table: Any) -> Any:
    return (postgresql.insert if dialect == "postgresql" else sqlite.insert)(table)


def _actor_id(value: str | None) -> str | None:
    return None if value is None or value in ("operator", "system") else value


def _for_update(stmt: Select[Any], enabled: bool) -> Select[Any]:
    return stmt.with_for_update(key_share=True) if enabled else stmt


class SqlCredentialGenerationRepo:
    def bump(
        self,
        conn: Connection,
        key: str,
        reason: str,
        now: int,
        *,
        writing: str | None = None,
    ) -> int:
        generation = int(
            conn.execute(
                update(_a)
                .where(_a.c.id == key)
                .values(
                    credential_generation=_a.c.credential_generation + 1, updated_at=now
                )
                .returning(_a.c.credential_generation)
            ).scalar_one()
        )
        stmt = update(_ct).where(_ct.c.account_id == key)
        if writing is not None:
            stmt = stmt.where(_ct.c.id != writing)
        conn.execute(stmt.values(generation=generation))
        return generation

    def get(self, conn: Connection, key: str) -> int:
        value = conn.execute(
            select(_a.c.credential_generation).where(_a.c.id == key)
        ).scalar_one_or_none()
        return 0 if value is None else int(value)


class SqlAccountRepo:
    def __init__(self, dialect: Dialect) -> None:
        self._dialect = dialect

    def get(
        self, conn: Connection, account_id: str, *, for_update: bool = False
    ) -> AccountRow | None:
        stmt = _for_update(select(_a).where(_a.c.id == account_id), for_update)
        row = conn.execute(stmt).mappings().one_or_none()
        return None if row is None else AccountRow(**row)


    def count_active_owners(
        self, conn: Connection, *, exclude: str | None = None
    ) -> int:
        stmt = (
            select(func.count())
            .select_from(_a)
            .where(_a.c.role == ROLE_OWNER, _a.c.status == STATUS_ACTIVE)
        )
        if exclude is not None:
            stmt = stmt.where(_a.c.id != exclude)
        return int(conn.execute(stmt).scalar_one())

    def usable_owner_ids(
        self,
        conn: Connection,
        provider_ids: Sequence[str] | None,
        *,
        exclude: str | None = None,
        for_update: bool = False,
    ) -> list[str]:
        """The ids of the usable owners: active owners that can still get an owner session.

        ``provider_ids`` are the listed sign-in providers (None: every provider counts as
        listed). An owner whose role the Entra owner rules granted (``role_source`` ``rules``)
        needs an Entra sign-in to show owner evidence, so it counts only while Entra is listed
        and it holds an Entra identity; any other owner needs one identity at a listed provider.
        This is :func:`accounts.owner_is_usable` as a statement; a test keeps the two equal.
        ``for_update`` locks the rows (PostgreSQL), ``exclude`` leaves one account out.
        """

        def holds(*conditions: Any) -> Any:
            return (
                select(_ei.c.account_id)
                .where(_ei.c.account_id == _a.c.id, *conditions)
                .exists()
            )

        listed = None if provider_ids is None else list(provider_ids)
        if listed is None:
            any_listed = holds()
            entra = holds(_ei.c.provider_id == PROVIDER_ENTRA)
        else:
            any_listed = holds(_ei.c.provider_id.in_(listed))
            entra = (
                holds(_ei.c.provider_id == PROVIDER_ENTRA)
                if PROVIDER_ENTRA in listed
                else false()
            )
        stmt = select(_a.c.id).where(
            _a.c.role == ROLE_OWNER,
            _a.c.status == STATUS_ACTIVE,
            or_(
                and_(_a.c.role_source == ROLE_SOURCE_RULES, entra),
                and_(
                    or_(
                        _a.c.role_source.is_(None),
                        _a.c.role_source != ROLE_SOURCE_RULES,
                    ),
                    any_listed,
                ),
            ),
        )
        if exclude is not None:
            stmt = stmt.where(_a.c.id != exclude)
        return [
            str(r[0])
            for r in conn.execute(_for_update(stmt.order_by(_a.c.id), for_update)).all()
        ]

    def count_usable_owners(
        self, conn: Connection, provider_ids: Sequence[str] | None
    ) -> int:
        return len(self.usable_owner_ids(conn, provider_ids))

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
                approved_at=now
                if status == STATUS_ACTIVE and approved_by is not None
                else None,
                approved_by=_actor_id(approved_by),
                disabled_reason=disabled_reason,
                disabled_at=now if status == STATUS_DISABLED else None,
                disabled_by=_actor_id(disabled_by),
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
                approved_by=_actor_id(approved_by),
                updated_at=now,
            )
        )
        return result.rowcount > 0

    def disable(
        self, conn: Connection, account_id: str, *, reason: str, by: str, now: int
    ) -> int:
        result = conn.execute(
            update(_a)
            .where(_a.c.id == account_id)
            .values(
                status=STATUS_DISABLED,
                disabled_reason=reason,
                disabled_at=now,
                disabled_by=_actor_id(by),
                session_epoch=_a.c.session_epoch + 1,
                updated_at=now,
            )
            .returning(_a.c.session_epoch)
        )
        return int(result.scalar_one())

    def enable(self, conn: Connection, account_id: str, now: int) -> int:
        result = conn.execute(
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
            .returning(_a.c.session_epoch)
        )
        return int(result.scalar_one())

    def end_sessions(self, conn: Connection, account_id: str, now: int) -> int:
        result = conn.execute(
            update(_a)
            .where(_a.c.id == account_id)
            .values(session_epoch=_a.c.session_epoch + 1, updated_at=now)
            .returning(_a.c.session_epoch)
        )
        return int(result.scalar_one())

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

    def set_admitted_via(
        self, conn: Connection, account_id: str, admitted_via: str, now: int
    ) -> None:
        conn.execute(
            update(_a)
            .where(_a.c.id == account_id)
            .values(admitted_via=admitted_via, updated_at=now)
        )

    def mark_role_seen(self, conn: Connection, account_id: str, now: int) -> None:
        conn.execute(
            update(_a)
            .where(_a.c.id == account_id)
            .values(role_seen_at=now, updated_at=now)
        )

    def touch_login(
        self, conn: Connection, account_id: str, *, display_name: str, now: int
    ) -> None:
        values: dict[str, Any] = {"last_login_at": now}
        if display_name:
            values["display_name"] = display_name
        conn.execute(update(_a).where(_a.c.id == account_id).values(**values))


class SqlIdentityRepo:
    def lookup(
        self, conn: Connection, provider_id: str, issuer: str, subject: str
    ) -> str | None:
        return conn.execute(
            select(_ei.c.account_id).where(
                _ei.c.provider_id == provider_id,
                _ei.c.issuer == issuer,
                _ei.c.subject == subject,
            )
        ).scalar_one_or_none()

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
        SqlProviderRepo(cast(Dialect, conn.dialect.name)).ensure(
            conn, provider_id, now=now
        )
        conn.execute(
            insert(_ei).values(
                id=new_id(),
                account_id=account_id,
                provider_id=provider_id,
                issuer=issuer,
                subject=subject,
                username=username or None,
                email=email,
                email_verified=email_verified,
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
        email: str | None = None,
        email_verified: bool | None = None,
    ) -> None:
        values: dict[str, Any] = {"last_login_at": now}
        if username:
            values["username"] = username
        if email is not None:
            values["email"] = email
            values["email_verified"] = bool(email_verified)
        conn.execute(
            update(_ei)
            .where(
                _ei.c.provider_id == provider_id,
                _ei.c.issuer == issuer,
                _ei.c.subject == subject,
            )
            .values(**values)
        )

    def for_account(self, conn: Connection, account_id: str) -> list[IdentityRow]:
        return [
            IdentityRow(**row)
            for row in conn.execute(
                select(_ei).where(_ei.c.account_id == account_id).order_by(_ei.c.id)
            ).mappings()
        ]

    def get_for_account(
        self,
        conn: Connection,
        identity_id: str,
        account_id: str,
        *,
        for_update: bool = False,
    ) -> IdentityRow | None:
        row = (
            conn.execute(
                _for_update(
                    select(_ei).where(
                        _ei.c.id == identity_id, _ei.c.account_id == account_id
                    ),
                    for_update,
                )
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else IdentityRow(**row)

    def account_of(self, conn: Connection, identity_id: str) -> str | None:
        return conn.execute(
            select(_ei.c.account_id).where(_ei.c.id == identity_id)
        ).scalar_one_or_none()

    def count_for_account(self, conn: Connection, account_id: str) -> int:
        return int(
            conn.execute(
                select(func.count())
                .select_from(_ei)
                .where(_ei.c.account_id == account_id)
            ).scalar_one()
        )

    def count_for_provider(
        self, conn: Connection, account_id: str, provider_id: str
    ) -> int:
        return int(
            conn.execute(
                select(func.count())
                .select_from(_ei)
                .where(_ei.c.account_id == account_id, _ei.c.provider_id == provider_id)
            ).scalar_one()
        )

    def delete_one(self, conn: Connection, identity_id: str, account_id: str) -> bool:
        return (
            conn.execute(
                delete(_ei).where(
                    _ei.c.id == identity_id, _ei.c.account_id == account_id
                )
            ).rowcount
            == 1
        )


class SqlProviderRepo:
    def __init__(self, dialect: Dialect) -> None:
        self._dialect = dialect

    def ensure(self, conn: Connection, identifier: str, *, now: int) -> None:
        protocol = "oidc" if identifier.startswith("oidc:") else identifier
        stmt = _upsert_insert(self._dialect, t.login_providers).values(
            id=identifier, protocol=protocol, created_at=now, updated_at=now
        )
        conn.execute(
            stmt.on_conflict_do_nothing(index_elements=[t.login_providers.c.id])
        )

    def reconcile(
        self, conn: Connection, identifiers: Sequence[str], *, now: int
    ) -> bool:
        p = t.login_providers
        changed = False
        for rank, identifier in enumerate(identifiers):
            self.ensure(conn, identifier, now=now)
            result = conn.execute(
                update(p)
                .where(
                    p.c.id == identifier,
                    p.c.config_source == "env",
                    or_(p.c.configured == false(), p.c.sort_rank != rank),
                )
                .values(
                    configured=True, sort_rank=rank, configured_at=now, updated_at=now
                )
            )
            changed = changed or result.rowcount > 0
        result = conn.execute(
            update(p)
            .where(
                p.c.config_source == "env", p.c.configured, p.c.id.not_in(identifiers)
            )
            .values(configured=False, updated_at=now)
        )
        changed = changed or result.rowcount > 0
        if changed:
            conn.execute(
                update(t.server_state)
                .where(t.server_state.c.id == 1)
                .values(
                    settings_revision=t.server_state.c.settings_revision + 1,
                    updated_at=now,
                )
            )
        return changed

    def configured(self, conn: Connection) -> frozenset[str]:
        return frozenset(
            conn.execute(
                select(t.login_providers.c.id).where(t.login_providers.c.configured)
            ).scalars()
        )


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
        ua_hash: bytes | None,
    ) -> None:
        conn.execute(
            insert(_ae).values(
                at=now,
                account_id=account_id,
                provider_id=provider_id,
                surface=surface,
                outcome=outcome,
                reason=reason,
                ua_hash=ua_hash,
            )
        )

    def list_for_account(
        self,
        conn: Connection,
        account_id: str,
        limit: int,
        *,
        before_id: int | None = None,
    ) -> list[AuthEventRow]:
        stmt = (
            select(_ae)
            .where(_ae.c.account_id == account_id, _ae.c.surface.in_(SIGN_IN_SURFACES))
            .order_by(_ae.c.id.desc())
            .limit(limit)
        )
        if before_id is not None:
            stmt = stmt.where(_ae.c.id < before_id)
        return [AuthEventRow(**row) for row in conn.execute(stmt).mappings()]


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
        detail: Mapping[str, Any],
        target_kind: str = "account",
        subject_account_id: str | None = None,
    ) -> None:
        kind = actor if actor in ("operator", "system") else "account"
        conn.execute(
            insert(_al).values(
                at=now,
                actor_kind=kind,
                actor_id=_actor_id(actor),
                subject_account_id=target
                if target_kind == "account"
                else subject_account_id,
                action=action,
                target_kind=target_kind if target else None,
                target_id=target,
                reason=reason,
                detail=dict(detail),
            )
        )

    def list(
        self,
        conn: Connection,
        limit: int,
        before_id: int | None,
        *,
        account_id: str | None = None,
    ) -> list[AuditRow]:
        stmt = select(_al)
        if before_id is not None:
            stmt = stmt.where(_al.c.id < before_id)
        if account_id is not None:
            stmt = stmt.where(_al.c.subject_account_id == account_id)
        return [
            AuditRow(**row)
            for row in conn.execute(
                stmt.order_by(_al.c.id.desc()).limit(limit)
            ).mappings()
        ]


class SqlPrefsRepo:
    def get(self, conn: Connection, key: str) -> list[WriteToolRow]:
        p = t.account_write_tools
        return [
            WriteToolRow(**row)
            for row in conn.execute(
                select(p).where(p.c.account_id == key).order_by(p.c.tool_name)
            ).mappings()
        ]

    def replace(
        self,
        conn: Connection,
        key: str,
        *,
        stamps: Mapping[str, int],
        now: int,
        via: str,
    ) -> int:
        p = t.account_write_tools
        conn.execute(delete(p).where(p.c.account_id == key))
        if stamps:
            conn.execute(
                insert(p),
                [
                    {
                        "account_id": key,
                        "tool_name": name,
                        "enabled_at": stamp,
                        "enabled_via": via,
                    }
                    for name, stamp in sorted(stamps.items())
                ],
            )
        return int(
            conn.execute(
                update(_a)
                .where(_a.c.id == key)
                .values(
                    write_tools_version=_a.c.write_tools_version + 1, updated_at=now
                )
                .returning(_a.c.write_tools_version)
            ).scalar_one()
        )


class SqlCanvasCredentialRepo:
    def acknowledge(
        self, conn: Connection, account_id: str, *, version: int, now: int
    ) -> None:
        conn.execute(
            update(_ct)
            .where(_ct.c.account_id == account_id, _ct.c.is_primary)
            .values(custody_notice_version=version, custody_ack_at=now, updated_at=now)
        )

    def __init__(self, dialect: Dialect) -> None:
        self._dialect = dialect

    def primary(self, conn: Connection, account_id: str) -> CredentialRow | None:
        row = (
            conn.execute(
                select(_ct).where(_ct.c.account_id == account_id, _ct.c.is_primary)
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else CredentialRow(**row)

    def at_host(
        self, conn: Connection, account_id: str, host: str
    ) -> CredentialRow | None:
        row = (
            conn.execute(
                select(_ct).where(
                    _ct.c.account_id == account_id, _ct.c.canvas_host == host
                )
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else CredentialRow(**row)


    def count(self, conn: Connection) -> int:
        return int(conn.execute(select(func.count()).select_from(_ct)).scalar_one())

    def ensure_school(
        self, conn: Connection, host: str, *, account_id: str, now: int
    ) -> None:
        school = t.canvas_schools
        stmt = _upsert_insert(self._dialect, school).values(
            host=host,
            origin="user",
            created_at=now,
            updated_at=now,
            created_by=account_id,
        )
        # Lock an existing parent before credential insertion. An orphan cull
        # skips this row, and a put that follows a cull inserts a fresh parent.
        conn.execute(
            stmt.on_conflict_do_update(
                index_elements=[school.c.host], set_={"updated_at": now}
            )
        )

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
    ) -> None:
        # v1 has exactly one credential per account. Its same-host id and creation
        # time survive replacement; changing schools removes the former row.
        conn.execute(
            delete(_ct).where(_ct.c.account_id == account_id, _ct.c.id != identifier)
        )
        stmt = _upsert_insert(self._dialect, _ct).values(
            id=identifier,
            account_id=account_id,
            canvas_host=canvas_host,
            kind="pat",
            is_primary=True,
            generation=generation,
            key_id=key_id,
            nonce=nonce,
            ciphertext=ciphertext,
            canvas_user_id=canvas_user_id,
            canvas_user_name=canvas_user_name,
            created_at=now,
            updated_at=now,
            status="active",
            last_verified_at=now,
            expires_hint_at=expires_hint_at,
            custody_notice_version=custody_notice_version,
            custody_ack_at=custody_ack_at,
        )
        fields = {
            name: stmt.excluded[name]
            for name in (
                "canvas_host",
                "kind",
                "is_primary",
                "generation",
                "key_id",
                "nonce",
                "ciphertext",
                "canvas_user_id",
                "canvas_user_name",
                "updated_at",
                "status",
                "last_verified_at",
                "expires_hint_at",
                "custody_notice_version",
                "custody_ack_at",
            )
        }
        fields.update(
            invalid_reason=None,
            invalid_since=None,
            oauth_app_id=None,
            access_expires_at=None,
            scopes=None,
        )
        conn.execute(stmt.on_conflict_do_update(index_elements=[_ct.c.id], set_=fields))

    def delete(self, conn: Connection, account_id: str) -> bool:
        return (
            conn.execute(delete(_ct).where(_ct.c.account_id == account_id)).rowcount > 0
        )

    @staticmethod
    def _guard(
        stmt: Any, expected_updated_at: int | None, expected_generation: int | None
    ) -> Any:
        if expected_updated_at is not None:
            stmt = stmt.where(_ct.c.updated_at == expected_updated_at)
        if expected_generation is not None:
            stmt = stmt.where(_ct.c.generation == expected_generation)
        return stmt

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
            .where(
                _ct.c.account_id == key, _ct.c.is_primary, _ct.c.status == STATUS_ACTIVE
            )
            .values(status=STATUS_INVALID, invalid_reason=reason, invalid_since=now)
        )
        return (
            conn.execute(
                self._guard(stmt, expected_updated_at, expected_generation)
            ).rowcount
            == 1
        )

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
            .where(
                _ct.c.account_id == key,
                _ct.c.is_primary,
                _ct.c.status == STATUS_INVALID,
            )
            .values(
                status=STATUS_ACTIVE,
                invalid_reason=None,
                invalid_since=None,
                last_verified_at=now,
            )
        )
        return (
            conn.execute(
                self._guard(stmt, expected_updated_at, expected_generation)
            ).rowcount
            == 1
        )

    def touch(self, conn: Connection, key: str, now: int, older_than: int) -> None:
        candidate = (
            select(_ct.c.id)
            .where(
                _ct.c.account_id == key,
                _ct.c.is_primary,
                or_(_ct.c.last_used_at.is_(None), _ct.c.last_used_at < older_than),
            )
            .with_for_update(key_share=True, skip_locked=True)
            .scalar_subquery()
        )
        conn.execute(update(_ct).where(_ct.c.id == candidate).values(last_used_at=now))

    def mark_verified(
        self,
        conn: Connection,
        key: str,
        *,
        now: int,
        older_than: int,
        expected_generation: int | None,
    ) -> bool:
        candidate = select(_ct.c.id).where(
            _ct.c.account_id == key,
            _ct.c.is_primary,
            _ct.c.status == STATUS_ACTIVE,
            or_(_ct.c.last_verified_at.is_(None), _ct.c.last_verified_at < older_than),
        )
        if expected_generation is not None:
            candidate = candidate.where(_ct.c.generation == expected_generation)
        identifier = candidate.with_for_update(
            key_share=True, skip_locked=True
        ).scalar_subquery()
        return (
            conn.execute(
                update(_ct).where(_ct.c.id == identifier).values(last_verified_at=now)
            ).rowcount
            == 1
        )

    def rows_not_under_key(self, conn: Connection, key_id: str) -> list[CredentialRow]:
        return [
            CredentialRow(**row)
            for row in conn.execute(
                select(_ct).where(_ct.c.key_id != key_id).order_by(_ct.c.id)
            ).mappings()
        ]

    def reseal(
        self,
        conn: Connection,
        *,
        identifier: str,
        key_id: str,
        nonce: bytes,
        ciphertext: bytes,
    ) -> None:
        conn.execute(
            update(_ct)
            .where(_ct.c.id == identifier)
            .values(key_id=key_id, nonce=nonce, ciphertext=ciphertext)
        )

    def key_ids_in_use(self, conn: Connection) -> list[str]:
        return list(
            conn.execute(
                select(_ct.c.key_id).distinct().order_by(_ct.c.key_id)
            ).scalars()
        )

    def probe_row(self, conn: Connection, key_id: str) -> CredentialRow | None:
        stmt = (
            select(_ct)
            .where(
                _ct.c.key_id == key_id,
                or_(
                    _ct.c.status != STATUS_INVALID,
                    _ct.c.invalid_reason.is_(None),
                    _ct.c.invalid_reason != REASON_DECRYPT_FAILED,
                ),
            )
            .order_by(_ct.c.id)
            .limit(1)
        )
        row = conn.execute(stmt).mappings().one_or_none()
        return None if row is None else CredentialRow(**row)


class Repositories:
    """Stateless statement bundles for the caller's selected database dialect."""

    def __init__(self, dialect: Dialect) -> None:
        self.dialect = dialect
        self.credentials = SqlCanvasCredentialRepo(dialect)
        self.generations = SqlCredentialGenerationRepo()
        self.accounts = SqlAccountRepo(dialect)
        self.identities = SqlIdentityRepo()
        self.providers = SqlProviderRepo(dialect)
        self.auth_events = SqlAuthEventRepo()
        self.audit = SqlAuditRepo()
        self.prefs = SqlPrefsRepo()
        self.clients = SqlOAuthClientRepo()
        self.cimd = SqlCimdRepo(dialect)
        self.grants = SqlGrantRepo()
        self.codes = SqlAuthCodeRepo()
        self.refresh = SqlRefreshRepo()
        self.login_states = SqlLoginStateRepo()
        self.jwt_epoch = SqlJwtEpochRepo()
