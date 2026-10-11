"""SQLAlchemy Core repositories of the self-hosted authorization server.

Same rules as :mod:`.repos`: stateless, one definition for SQLite and PostgreSQL, a
caller-owned ``Connection``, no transaction handling. The transaction boundaries live in
``authz/store.py``.

Every statement that *consumes* something (a login state, an authorization code, a
refresh token, a revocation) is one conditional ``UPDATE``/``DELETE`` whose ``WHERE``
holds the condition ("not yet used", "not yet revoked", "not yet expired"), and the
caller acts on ``rowcount == 1``. That is what makes it atomic on both backends: on SQLite
the write lock serialises the transactions; on PostgreSQL the second writer blocks on the
row lock and then re-evaluates the ``WHERE`` against the committed row, so it matches
nothing. No statement here reads a row and writes it back in a second statement where a
concurrent transaction could slip in between.

Rows are frozen records with named fields; the database driver row never escapes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import delete, exists, insert, or_, select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import Connection

from ..authz.models import (
    CimdSnapshot,
    ClientRecord,
    CodeRecord,
    GrantRecord,
    GrantStatus,
    RefreshView,
    split_scopes,
)
from . import schema as t

Dialect = Literal["sqlite", "postgresql"]


def _upsert_insert(dialect: Dialect, table: Any) -> Any:
    return (postgresql.insert if dialect == "postgresql" else sqlite.insert)(table)


_oc = t.oauth_clients
_cc = t.cimd_clients
_g = t.oauth_grants
_c = t.oauth_codes
_r = t.oauth_refresh_tokens
_ls = t.login_states
_a = t.accounts
_s = t.server_state


@dataclass(frozen=True)
class RefreshTokenRecord:
    token_hash: str
    grant_id: str
    parent_hash: str | None
    created_at: int
    used_at: int | None
    replaced_by: str | None
    grace_replays: int


def _hash(value: str | None) -> bytes | None:
    return None if value is None else bytes.fromhex(value)


def _grant(row: Any) -> GrantRecord:
    fields = dict(row)
    fields["scopes"] = split_scopes(fields["scopes"])
    return GrantRecord(**fields)


def _code(row: Any) -> CodeRecord | None:
    if row is None:
        return None
    fields = dict(row)
    fields["code_hash"] = bytes(fields["code_hash"]).hex()
    fields["scopes"] = split_scopes(fields["scopes"])
    return CodeRecord(**fields)


def _refresh(row: Any) -> RefreshTokenRecord | None:
    if row is None:
        return None
    fields = dict(row)
    for key in ("token_hash", "parent_hash", "replaced_by"):
        fields[key] = None if fields[key] is None else bytes(fields[key]).hex()
    return RefreshTokenRecord(**fields)


def _by(value: str) -> str | None:
    return None if value in ("system", "operator") else value


class SqlOAuthClientRepo:
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
    ) -> None:
        conn.execute(
            insert(_oc).values(
                id=client_id,
                info=json.loads(info_json),
                client_name=client_name,
                created_at=now,
                expires_at=expires_at,
            )
        )

    def get(self, conn: Connection, client_id: str) -> ClientRecord | None:
        row = (
            conn.execute(select(_oc).where(_oc.c.id == client_id))
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        return ClientRecord(
            client_id=row["id"],
            info=row["info"],
            client_name=row["client_name"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
        )

    def extend(self, conn: Connection, client_id: str, expires_at: int) -> bool:
        """Raise the expiry; never lowers it."""
        stmt = (
            update(_oc)
            .where(_oc.c.id == client_id, _oc.c.expires_at < expires_at)
            .values(expires_at=expires_at)
        )
        return conn.execute(stmt).rowcount == 1


class SqlCimdRepo:
    """``cimd_clients``: the last known good client metadata documents."""

    def __init__(self, dialect: Dialect) -> None:
        self._dialect = dialect

    def get(self, conn: Connection, url: str) -> CimdSnapshot | None:
        row = conn.execute(select(_cc).where(_cc.c.url == url)).mappings().one_or_none()
        if row is None:
            return None
        return CimdSnapshot(
            url=row["url"],
            doc=row["doc"],
            fetched_at=row["fetched_at"],
            fresh_until=row["fresh_until"],
            last_error_at=row["last_error_at"],
            last_error=row["last_error"],
        )

    def upsert(
        self,
        conn: Connection,
        *,
        url: str,
        doc_json: str,
        fetched_at: int,
        fresh_until: int,
    ) -> bool:
        """Store a document unless a newer one is stored; True if this call wrote.

        Monotonic: a fetch that finished late (an older ``fetched_at``) never overwrites
        a newer document (nor one fetched in the same second). The comparison is part of
        the one statement.
        """
        stmt = _upsert_insert(self._dialect, _cc).values(
            url=url,
            doc=json.loads(doc_json),
            fetched_at=fetched_at,
            fresh_until=fresh_until,
            last_error_at=None,
            last_error=None,
        )
        excluded = stmt.excluded
        stmt = stmt.on_conflict_do_update(
            index_elements=[_cc.c.url],
            set_={
                "doc": excluded.doc,
                "fetched_at": excluded.fetched_at,
                "fresh_until": excluded.fresh_until,
                "last_error_at": None,
                "last_error": None,
            },
            where=excluded.fetched_at > _cc.c.fetched_at,
        ).returning(_cc.c.url)
        # RETURNING, not rowcount: the PostgreSQL driver reports -1 for an upsert. A row
        # comes back only if the row was inserted or really updated.
        return conn.execute(stmt).first() is not None

    def record_error(self, conn: Connection, url: str, *, now: int, code: str) -> bool:
        """Note why the last refresh failed; only for a URL that has a stored document."""
        stmt = (
            update(_cc)
            .where(_cc.c.url == url)
            .values(last_error_at=now, last_error=code)
        )
        return conn.execute(stmt).rowcount == 1


class SqlGrantRepo:
    """``oauth_grants``: one row per connection of an app to an account."""

    def insert(self, conn: Connection, **fields: Any) -> None:
        conn.execute(insert(_g).values(**fields))

    def get(self, conn: Connection, grant_id: str) -> GrantRecord | None:
        row = (
            conn.execute(select(_g).where(_g.c.id == grant_id)).mappings().one_or_none()
        )
        return None if row is None else _grant(row)

    def status_row(self, conn: Connection, grant_id: str) -> GrantStatus:
        stmt = (
            select(
                _g.c.account_id,
                _g.c.client_id,
                _g.c.revoked_at,
                _g.c.expires_at,
                _g.c.last_used_at,
                _a.c.status.label("account_status"),
            )
            .select_from(_g.join(_a, _a.c.id == _g.c.account_id))
            .where(_g.c.id == grant_id)
        )
        row = conn.execute(stmt).mappings().one_or_none()
        if row is None:
            return GrantStatus(found=False)
        return GrantStatus(
            found=True,
            account_id=row["account_id"],
            client_id=row["client_id"],
            revoked=row["revoked_at"] is not None,
            expires_at=row["expires_at"],
            last_used_at=row["last_used_at"],
            account_status=row["account_status"],
        )

    def lock_live(self, conn: Connection, grant_id: str, now: int) -> bool:
        """Take the grant's row lock if it is live, and note the use; True if live.

        Every rotation of a family and every revocation write this row, so they
        serialise on it (on PostgreSQL through the row lock, on SQLite through the
        database write lock).
        """
        stmt = (
            update(_g)
            .where(
                _g.c.id == grant_id, _g.c.revoked_at.is_(None), _g.c.expires_at > now
            )
            .values(last_used_at=now)
        )
        return conn.execute(stmt).rowcount == 1

    def revoke(
        self, conn: Connection, grant_id: str, *, reason: str, by: str, now: int
    ) -> bool:
        """Revoke a live grant; True only if this call revoked it."""
        stmt = (
            update(_g)
            .where(_g.c.id == grant_id, _g.c.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason=reason, revoked_by=_by(by))
        )
        return conn.execute(stmt).rowcount == 1

    def revoke_own(
        self,
        conn: Connection,
        grant_id: str,
        account_id: str,
        *,
        reason: str,
        by: str,
        now: int,
    ) -> bool:
        """Like :meth:`revoke`, but only if the grant belongs to ``account_id``."""
        stmt = (
            update(_g)
            .where(
                _g.c.id == grant_id,
                _g.c.account_id == account_id,
                _g.c.revoked_at.is_(None),
            )
            .values(revoked_at=now, revoked_reason=reason, revoked_by=_by(by))
        )
        return conn.execute(stmt).rowcount == 1

    def revoke_for_account(
        self, conn: Connection, account_id: str, *, reason: str, by: str, now: int
    ) -> int:
        """Revoke every live grant of an account; returns how many."""
        stmt = (
            update(_g)
            .where(_g.c.account_id == account_id, _g.c.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason=reason, revoked_by=_by(by))
        )
        return int(conn.execute(stmt).rowcount or 0)

    def touch_used(
        self, conn: Connection, grant_id: str, *, now: int, older_than: int
    ) -> bool:
        candidate = (
            select(_g.c.id)
            .where(
                _g.c.id == grant_id,
                _g.c.revoked_at.is_(None),
                _g.c.expires_at > now,
                or_(_g.c.last_used_at.is_(None), _g.c.last_used_at < older_than),
            )
            .with_for_update(key_share=True, skip_locked=True)
            .scalar_subquery()
        )
        stmt = update(_g).where(_g.c.id == candidate).values(last_used_at=now)
        return conn.execute(stmt).rowcount == 1

    def list_all(
        self,
        conn: Connection,
        *,
        include_inactive: bool,
        now: int,
        limit: int,
        account_id: str | None = None,
        before_id: str | None = None,
    ) -> list[GrantRecord]:
        stmt = select(_g)
        if account_id is not None:
            stmt = stmt.where(_g.c.account_id == account_id)
        if not include_inactive:
            stmt = stmt.where(_g.c.revoked_at.is_(None), _g.c.expires_at > now)
        if before_id is not None:
            stmt = stmt.where(_g.c.id < before_id)
        stmt = stmt.order_by(_g.c.id.desc()).limit(limit)
        return [_grant(row) for row in conn.execute(stmt).mappings()]


class SqlAuthCodeRepo:
    """``oauth_codes``: authorization codes, kept as tombstones after use."""

    def insert(self, conn: Connection, **fields: Any) -> None:
        fields["code_hash"] = _hash(fields["code_hash"])
        conn.execute(insert(_c).values(**fields))

    def get(
        self, conn: Connection, code_hash: str, *, for_update: bool = False
    ) -> CodeRecord | None:
        stmt = select(_c).where(_c.c.code_hash == _hash(code_hash))
        if for_update:
            stmt = stmt.with_for_update(key_share=True)
        return _code(conn.execute(stmt).mappings().one_or_none())

    def consume(
        self,
        conn: Connection,
        code_hash: str,
        client_id: str,
        *,
        grant_id: str,
        now: int,
    ) -> bool:
        """Mark an unused, unexpired code of ``client_id`` as used; True for the one winner."""
        stmt = (
            update(_c)
            .where(
                _c.c.code_hash == _hash(code_hash),
                _c.c.client_id == client_id,
                _c.c.consumed_at.is_(None),
                _c.c.expires_at > now,
            )
            .values(consumed_at=now, grant_id=grant_id)
        )
        return conn.execute(stmt).rowcount == 1

    def bump_grace(self, conn: Connection, code_hash: str, cap: int) -> bool:
        """Count one more benign replay, up to ``cap``; False once the cap is reached."""
        stmt = (
            update(_c)
            .where(_c.c.code_hash == _hash(code_hash), _c.c.grace_replays < cap)
            .values(grace_replays=_c.c.grace_replays + 1)
        )
        return conn.execute(stmt).rowcount == 1

    def delete_unconsumed_for_account(self, conn: Connection, account_id: str) -> int:
        stmt = delete(_c).where(
            _c.c.account_id == account_id, _c.c.consumed_at.is_(None)
        )
        return int(conn.execute(stmt).rowcount or 0)

    def delete_for_account(self, conn: Connection, account_id: str) -> int:
        return int(
            conn.execute(delete(_c).where(_c.c.account_id == account_id)).rowcount or 0
        )


class SqlRefreshRepo:
    """``oauth_refresh_tokens``: hashes of refresh tokens and their rotation chain."""

    def insert(
        self,
        conn: Connection,
        *,
        token_hash: str,
        grant_id: str,
        parent_hash: str | None,
        now: int,
    ) -> None:
        conn.execute(
            insert(_r).values(
                token_hash=_hash(token_hash),
                grant_id=grant_id,
                parent_hash=_hash(parent_hash),
                created_at=now,
            )
        )

    def get(self, conn: Connection, token_hash: str) -> RefreshTokenRecord | None:
        return _refresh(
            conn.execute(select(_r).where(_r.c.token_hash == _hash(token_hash)))
            .mappings()
            .one_or_none()
        )

    def get_with_grant(self, conn: Connection, token_hash: str) -> RefreshView | None:
        stmt = (
            select(
                _r,
                _g.c.client_id,
                _g.c.scopes,
                _g.c.resource,
                _g.c.account_id,
                _g.c.revoked_at.label("grant_revoked_at"),
                _g.c.expires_at,
            )
            .select_from(_r.join(_g, _g.c.id == _r.c.grant_id))
            .where(_r.c.token_hash == _hash(token_hash))
        )
        row = conn.execute(stmt).mappings().one_or_none()
        if row is None:
            return None
        fields = dict(row)
        for key in ("token_hash", "parent_hash", "replaced_by"):
            fields[key] = None if fields[key] is None else bytes(fields[key]).hex()
        fields["scopes"] = split_scopes(fields["scopes"])
        return RefreshView(**fields)

    def mark_used(
        self, conn: Connection, token_hash: str, *, replaced_by: str, now: int
    ) -> bool:
        """Mark a token as used and name its successor; True for the one winner."""
        stmt = (
            update(_r)
            .where(_r.c.token_hash == _hash(token_hash), _r.c.used_at.is_(None))
            .values(used_at=now, replaced_by=_hash(replaced_by))
        )
        return conn.execute(stmt).rowcount == 1

    def retire_siblings(
        self,
        conn: Connection,
        *,
        grant_id: str,
        parent_hash: str | None,
        keep: str,
        now: int,
    ) -> int:
        """Mark the unused siblings of ``keep`` as used without a successor (retired).

        Siblings are the tokens issued for a replayed request: a later presentation of a
        retired one is a reuse.
        """
        stmt = (
            update(_r)
            .where(
                _r.c.grant_id == grant_id,
                _r.c.parent_hash.is_not_distinct_from(_hash(parent_hash)),
                _r.c.token_hash != _hash(keep),
                _r.c.used_at.is_(None),
            )
            .values(used_at=now)
        )
        return int(conn.execute(stmt).rowcount or 0)

    def has_rotated_child(
        self, conn: Connection, grant_id: str, token_hash: str
    ) -> bool:
        """True if some token that replaced ``token_hash`` has itself been rotated."""
        child = _r.alias("child")
        stmt = select(
            exists().where(
                child.c.grant_id == grant_id,
                child.c.parent_hash == _hash(token_hash),
                child.c.replaced_by.is_not(None),
            )
        )
        return bool(conn.execute(stmt).scalar_one())

    def any_used(self, conn: Connection, grant_id: str) -> bool:
        stmt = select(
            exists().where(_r.c.grant_id == grant_id, _r.c.used_at.is_not(None))
        )
        return bool(conn.execute(stmt).scalar_one())

    def bump_grace(self, conn: Connection, token_hash: str, cap: int) -> bool:
        stmt = (
            update(_r)
            .where(_r.c.token_hash == _hash(token_hash), _r.c.grace_replays < cap)
            .values(grace_replays=_r.c.grace_replays + 1)
        )
        return conn.execute(stmt).rowcount == 1


class SqlLoginStateRepo:
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
    ) -> None:
        conn.execute(
            insert(_ls).values(
                kind=kind,
                id_hash=_hash(id_hash),
                binding_hash=_hash(binding_hash),
                payload=payload.encode("utf-8"),
                created_at=now,
                expires_at=expires_at,
            )
        )

    @staticmethod
    def _match(
        kind: str, id_hash: str, binding_hash: str | None, now: int
    ) -> list[Any]:
        conditions = [
            _ls.c.kind == kind,
            _ls.c.id_hash == _hash(id_hash),
            _ls.c.expires_at > now,
        ]
        # A bound state needs its binding and an unbound one is read without: knowing the
        # id alone is never enough to read or to consume a state that belongs to a browser.
        conditions.append(
            _ls.c.binding_hash.is_(None)
            if binding_hash is None
            else _ls.c.binding_hash == _hash(binding_hash)
        )
        return conditions

    def peek(
        self,
        conn: Connection,
        *,
        kind: str,
        id_hash: str,
        binding_hash: str | None,
        now: int,
    ) -> str | None:
        stmt = select(_ls.c.payload).where(
            *self._match(kind, id_hash, binding_hash, now)
        )
        value = conn.execute(stmt).scalar_one_or_none()
        return None if value is None else bytes(value).decode("utf-8")

    def pop(
        self,
        conn: Connection,
        *,
        kind: str,
        id_hash: str,
        binding_hash: str | None,
        now: int,
    ) -> str | None:
        """Consume and return the payload in one conditional statement."""
        stmt = (
            delete(_ls)
            .where(*self._match(kind, id_hash, binding_hash, now))
            .returning(_ls.c.payload)
        )
        value = conn.execute(stmt).scalar_one_or_none()
        return None if value is None else bytes(value).decode("utf-8")


class SqlJwtEpochRepo:
    """The server-state JWT epoch, raised atomically to invalidate access tokens."""

    def get(self, conn: Connection) -> int:
        return int(
            conn.execute(select(_s.c.jwt_epoch).where(_s.c.id == 1)).scalar_one()
        )

    def bump(self, conn: Connection, *, now: int) -> int:
        return int(
            conn.execute(
                update(_s)
                .where(_s.c.id == 1)
                .values(jwt_epoch=_s.c.jwt_epoch + 1, updated_at=now)
                .returning(_s.c.jwt_epoch)
            ).scalar_one()
        )

    def set(self, conn: Connection, value: int, *, now: int) -> None:
        conn.execute(
            update(_s)
            .where(_s.c.id == 1, _s.c.jwt_epoch < value)
            .values(jwt_epoch=value, updated_at=now)
        )


__all__ = [
    "SqlAuthCodeRepo",
    "SqlCimdRepo",
    "SqlGrantRepo",
    "SqlJwtEpochRepo",
    "SqlLoginStateRepo",
    "SqlOAuthClientRepo",
    "SqlRefreshRepo",
]
