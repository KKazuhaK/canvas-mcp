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

Rows come back as tuples in the documented column order.
"""

from __future__ import annotations

from typing import Any, Literal

from sqlalchemy import and_, delete, exists, insert, or_, select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import Connection

from . import schema as t
from .ports import Row

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
_m = t.meta

#: Column order of a grant row (``GrantRepo.get`` and ``list_*``).
GRANT_COLUMNS = (
    "id",
    "account_id",
    "client_id",
    "client_kind",
    "client_name",
    "client_host",
    "redirect_host",
    "scopes",
    "resource",
    "created_at",
    "last_used_at",
    "upstream_auth_at",
    "expires_at",
    "revoked_at",
    "revoked_reason",
    "revoked_by",
)
#: Column order of a code row.
CODE_COLUMNS = (
    "code_hash",
    "client_id",
    "account_id",
    "redirect_uri",
    "redirect_uri_explicit",
    "code_challenge",
    "scopes",
    "resource",
    "client_kind",
    "client_name",
    "client_host",
    "redirect_host",
    "upstream_auth_at",
    "session_epoch",
    "created_at",
    "expires_at",
    "consumed_at",
    "grant_id",
    "grace_replays",
)
#: Column order of a refresh-token row.
REFRESH_COLUMNS = (
    "token_hash",
    "grant_id",
    "parent_hash",
    "created_at",
    "expires_at",
    "used_at",
    "replaced_by",
    "grace_replays",
)


def _grant_columns() -> list[Any]:
    return [_g.c[name] for name in GRANT_COLUMNS]


def _code_columns() -> list[Any]:
    return [_c.c[name] for name in CODE_COLUMNS]


def _refresh_columns() -> list[Any]:
    return [_r.c[name] for name in REFRESH_COLUMNS]


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
                info_json=info_json,
                client_name=client_name,
                created_at=now,
                expires_at=expires_at,
            )
        )

    def get(self, conn: Connection, client_id: str) -> Row | None:
        stmt = select(_oc.c.id, _oc.c.info_json, _oc.c.client_name, _oc.c.created_at, _oc.c.expires_at)
        return conn.execute(stmt.where(_oc.c.id == client_id)).one_or_none()

    def extend(self, conn: Connection, client_id: str, expires_at: int) -> bool:
        """Raise the expiry; never lowers it."""
        stmt = (
            update(_oc)
            .where(_oc.c.id == client_id, _oc.c.expires_at < expires_at)
            .values(expires_at=expires_at)
        )
        return conn.execute(stmt).rowcount == 1

    def delete_expired(self, conn: Connection, now: int) -> int:
        return int(conn.execute(delete(_oc).where(_oc.c.expires_at < now)).rowcount or 0)


class SqlCimdRepo:
    """``cimd_clients``: the last known good client metadata documents."""

    def __init__(self, dialect: Dialect) -> None:
        self._dialect = dialect

    def get(self, conn: Connection, url: str) -> Row | None:
        """``(url, doc_json, fetched_at, fresh_until, last_error_at, last_error)``."""
        stmt = select(
            _cc.c.url,
            _cc.c.doc_json,
            _cc.c.fetched_at,
            _cc.c.fresh_until,
            _cc.c.last_error_at,
            _cc.c.last_error,
        )
        return conn.execute(stmt.where(_cc.c.url == url)).one_or_none()

    def upsert(
        self, conn: Connection, *, url: str, doc_json: str, fetched_at: int, fresh_until: int
    ) -> bool:
        """Store a document unless a newer one is stored; True if this call wrote.

        Monotonic: a fetch that finished late (an older ``fetched_at``) never overwrites
        a newer document (nor one fetched in the same second). The comparison is part of
        the one statement.
        """
        stmt = _upsert_insert(self._dialect, _cc).values(
            url=url,
            doc_json=doc_json,
            fetched_at=fetched_at,
            fresh_until=fresh_until,
            last_error_at=None,
            last_error=None,
        )
        excluded = stmt.excluded
        stmt = stmt.on_conflict_do_update(
            index_elements=[_cc.c.url],
            set_={
                "doc_json": excluded.doc_json,
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
        stmt = update(_cc).where(_cc.c.url == url).values(last_error_at=now, last_error=code)
        return conn.execute(stmt).rowcount == 1

    def delete_fetched_before(self, conn: Connection, cutoff: int) -> int:
        return int(conn.execute(delete(_cc).where(_cc.c.fetched_at < cutoff)).rowcount or 0)


class SqlGrantRepo:
    """``oauth_grants``: one row per connection of an app to an account."""

    def insert(self, conn: Connection, **fields: Any) -> None:
        conn.execute(insert(_g).values(**fields))

    def get(self, conn: Connection, grant_id: str) -> Row | None:
        return conn.execute(select(*_grant_columns()).where(_g.c.id == grant_id)).one_or_none()

    def status_row(self, conn: Connection, grant_id: str) -> Row | None:
        """``(account_id, client_id, revoked_at, expires_at, last_used_at, account_status)``.

        The account status is ``None`` when the account row is gone. One statement, so
        the grant and its account are read together.
        """
        stmt = (
            select(
                _g.c.account_id,
                _g.c.client_id,
                _g.c.revoked_at,
                _g.c.expires_at,
                _g.c.last_used_at,
                _a.c.status,
            )
            .select_from(_g.outerjoin(_a, _a.c.id == _g.c.account_id))
            .where(_g.c.id == grant_id)
        )
        return conn.execute(stmt).one_or_none()

    def lock_live(self, conn: Connection, grant_id: str, now: int) -> bool:
        """Take the grant's row lock if it is live, and note the use; True if live.

        Every rotation of a family and every revocation write this row, so they
        serialise on it (on PostgreSQL through the row lock, on SQLite through the
        database write lock).
        """
        stmt = (
            update(_g)
            .where(_g.c.id == grant_id, _g.c.revoked_at.is_(None), _g.c.expires_at > now)
            .values(last_used_at=now)
        )
        return conn.execute(stmt).rowcount == 1

    def revoke(self, conn: Connection, grant_id: str, *, reason: str, by: str, now: int) -> bool:
        """Revoke a live grant; True only if this call revoked it."""
        stmt = (
            update(_g)
            .where(_g.c.id == grant_id, _g.c.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason=reason, revoked_by=by)
        )
        return conn.execute(stmt).rowcount == 1

    def revoke_own(
        self, conn: Connection, grant_id: str, account_id: str, *, reason: str, by: str, now: int
    ) -> bool:
        """Like :meth:`revoke`, but only if the grant belongs to ``account_id``."""
        stmt = (
            update(_g)
            .where(_g.c.id == grant_id, _g.c.account_id == account_id, _g.c.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason=reason, revoked_by=by)
        )
        return conn.execute(stmt).rowcount == 1

    def revoke_for_account(
        self, conn: Connection, account_id: str, *, reason: str, by: str, now: int
    ) -> int:
        """Revoke every live grant of an account; returns how many."""
        stmt = (
            update(_g)
            .where(_g.c.account_id == account_id, _g.c.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason=reason, revoked_by=by)
        )
        return int(conn.execute(stmt).rowcount or 0)

    def touch_used(self, conn: Connection, grant_id: str, *, now: int, older_than: int) -> bool:
        stmt = (
            update(_g)
            .where(
                _g.c.id == grant_id,
                _g.c.revoked_at.is_(None),
                or_(_g.c.last_used_at.is_(None), _g.c.last_used_at < older_than),
            )
            .values(last_used_at=now)
        )
        return conn.execute(stmt).rowcount == 1

    def list_for_account(self, conn: Connection, account_id: str, now: int) -> list[Row]:
        """Live grants of an account (not revoked, not expired), newest first."""
        stmt = (
            select(*_grant_columns())
            .where(_g.c.account_id == account_id, _g.c.revoked_at.is_(None), _g.c.expires_at > now)
            .order_by(_g.c.created_at.desc(), _g.c.id)
        )
        return list(conn.execute(stmt).all())

    def list_all(
        self,
        conn: Connection,
        *,
        include_inactive: bool,
        now: int,
        limit: int,
        account_id: str | None = None,
    ) -> list[Row]:
        stmt = select(*_grant_columns())
        if account_id is not None:
            stmt = stmt.where(_g.c.account_id == account_id)
        if not include_inactive:
            stmt = stmt.where(_g.c.revoked_at.is_(None), _g.c.expires_at > now)
        stmt = stmt.order_by(_g.c.created_at.desc(), _g.c.id).limit(limit)
        return list(conn.execute(stmt).all())

    def delete_inactive_before(self, conn: Connection, cutoff: int) -> int:
        """Delete grants revoked, or expired, before ``cutoff``."""
        stmt = delete(_g).where(
            or_(
                and_(_g.c.revoked_at.is_not(None), _g.c.revoked_at < cutoff),
                _g.c.expires_at < cutoff,
            )
        )
        return int(conn.execute(stmt).rowcount or 0)


class SqlAuthCodeRepo:
    """``oauth_codes``: authorization codes, kept as tombstones after use."""

    def insert(self, conn: Connection, **fields: Any) -> None:
        conn.execute(insert(_c).values(**fields))

    def get(self, conn: Connection, code_hash: str) -> Row | None:
        return conn.execute(select(*_code_columns()).where(_c.c.code_hash == code_hash)).one_or_none()

    def consume(
        self, conn: Connection, code_hash: str, client_id: str, *, grant_id: str, now: int
    ) -> bool:
        """Mark an unused, unexpired code of ``client_id`` as used; True for the one winner."""
        stmt = (
            update(_c)
            .where(
                _c.c.code_hash == code_hash,
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
            .where(_c.c.code_hash == code_hash, _c.c.grace_replays < cap)
            .values(grace_replays=_c.c.grace_replays + 1)
        )
        return conn.execute(stmt).rowcount == 1

    def delete_unconsumed_for_account(self, conn: Connection, account_id: str) -> int:
        stmt = delete(_c).where(_c.c.account_id == account_id, _c.c.consumed_at.is_(None))
        return int(conn.execute(stmt).rowcount or 0)

    def delete_expired_before(self, conn: Connection, cutoff: int) -> int:
        return int(conn.execute(delete(_c).where(_c.c.expires_at < cutoff)).rowcount or 0)


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
        expires_at: int,
    ) -> None:
        conn.execute(
            insert(_r).values(
                token_hash=token_hash,
                grant_id=grant_id,
                parent_hash=parent_hash,
                created_at=now,
                expires_at=expires_at,
            )
        )

    def get(self, conn: Connection, token_hash: str) -> Row | None:
        return conn.execute(
            select(*_refresh_columns()).where(_r.c.token_hash == token_hash)
        ).one_or_none()

    def get_with_grant(self, conn: Connection, token_hash: str) -> Row | None:
        """The token row followed by ``(client_id, scopes, resource, account_id, revoked_at)``
        of its grant (``None`` for the grant columns when the grant is gone)."""
        stmt = (
            select(
                *_refresh_columns(),
                _g.c.client_id,
                _g.c.scopes,
                _g.c.resource,
                _g.c.account_id,
                _g.c.revoked_at,
            )
            .select_from(_r.outerjoin(_g, _g.c.id == _r.c.grant_id))
            .where(_r.c.token_hash == token_hash)
        )
        return conn.execute(stmt).one_or_none()

    def mark_used(self, conn: Connection, token_hash: str, *, replaced_by: str, now: int) -> bool:
        """Mark a token as used and name its successor; True for the one winner."""
        stmt = (
            update(_r)
            .where(_r.c.token_hash == token_hash, _r.c.used_at.is_(None))
            .values(used_at=now, replaced_by=replaced_by)
        )
        return conn.execute(stmt).rowcount == 1

    def retire_siblings(
        self, conn: Connection, *, grant_id: str, parent_hash: str | None, keep: str, now: int
    ) -> int:
        """Mark the unused siblings of ``keep`` as used without a successor (retired).

        Siblings are the tokens issued for a replayed request: a later presentation of a
        retired one is a reuse.
        """
        stmt = (
            update(_r)
            .where(
                _r.c.grant_id == grant_id,
                _r.c.parent_hash.is_not_distinct_from(parent_hash),
                _r.c.token_hash != keep,
                _r.c.used_at.is_(None),
            )
            .values(used_at=now)
        )
        return int(conn.execute(stmt).rowcount or 0)

    def has_rotated_child(self, conn: Connection, token_hash: str) -> bool:
        """True if some token that replaced ``token_hash`` has itself been rotated."""
        child = _r.alias("child")
        stmt = select(
            exists().where(child.c.parent_hash == token_hash, child.c.replaced_by.is_not(None))
        )
        return bool(conn.execute(stmt).scalar_one())

    def any_used(self, conn: Connection, grant_id: str) -> bool:
        stmt = select(exists().where(_r.c.grant_id == grant_id, _r.c.used_at.is_not(None)))
        return bool(conn.execute(stmt).scalar_one())

    def bump_grace(self, conn: Connection, token_hash: str, cap: int) -> bool:
        stmt = (
            update(_r)
            .where(_r.c.token_hash == token_hash, _r.c.grace_replays < cap)
            .values(grace_replays=_r.c.grace_replays + 1)
        )
        return conn.execute(stmt).rowcount == 1

    def delete_dead(self, conn: Connection, *, now: int, revoked_before: int) -> int:
        """Delete tokens past their cap, and those of grants revoked before ``revoked_before``."""
        revoked = select(_g.c.id).where(
            _g.c.revoked_at.is_not(None), _g.c.revoked_at < revoked_before
        )
        stmt = delete(_r).where(or_(_r.c.expires_at < now, _r.c.grant_id.in_(revoked)))
        return int(conn.execute(stmt).rowcount or 0)


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
                id_hash=id_hash,
                binding_hash=binding_hash,
                payload=payload,
                created_at=now,
                expires_at=expires_at,
            )
        )

    @staticmethod
    def _match(kind: str, id_hash: str, binding_hash: str | None, now: int) -> list[Any]:
        conditions = [_ls.c.kind == kind, _ls.c.id_hash == id_hash, _ls.c.expires_at > now]
        # A bound state needs its binding and an unbound one is read without: knowing the
        # id alone is never enough to read or to consume a state that belongs to a browser.
        conditions.append(
            _ls.c.binding_hash.is_(None) if binding_hash is None else _ls.c.binding_hash == binding_hash
        )
        return conditions

    def peek(
        self, conn: Connection, *, kind: str, id_hash: str, binding_hash: str | None, now: int
    ) -> str | None:
        stmt = select(_ls.c.payload).where(*self._match(kind, id_hash, binding_hash, now))
        value = conn.execute(stmt).scalar_one_or_none()
        return None if value is None else str(value)

    def delete_matching(
        self, conn: Connection, *, kind: str, id_hash: str, binding_hash: str | None, now: int
    ) -> bool:
        """Delete the state if it matches; True for the one caller that deleted it."""
        stmt = delete(_ls).where(*self._match(kind, id_hash, binding_hash, now))
        return conn.execute(stmt).rowcount == 1

    def delete_expired(self, conn: Connection, now: int) -> int:
        return int(conn.execute(delete(_ls).where(_ls.c.expires_at < now)).rowcount or 0)


class SqlJwtEpochRepo:
    """``meta['mcp_jwt_epoch']``: raised to invalidate every access token at once."""

    KEY = "mcp_jwt_epoch"

    def get(self, conn: Connection) -> int:
        value = conn.execute(select(_m.c.value).where(_m.c.key == self.KEY)).scalar_one_or_none()
        try:
            return max(0, int(value)) if value is not None else 0
        except (TypeError, ValueError):
            return 0

    def bump(self, conn: Connection) -> int:
        """Raise the epoch by one and return it (inside the caller's write transaction)."""
        current = conn.execute(select(_m.c.value).where(_m.c.key == self.KEY)).scalar_one_or_none()
        if current is None:
            conn.execute(insert(_m).values(key=self.KEY, value="1"))
            return 1
        try:
            new = max(0, int(current)) + 1
        except (TypeError, ValueError):
            new = 1
        conn.execute(update(_m).where(_m.c.key == self.KEY).values(value=str(new)))
        return new

    def set(self, conn: Connection, value: int) -> None:
        value = max(0, int(value))
        current = conn.execute(select(_m.c.value).where(_m.c.key == self.KEY)).scalar_one_or_none()
        if current is None:
            conn.execute(insert(_m).values(key=self.KEY, value=str(value)))
        else:
            conn.execute(update(_m).where(_m.c.key == self.KEY).values(value=str(value)))


__all__ = [
    "CODE_COLUMNS",
    "GRANT_COLUMNS",
    "REFRESH_COLUMNS",
    "SqlAuthCodeRepo",
    "SqlCimdRepo",
    "SqlGrantRepo",
    "SqlJwtEpochRepo",
    "SqlLoginStateRepo",
    "SqlOAuthClientRepo",
    "SqlRefreshRepo",
]
