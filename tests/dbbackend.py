"""Backend selection for the self-hosted tests: SQLite (default) or PostgreSQL.

Environment:

* ``CANVAS_MCP_TEST_BACKEND=postgres`` runs every store-backed test on PostgreSQL.
  It needs ``CANVAS_MCP_TEST_DATABASE_URL`` (``postgresql+psycopg://...``). When the
  backend is requested but the URL is missing or the server is unreachable, the run
  FAILS (it does not skip), so CI can never go green without exercising PostgreSQL.
* ``CANVAS_MCP_TEST_DATABASE_URL`` alone enables the PostgreSQL-only tests
  (``@pytest.mark.postgres``) next to the default SQLite run; they skip otherwise.

The database named by the URL is scratch space: tests create and drop schemas in it
(one schema per store path, ``public`` for whole-server stacks). Under pytest-xdist
each worker gets its own database on the same server (``<name>_gw0``, ``<name>_gw1``,
...), created on first use from ``template1``, because whole-server stacks reset
``public``.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import time
import weakref
from collections.abc import Callable, Mapping, Sequence
from typing import Any

import pytest

BACKEND_ENV = "CANVAS_MCP_TEST_BACKEND"
URL_ENV = "CANVAS_MCP_TEST_DATABASE_URL"

BACKEND = (os.environ.get(BACKEND_ENV) or "sqlite").strip().lower()
BASE_PG_URL = (os.environ.get(URL_ENV) or "").strip()
IS_POSTGRES = BACKEND == "postgres"
WORKER = os.environ.get("PYTEST_XDIST_WORKER", "")


def _worker_url(url: str, worker: str) -> str:
    if not url or not worker:
        return url
    from sqlalchemy.engine import make_url

    parsed = make_url(url)
    return parsed.set(database=f"{parsed.database}_{worker}").render_as_string(
        hide_password=False
    )


PG_URL = _worker_url(BASE_PG_URL, WORKER)
#: Why this worker's database could not be set up, when the backend is PostgreSQL. A
#: worker that calls ``pytest.exit`` is only replaced by xdist and the run can still
#: pass, so the ``fail_without_worker_database`` fixture fails every test instead.
WORKER_ERROR: str | None = None

_SCHEMAS: set[str] = set()
_DATABASES: list[weakref.ref[Any]] = []


def require_backend() -> None:
    """Abort the whole run if PostgreSQL was requested but cannot be used."""
    global PG_URL, WORKER_ERROR
    if BACKEND not in ("sqlite", "postgres"):
        pytest.exit(f"{BACKEND_ENV} must be 'sqlite' or 'postgres'", returncode=2)
    if PG_URL != BASE_PG_URL:
        try:
            _create_worker_database()
        except Exception as exc:  # noqa: BLE001 - report the failure class, never the URL
            if IS_POSTGRES:
                WORKER_ERROR = (
                    f"{BACKEND_ENV}=postgres but worker {WORKER} could not create its "
                    f"database ({type(exc).__name__}); the URL's user needs CREATEDB"
                )
                return
            # Only the PostgreSQL-only tests use it: they skip, as without a URL.
            PG_URL = ""
    if not IS_POSTGRES:
        return
    if not PG_URL:
        pytest.exit(f"{BACKEND_ENV}=postgres needs {URL_ENV}", returncode=2)
    try:
        engine = _bootstrap()
        try:
            with engine.connect() as conn:
                conn.exec_driver_sql("SELECT 1")
        finally:
            engine.dispose()
    except Exception as exc:  # noqa: BLE001 - report the failure class, never the URL
        pytest.exit(
            f"{BACKEND_ENV}=postgres but {URL_ENV} is unreachable ({type(exc).__name__})",
            returncode=2,
        )


def install_tracking() -> None:
    """Remember every ``Database`` built during the run so the tests can dispose it."""
    from canvas_mcp.core.selfhost.db.engine import Database

    original = Database.__init__

    def tracked(self: Any, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        track_database(self)

    Database.__init__ = tracked  # type: ignore[method-assign]


def _create_worker_database() -> None:
    """Create this xdist worker's database if it is missing, connecting through the base URL."""
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url

    name = make_url(PG_URL).database
    engine = create_engine(BASE_PG_URL, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            exists = conn.exec_driver_sql(
                "SELECT 1 FROM pg_database WHERE datname = %(name)s", {"name": name}
            ).first()
            if exists is None:
                conn.exec_driver_sql(f'CREATE DATABASE "{name}"')
    finally:
        engine.dispose()


def pg_available() -> bool:
    return bool(PG_URL)


def _bootstrap() -> Any:
    from sqlalchemy import create_engine

    return create_engine(PG_URL, pool_pre_ping=True)


def reset_public_schema() -> None:
    """Empty database for a whole-server stack test."""
    engine = _bootstrap()
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
            conn.exec_driver_sql("CREATE SCHEMA public")
    finally:
        engine.dispose()


def schema_for(path: str | os.PathLike[str]) -> str:
    return "t_" + hashlib.sha1(str(path).encode("utf-8")).hexdigest()[:20]  # noqa: S324


def pg_database(path: str | os.PathLike[str], url: str | None = None) -> Any:
    """A ``Database`` on PostgreSQL whose tables live in a schema derived from ``path``."""
    from sqlalchemy import event

    from canvas_mcp.core.selfhost.db.engine import Database
    from canvas_mcp.core.selfhost.db.url import parse_database_url

    schema = schema_for(path)
    if schema not in _SCHEMAS:
        engine = _bootstrap()
        try:
            with engine.begin() as conn:
                conn.exec_driver_sql(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
        finally:
            engine.dispose()
        _SCHEMAS.add(schema)
    target = parse_database_url(url or PG_URL, pathlib.Path("/data"))
    db = Database(target)

    def set_search_path(dbapi_connection: Any, record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute(f'SET search_path TO "{schema}"')
        cursor.close()
        dbapi_connection.commit()

    event.listen(db.engine, "connect", set_search_path)
    return db


def make_store(
    path: str | os.PathLike[str],
    keyring: Any,
    *,
    clock: Callable[[], float] = time.time,
    public: bool = False,
) -> Any:
    """A ``TokenStore`` for the selected backend.

    On SQLite ``path`` is the database file. On PostgreSQL it only names the
    database: the same path always means the same schema, a different path a
    different, empty one. ``public=True`` uses the default schema instead, which is
    where a server or the ``token_admin`` CLI started from ``DATABASE_URL`` looks.
    """
    from canvas_mcp.core.selfhost.token_store import TokenStore

    if IS_POSTGRES:
        if public:
            from canvas_mcp.core.selfhost.db.engine import Database
            from canvas_mcp.core.selfhost.db.url import parse_database_url

            db = Database(parse_database_url(PG_URL, pathlib.Path("/data")))
            return TokenStore(db, keyring, clock=clock)
        return TokenStore(pg_database(path), keyring, clock=clock)
    return TokenStore(pathlib.Path(path), keyring, clock=clock)


def raw_sql(
    store: Any, sql: str, params: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None
) -> list[Any]:
    """Run ``sql`` (with ``:name`` binds) on the store's database and commit.

    Backend-neutral replacement for a raw ``sqlite3`` connection: tests use it to
    tamper with or inspect rows behind the store's back.
    """
    from sqlalchemy import text

    with store.database.engine.begin() as conn:
        result = conn.execute(text(sql), params or {})
        return list(result.all()) if result.returns_rows else []


_HEX_BLOB = re.compile(r"[xX]'([0-9a-fA-F]*)'")


def _translate(sql: str, params: Sequence[Any]) -> tuple[str, dict[str, Any]]:
    """``?`` placeholders and ``x'..'`` blob literals to named binds (outside quoted text)."""
    binds: dict[str, Any] = {}
    out: list[str] = []
    values = list(params)
    in_quote = False
    i = 0
    while i < len(sql):
        ch = sql[i]
        if ch == "'":
            blob = None
            if not in_quote and i and sql[i - 1] in "xX":
                before = sql[i - 2] if i >= 2 else " "
                if not (before.isalnum() or before == "_"):
                    blob = _HEX_BLOB.match(sql, i - 1)
            if blob is not None:
                # drop the 'x' already copied, bind the bytes instead
                out.pop()
                name = f"b{len(binds)}"
                binds[name] = bytes.fromhex(blob.group(1))
                out.append(f":{name}")
                i = blob.end()
                continue
            in_quote = not in_quote
        elif ch == "?" and not in_quote:
            name = f"p{len(binds)}"
            binds[name] = values.pop(0)
            out.append(f":{name}")
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), binds


class _Cursor:
    def __init__(self, result: Any) -> None:
        self._rows = [tuple(r) for r in result.all()] if result.returns_rows else []
        self.rowcount = result.rowcount

    def __iter__(self) -> Any:
        return iter(self._rows)

    def fetchone(self) -> Any:
        return self._rows.pop(0) if self._rows else None

    def fetchall(self) -> list[Any]:
        rows, self._rows = self._rows, []
        return rows


class RawConnection:
    """The slice of ``sqlite3.Connection`` the tamper tests use, over SQLAlchemy.

    ``execute(sql, params)`` takes qmark parameters; ``x'00'`` blob literals become
    binds. ``with`` commits on success and rolls back on error, then closes.
    """

    def __init__(self, store: Any) -> None:
        self._conn = store.database.engine.connect()
        self._conn.begin()

    def execute(self, sql: str, params: Sequence[Any] = ()) -> _Cursor:
        from sqlalchemy import text

        translated, binds = _translate(sql, params)
        return _Cursor(self._conn.execute(text(translated), binds))

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> RawConnection:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        try:
            if exc_type is None:
                self._conn.commit()
            else:
                self._conn.rollback()
        finally:
            self._conn.close()


def raw_connection(store: Any) -> Any:
    """A raw connection to the store's database: real ``sqlite3`` on SQLite."""
    if IS_POSTGRES:
        return RawConnection(store)
    import sqlite3

    return sqlite3.connect(str(store._path), isolation_level=None)


def drop_test_schemas() -> None:
    """Dispose every database the tests built and drop the schemas they created."""
    for ref in _DATABASES:
        db = ref()
        if db is not None:
            db.dispose()
    _DATABASES.clear()
    if _SCHEMAS:
        engine = _bootstrap()
        try:
            # One transaction per schema: a CASCADE drop locks every object it
            # removes until commit, and all xdist workers share the server's lock
            # table, so dropping several schemas at once can run it out
            # ("out of shared memory").
            for schema in sorted(_SCHEMAS):
                with engine.begin() as conn:
                    conn.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
                # Forget each schema once it is gone, so a failure part way
                # through leaves only the ones that still exist.
                _SCHEMAS.discard(schema)
        finally:
            engine.dispose()


def track_database(db: Any) -> None:
    _DATABASES.append(weakref.ref(db))


def stack_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Environment entries that point a whole-server stack at the selected backend."""
    env = dict(extra or {})
    if IS_POSTGRES:
        reset_public_schema()
        env["DATABASE_URL"] = PG_URL
    return env
