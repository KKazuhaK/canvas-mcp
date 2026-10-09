"""Engines and transaction boundaries for SQLite and PostgreSQL (SQLAlchemy Core).

Every write the token store makes is one transaction that spans several tables
(an enrollment checks the principal's status, upserts the token and raises the
credential generation; a disable re-checks the actor, counts the other owners,
writes the status and the history and raises the generation). The boundaries are
therefore owned here and used from one place, ``token_store.py``; the
repositories only ever receive a connection that is already inside one.

How "one writer at a time" is kept on each backend:

* **SQLite**: a per-instance lock for the threads of this process, then
  ``BEGIN IMMEDIATE``, which takes the database write lock before the first read
  (``busy_timeout`` of 5 s covers other processes such as the operator CLI).
* **PostgreSQL**: a transaction at ``READ COMMITTED`` whose *first statement* is
  ``pg_advisory_xact_lock(<one constant key>)``. After it every later statement
  of the transaction sees every transaction that committed before the lock was
  granted, which is exactly what ``BEGIN IMMEDIATE`` gives SQLite. A global
  lock is used rather than row locks only because (a) the last-owner guard is a
  predicate over many rows (write skew), (b) the status gate of an enrollment may
  read a row that does not exist yet, and (c) under ``READ COMMITTED`` a
  conditional ``UPDATE`` whose ``WHERE`` has a correlated subquery
  (``credential_generations``) is re-checked only against the target row, so a late
  verdict could match a stale generation. ``REPEATABLE READ``/``SERIALIZABLE`` must
  not be used for writes: their snapshot would predate the lock wait.

Errors from the driver can quote SQL, bound values (ciphertext, principal keys),
file paths and the URL. They are translated to :class:`StoreUnavailable` with a
fixed message and ``from None``; engines are created with ``hide_parameters``.
"""

from __future__ import annotations

import hashlib
import pathlib
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from typing import Any, Literal

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import URL, Connection, Engine, make_url
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.pool import NullPool

from .errors import StoreUnavailable
from .url import DatabaseTarget, sqlite_target


def _advisory_key(label: str) -> int:
    """A signed 64-bit advisory-lock key derived from a fixed label."""
    return int.from_bytes(hashlib.sha256(label.encode("ascii")).digest()[:8], "big", signed=True)


#: The one lock every PostgreSQL write transaction takes first.
WRITER_LOCK_KEY = _advisory_key("canvas-mcp/token-store/writer")
#: Session-level lock that serialises schema migrations across processes.
MIGRATION_LOCK_KEY = _advisory_key("canvas-mcp/token-store/migrations")

_ADVISORY_XACT_SQL = f"SELECT pg_advisory_xact_lock({WRITER_LOCK_KEY})"

SQLITE_BUSY_TIMEOUT_SECONDS = 5.0
PG_STATEMENT_TIMEOUT_MS = 15_000
PG_LOCK_TIMEOUT_MS = 5_000
PG_IDLE_IN_TRANSACTION_TIMEOUT_MS = 30_000
PG_POOL_SIZE = 5
PG_MAX_OVERFLOW = 5
PG_POOL_TIMEOUT_SECONDS = 10
PG_POOL_RECYCLE_SECONDS = 1800
PG_CONNECT_TIMEOUT_SECONDS = 5
PG_BEST_EFFORT_LOCK_TIMEOUT = "2s"

BEGIN_OPTION = "canvas_begin"


def _driver_kind(exc: SQLAlchemyError) -> str:
    inner = exc.orig if isinstance(exc, DBAPIError) and exc.orig is not None else exc
    return type(inner).__name__


class Database:
    """A SQLite file or a PostgreSQL database, with the transaction helpers of the store."""

    def __init__(self, target: DatabaseTarget | pathlib.Path) -> None:
        if isinstance(target, pathlib.Path):
            target = sqlite_target(target)
        self._target = target
        self.kind: Literal["sqlite", "postgresql"] = target.kind
        self._write_lock = threading.Lock()
        self._engine = self._build_engine(target)

    # -- construction ------------------------------------------------------

    @staticmethod
    def _build_engine(target: DatabaseTarget) -> Engine:
        if target.kind == "sqlite":
            assert target.sqlite_path is not None
            engine = create_engine(
                URL.create("sqlite+pysqlite", database=str(target.sqlite_path)),
                poolclass=NullPool,
                connect_args={"timeout": SQLITE_BUSY_TIMEOUT_SECONDS},
                hide_parameters=True,
            )
            event.listen(engine, "connect", _sqlite_on_connect)
            event.listen(engine, "begin", _sqlite_on_begin)
            return engine
        url = make_url(target.url)
        connect_args: dict[str, Any] = {
            "options": (
                f"-c statement_timeout={PG_STATEMENT_TIMEOUT_MS}"
                f" -c lock_timeout={PG_LOCK_TIMEOUT_MS}"
                f" -c idle_in_transaction_session_timeout={PG_IDLE_IN_TRANSACTION_TIMEOUT_MS}"
            )
        }
        if "connect_timeout" not in url.query:
            connect_args["connect_timeout"] = PG_CONNECT_TIMEOUT_SECONDS
        if "application_name" not in url.query:
            connect_args["application_name"] = "canvas-mcp"
        return create_engine(
            url,
            pool_size=PG_POOL_SIZE,
            max_overflow=PG_MAX_OVERFLOW,
            pool_timeout=PG_POOL_TIMEOUT_SECONDS,
            pool_recycle=PG_POOL_RECYCLE_SECONDS,
            pool_pre_ping=True,
            hide_parameters=True,
            connect_args=connect_args,
        )

    @classmethod
    def sqlite(cls, path: pathlib.Path) -> Database:
        return cls(sqlite_target(pathlib.Path(path)))

    # -- properties --------------------------------------------------------

    @property
    def engine(self) -> Engine:
        return self._engine

    @property
    def target(self) -> DatabaseTarget:
        return self._target

    @property
    def description(self) -> str:
        return self._target.description

    @property
    def sqlite_path(self) -> pathlib.Path | None:
        return self._target.sqlite_path

    @property
    def write_lock(self) -> threading.Lock:
        """Serialises writers inside this process (SQLite; PostgreSQL uses the DB lock)."""
        return self._write_lock

    def __repr__(self) -> str:
        return f"Database({self._target.description})"

    def dispose(self) -> None:
        self._engine.dispose()

    # -- error translation -------------------------------------------------

    @staticmethod
    @contextmanager
    def guard() -> Iterator[None]:
        """Turn any driver or pool error into :class:`StoreUnavailable` (no details)."""
        try:
            yield
        except SQLAlchemyError as exc:
            raise StoreUnavailable(kind=_driver_kind(exc)) from None

    # -- transactions ------------------------------------------------------

    @contextmanager
    def write(self) -> Iterator[Connection]:
        """One serialised write transaction; commits on success, rolls back on any error."""
        if self.kind == "sqlite":
            with self.guard(), self._write_lock:
                yield from self._sqlite_tx("IMMEDIATE")
        else:
            with self.guard():
                yield from self._pg_tx(lock=True, lock_timeout=None)

    @contextmanager
    def read(self) -> Iterator[Connection]:
        """A connection for reads. Each statement sees a committed state."""
        with self.guard():
            conn = self._engine.connect()
            try:
                yield conn
            finally:
                conn.close()

    @contextmanager
    def best_effort_write(self, *, lock: bool) -> Iterator[Connection]:
        """A short write that callers may let fail (``touch``, ``mark_verified``).

        SQLite: one deferred transaction, no Python lock (as the single autocommit
        statement it replaces). PostgreSQL: a write transaction with a short lock
        timeout; ``lock=False`` skips the global writer lock for an update whose
        correctness does not depend on other writers.
        """
        if self.kind == "sqlite":
            with self.guard():
                yield from self._sqlite_tx("DEFERRED")
        else:
            with self.guard():
                yield from self._pg_tx(lock=lock, lock_timeout=PG_BEST_EFFORT_LOCK_TIMEOUT)

    def _sqlite_tx(self, mode: str) -> Iterator[Connection]:
        conn = self._engine.connect().execution_options(**{BEGIN_OPTION: mode})
        try:
            trans = conn.begin()
            try:
                yield conn
            except BaseException:
                with suppress(SQLAlchemyError):
                    trans.rollback()
                raise
            trans.commit()
        finally:
            conn.close()

    def _pg_tx(self, *, lock: bool, lock_timeout: str | None) -> Iterator[Connection]:
        conn = self._engine.connect().execution_options(isolation_level="READ COMMITTED")
        try:
            trans = conn.begin()
            try:
                if lock_timeout is not None:
                    conn.execute(text(f"SET LOCAL lock_timeout = '{lock_timeout}'"))
                if lock:
                    # The first statement that touches data: see the module docstring.
                    conn.execute(text(_ADVISORY_XACT_SQL))
                yield conn
            except BaseException:
                with suppress(SQLAlchemyError):
                    trans.rollback()
                raise
            trans.commit()
        finally:
            conn.close()


def _sqlite_on_connect(dbapi_connection: Any, record: Any) -> None:
    # Transactions are driven explicitly (BEGIN IMMEDIATE), never implicitly by
    # the driver.
    dbapi_connection.isolation_level = None
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=FULL")
    finally:
        cursor.close()


def _sqlite_on_begin(conn: Connection) -> None:
    mode = conn.get_execution_options().get(BEGIN_OPTION, "DEFERRED")
    conn.exec_driver_sql("BEGIN IMMEDIATE" if mode == "IMMEDIATE" else "BEGIN")
