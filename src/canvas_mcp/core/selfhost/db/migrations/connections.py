"""Dedicated migration connections; none enters the application's request pool."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, suppress
from typing import Any

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool

from ..engine import (
    BEGIN_OPTION,
    PG_CONNECT_TIMEOUT_SECONDS,
    SQLITE_BUSY_TIMEOUT_SECONDS,
    Database,
    _advisory_key,
    _sqlite_on_begin,
    _sqlite_on_connect,
)
from ..errors import TokenStoreError

MIGRATION_LOCK_KEY = _advisory_key("canvas-mcp/token-store/migrations")


@contextmanager
def sqlite_migration(db: Database) -> Iterator[Connection]:
    """Keep foreign-key-disabled DDL connections outside the request pool."""
    if db.kind != "sqlite":
        raise TokenStoreError("SQLite migration connection requires a SQLite database")
    dedicated = create_engine(
        db.engine.url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={
            "timeout": SQLITE_BUSY_TIMEOUT_SECONDS,
            "check_same_thread": False,
        },
    )

    def setup(raw: Any, record: Any) -> None:
        _sqlite_on_connect(raw, record)
        raw.execute("PRAGMA foreign_keys=OFF")

    event.listen(dedicated, "connect", setup)
    event.listen(dedicated, "begin", _sqlite_on_begin)
    try:
        with db.guard(), db.write_gate():
            conn = dedicated.connect().execution_options(**{BEGIN_OPTION: "IMMEDIATE"})
            try:
                trans = conn.begin()
                try:
                    yield conn
                    if (
                        conn.exec_driver_sql("PRAGMA foreign_key_check").first()
                        is not None
                    ):
                        raise TokenStoreError("migration failed foreign key validation")
                except BaseException:
                    with suppress(SQLAlchemyError):
                        trans.rollback()
                    raise
                trans.commit()
            finally:
                conn.close()
    finally:
        dedicated.dispose()


@contextmanager
def postgres_migration_connection(db: Database) -> Iterator[Connection]:
    """A direct, unpooled connection for a session migration advisory lock."""
    if db.kind != "postgresql":
        raise TokenStoreError("PostgreSQL migration connection requires PostgreSQL")
    direct = create_engine(
        db.engine.url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"connect_timeout": PG_CONNECT_TIMEOUT_SECONDS},
    )
    try:
        with (
            db.guard(),
            direct.connect().execution_options(isolation_level="AUTOCOMMIT") as conn,
        ):
            yield conn
    finally:
        direct.dispose()


@contextmanager
def postgres_upgrade_connection(db: Database) -> Iterator[Connection]:
    """An unpooled DDL connection, separate from the session migration lock."""
    if db.kind != "postgresql":
        raise TokenStoreError("PostgreSQL upgrade connection requires PostgreSQL")
    with db.read() as reader:
        search_path: str = reader.exec_driver_sql("SHOW search_path").scalar_one()
    direct = create_engine(
        db.engine.url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"connect_timeout": PG_CONNECT_TIMEOUT_SECONDS},
    )
    try:
        with direct.connect() as conn:
            conn.execute(
                text("SELECT set_config('search_path', :path, false)"),
                {"path": search_path},
            )
            conn.execute(text("SET lock_timeout = '30s'"))
            conn.execute(text("SET statement_timeout = '120s'"))
            conn.commit()
            yield conn
    finally:
        direct.dispose()


@contextmanager
def postgres_upgrade_transaction(db: Database) -> Iterator[Connection]:
    with postgres_upgrade_connection(db) as conn, conn.begin():
        yield conn
