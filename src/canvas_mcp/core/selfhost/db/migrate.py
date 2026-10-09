"""Schema management with Alembic, run programmatically.

* ``meta.schema_version`` stays the cross-release compatibility marker (still
  ``4``): a server refuses a database whose marker is newer than it supports.
  Alembic keeps its own table (``canvas_mcp_alembic_version``). Rule for
  future revisions: one that an older server would misread must raise the marker
  by declaring a higher ``COMPAT_SCHEMA_VERSION``; this module writes the head
  revision's value into ``meta`` after every upgrade.
* A database file created before Alembic (schema versions 1 to 4) is adopted by
  running the baseline's idempotent steps, then recording the baseline revision,
  inside one transaction. No row's ciphertext, nonce or key id is touched.
* A newer database (higher marker, or an Alembic revision this build does not
  know) is refused and left untouched.
* SQLite: the whole adoption plus upgrade runs on one connection inside
  ``BEGIN IMMEDIATE`` (a crash leaves the file unchanged). PostgreSQL: DDL is
  transactional; a session-level advisory lock serialises concurrent starters
  (one migrates, the others wait and find the schema current).
* There is no downgrade. Back up first (``token_admin db upgrade --backup``).
"""

from __future__ import annotations

import os
import pathlib
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection

from . import baseline_v4, schema
from .engine import MIGRATION_LOCK_KEY, Database
from .errors import StoreUnavailable, TokenStoreError
from .repos import SqlMetaRepo

#: The newest ``meta.schema_version`` this server understands (the head's marker).
BASELINE_REVISION = "0001_baseline_v4"

MIGRATION_LOCK_WAIT_SECONDS = 30.0

STATE_UNINITIALIZED = "uninitialized"  # an empty database
STATE_LEGACY = "legacy"  # tables from before Alembic, not yet recorded
STATE_BEHIND = "behind"  # recorded, but older than this build (or damaged)
STATE_CURRENT = "current"
STATE_NEWER = "newer"  # written by a newer server: refused
STATE_UNREADABLE = "unreadable"  # the compatibility marker cannot be read: refused

_MIGRATIONS_DIR = pathlib.Path(__file__).parent / "migrations"


@dataclass(frozen=True)
class MigrationStatus:
    backend: str
    alembic_revision: str | None
    meta_version: str | None
    head: str
    state: str


def _config(connection: Connection | None = None, dialect: str | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(_MIGRATIONS_DIR).replace("%", "%%"))
    if connection is not None:
        cfg.attributes["connection"] = connection
    if dialect is not None:
        cfg.attributes["dialect"] = dialect
    return cfg


@lru_cache(maxsize=1)
def _script() -> ScriptDirectory:
    return ScriptDirectory.from_config(_config())


def head_revision() -> str:
    head = _script().get_current_head()
    assert head is not None
    return head


def known_revisions() -> set[str]:
    return {rev.revision for rev in _script().walk_revisions()}


def revision_compat_versions() -> dict[str, int]:
    """``COMPAT_SCHEMA_VERSION`` of every revision, oldest first (for the policy test)."""
    result: dict[str, int] = {}
    for rev in reversed(list(_script().walk_revisions())):
        module: Any = rev.module
        result[rev.revision] = int(module.COMPAT_SCHEMA_VERSION)
    return result


def head_compat_version() -> int:
    return revision_compat_versions()[head_revision()]


def read_status(conn: Connection) -> MigrationStatus:
    """Classify the database behind ``conn`` without changing it."""
    backend = conn.dialect.name
    tables = set(inspect(conn).get_table_names())
    head = head_revision()

    revision: str | None = None
    if schema.VERSION_TABLE in tables:
        rows = conn.execute(text(f"SELECT version_num FROM {schema.VERSION_TABLE}")).all()
        if len(rows) > 1:
            return MigrationStatus(backend, "?", None, head, STATE_UNREADABLE)
        revision = rows[0][0] if rows else None

    meta_version: str | None = None
    if "meta" in tables:
        meta_version = SqlMetaRepo().schema_version(conn)

    parsed: int | None = None
    if meta_version is not None:
        try:
            parsed = int(meta_version)
        except ValueError:
            return MigrationStatus(backend, revision, meta_version, head, STATE_UNREADABLE)
        if parsed > head_compat_version():
            return MigrationStatus(backend, revision, meta_version, head, STATE_NEWER)
    if revision is not None and revision not in known_revisions():
        return MigrationStatus(backend, revision, meta_version, head, STATE_NEWER)

    if revision == head and parsed == head_compat_version():
        state = STATE_CURRENT
    elif revision is not None:
        state = STATE_BEHIND
    elif tables & set(schema.TABLE_NAMES):
        state = STATE_LEGACY
    else:
        state = STATE_UNINITIALIZED
    return MigrationStatus(backend, revision, meta_version, head, state)


def _refuse_unusable(status: MigrationStatus) -> None:
    if status.state == STATE_UNREADABLE:
        raise TokenStoreError("token database has an unreadable schema version")
    if status.state == STATE_NEWER:
        if status.meta_version is not None and status.meta_version.isdigit() and int(
            status.meta_version
        ) > head_compat_version():
            raise TokenStoreError(
                f"token database schema version {status.meta_version} is newer "
                f"than this server supports ({head_compat_version()})"
            )
        raise TokenStoreError(
            "token database was migrated by a newer server (unknown revision); "
            "this server supports up to revision " + status.head
        )


def _needs_migration_error() -> TokenStoreError:
    return TokenStoreError(
        "the token database schema is not current and DATABASE_AUTO_MIGRATE is off; "
        "back it up and run: python -m canvas_mcp.core.selfhost.token_admin db upgrade"
    )


def _apply(conn: Connection, status: MigrationStatus) -> None:
    """Upgrade to head on a connection that is inside the caller's transaction."""
    cfg = _config(connection=conn)
    if status.alembic_revision == BASELINE_REVISION and conn.dialect.name == "sqlite":
        # Always repair at baseline level: a half-migrated or tampered file is
        # completed, exactly as the pre-Alembic code did at every start.
        baseline_v4.ensure_sqlite_v4(conn)
    command.upgrade(cfg, "head")
    meta = SqlMetaRepo()
    target = head_compat_version()
    current = meta.schema_version(conn)
    if current is None or int(current) < target:
        meta.set_schema_version(conn, str(target))


def ensure_ready(db: Database, *, auto: bool = True) -> None:
    """Make the database current, or refuse. Used at every start of the server."""
    with db.guard():
        if db.kind == "sqlite":
            _ensure_sqlite(db, auto)
        else:
            _ensure_postgresql(db, auto)


def _ensure_sqlite(db: Database, auto: bool) -> None:
    with db.write() as conn:
        status = read_status(conn)
        _refuse_unusable(status)
        if not auto:
            if status.state != STATE_CURRENT:
                raise _needs_migration_error()
            return
        _apply(conn, status)


def _ensure_postgresql(db: Database, auto: bool) -> None:
    with db.read() as conn:
        status = read_status(conn)
    _refuse_unusable(status)
    if status.state == STATE_CURRENT:
        return
    if not auto:
        raise _needs_migration_error()
    with _postgres_migration_lock(db):
        with db.write() as conn:
            status = read_status(conn)
            _refuse_unusable(status)
            if status.state != STATE_CURRENT:
                _apply(conn, status)


@contextmanager
def _postgres_migration_lock(db: Database) -> Iterator[None]:
    """A session-level advisory lock; waits for another migrating process, then refuses."""
    conn = db.engine.connect().execution_options(isolation_level="AUTOCOMMIT")
    locked = False
    try:
        deadline = time.monotonic() + MIGRATION_LOCK_WAIT_SECONDS
        while True:
            locked = bool(
                conn.execute(text(f"SELECT pg_try_advisory_lock({MIGRATION_LOCK_KEY})")).scalar_one()
            )
            if locked:
                break
            if time.monotonic() >= deadline:
                raise TokenStoreError(
                    "another process is migrating the token database; retry in a moment, "
                    "or run token_admin db upgrade"
                )
            time.sleep(0.2)
        yield
    finally:
        if locked:
            with suppress(Exception):
                conn.execute(text(f"SELECT pg_advisory_unlock({MIGRATION_LOCK_KEY})"))
        conn.close()


def current(db: Database) -> MigrationStatus:
    """The migration state, without migrating (``token_admin db current``).

    A SQLite file that does not exist yet is "uninitialized"; nothing is created.
    """
    path = db.sqlite_path
    if path is not None and not path.exists():
        return MigrationStatus("sqlite", None, None, head_revision(), STATE_UNINITIALIZED)
    with db.guard(), db.read() as conn:
        return read_status(conn)


def upgrade(db: Database, *, backup_to: pathlib.Path | None = None) -> tuple[MigrationStatus, MigrationStatus]:
    """Upgrade to head (``token_admin db upgrade``); returns the status before and after."""
    before = current(db)
    _refuse_unusable(before)
    db.prepare_storage()
    if backup_to is not None:
        backup_sqlite(db, backup_to)
    ensure_ready(db, auto=True)
    return before, current(db)


def backup_sqlite(db: Database, destination: pathlib.Path) -> None:
    """Copy the SQLite database to a new private file with the sqlite3 backup API."""
    source_path = db.sqlite_path
    if db.kind != "sqlite" or source_path is None:
        raise TokenStoreError("--backup copies a SQLite file; back up PostgreSQL with pg_dump")
    if not source_path.exists():
        return
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise TokenStoreError("the backup file already exists; choose a new path") from None
    os.close(fd)
    src = sqlite3.connect(str(source_path), timeout=5.0)
    try:
        dst = sqlite3.connect(str(destination))
        try:
            src.backup(dst)
        finally:
            dst.close()
    except sqlite3.Error:
        with suppress(OSError):
            destination.unlink()
        raise StoreUnavailable(kind="BackupFailed") from None
    finally:
        src.close()
    if os.name == "posix":
        os.chmod(destination, 0o600)


def compare_schema(conn: Connection) -> list[Any]:
    """Differences between the live tables and ``schema.metadata`` (empty = identical)."""
    ctx = MigrationContext.configure(
        conn,
        opts={
            "compare_type": True,
            "include_object": lambda obj, name, type_, reflected, compare_to: not (
                type_ == "table" and name == schema.VERSION_TABLE
            ),
        },
    )
    return list(compare_metadata(ctx, schema.metadata))


def render_sql(dialect: str) -> str:
    """The DDL ``upgrade head`` would run on ``dialect``, as offline SQL."""
    import io
    from contextlib import redirect_stdout

    buffer = io.StringIO()
    cfg = _config(dialect=dialect)
    cfg.output_buffer = buffer
    with redirect_stdout(buffer):
        command.upgrade(cfg, "head", sql=True)
    return buffer.getvalue()


__all__ = [
    "BASELINE_REVISION",
    "MigrationStatus",
    "backup_sqlite",
    "compare_schema",
    "current",
    "ensure_ready",
    "head_compat_version",
    "head_revision",
    "known_revisions",
    "read_status",
    "render_sql",
    "revision_compat_versions",
    "upgrade",
]
