"""The v1 Alembic graph and expand/contract compatibility gate.

Pre-v1 databases are never adopted or re-encrypted. Revisions use frozen DDL;
current metadata is used only for schema comparison. A compatible newer expand
release can be served, but this build never migrates its unknown revision.
"""

from __future__ import annotations

import logging
import os
import pathlib
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from uuid import UUID

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection

from .. import schema
from ..engine import Database
from ..errors import StoreUnavailable, TokenStoreError
from .connections import (
    MIGRATION_LOCK_KEY,
    postgres_migration_connection,
    postgres_upgrade_connection,
    postgres_upgrade_transaction,
    sqlite_migration,
)
from .policy import RevisionPolicy, pending

SCHEMA_EPOCH = 1
MIGRATION_LOCK_WAIT_SECONDS = 30.0
PG_MIGRATION_LOCK_TIMEOUT = "30s"
PG_MIGRATION_STATEMENT_TIMEOUT = "120s"
STATE_UNINITIALIZED = "uninitialized"
STATE_BEHIND = "behind"
STATE_CURRENT = "current"
STATE_NEWER = "newer"
STATE_TOO_NEW = "too_new"
STATE_PRE_V1 = "pre_v1"
STATE_UNREADABLE = "unreadable"
_PRE_V1_REVISIONS = {"0001_baseline_v4", "0002_accounts", "0003_oauth_authz"}
_MIGRATIONS_DIR = pathlib.Path(__file__).parent
logger = logging.getLogger("canvas_mcp.selfhost.account")


@dataclass(frozen=True)
class MigrationStatus:
    backend: str
    alembic_revision: str | None
    database_id: str | None
    compat_floor: int | None
    head: str
    state: str


class _DryRun(Exception):
    """Roll back a reviewed upgrade without changing the database."""


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


def read_status(conn: Connection) -> MigrationStatus:
    tables = set(inspect(conn).get_table_names())
    revision = None
    identifier = None
    floor = None
    state = STATE_UNREADABLE
    if schema.VERSION_TABLE in tables:
        rows = conn.execute(
            text("SELECT version_num FROM " + schema.VERSION_TABLE)
        ).all()
        if len(rows) > 1:
            return MigrationStatus(
                conn.dialect.name, None, None, None, head_revision(), state
            )
        revision = rows[0][0] if rows else None
    if "meta" in tables or revision in _PRE_V1_REVISIONS:
        state = STATE_PRE_V1
    elif not tables or tables == {schema.VERSION_TABLE} and revision is None:
        state = STATE_UNINITIALIZED
    elif "server_state" in tables:
        state_rows = (
            conn.execute(text("SELECT id,database_id,compat_floor FROM server_state"))
            .mappings()
            .all()
        )
        if len(state_rows) == 1 and state_rows[0]["id"] == 1:
            row = state_rows[0]
            try:
                identifier = str(UUID(str(row["database_id"])))
            except (TypeError, ValueError):
                return MigrationStatus(
                    conn.dialect.name,
                    revision,
                    None,
                    None,
                    head_revision(),
                    STATE_UNREADABLE,
                )
            floor = row["compat_floor"]
            if not isinstance(floor, int) or isinstance(floor, bool) or floor < 1:
                state = STATE_UNREADABLE
            elif floor > SCHEMA_EPOCH:
                state = STATE_TOO_NEW
            elif (
                revision is not None
                and revision in known_revisions()
                and revision != head_revision()
            ):
                state = STATE_BEHIND
            elif revision is None or not set(schema.metadata.tables).issubset(tables):
                state = STATE_UNREADABLE
            elif revision == head_revision():
                state = STATE_CURRENT
            else:
                state = STATE_NEWER
    return MigrationStatus(
        conn.dialect.name, revision, identifier, floor, head_revision(), state
    )


def _refuse_unusable(status: MigrationStatus) -> None:
    if status.state == STATE_PRE_V1:
        raise TokenStoreError(
            "database from a pre-v1 build; nothing is deployed, so delete it"
        )
    if status.state == STATE_TOO_NEW:
        raise TokenStoreError(
            "database compatibility floor exceeds this server schema epoch"
        )
    if status.state == STATE_UNREADABLE:
        raise TokenStoreError("database schema state is unreadable")


def _apply(
    conn: Connection, revision: str = "head", *, per_migration: bool = False
) -> None:
    cfg = _config(connection=conn)
    cfg.attributes["transaction_per_migration"] = per_migration
    command.upgrade(cfg, revision)


def ensure_ready(
    db: Database,
    *,
    auto: bool = True,
    dry_run: bool = False,
    populate: Callable[[Connection], None] | None = None,
    backup_to: pathlib.Path | None = None,
) -> None:
    if populate is not None and (db.kind != "postgresql" or dry_run):
        raise TokenStoreError("populate runs on PostgreSQL, outside a dry run")
    with db.guard():
        lock = (
            _postgres_migration_lock(db) if db.kind == "postgresql" else nullcontext()
        )
        try:
            with lock:
                transaction = (
                    postgres_upgrade_transaction(db)
                    if db.kind == "postgresql"
                    else sqlite_migration(db)
                )
                standalone: tuple[RevisionPolicy, ...] = ()
                with transaction as conn:
                    status = read_status(conn)
                    _refuse_unusable(status)
                    if status.state == STATE_NEWER:
                        if populate is not None:
                            raise TokenStoreError(
                                "cannot import into an unknown newer revision"
                            )
                        logger.warning("database is newer than this release")
                        return
                    if backup_to is not None and db.kind == "sqlite" and not dry_run:
                        backup_sqlite(db, backup_to)
                    if status.state != STATE_CURRENT:
                        if not auto:
                            raise TokenStoreError(
                                "database schema is not current and DATABASE_AUTO_MIGRATE is off; run token_admin db upgrade"
                            )
                        plan = pending(_script(), status.alembic_revision)
                        if db.kind == "postgresql" and any(
                            step.non_transactional for step in plan
                        ):
                            if dry_run or populate is not None:
                                raise TokenStoreError(
                                    "non-transactional revisions cannot run in a dry run or atomic import"
                                )
                            standalone = plan
                        else:
                            if db.kind == "sqlite" and not dry_run:
                                contract = next(
                                    (step for step in plan if step.contract), None
                                )
                                path = db.sqlite_path
                                if (
                                    status.state == STATE_BEHIND
                                    and backup_to is None
                                    and contract is not None
                                    and path is not None
                                ):
                                    backup_sqlite(
                                        db,
                                        path.with_name(
                                            path.name
                                            + f".pre-{contract.revision}-{time.time_ns()}.bak"
                                        ),
                                    )
                            _apply(conn)
                            if dry_run:
                                raise _DryRun
                    if populate is not None and not standalone:
                        populate(conn)
                if standalone:
                    with postgres_upgrade_connection(db) as conn:
                        for step in standalone:
                            if step.non_transactional:
                                # Alembic owns short transactions; the revision's
                                # concurrent_index/autocommit_block commits only
                                # this revision, never an atomic import transaction.
                                _apply(conn, step.revision, per_migration=True)
                            else:
                                with conn.begin():
                                    _apply(conn, step.revision)
        except _DryRun:
            return


@contextmanager
def _postgres_migration_lock(db: Database) -> Iterator[None]:
    with postgres_migration_connection(db) as conn:
        locked = False
        try:
            deadline = time.monotonic() + MIGRATION_LOCK_WAIT_SECONDS
            while not locked:
                locked = bool(
                    conn.execute(
                        text(f"SELECT pg_try_advisory_lock({MIGRATION_LOCK_KEY})")
                    ).scalar_one()
                )
                if not locked:
                    if time.monotonic() >= deadline:
                        raise TokenStoreError(
                            "another process is migrating the database; retry token_admin db upgrade"
                        )
                    time.sleep(0.2)
            yield
        finally:
            if locked:
                with suppress(Exception):
                    conn.execute(
                        text(f"SELECT pg_advisory_unlock({MIGRATION_LOCK_KEY})")
                    )


def current(db: Database) -> MigrationStatus:
    path = db.sqlite_path
    if path is not None and not path.exists():
        return MigrationStatus(
            "sqlite", None, None, None, head_revision(), STATE_UNINITIALIZED
        )
    with db.guard(), db.read() as conn:
        return read_status(conn)


def upgrade(
    db: Database, *, backup_to: pathlib.Path | None = None, dry_run: bool = False
) -> tuple[MigrationStatus, MigrationStatus]:
    before = current(db)
    _refuse_unusable(before)
    path = db.sqlite_path
    if dry_run and path is not None and not path.exists():
        return before, before
    db.prepare_storage()
    if backup_to is not None and db.kind != "sqlite":
        raise TokenStoreError(
            "--backup copies a SQLite file; back up PostgreSQL with pg_dump"
        )
    ensure_ready(db, dry_run=dry_run, backup_to=backup_to)
    return before, current(db)


def backup_sqlite(db: Database, destination: pathlib.Path) -> None:
    """Copy the SQLite database to a new private file with the sqlite3 backup API."""
    source_path = db.sqlite_path
    if db.kind != "sqlite" or source_path is None:
        raise TokenStoreError(
            "--backup copies a SQLite file; back up PostgreSQL with pg_dump"
        )
    if not source_path.exists():
        return
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise TokenStoreError(
            "the backup file already exists; choose a new path"
        ) from None
    os.close(fd)
    src = None
    try:
        src = sqlite3.connect(
            source_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5.0
        )
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
        if src is not None:
            src.close()
    if os.name == "posix":
        os.chmod(destination, 0o600)


def compare_schema(conn: Connection) -> list[Any]:
    """Differences between the live tables and ``schema.metadata`` (empty = identical)."""
    ctx = MigrationContext.configure(
        conn,
        opts={
            "compare_type": True,
            "include_object": lambda obj, name, type_, reflected, compare_to: (
                not (type_ == "table" and name == schema.VERSION_TABLE)
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
