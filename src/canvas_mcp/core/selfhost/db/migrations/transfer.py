"""Atomic v1 SQLite-to-PostgreSQL transfer; all upgrade tooling stays here."""

from __future__ import annotations

import pathlib
import sqlite3
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from dataclasses import dataclass

from sqlalchemy import Table, delete, func, insert, inspect, select, text, update
from sqlalchemy.engine import Connection

from .. import schema
from ..engine import Database
from ..errors import StoreUnavailable, TokenStoreError
from ..sealed import SealKeys, verify
from . import runner


@dataclass(frozen=True)
class ImportReport:
    counts: dict[str, int]
    sealed_values_checked: int


def copied_tables() -> tuple[Table, ...]:
    return tuple(
        table
        for table in schema.metadata.sorted_tables
        if table.info["lifecycle"] in ("durable", "history", "reserved")
    )


def sqlite_has_rows(path: pathlib.Path) -> bool:
    """Fail closed for unreadable files and unknown historical tables holding data."""
    if not path.is_file():
        return False
    try:
        with closing(
            sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=5)
        ) as conn:
            names = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            for (name,) in names:
                if name.startswith("sqlite_") or name in (
                    schema.VERSION_TABLE,
                    "server_state",
                    "login_providers",
                ):
                    continue
                quoted = '"' + name.replace('"', '""') + '"'
                if conn.execute(f"SELECT 1 FROM {quoted} LIMIT 1").fetchone():
                    return True
        return False
    except sqlite3.Error:
        return True


def _holds_rows(conn: Connection) -> bool:
    existing = set(inspect(conn).get_table_names())
    for table in schema.metadata.sorted_tables:
        if (
            table.name in ("server_state", "login_providers")
            or table.name not in existing
        ):
            continue
        if conn.execute(select(1).select_from(table).limit(1)).first():
            return True
    return False


def target_holds_rows(target: Database) -> bool:
    # A preflight must not create an empty SQLite database merely by connecting.
    if target.sqlite_path is not None and not target.sqlite_path.exists():
        return False
    with target.guard(), target.read() as conn:
        return _holds_rows(conn)


def refuse_silent_switch(target: Database, sqlite_path: pathlib.Path) -> None:
    if (
        target.sqlite_path is not None
        and target.sqlite_path.resolve() == sqlite_path.resolve()
    ):
        return
    if not sqlite_has_rows(sqlite_path):
        return
    state = runner.current(target).state
    if state in (
        runner.STATE_NEWER,
        runner.STATE_TOO_NEW,
        runner.STATE_PRE_V1,
        runner.STATE_UNREADABLE,
    ):
        return  # The schema compatibility gate gives the precise refusal.
    if target_holds_rows(target):
        return
    instruction = (
        "Import it with: python -m canvas_mcp.core.selfhost.token_admin db import-sqlite PATH"
        if target.kind == "postgresql"
        else "Point DATABASE_URL back at the SQLite file"
    )
    raise TokenStoreError(
        "DATABASE_URL names a database that holds no data, but the SQLite token database "
        f"in the data directory still holds data (including access decisions). {instruction}, "
        "or move the SQLite file away if it is meant to be abandoned"
    )


@contextmanager
def _private_copy(source: pathlib.Path) -> Iterator[Database]:
    """Use SQLite's backup API; only the private snapshot is upgraded."""
    with tempfile.TemporaryDirectory(prefix="canvas-mcp-import-") as directory:
        path = pathlib.Path(directory) / "source.sqlite3"
        try:
            src = sqlite3.connect(
                f"{source.resolve().as_uri()}?mode=ro", uri=True, timeout=5
            )
            try:
                dst = sqlite3.connect(path)
                try:
                    src.backup(dst)
                finally:
                    dst.close()
            finally:
                src.close()
        except sqlite3.Error:
            raise StoreUnavailable(
                "the SQLite file cannot be read", "sqlite3.Error"
            ) from None
        origin = Database.sqlite(path)
        try:
            runner.ensure_ready(origin)
            if runner.current(origin).state != runner.STATE_CURRENT:
                raise TokenStoreError(
                    "the SQLite source must use a known v1 schema; nothing was imported"
                )
            with origin.read() as conn:
                if conn.exec_driver_sql("PRAGMA foreign_key_check").first():
                    raise TokenStoreError(
                        "the SQLite source has foreign-key violations; nothing was imported"
                    )
            yield origin
        finally:
            origin.dispose()


def _populate(conn: Connection, source: Connection, keys: SealKeys) -> ImportReport:
    state = schema.server_state
    original = source.execute(select(state)).mappings().one()
    target = conn.execute(select(state)).mappings().one()
    if original["database_id"] == target["database_id"]:
        raise TokenStoreError("refusing to import a database with the same database_id")
    if _holds_rows(conn):
        raise TokenStoreError(
            "refusing to import into a PostgreSQL database that already holds data"
        )
    counts: dict[str, int] = {}
    for table in copied_tables():
        if table.name == "login_providers":
            # Source settings win; keep target-only startup reconciled providers.
            identifiers: Sequence[str] = source.execute(select(table.c.id)).scalars().all()
            conn.execute(delete(table).where(table.c.id.in_(identifiers)))
        rows = source.execute(select(table)).mappings()
        count = 0
        for chunk in rows.partitions(1000):
            conn.execute(insert(table), [dict(row) for row in chunk])
            count += len(chunk)
        counts[table.name] = count
        if table.name == "login_providers":
            actual = conn.execute(
                select(func.count())
                .select_from(table)
                .where(table.c.id.in_(identifiers))
            ).scalar_one()
        else:
            actual = conn.execute(select(func.count()).select_from(table)).scalar_one()
        if actual != count:
            raise TokenStoreError(
                "row counts differ after the copy; nothing was imported"
            )
        for column in table.columns:
            if column.identity is not None:
                # Names come exclusively from the reviewed schema registry.
                sequence = conn.execute(
                    text(
                        "SELECT n.nspname,c.relname FROM pg_class c "
                        "JOIN pg_namespace n ON n.oid=c.relnamespace "
                        "WHERE c.oid=pg_get_serial_sequence(:table_name,:column_name)::regclass"
                    ),
                    {"table_name": table.name, "column_name": column.name},
                ).one()
                maximum: int | None = conn.execute(select(func.max(column))).scalar_one()
                next_value = int(maximum or 0) + 1
                quote = conn.dialect.identifier_preparer.quote
                # RESTART is transactional, unlike setval: a failed import must
                # also preserve sequences of an already initialized empty target.
                name = quote(sequence.nspname) + "." + quote(sequence.relname)
                conn.execute(text(f"ALTER SEQUENCE {name} RESTART WITH {next_value}"))
    conn.execute(
        update(state)
        .where(state.c.id == 1)
        .values(
            jwt_epoch=original["jwt_epoch"],
            settings_revision=original["settings_revision"] + 1,
            updated_at=original["updated_at"],
        )
    )
    return ImportReport(counts, verify(conn, keys, all_values=True))


def import_sqlite(
    target: Database, source: pathlib.Path, keys: SealKeys
) -> ImportReport:
    """One target transaction includes DDL, every copy, count checks and decryption."""
    if target.kind != "postgresql":
        raise TokenStoreError(
            "import-sqlite writes to PostgreSQL; DATABASE_URL must name it"
        )
    if not source.is_file():
        raise TokenStoreError("the SQLite file to import does not exist")
    with _private_copy(source) as origin, origin.read() as source_conn:
        report: ImportReport | None = None

        def populate(conn: Connection) -> None:
            nonlocal report
            report = _populate(conn, source_conn, keys)

        runner.ensure_ready(target, populate=populate)
        assert report is not None
        return report
