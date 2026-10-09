"""Moving an existing SQLite token database into PostgreSQL.

Switching ``DATABASE_URL`` to an empty PostgreSQL database would silently drop
``principal_status`` (the disablements) and re-activate disabled users, who could
then enroll again. The server therefore refuses to start in that situation
(``legacy_sqlite_has_rows``) and ``token_admin db import-sqlite`` is the way
across: one transaction, ciphertexts copied unchanged (the AAD does not depend
on the backend), and a check that the counts match and that every stored token
still decrypts with the keyring. Anything wrong rolls the whole import back.
"""

from __future__ import annotations

import pathlib
import sqlite3
import tempfile
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, insert, select, text

from . import migrate, schema
from .engine import Database
from .errors import StoreUnavailable, TokenStoreError

#: Tables copied, in order. ``meta`` is not copied: the target is created by Alembic.
COPIED_TABLES = (
    "canvas_tokens",
    "user_tool_prefs",
    "principal_status",
    "principal_status_events",
    "credential_generations",
)
_PROBE_TABLES = ("canvas_tokens", "principal_status", "principal_status_events", "user_tool_prefs")


@dataclass(frozen=True)
class ImportReport:
    counts: dict[str, int]


def legacy_sqlite_has_rows(path: pathlib.Path) -> bool:
    """True if the SQLite file at ``path`` exists and holds enrollments or access state.

    A file that exists but cannot be read counts as "has rows": the caller refuses
    rather than guess that nothing would be lost.
    """
    if not path.is_file():
        return False
    try:
        conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error:
        return True
    try:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        for table in _PROBE_TABLES:
            if table in names and conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                return True
        return False
    except sqlite3.Error:
        return True
    finally:
        conn.close()


def import_sqlite(target: Database, source: pathlib.Path, keyring: Any) -> ImportReport:
    """Copy every table of the SQLite file ``source`` into the empty PostgreSQL ``target``.

    ``source`` is never modified: it is copied to a private temporary file, adopted
    to the current schema there, and read from the copy.
    """
    from ..token_store import (
        KeyringError,
        TokenDecryptionError,
        _aad_for_principal,
    )

    if target.kind != "postgresql":
        raise TokenStoreError("import-sqlite writes to PostgreSQL; DATABASE_URL must name it")
    if not source.is_file():
        raise TokenStoreError("the SQLite file to import does not exist")

    with tempfile.TemporaryDirectory(prefix="canvas-mcp-import-") as tmp:
        copy = pathlib.Path(tmp) / "source.sqlite3"
        try:
            src = sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True, timeout=5.0)
            try:
                dst = sqlite3.connect(str(copy))
                try:
                    src.backup(dst)
                finally:
                    dst.close()
            finally:
                src.close()
        except sqlite3.Error:
            raise StoreUnavailable("the SQLite file cannot be read", "sqlite3.Error") from None
        origin = Database.sqlite(copy)
        try:
            migrate.ensure_ready(origin, auto=True)
            with origin.read() as oconn:
                rows = {name: oconn.execute(select(schema.metadata.tables[name])).all() for name in COPIED_TABLES}
        finally:
            origin.dispose()

    migrate.ensure_ready(target, auto=True)
    counts: dict[str, int] = {}
    with target.guard(), target.write() as conn:
        for name in COPIED_TABLES:
            table = schema.metadata.tables[name]
            if conn.execute(select(func.count()).select_from(table)).scalar_one():
                raise TokenStoreError(
                    "refusing to import into a PostgreSQL database that already holds data"
                )
        for name in COPIED_TABLES:
            table = schema.metadata.tables[name]
            data = [dict(row._mapping) for row in rows[name]]
            if data:
                conn.execute(insert(table), data)
            counts[name] = len(data)
        # Keep the identity of the history table ahead of the ids just copied.
        conn.execute(
            text(
                "SELECT setval(pg_get_serial_sequence('principal_status_events', 'id'),"
                " COALESCE((SELECT MAX(id) FROM principal_status_events), 1),"
                " (SELECT MAX(id) IS NOT NULL FROM principal_status_events))"
            )
        )
        for name in COPIED_TABLES:
            stored = conn.execute(select(func.count()).select_from(schema.metadata.tables[name])).scalar_one()
            if stored != counts[name]:
                raise TokenStoreError("row counts differ after the import; nothing was imported")
        tokens = schema.canvas_tokens
        key_ids = set(keyring.key_ids)
        for row in conn.execute(
            select(
                tokens.c.principal_key,
                tokens.c.canvas_host,
                tokens.c.key_id,
                tokens.c.nonce,
                tokens.c.ciphertext,
            )
        ):
            if row.key_id not in key_ids:
                raise KeyringError(
                    f"CANVAS_TOKEN_KEYS is missing key id {row.key_id}; nothing was imported"
                )
            try:
                aad = _aad_for_principal(row.principal_key, row.canvas_host, row.key_id)
                keyring.decrypt(row.key_id, bytes(row.nonce), bytes(row.ciphertext), aad)
            except (TokenDecryptionError, ValueError):
                raise TokenStoreError(
                    "a stored token does not decrypt with CANVAS_TOKEN_KEYS; nothing was imported"
                ) from None
    return ImportReport(counts)
