"""Moving an existing SQLite token database into PostgreSQL.

Switching ``DATABASE_URL`` to an empty database would silently drop
``accounts`` (the disablements) and re-activate disabled users, who could
then enroll again. The server and the operator CLI therefore refuse to run in that
situation (``refuse_silent_switch``: the target holds no rows while the default
SQLite file does; an empty schema does not count as data) and
``token_admin db import-sqlite`` is the way across: one transaction, ciphertexts copied unchanged (the AAD does not depend
on the backend), and a check that the counts match and that every stored token
still decrypts with the keyring. A SQLite file from before the account model is
migrated (on a private copy) with that keyring first. Anything wrong rolls the whole
import back.
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
    "accounts",
    "external_identities",
    "principal_status_events",
    "credential_generations",
    "auth_events",
    "audit_log",
)
#: The tables whose rows make a database "hold data" for the silent-switch guard.
#: (The sign-in history and the audit log only exist next to accounts.)
_DATA_TABLES = (
    "canvas_tokens",
    "user_tool_prefs",
    "accounts",
    "external_identities",
    "principal_status_events",
    "credential_generations",
)
#: Probed in a SQLite file of any release: the legacy ``principal_status`` is still
#: listed, because a file from before the account model keeps its disablements there.
_PROBE_TABLES = (
    "canvas_tokens",
    "principal_status",
    "principal_status_events",
    "user_tool_prefs",
    "accounts",
    "external_identities",
)
#: Tables with an identity column: the sequence is moved past the copied ids.
_IDENTITY_TABLES = ("principal_status_events", "external_identities", "auth_events", "audit_log")


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


def target_holds_rows(target: Database) -> bool:
    """True if any table that holds accounts, tokens or access state of ``target`` has a row.

    Judged by data, not by schema: a schema that a failed import, ``db upgrade`` or
    a read-only CLI command created is still an empty database.
    """
    from sqlalchemy import inspect

    with target.guard(), target.read() as conn:
        existing = set(inspect(conn).get_table_names())
        for name in _DATA_TABLES:
            if name in existing:
                table = schema.metadata.tables[name]
                if conn.execute(select(table).limit(1)).first() is not None:
                    return True
    return False


def refuse_silent_switch(target: Database, legacy_path: pathlib.Path) -> None:
    """Fail closed when ``target`` holds no data but the default SQLite file does.

    Starting on such a target would drop the disablements stored in the SQLite file,
    and a disabled user could enroll again. Does nothing when ``target`` is that
    SQLite file itself, when the file holds nothing, or when the target is a
    database this build refuses anyway (newer or unreadable: ``ensure_ready``
    reports that with its own message). Raises :class:`TokenStoreError`.
    """
    sqlite_path = target.sqlite_path
    if sqlite_path is not None:
        try:
            if sqlite_path.resolve() == legacy_path.resolve():
                return
        except OSError:
            if sqlite_path == legacy_path:
                return
    if not legacy_sqlite_has_rows(legacy_path):
        return
    state = migrate.current(target).state
    if state in (migrate.STATE_NEWER, migrate.STATE_UNREADABLE):
        return
    if state != migrate.STATE_UNINITIALIZED and target_holds_rows(target):
        return
    way_across = (
        "Import it with: python -m canvas_mcp.core.selfhost.token_admin db import-sqlite PATH, "
        "or move the SQLite file away if it is meant to be abandoned"
        if target.kind == "postgresql"
        else "Point DATABASE_URL back at it, or move the SQLite file away if it is meant "
        "to be abandoned"
    )
    raise TokenStoreError(
        "DATABASE_URL names a database that holds no data, but the SQLite token database "
        f"in the data directory still holds data (including access decisions). {way_across}"
    )


def import_sqlite(target: Database, source: pathlib.Path, keyring: Any) -> ImportReport:
    """Copy every table of the SQLite file ``source`` into the empty PostgreSQL ``target``.

    ``source`` is never modified: it is copied to a private temporary file, adopted
    to the current schema there (with ``keyring``, because the account model
    re-encrypts the tokens), and read from the copy.
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
            migrate.ensure_ready(origin, auto=True, keyring=keyring, auto_backup=False)
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
        # Keep every identity column ahead of the ids just copied.
        for identity_table in _IDENTITY_TABLES:
            conn.execute(
                text(
                    f"SELECT setval(pg_get_serial_sequence('{identity_table}', 'id'),"
                    f" COALESCE((SELECT MAX(id) FROM {identity_table}), 1),"
                    f" (SELECT MAX(id) IS NOT NULL FROM {identity_table}))"
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
                tokens.c.status,
                tokens.c.invalid_reason,
            )
        ):
            if row.status == "invalid" and row.invalid_reason == "decrypt_failed":
                # Already known to be unreadable in the source: carried over as it was.
                continue
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
