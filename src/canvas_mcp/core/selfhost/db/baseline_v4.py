"""FROZEN: schema version 4 of the token database, as the pre-Alembic releases wrote it.

Do not edit. This module is the body of the Alembic baseline revision
``0001_baseline_v4`` and is also what adopts a database file that was created
before Alembic existed (schema versions 1 to 4). Changing the DDL or the steps
here would change what a fresh or an adopted SQLite file looks like; a new
schema change is a new revision instead.

SQLite: the same idempotent steps the store ran at every start before Alembic
(create what is missing, add each missing column, backfill ``principal_key``,
create the unique index and the side tables, raise ``meta.schema_version`` to 4).
Version 2 exists in three historical shapes, so adoption is structural and never
trusts the version number alone.

PostgreSQL has no pre-Alembic databases: the baseline creates the same tables
with ``op.create_table`` (see the revision).
"""

from __future__ import annotations

from typing import Any

from .errors import TokenStoreError

SCHEMA_VERSION_V4 = 4

SCHEMA_META = (
    "CREATE TABLE IF NOT EXISTS meta ("
    " key TEXT PRIMARY KEY,"
    " value TEXT NOT NULL"
    ") WITHOUT ROWID"
)
SCHEMA_TOKENS = (
    "CREATE TABLE IF NOT EXISTS canvas_tokens ("
    " tenant_id TEXT NOT NULL,"
    " object_id TEXT NOT NULL,"
    " key_id TEXT NOT NULL,"
    " nonce BLOB NOT NULL,"
    " ciphertext BLOB NOT NULL,"
    " canvas_user_id TEXT NOT NULL,"
    " canvas_user_name TEXT NOT NULL,"
    " entra_display_name TEXT NOT NULL DEFAULT '',"
    " entra_upn TEXT NOT NULL DEFAULT '',"
    " created_at INTEGER NOT NULL,"
    " updated_at INTEGER NOT NULL,"
    " last_used_at INTEGER,"
    " canvas_host TEXT,"
    " principal_key TEXT,"
    " status TEXT NOT NULL DEFAULT 'active',"
    " invalid_reason TEXT,"
    " invalid_since INTEGER,"
    " last_verified_at INTEGER,"
    " expires_hint_at INTEGER,"
    " PRIMARY KEY (tenant_id, object_id)"
    ") WITHOUT ROWID"
)
SCHEMA_TOOL_PREFS = (
    "CREATE TABLE IF NOT EXISTS user_tool_prefs ("
    " principal_key TEXT PRIMARY KEY,"
    " enabled_write_tools TEXT NOT NULL DEFAULT '[]',"
    " enabled_at TEXT NOT NULL DEFAULT '{}',"
    " updated_at INTEGER NOT NULL,"
    " updated_via TEXT NOT NULL DEFAULT 'account_web'"
    ") WITHOUT ROWID"
)
SCHEMA_PRINCIPAL_STATUS = (
    "CREATE TABLE IF NOT EXISTS principal_status ("
    " principal_key TEXT PRIMARY KEY,"
    " status TEXT NOT NULL DEFAULT 'active',"
    " disabled_reason TEXT,"
    " disabled_at INTEGER,"
    " disabled_by TEXT,"
    " display_name TEXT NOT NULL DEFAULT '',"
    " upn TEXT NOT NULL DEFAULT '',"
    " session_epoch INTEGER NOT NULL DEFAULT 0,"
    " is_owner INTEGER NOT NULL DEFAULT 0,"
    " owner_seen_at INTEGER,"
    " updated_at INTEGER NOT NULL"
    ") WITHOUT ROWID"
)
SCHEMA_STATUS_EVENTS = (
    "CREATE TABLE IF NOT EXISTS principal_status_events ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " principal_key TEXT NOT NULL,"
    " action TEXT NOT NULL,"
    " actor TEXT,"
    " reason TEXT,"
    " session_epoch INTEGER NOT NULL,"
    " at INTEGER NOT NULL"
    ")"
)
SCHEMA_STATUS_EVENTS_INDEX = (
    "CREATE INDEX IF NOT EXISTS principal_status_events_principal"
    " ON principal_status_events (principal_key, id)"
)
SCHEMA_CREDENTIAL_GENERATIONS = (
    "CREATE TABLE IF NOT EXISTS credential_generations ("
    " principal_key TEXT PRIMARY KEY,"
    " generation INTEGER NOT NULL,"
    " reason TEXT NOT NULL DEFAULT '',"
    " updated_at INTEGER NOT NULL"
    ") WITHOUT ROWID"
)
SCHEMA_PRINCIPAL_INDEX = (
    "CREATE UNIQUE INDEX IF NOT EXISTS canvas_tokens_principal_key"
    " ON canvas_tokens (principal_key)"
)
# Columns added after version 1, as (name, definition). A database that lacks one
# gets it with ALTER TABLE; a freshly created table already has them all.
ADDED_COLUMNS = (
    ("canvas_host", "TEXT"),
    ("principal_key", "TEXT"),
    ("status", "TEXT NOT NULL DEFAULT 'active'"),
    ("invalid_reason", "TEXT"),
    ("invalid_since", "INTEGER"),
    ("last_verified_at", "INTEGER"),
    ("expires_hint_at", "INTEGER"),
)


def ensure_sqlite_v4(bind: Any) -> None:
    """Create or complete the version 4 schema on a SQLite connection; safe to repeat.

    ``bind`` is a SQLAlchemy ``Connection`` already inside a transaction. Refuses
    (changing nothing) a ``meta.schema_version`` that is unreadable or newer than 4.
    """
    bind.exec_driver_sql(SCHEMA_META)
    row = bind.exec_driver_sql("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    version: int | None = None
    if row is not None:
        try:
            version = int(row[0])
        except (TypeError, ValueError):
            raise TokenStoreError("token database has an unreadable schema version") from None
        if version > SCHEMA_VERSION_V4:
            raise TokenStoreError(
                f"token database schema version {version} is newer "
                f"than this server supports ({SCHEMA_VERSION_V4})"
            )
    bind.exec_driver_sql(SCHEMA_TOKENS)
    _migrate_columns(bind)
    _create_side_tables(bind)
    if version is None:
        bind.exec_driver_sql(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION_V4),),
        )
    elif version < SCHEMA_VERSION_V4:
        bind.exec_driver_sql(
            "UPDATE meta SET value = ? WHERE key = 'schema_version'",
            (str(SCHEMA_VERSION_V4),),
        )


def _create_side_tables(bind: Any) -> None:
    """The tables keyed by principal: tool switches, access status and its history."""
    bind.exec_driver_sql(SCHEMA_TOOL_PREFS)
    bind.exec_driver_sql(SCHEMA_PRINCIPAL_STATUS)
    bind.exec_driver_sql(SCHEMA_STATUS_EVENTS)
    bind.exec_driver_sql(SCHEMA_STATUS_EVENTS_INDEX)
    bind.exec_driver_sql(SCHEMA_CREDENTIAL_GENERATIONS)


def _migrate_columns(bind: Any) -> None:
    """Bring an older ``canvas_tokens`` up to date; a current one is left unchanged.

    Adds each missing column, gives every row without a principal key the key
    ``entra:<tenant>:<object>`` (both ids are stored lower-case) and makes the
    key unique. Ciphertext, nonce and key id are never touched.
    """
    columns = {r[1] for r in bind.exec_driver_sql("PRAGMA table_info(canvas_tokens)")}
    for name, definition in ADDED_COLUMNS:
        if name not in columns:
            bind.exec_driver_sql(f"ALTER TABLE canvas_tokens ADD COLUMN {name} {definition}")
    bind.exec_driver_sql(
        "UPDATE canvas_tokens"
        " SET principal_key = 'entra:' || tenant_id || ':' || object_id"
        " WHERE principal_key IS NULL"
    )
    bind.exec_driver_sql(SCHEMA_PRINCIPAL_INDEX)
