"""The tables of the self-hosted state, as SQLAlchemy Core metadata.

This is the shape the queries are written against and the shape Alembic's
``compare_metadata`` checks a migrated database against. It is structurally
identical to schema version 4 of the SQLite file. The tables are *created* by
the Alembic revisions (frozen DDL, so a revision never changes when this module
does); nothing calls ``metadata.create_all``.

Portability notes:

* Key columns use collation ``C`` on PostgreSQL so ``ORDER BY`` sorts like
  SQLite's BINARY collation.
* Integers that can exceed 32 bits (timestamps up to 4_102_444_800 in
  ``expires_hint_at``, counters) are BIGINT on PostgreSQL. On SQLite they stay
  ``INTEGER`` (a 64-bit affinity there), which keeps ``INTEGER PRIMARY KEY``.
* ``is_owner`` stays an integer 0/1 on both backends.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Column,
    Identity,
    Index,
    LargeBinary,
    MetaData,
    Table,
    Text,
    text,
)
from sqlalchemy.dialects import sqlite

#: Alembic's own version table. Named so it cannot collide with another
#: application that shares a PostgreSQL database.
VERSION_TABLE = "canvas_mcp_alembic_version"

metadata = MetaData()

_INT = BigInteger().with_variant(sqlite.INTEGER(), "sqlite")
_KEY = Text().with_variant(Text(collation="C"), "postgresql")

meta = Table(
    "meta",
    metadata,
    Column("key", Text, primary_key=True),
    Column("value", Text, nullable=False),
    sqlite_with_rowid=False,
)

canvas_tokens = Table(
    "canvas_tokens",
    metadata,
    Column("tenant_id", _KEY, primary_key=True),
    Column("object_id", _KEY, primary_key=True),
    Column("key_id", _KEY, nullable=False),
    Column("nonce", LargeBinary, nullable=False),
    Column("ciphertext", LargeBinary, nullable=False),
    Column("canvas_user_id", Text, nullable=False),
    Column("canvas_user_name", Text, nullable=False),
    Column("entra_display_name", Text, nullable=False, server_default=text("''")),
    Column("entra_upn", Text, nullable=False, server_default=text("''")),
    Column("created_at", _INT, nullable=False),
    Column("updated_at", _INT, nullable=False),
    Column("last_used_at", _INT),
    Column("canvas_host", Text),
    Column("principal_key", _KEY),
    Column("status", Text, nullable=False, server_default=text("'active'")),
    Column("invalid_reason", Text),
    Column("invalid_since", _INT),
    Column("last_verified_at", _INT),
    Column("expires_hint_at", _INT),
    Index("canvas_tokens_principal_key", "principal_key", unique=True),
    sqlite_with_rowid=False,
)

user_tool_prefs = Table(
    "user_tool_prefs",
    metadata,
    Column("principal_key", _KEY, primary_key=True),
    Column("enabled_write_tools", Text, nullable=False, server_default=text("'[]'")),
    Column("enabled_at", Text, nullable=False, server_default=text("'{}'")),
    Column("updated_at", _INT, nullable=False),
    Column("updated_via", Text, nullable=False, server_default=text("'account_web'")),
    sqlite_with_rowid=False,
)

principal_status = Table(
    "principal_status",
    metadata,
    Column("principal_key", _KEY, primary_key=True),
    Column("status", Text, nullable=False, server_default=text("'active'")),
    Column("disabled_reason", Text),
    Column("disabled_at", _INT),
    Column("disabled_by", Text),
    Column("display_name", Text, nullable=False, server_default=text("''")),
    Column("upn", Text, nullable=False, server_default=text("''")),
    Column("session_epoch", _INT, nullable=False, server_default=text("0")),
    Column("is_owner", _INT, nullable=False, server_default=text("0")),
    Column("owner_seen_at", _INT),
    Column("updated_at", _INT, nullable=False),
    sqlite_with_rowid=False,
)

principal_status_events = Table(
    "principal_status_events",
    metadata,
    Column("id", _INT, Identity(), primary_key=True, autoincrement=True),
    Column("principal_key", _KEY, nullable=False),
    Column("action", Text, nullable=False),
    Column("actor", Text),
    Column("reason", Text),
    Column("session_epoch", _INT, nullable=False),
    Column("at", _INT, nullable=False),
    Index("principal_status_events_principal", "principal_key", "id"),
    sqlite_autoincrement=True,
)

credential_generations = Table(
    "credential_generations",
    metadata,
    Column("principal_key", _KEY, primary_key=True),
    Column("generation", _INT, nullable=False),
    Column("reason", Text, nullable=False, server_default=text("''")),
    Column("updated_at", _INT, nullable=False),
    sqlite_with_rowid=False,
)

#: Every table the store owns, in dependency-free order (there are no foreign keys).
TABLE_NAMES = (
    "meta",
    "canvas_tokens",
    "user_tool_prefs",
    "principal_status",
    "principal_status_events",
    "credential_generations",
)
