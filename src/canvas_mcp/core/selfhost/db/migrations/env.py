"""Alembic environment of the self-hosted token database.

Run programmatically by ``db.migrate`` (there is no ``alembic.ini``): the caller
hands in a connection that is already inside its own transaction, through
``config.attributes['connection']``, so the whole migration commits or rolls back
as one unit on both SQLite and PostgreSQL. Offline mode (``--sql``) renders the
DDL for the dialect named in ``config.attributes['dialect']``.
"""

from __future__ import annotations

from alembic import context

from canvas_mcp.core.selfhost.db import schema

config = context.config
target_metadata = schema.metadata


def _include_object(obj, name, type_, reflected, compare_to):  # type: ignore[no-untyped-def]
    # Alembic's own table is not part of the application metadata.
    return not (type_ == "table" and name == schema.VERSION_TABLE)


def run_migrations_offline() -> None:
    dialect = config.attributes.get("dialect", "postgresql")
    context.configure(
        dialect_name=dialect,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table=schema.VERSION_TABLE,
        transactional_ddl=True,
        transaction_per_migration=False,
        include_object=_include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is None:
        raise RuntimeError("the migration environment needs a connection")
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        version_table=schema.VERSION_TABLE,
        # SQLite DDL is transactional too; the caller's BEGIN IMMEDIATE makes the
        # whole adoption one unit, so a crash leaves the file unchanged.
        transactional_ddl=True,
        transaction_per_migration=False,
        compare_type=True,
        include_object=_include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
