"""Upgrade-only revision policy and DDL helpers; removable with this package."""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from alembic import op
from alembic.operations import BatchOperations
from alembic.script import ScriptDirectory
from sqlalchemy import text

from ..errors import TokenStoreError


@dataclass(frozen=True)
class RevisionPolicy:
    revision: str
    contract: bool
    non_transactional: bool


def pending(script: ScriptDirectory, before: str | None) -> tuple[RevisionPolicy, ...]:
    """The linear forward graph, in application order, with exact boolean flags."""
    result = []
    for revision in reversed(list(script.iterate_revisions("head", before))):
        flags = [
            getattr(revision.module, name, False)
            for name in ("CONTRACT", "NON_TRANSACTIONAL")
        ]
        if any(type(flag) is not bool for flag in flags):
            raise TokenStoreError("revision policy flags must be booleans")
        result.append(RevisionPolicy(revision.revision, flags[0], flags[1]))
    return tuple(result)


@contextmanager
def rebuild_sqlite_table(name: str, **kwargs: Any) -> Iterator[BatchOperations]:
    """Retain native SQLite table properties which reflection can otherwise lose."""
    conn = op.get_bind()
    if conn.dialect.name != "sqlite":
        raise TokenStoreError(
            "SQLite rebuild requires the dedicated migration connection"
        )
    if conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one() != 0:
        raise TokenStoreError("SQLite rebuild requires foreign keys off")
    properties = next(
        (
            row
            for row in conn.exec_driver_sql("PRAGMA table_list").mappings()
            if row["schema"] == "main" and row["name"] == name
        ),
        None,
    )
    ddl = conn.execute(
        text("SELECT sql FROM sqlite_master WHERE type='table' AND name=:name"),
        {"name": name},
    ).scalar_one_or_none()
    if properties is None or ddl is None:
        raise TokenStoreError("SQLite rebuild table does not exist")
    table_kwargs = dict(kwargs.pop("table_kwargs", {}))
    # These are invariants, not caller options. Named CHECKs and partial indexes
    # are reflected by batch mode; revisions must explicitly remove changed ones.
    table_kwargs.update(
        sqlite_strict=bool(properties["strict"]),
        sqlite_with_rowid=not bool(properties["wr"]),
        sqlite_autoincrement=bool(re.search(r"\bAUTOINCREMENT\b", ddl, re.I)),
    )
    sequence = None
    if table_kwargs["sqlite_autoincrement"]:
        sequence = conn.execute(
            text("SELECT seq FROM sqlite_sequence WHERE name=:name"), {"name": name}
        ).scalar_one_or_none()
    with op.batch_alter_table(
        name, recreate="always", table_kwargs=table_kwargs, **kwargs
    ) as batch:
        yield batch
    if sequence is not None:
        conn.execute(
            text("UPDATE sqlite_sequence SET seq=:seq WHERE name=:name AND seq<:seq"),
            {"name": name, "seq": sequence},
        )
        conn.execute(
            text(
                "INSERT INTO sqlite_sequence(name,seq) SELECT :name,:seq WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name=:name)"
            ),
            {"name": name, "seq": sequence},
        )


def concurrent_index(
    name: str,
    table: str,
    columns: Sequence[str],
    *,
    unique: bool = False,
    where: str | None = None,
) -> None:
    """Create a reviewed index outside a PostgreSQL transaction; retry INVALID remnants."""
    conn = op.get_bind()
    options: dict[str, Any] = {}
    if where is not None:
        options[conn.dialect.name + "_where"] = text(where)
    if conn.dialect.name == "sqlite":
        op.create_index(name, table, list(columns), unique=unique, **options)
        return
    if conn.dialect.name != "postgresql":
        raise TokenStoreError("concurrent indexes require PostgreSQL or SQLite")
    with op.get_context().autocommit_block():
        existing = (
            conn.execute(
                text("""
            SELECT i.indisvalid, t.relname AS table_name, i.indisunique,
                   ARRAY(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY k(attnum, ord)
                         JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum
                         ORDER BY k.ord) AS columns,
                   pg_get_expr(i.indpred, i.indrelid) AS predicate
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            JOIN pg_index i ON i.indexrelid=c.oid JOIN pg_class t ON t.oid=i.indrelid
            WHERE n.nspname=current_schema() AND c.relname=:name
        """),
                {"name": name},
            )
            .mappings()
            .first()
        )
        if existing is not None:
            if existing["indisvalid"]:
                # A completed previous attempt can be retried after its version
                # update failed. Partial indexes need explicit revision validation:
                # PostgreSQL rewrites predicates, so raw SQL equality is unsound.
                if (
                    existing["table_name"] != table
                    or existing["indisunique"] != unique
                    or list(existing["columns"]) != list(columns)
                    or existing["predicate"] is not None
                    or where is not None
                ):
                    raise TokenStoreError(
                        "existing index needs explicit revision validation"
                    )
                return
            op.drop_index(name, table_name=table, postgresql_concurrently=True)
        op.create_index(
            name,
            table,
            list(columns),
            unique=unique,
            postgresql_concurrently=True,
            **options,
        )
