"""Create the reviewed nineteen-table v1 baseline in the caller's transaction."""

from __future__ import annotations

from importlib.resources import files
from uuid import uuid4

from sqlalchemy import bindparam, inspect, text
from sqlalchemy.engine import Connection

from ..errors import TokenStoreError
from ..types import Uuid

SCHEMA_EPOCH = 1
BASELINE_REVISION = "0001_v1_baseline"
VERSION_TABLE = "canvas_mcp_alembic_version"


def statements(dialect: str) -> tuple[str, ...]:
    """Read shipped frozen statements; do not regenerate DDL from current metadata."""
    if dialect not in ("sqlite", "postgresql"):
        raise TokenStoreError("unsupported baseline database backend")
    raw = (
        files("canvas_mcp.core.selfhost.db.migrations.baselines")
        .joinpath(dialect + "-v1.sql")
        .read_text(encoding="utf-8")
    )
    # These frozen files contain DDL only, with no semicolons in quoted values.
    return tuple(statement.strip() for statement in raw.split(";") if statement.strip())


def create(conn: Connection, *, now: int) -> str:
    """Create only an empty database; never adopt or re-encrypt pre-v1 data."""
    tables = set(inspect(conn).get_table_names())
    # Alembic creates its empty version table before invoking the first upgrade.
    # It is the only pre-existing table permitted, and a recorded revision still
    # means this is an existing database rather than a new v1 installation.
    if tables == {VERSION_TABLE}:
        if conn.exec_driver_sql("SELECT count(*) FROM " + VERSION_TABLE).scalar_one():
            raise TokenStoreError("the v1 baseline requires an empty database")
    elif tables:
        raise TokenStoreError("the v1 baseline requires an empty database")
    for statement in statements(conn.dialect.name):
        conn.exec_driver_sql(statement)
    database_id = str(uuid4())
    insert = text(
        "INSERT INTO server_state (id, database_id, compat_floor, jwt_epoch, "
        "settings_revision, created_at, updated_at) "
        "VALUES (1, :database_id, :compat_floor, 0, 0, :now, :now)"
    ).bindparams(bindparam("database_id", type_=Uuid()))
    conn.execute(
        insert, {"database_id": database_id, "compat_floor": SCHEMA_EPOCH, "now": now}
    )
    return database_id
