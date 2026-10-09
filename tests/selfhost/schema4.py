"""Load the schema 4 fixture (built with release d40a2e1) into a database of either backend.

``fixtures/schema4_d40a2e1.json`` was produced by ``fixtures/make_schema4_fixture.py``
running the real code of that release (see its docstring). The loader stamps an empty
database at the baseline revision with Alembic, exactly as a schema 4 server leaves
it, and inserts the rows verbatim, so the migration tests start from a real file.
"""

from __future__ import annotations

import base64
import json
import pathlib
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text

from canvas_mcp.core.selfhost.db import migrate
from canvas_mcp.core.selfhost.token_store import Keyring

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "schema4_d40a2e1.json"
BASELINE = "0001_baseline_v4"

#: Insert order; the history table keeps its ids.
_TABLES = (
    "canvas_tokens",
    "user_tool_prefs",
    "principal_status",
    "principal_status_events",
    "credential_generations",
)


@dataclass(frozen=True)
class Schema4:
    """The fixture: raw rows and the plaintexts every token must decrypt to."""

    raw: dict[str, Any]

    @property
    def principals(self) -> dict[str, str]:
        """Name -> legacy ``entra:<tid>:<oid>`` key."""
        return dict(self.raw["principals"])

    @property
    def plaintexts(self) -> dict[str, str]:
        """Legacy principal key -> the token it must decrypt to."""
        return dict(self.raw["plaintexts"])

    @property
    def host(self) -> str:
        return str(self.raw["host"])

    @property
    def tenant_id(self) -> str:
        return str(self.raw["tenant_id"])

    @property
    def other_key(self) -> str:
        return str(self.raw["other_key"])

    def key(self, name: str) -> str:
        return self.raw["principals"][name]

    def rows(self, table: str) -> list[dict[str, Any]]:
        spec = self.raw["tables"][table]
        columns: list[str] = spec["columns"]
        return [
            dict(zip(columns, (_decode(v) for v in row), strict=True)) for row in spec["rows"]
        ]


def _decode(value: Any) -> Any:
    if isinstance(value, dict) and "b64" in value:
        return base64.b64decode(value["b64"])
    return value


def keyring(*, only: str | None = None, order: tuple[str, ...] = ("k2", "k1")) -> Keyring:
    """The ring the fixture was built with (``k2`` active, ``k1`` old), or a part of it."""
    keys = {"k1": 1, "k2": 2, "k3": 3}
    ids = (only,) if only else order
    return Keyring.parse(
        ",".join(f"{kid}:{base64.b64encode(bytes([keys[kid]]) * 32).decode()}" for kid in ids)
    )


def load_fixture() -> Schema4:
    return Schema4(json.loads(FIXTURE.read_text(encoding="utf-8")))


def build_schema4(db: Any, fixture: Schema4 | None = None) -> Schema4:
    """Create the schema 4 database in ``db`` (empty) and insert the fixture's rows."""
    from alembic import command

    data = fixture or load_fixture()
    with db.write() as conn:
        cfg = migrate._config(connection=conn)
        command.upgrade(cfg, BASELINE)
        # The baseline leaves meta at 4 on both backends.
        for table in _TABLES:
            rows = data.rows(table)
            if not rows:
                continue
            columns = list(rows[0])
            stmt = text(
                f"INSERT INTO {table} ({', '.join(columns)}) "
                f"VALUES ({', '.join(':' + c for c in columns)})"
            )
            conn.execute(stmt, rows)
        if db.kind == "postgresql":
            conn.execute(
                text(
                    "SELECT setval(pg_get_serial_sequence('principal_status_events', 'id'),"
                    " COALESCE((SELECT MAX(id) FROM principal_status_events), 1),"
                    " (SELECT MAX(id) IS NOT NULL FROM principal_status_events))"
                )
            )
    return data


def dump(db: Any, tables: tuple[str, ...] | None = None) -> dict[str, list[tuple[Any, ...]]]:
    """Every row of the given tables (default: all but the Alembic table), sorted, as tuples."""
    from sqlalchemy import inspect

    from canvas_mcp.core.selfhost.db import schema

    with db.read() as conn:
        names = sorted(
            n
            for n in inspect(conn).get_table_names()
            if n != schema.VERSION_TABLE and (tables is None or n in tables)
        )
        return {
            n: sorted((tuple(r) for r in conn.execute(text(f"SELECT * FROM {n}")).all()), key=repr)
            for n in names
        }
