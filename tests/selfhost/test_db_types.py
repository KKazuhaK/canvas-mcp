"""Exercise the portable representation and the oldest-Python id fallback."""

import concurrent.futures
import uuid

import pytest
from sqlalchemy import CheckConstraint, Column, MetaData, Table, create_engine, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.schema import CreateTable

from canvas_mcp.core.selfhost.db import types


def portable_table():
    return Table(
        "portable", MetaData(),
        Column("id", types.Uuid(), primary_key=True),
        Column("enabled", types.Flag(), nullable=False),
        Column("document", types.JsonDoc()),
        Column("at", types.Epoch, nullable=False),
        Column("nonce", types.Bytes, nullable=False),
        CheckConstraint("enabled IN (0,1)", name="flag").ddl_if(dialect="sqlite"),
        sqlite_strict=True,
    )


def test_strict_sqlite_roundtrip():
    table = portable_table()
    engine = create_engine("sqlite://")
    table.metadata.create_all(engine)
    identifier = types.new_id()
    with engine.begin() as conn:
        conn.execute(table.insert().values(
            id=identifier.upper(), enabled=True, document={"items": [1, False]}, at=2**40, nonce=b"123",
        ))
        row = conn.execute(select(table)).one()._mapping
        assert row["id"] == identifier
        assert row["enabled"] is True
        assert row["document"] == {"items": [1, False]}
        assert row["at"] == 2**40
        assert row["nonce"] == b"123"


def test_dialects_use_native_types():
    table = portable_table()
    pg = str(CreateTable(table).compile(dialect=postgresql.dialect()))
    sq = str(CreateTable(table).compile(dialect=sqlite.dialect()))
    for fragment in ("UUID", "BOOLEAN", "JSONB", "BIGINT", "BYTEA"):
        assert fragment in pg
        assert fragment not in sq
    assert "STRICT" in sq


@pytest.mark.parametrize("document", [{"key": "bad\x00text"}, {"bad\x00key": 1}, ["\x00"]])
@pytest.mark.parametrize("dialect", [postgresql.dialect(), sqlite.dialect()])
def test_nul_refused_on_both_backends(document, dialect):
    with pytest.raises(ValueError, match="NUL"):
        types.JsonDoc().process_bind_param(document, dialect)


def test_literal_unicode_escape_is_not_nul():
    assert types.JsonDoc().process_bind_param({"text": r"\u0000"}, postgresql.dialect()) == {"text": r"\u0000"}


def test_uuid7_fallback_has_version_variant_and_monotonic_time(monkeypatch):
    monkeypatch.setattr(types.time, "time_ns", lambda: 1_800_000_000_000_000_000)
    monkeypatch.setattr(types, "_last_ms", -1)
    ids = [types._fallback_uuid7() for _ in range(5000)]
    assert len(set(ids)) == len(ids)
    assert ids == sorted(ids)
    assert all(item.version == 7 and item.variant == uuid.RFC_4122 for item in ids)
    assert all(item.int >> 80 == 1_800_000_000_000 for item in ids)
    monkeypatch.setattr(types.time, "time_ns", lambda: 1_799_000_000_000_000_000)
    assert types._fallback_uuid7() > ids[-1]


def test_uuid7_fallback_counter_overflow(monkeypatch):
    monkeypatch.setattr(types.time, "time_ns", lambda: 1_800_000_000_000_000_000)
    monkeypatch.setattr(types, "_last_ms", 1_800_000_000_000)
    monkeypatch.setattr(types, "_counter", (1 << 42) - 1)
    identifier = types._fallback_uuid7()
    assert identifier.int >> 80 == 1_800_000_000_001
    assert identifier.version == 7 and identifier.variant == uuid.RFC_4122


def test_uuid7_fallback_concurrent_uniqueness():
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        ids = list(executor.map(lambda _: types._fallback_uuid7(), range(8000)))
    assert len(set(ids)) == len(ids)
