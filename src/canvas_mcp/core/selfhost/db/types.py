"""Portable logical types for the self-hosted v1 schema."""

from __future__ import annotations

import json
import secrets
import threading
import time
import uuid
from typing import Any

from sqlalchemy import BigInteger, Boolean, Integer, LargeBinary, Text, TypeDecorator
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import Dialect

Key = Text().with_variant(postgresql.TEXT(collation="C"), "postgresql")
Epoch = BigInteger().with_variant(sqlite.INTEGER(), "sqlite")
Bytes = LargeBinary().with_variant(sqlite.BLOB(), "sqlite")


class Uuid(TypeDecorator[str]):
    """Native PostgreSQL UUID; canonical, hyphenated TEXT on SQLite."""

    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(postgresql.UUID(as_uuid=False))
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value: str | None, dialect: Dialect) -> str | None:
        return None if value is None else str(uuid.UUID(value))

    def process_result_value(self, value: Any, dialect: Dialect) -> str | None:
        return None if value is None else str(uuid.UUID(str(value)))


class Flag(TypeDecorator[bool]):
    """BOOLEAN on PostgreSQL, INTEGER on SQLite STRICT tables."""

    impl = Boolean(create_constraint=False)
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> Any:
        return dialect.type_descriptor(
            Integer() if dialect.name == "sqlite" else self.impl
        )

    def process_bind_param(
        self, value: bool | None, dialect: Dialect
    ) -> bool | int | None:
        if value is None:
            return None
        return int(bool(value)) if dialect.name == "sqlite" else bool(value)

    def process_result_value(self, value: Any, dialect: Dialect) -> bool | None:
        return None if value is None else bool(value)


def _reject_nul(value: Any) -> None:
    if isinstance(value, str):
        if "\x00" in value:
            raise ValueError("JSON documents must not contain NUL characters")
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_nul(key)
            _reject_nul(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_nul(item)


class JsonDoc(TypeDecorator[Any]):
    """Whole JSON documents: JSONB on PostgreSQL, deterministic TEXT on SQLite."""

    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(postgresql.JSONB(none_as_null=True))
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value: Any, dialect: Dialect) -> Any:
        if value is None:
            return None
        _reject_nul(value)
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        return json.loads(encoded) if dialect.name == "postgresql" else encoded

    def process_result_value(self, value: Any, dialect: Dialect) -> Any:
        if value is None or dialect.name == "postgresql":
            return value
        return json.loads(value)


_id_lock = threading.Lock()
_last_ms = -1
_counter = 0


def _fallback_uuid7() -> uuid.UUID:
    """RFC 9562 counter method: 48-bit time, 42-bit counter and 32 random bits.

    The lock and logical clock keep ids increasing when the wall clock goes
    backwards. A counter overflow advances the logical millisecond. The counter
    starts with a clear leading bit to retain ample space for the same instant.
    """
    global _last_ms, _counter
    with _id_lock:
        now_ms = time.time_ns() // 1_000_000
        if now_ms > _last_ms:
            _last_ms = now_ms
            _counter = secrets.randbits(41)
        else:
            _counter += 1
            if _counter >= 1 << 42:
                _last_ms += 1
                _counter = secrets.randbits(41)
        value = (
            (_last_ms << 80)
            | (7 << 76)
            | ((_counter >> 30) << 64)
            | (2 << 62)
            | ((_counter & ((1 << 30) - 1)) << 32)
            | secrets.randbits(32)
        )
        return uuid.UUID(int=value)


def new_id() -> str:
    """Mint the account/entity id before encryption and multi-row writes."""
    native = getattr(uuid, "uuid7", None)
    return str(native() if native is not None else _fallback_uuid7())
