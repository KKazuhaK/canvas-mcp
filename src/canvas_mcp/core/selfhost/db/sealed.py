"""Current-runtime encryption registry, derived from the schema's sealed metadata."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy import Table, or_, select, update
from sqlalchemy.engine import Connection
from sqlalchemy.sql.elements import ColumnElement

from . import schema
from .engine import Database


class SealKeys(Protocol):
    @property
    def active_key_id(self) -> str: ...

    @property
    def key_ids(self) -> tuple[str, ...]: ...

    def encrypt(self, plaintext: bytes, aad: bytes) -> tuple[str, bytes, bytes]: ...

    def decrypt(
        self, key_id: str, nonce: bytes, ciphertext: bytes, aad: bytes
    ) -> bytes: ...


@dataclass(frozen=True)
class SealedColumn:
    table: Table
    key_id: str
    nonce: str
    ciphertext: str
    prefix: str
    fields: tuple[str, ...]

    def aad(self, row: Mapping[Any, Any], *, key_id: str | None = None) -> bytes:
        values = [self.prefix]
        for field in self.fields:
            value = (
                key_id if field == self.key_id and key_id is not None else row[field]
            )
            if (
                not isinstance(value, str)
                or not value
                or "\x1f" in value
                or "\x00" in value
            ):
                raise ValueError("invalid sealed AAD field")
            values.append(value)
        return "\x1f".join(values).encode("utf-8")


SEALED = tuple(
    SealedColumn(table=table, **table.info["sealed"])
    for table in schema.metadata.sorted_tables
    if "sealed" in table.info
)


def verify(conn: Connection, keys: SealKeys, *, all_values: bool = False) -> int:
    """Require every referenced key; probe each table/key, or decrypt every value."""
    from ..token_store import KeyringError, TokenDecryptionError

    checked = 0
    for sealed in SEALED:
        table = sealed.table
        kid_column = table.c[sealed.key_id]
        present = table.c[sealed.ciphertext].is_not(None)
        used: Sequence[str] = (
            conn.execute(select(kid_column).where(present).distinct()).scalars().all()
        )
        missing = sorted(set(used) - set(keys.key_ids))
        if missing:
            raise KeyringError(
                "CANVAS_TOKEN_KEYS is missing key id(s): " + ", ".join(missing)
            )
        probe: ColumnElement[bool] = present
        if table is schema.canvas_credentials:
            # A previously diagnosed corrupt credential cannot establish whether
            # a key is correct. Still require its key id above, and verify it
            # during strict transfer verification below.
            probe = present & or_(
                table.c.invalid_reason.is_(None),
                table.c.invalid_reason != "decrypt_failed",
            )
        statements = (
            [select(table).where(present)]
            if all_values
            else [
                select(table).where(probe, kid_column == kid).limit(1) for kid in used
            ]
        )
        for statement in statements:
            rows = conn.execute(statement).mappings()
            for row in rows:
                try:
                    keys.decrypt(
                        row[sealed.key_id],
                        bytes(row[sealed.nonce]),
                        bytes(row[sealed.ciphertext]),
                        sealed.aad(row),
                    )
                except (TokenDecryptionError, ValueError):
                    raise KeyringError(
                        f"CANVAS_TOKEN_KEYS key {row[sealed.key_id]} does not match the stored data"
                    ) from None
                checked += 1
    return checked


def rotate(db: Database, keys: SealKeys, *, chunk_size: int = 500) -> int:
    """Re-seal every registered column in bounded governance transactions."""
    if chunk_size < 1:
        raise ValueError("rotation chunk size must be positive")
    changed = 0
    for sealed in SEALED:
        table = sealed.table
        primary = next(iter(table.primary_key.columns))
        cursor: Any = None
        while True:
            with db.write() as conn:
                statement = (
                    select(table)
                    .where(
                        table.c[sealed.ciphertext].is_not(None),
                        table.c[sealed.key_id] != keys.active_key_id,
                    )
                    .order_by(primary)
                    .limit(chunk_size)
                )
                if cursor is not None:
                    statement = statement.where(primary > cursor)
                rows = conn.execute(statement).mappings().all()
                for row in rows:
                    plaintext = keys.decrypt(
                        row[sealed.key_id],
                        bytes(row[sealed.nonce]),
                        bytes(row[sealed.ciphertext]),
                        sealed.aad(row),
                    )
                    kid, nonce, ciphertext = keys.encrypt(
                        plaintext, sealed.aad(row, key_id=keys.active_key_id)
                    )
                    condition = (primary == row[primary.name]) & (
                        table.c[sealed.key_id] == row[sealed.key_id]
                    )
                    if "generation" in table.c:
                        condition &= table.c.generation == row["generation"]
                    result = conn.execute(
                        update(table)
                        .where(condition)
                        .values(
                            {
                                sealed.key_id: kid,
                                sealed.nonce: nonce,
                                sealed.ciphertext: ciphertext,
                            }
                        )
                        .returning(primary)
                    )
                    changed += int(result.first() is not None)
                if rows:
                    cursor = rows[-1][primary.name]
            if len(rows) < chunk_size:
                break
    return changed
