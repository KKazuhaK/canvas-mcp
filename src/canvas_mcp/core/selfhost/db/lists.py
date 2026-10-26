"""Bounded list reads and aggregates on caller-owned connections."""

from collections.abc import Sequence
from typing import cast

from sqlalchemy import distinct, func, select, true
from sqlalchemy.engine import Connection

from . import schema as s
from .rows import AccountRow, CredentialRow, IdentityRow


def accounts(
    conn: Connection, *, before: str | None, limit: int, status: str | None = None
) -> list[AccountRow]:
    query = select(s.accounts)
    if before is not None:
        query = query.where(s.accounts.c.id < before)
    if status is not None:
        query = query.where(s.accounts.c.status == status)
    return [
        AccountRow(**row)
        for row in conn.execute(
            query.order_by(s.accounts.c.id.desc()).limit(limit)
        ).mappings()
    ]


def credentials(
    conn: Connection, *, before: str | None, limit: int, invalid_only: bool = False
) -> list[CredentialRow]:
    query = select(s.canvas_credentials)
    if before is not None:
        query = query.where(s.canvas_credentials.c.id < before)
    if invalid_only:
        query = query.where(s.canvas_credentials.c.status == "invalid")
    return [
        CredentialRow(**row)
        for row in conn.execute(
            query.order_by(s.canvas_credentials.c.id.desc()).limit(limit)
        ).mappings()
    ]


def accounts_by_ids(conn: Connection, ids: Sequence[str]) -> list[AccountRow]:
    if not ids:
        return []
    return [
        AccountRow(**row)
        for row in conn.execute(
            select(s.accounts).where(s.accounts.c.id.in_(ids))
        ).mappings()
    ]


def identities(conn: Connection, ids: Sequence[str]) -> list[IdentityRow]:
    if not ids:
        return []
    return [
        IdentityRow(**row)
        for row in conn.execute(
            select(s.external_identities)
            .where(s.external_identities.c.account_id.in_(ids))
            .order_by(s.external_identities.c.id)
        ).mappings()
    ]


def primary_credentials(conn: Connection, ids: Sequence[str]) -> list[CredentialRow]:
    if not ids:
        return []
    return [
        CredentialRow(**row)
        for row in conn.execute(
            select(s.canvas_credentials).where(
                s.canvas_credentials.c.account_id.in_(ids),
                s.canvas_credentials.c.is_primary == true(),
            )
        ).mappings()
    ]


def account_counts(conn: Connection) -> dict[str, int]:
    counts = dict.fromkeys(("total", "active", "pending", "disabled", "owners"), 0)
    for status, role, total in conn.execute(
        select(s.accounts.c.status, s.accounts.c.role, func.count()).group_by(
            s.accounts.c.status, s.accounts.c.role
        )
    ):
        count = cast(int, total)
        counts["total"] += count
        if status in counts:
            counts[status] += count
        if status == "active" and role == "owner":
            counts["owners"] += count
    return counts


def enrollment_counts(conn: Connection) -> dict[str, int]:
    counts = account_counts(conn)
    by_status: dict[str, int] = dict(
        conn.execute(
            select(s.canvas_credentials.c.status, func.count()).group_by(
                s.canvas_credentials.c.status
            )
        ).all()
    )
    return {
        "total_enrollments": sum(by_status.values()),
        "needing": by_status.get("invalid", 0),
        "disabled": counts["disabled"],
        "pending": counts["pending"],
    }


def account_names(conn: Connection, ids: Sequence[str]) -> dict[str, str]:
    if not ids:
        return {}
    return {
        row.id: row.display_name
        for row in conn.execute(
            select(s.accounts.c.id, s.accounts.c.display_name).where(
                s.accounts.c.id.in_(ids)
            )
        )
        if row.display_name
    }


def credential_inventory(conn: Connection) -> tuple[int, int, tuple[str, ...]]:
    """Operator counts without loading credential/account records or ciphertext."""
    total, schools = conn.execute(
        select(
            func.count(), func.count(distinct(s.canvas_credentials.c.canvas_host))
        ).select_from(s.canvas_credentials)
    ).one()
    kids: tuple[str, ...] = tuple(
        conn.execute(
            select(s.canvas_credentials.c.key_id)
            .distinct()
            .order_by(s.canvas_credentials.c.key_id)
        ).scalars()
    )
    return total, schools, kids
