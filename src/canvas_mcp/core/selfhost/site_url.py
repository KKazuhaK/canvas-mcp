"""Database-owned canonical origin, read before constructing OAuth and host guards."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .db.url import DatabaseTarget

SITE_URL_KEY = "site.public_base_url"


def validate_site_url(value: object) -> str:
    from .settings import _parse_public_base_url

    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("invalid site address")
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in value) or any(
        ch in value for ch in "\\%<>{}"
    ):
        raise ValueError("invalid site address")
    problems: list[str] = []
    parsed = _parse_public_base_url(value, problems)
    if parsed is None or problems or parsed[0].endswith(":443"):
        raise ValueError("invalid site address")
    parts = urlsplit(parsed[0])
    if parts.port == 0:
        raise ValueError("invalid site address")
    host = parts.hostname or ""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        ):
            raise ValueError("invalid site address") from None
    return parsed[0]


def saved_site_url(target: DatabaseTarget) -> str | None:
    """Read an existing database without creating files, tables or migration state."""
    if target.sqlite_path is not None and not target.sqlite_path.exists():
        return None
    from sqlalchemy import inspect, select

    from .db import schema as s
    from .db.engine import Database

    database = Database(target)
    try:
        with database.read() as conn:
            if "settings" not in inspect(conn).get_table_names():
                return None
            row = conn.execute(
                select(s.settings.c.value).where(s.settings.c.key == SITE_URL_KEY)
            ).first()
            return validate_site_url(row[0]) if row is not None else None
    finally:
        database.dispose()
