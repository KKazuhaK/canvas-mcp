"""Adopt the former environment-owned browser duration once; SQL wins thereafter."""

from sqlalchemy import insert, select

from ...server_settings import validate_setting
from .. import schema as s
from ..engine import Database

KEY = "auth.browser_session_ttl_seconds"


def adopt_browser_session_duration(
    database: Database, initial: int, *, now: int
) -> int:
    with database.write() as conn:
        row = conn.execute(
            select(s.settings.c.value).where(s.settings.c.key == KEY)
        ).first()
        if row is not None:
            return int(validate_setting(KEY, row[0]))
        value = int(validate_setting(KEY, initial))
        conn.execute(insert(s.settings).values(key=KEY, value=value, updated_at=now))
        return value
