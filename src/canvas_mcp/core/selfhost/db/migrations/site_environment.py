"""One-time adoption of the old environment-owned public origin."""

from sqlalchemy import insert, select

from ...site_url import SITE_URL_KEY, validate_site_url
from .. import schema as s
from ..engine import Database


def adopt_site_url(database: Database, initial_url: str, *, now: int) -> str:
    with database.write() as conn:
        row = conn.execute(
            select(s.settings.c.value).where(s.settings.c.key == SITE_URL_KEY)
        ).first()
        if row is not None:
            return validate_site_url(row[0])
        value = validate_site_url(initial_url)
        conn.execute(
            insert(s.settings).values(
                key=SITE_URL_KEY,
                value=value,
                updated_at=now,
            )
        )
        return value
