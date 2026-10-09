"""Persistence of the self-hosted mode: SQLite by default, PostgreSQL optionally.

Importing this package pulls in the standard library only. ``Database`` and the
repositories need SQLAlchemy (``pip install 'canvas-mcp[selfhost]'``) and load
on first use, so the upstream modes never depend on it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .errors import StoreUnavailable, TokenStoreError
from .url import DatabaseTarget, parse_database_url

if TYPE_CHECKING:
    from .engine import Database as Database

__all__ = [
    "Database",
    "DatabaseTarget",
    "StoreUnavailable",
    "TokenStoreError",
    "parse_database_url",
]


def __getattr__(name: str) -> Any:
    if name == "Database":
        from .engine import Database

        return Database
    raise AttributeError(name)
