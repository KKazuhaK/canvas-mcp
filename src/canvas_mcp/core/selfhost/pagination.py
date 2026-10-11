"""Strict opaque cursors and immutable keyset pages for v1 lists."""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Generic, TypeVar
from uuid import UUID

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
_ENCODED = re.compile(r"[A-Za-z0-9_-]{1,512}")


T = TypeVar("T")


@dataclass(frozen=True)
class Page(Generic[T]):
    items: tuple[T, ...]
    next_cursor: str | None


def page_limit(value: int = DEFAULT_LIMIT) -> int:
    if type(value) is not int or not 1 <= value <= MAX_LIMIT:
        raise ValueError("invalid page limit")
    return value


def decode_cursor(
    cursor: str | None, scope: str, *, integer: bool = False
) -> str | int | None:
    if cursor is None:
        return None
    if not isinstance(cursor, str) or _ENCODED.fullmatch(cursor) is None:
        raise ValueError("invalid page cursor")
    try:
        raw = base64.b64decode(
            cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True
        )
        if base64.urlsafe_b64encode(raw).decode().rstrip("=") != cursor:
            raise ValueError
        value = json.loads(raw)
        if (
            not isinstance(value, list)
            or len(value) != 3
            or type(value[0]) is not int
            or value[:2] != [1, scope]
        ):
            raise ValueError
        key = value[2]
        if integer:
            if type(key) is not int or not 1 <= key <= 2**63 - 1:
                raise ValueError
            return int(key)
        elif type(key) is not str or str(UUID(key)) != key:
            raise ValueError
        return str(key)
    except (ValueError, TypeError, binascii.Error, UnicodeDecodeError):
        raise ValueError("invalid page cursor") from None


def make_page(
    rows: Sequence[T], *, limit: int, scope: str, key: Callable[[T], str | int]
) -> Page[T]:
    shown = tuple(rows[:limit])
    cursor = None
    if len(rows) > limit:
        raw = json.dumps([1, scope, key(shown[-1])], separators=(",", ":")).encode()
        cursor = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return Page(shown, cursor)
