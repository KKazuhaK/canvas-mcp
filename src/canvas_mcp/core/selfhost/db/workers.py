"""Bound concurrent worker calls to the database connection budget."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

import anyio

STORE_LIMITER = anyio.CapacityLimiter(10)
_Result = TypeVar('_Result')


async def run_store(func: Callable[..., _Result], *args: Any) -> _Result:
    """Queue before acquiring a pooled connection; preserve the request context."""
    return await anyio.to_thread.run_sync(
        functools.partial(func, *args), limiter=STORE_LIMITER,
    )
