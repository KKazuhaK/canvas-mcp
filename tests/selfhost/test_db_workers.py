"""Database work queues before checkout and keeps request-local context."""

import contextvars
import threading
import time

import anyio
import pytest

from canvas_mcp.core.selfhost.db.workers import STORE_LIMITER, run_store


async def test_burst_queues_at_the_ten_connection_budget():
    active = 0
    maximum = 0
    completed = 0
    lock = threading.Lock()

    def work():
        nonlocal active, maximum, completed
        with lock:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.02)
        with lock:
            active -= 1
            completed += 1

    async with anyio.create_task_group() as group:
        for _ in range(40):
            group.start_soon(run_store, work)
    assert maximum == 10
    assert completed == 40
    assert STORE_LIMITER.borrowed_tokens == 0


async def test_exceptions_release_capacity_and_context_is_preserved():
    principal = contextvars.ContextVar('test_principal', default='none')
    principal.set('the-request-account')
    assert await run_store(principal.get) == 'the-request-account'

    def fail():
        raise RuntimeError('test failure')

    with pytest.raises(RuntimeError, match='test failure'):
        await run_store(fail)
    assert STORE_LIMITER.borrowed_tokens == 0
    assert await run_store(lambda: 42) == 42
