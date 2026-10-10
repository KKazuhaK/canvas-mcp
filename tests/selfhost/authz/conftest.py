"""Shared fixtures of the authorization server tests.

Everything store-backed goes through ``dbbackend`` so it runs on SQLite by default and on
PostgreSQL with ``CANVAS_MCP_TEST_BACKEND=postgres``.
"""

from __future__ import annotations

import base64
import pathlib
import time
from collections.abc import Callable
from typing import Any

import pytest
from dbbackend import make_store

import canvas_mcp
from canvas_mcp.core.selfhost.token_store import Keyring, TokenStore

#: The checkout under test must be the code that runs (a stale site-packages copy of an
#: older checkout would silently test the wrong implementation).
REPO = pathlib.Path(__file__).resolve().parents[3]
assert pathlib.Path(canvas_mcp.__file__).resolve().is_relative_to(REPO), canvas_mcp.__file__

KEYS_RAW = (
    "k1:"
    + base64.b64encode(bytes(range(32))).decode()
    + ",k0:"
    + base64.b64encode(bytes(range(100, 132))).decode()
)


@pytest.fixture
def keyring() -> Keyring:
    return Keyring.parse(KEYS_RAW)


class Clock:
    """A settable wall clock (seconds) for the store and the services."""

    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def token_store(tmp_path: pathlib.Path, keyring: Keyring, clock: Clock) -> TokenStore:
    store = make_store(tmp_path / "authz.sqlite3", keyring, clock=clock)
    store.initialize()
    return store


@pytest.fixture
def make_second_store(
    tmp_path: pathlib.Path, keyring: Keyring, clock: Clock
) -> Callable[..., Any]:
    """A second ``TokenStore`` over the same database (its own engine and connections)."""

    def build() -> TokenStore:
        return make_store(tmp_path / "authz.sqlite3", keyring, clock=clock)

    return build


def now_of(clock: Callable[[], float] = time.time) -> int:
    return int(clock())
