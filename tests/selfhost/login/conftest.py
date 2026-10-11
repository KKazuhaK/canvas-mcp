"""Entra-only stacks (the unchanged deployment) for the golden tests of this package."""

from __future__ import annotations

import pathlib
from collections.abc import Iterator

import pytest

from ..authz.stack import Stack, local_stack
from ..spa_fixture import make_dist


@pytest.fixture
def entra_local(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Stack]:
    """Entra alone, with the server's own authorization server."""
    with local_stack(tmp_path, monkeypatch) as running:
        yield running


@pytest.fixture
def entra_proxy(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Stack]:
    """Entra alone, in the default entra_proxy mode."""
    with local_stack(tmp_path, monkeypatch, env={}) as running:
        yield running


@pytest.fixture
def entra_react(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Stack]:
    env = { "ACCOUNT_WEB_DIST": str(make_dist(tmp_path / "dist"))}
    with local_stack(tmp_path / "app", monkeypatch, env=env) as running:
        yield running
