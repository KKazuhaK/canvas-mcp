"""A running stack with a trusted external issuer (the hub) in front of /mcp."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from canvas_mcp.core.selfhost.federation.config import TrustedIssuer, build_issuer

from ..authz.stack import AUDIENCE, BASE, Stack, local_stack
from .issuer import FakeIssuer


@dataclass
class Hub:
    stack: Stack
    issuer: FakeIssuer

    @property
    def federation(self) -> Any:
        assert self.stack.authz.federation is not None
        return self.stack.authz.federation

    def trust(self, **options: Any) -> TrustedIssuer:
        """Add the issuer to the database the way ``trusted-issuers add`` does."""
        issuer = build_issuer(self.issuer.issuer, **options)
        self.federation.store.add_issuer(issuer)
        self.federation.reload()
        return issuer

    def call(self, token: str | None, tool: str = "list_courses") -> Any:
        return self.stack.rpc(token, "tools/call", {"name": tool, "arguments": {}})

    def status(self, token: str | None) -> int:
        return self.stack.mcp_status(token)

    def accounts(self) -> list[str]:
        from sqlalchemy import text

        with self.stack.store.database.read() as conn:
            return [
                str(r[0])
                for r in conn.execute(text("SELECT id FROM accounts ORDER BY id"))
            ]

    def grants(self) -> list[tuple[str, str]]:
        from sqlalchemy import text

        with self.stack.store.database.read() as conn:
            return [
                (str(r[0]), str(r[1]))
                for r in conn.execute(
                    text(
                        "SELECT account_id, client_id FROM oauth_grants WHERE client_id LIKE 'federated:%'"
                    )
                )
            ]


def make_hub(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    env: dict[str, str] | None = None,
    **stack_options: Any,
) -> Iterator[Hub]:
    with local_stack(tmp_path, monkeypatch, env=env, **stack_options) as stack:
        issuer = FakeIssuer(stack.clock, audience=AUDIENCE)
        assert stack.authz.federation is not None
        stack.authz.federation.http._transport = issuer.transport
        yield Hub(stack, issuer)


@pytest.fixture
def hub(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Hub]:
    """The default admission policy (``rules``, Entra roles only): a stranger is not admitted."""
    yield from make_hub(tmp_path, monkeypatch)


@pytest.fixture
def open_hub(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Hub]:
    yield from make_hub(tmp_path, monkeypatch, {"ACCESS_POLICY": "open"})


@pytest.fixture
def hub_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[..., Hub]]:
    """Build a hub with the given environment (one per test)."""
    managers: list[Any] = []

    def build(env: dict[str, str]) -> Hub:
        from contextlib import contextmanager

        @contextmanager
        def manager() -> Iterator[Hub]:
            yield from make_hub(tmp_path / f"hub{len(managers)}", monkeypatch, env)

        cm = manager()
        managers.append(cm)
        return cm.__enter__()

    yield build
    for cm in reversed(managers):
        cm.__exit__(None, None, None)


__all__ = ["BASE", "Hub"]
