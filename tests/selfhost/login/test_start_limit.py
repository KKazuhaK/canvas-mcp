"""The process-wide sign-in start limit is a backstop on pending ceremonies, not a per-client throttle."""

from __future__ import annotations

import pathlib
from urllib.parse import parse_qs, urlsplit

import pytest

from canvas_mcp.core.selfhost.login.registry import START_BURST, START_REFILL_PER_SECOND

from ..authz.stack import Clock
from .stack_providers import provider_stack
from .test_entra_only_golden import account_app

#: What the documented proxy examples allow one address to start in a minute (nginx canvas_signin).
PROXY_PER_IP_PER_MINUTE = 30


class FrozenClock(Clock):
    """Advance only on request; scheduler delays cannot refill the start bucket."""

    def __init__(self) -> None:
        super().__init__()
        self.frozen_at = super().__call__()

    def __call__(self) -> float:
        return self.frozen_at + self.offset


def test_the_backstop_is_far_above_what_one_proxied_address_may_start() -> None:
    assert START_BURST >= 10 * PROXY_PER_IP_PER_MINUTE
    assert START_REFILL_PER_SECOND * 60 >= 10 * PROXY_PER_IP_PER_MINUTE


def test_one_client_spending_its_proxy_allowance_does_not_lock_out_another(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with provider_stack(tmp_path, monkeypatch) as ps:
        attacker = ps.person()
        for _ in range(2 * PROXY_PER_IP_PER_MINUTE):
            assert attacker.get("/auth/login/github").status_code == 302
        victim = ps.person()
        assert victim.get("/auth/login/github").status_code == 302
        assert victim.get("/auth/login/google").status_code == 302


def test_the_backstop_still_refuses_once_the_pending_ceremonies_reach_it(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with provider_stack(tmp_path, monkeypatch, clock=FrozenClock()) as ps:
        app = account_app(ps.stack)
        assert app.logins is not None
        bucket = app.logins.start_buckets["github"]
        # No elapsed wall time between draining and the HTTP request may refill
        # a token; 100 ms of scheduling delay used to make the refusal flaky.
        for _ in range(START_BURST):
            assert bucket.take() == 0
        assert bucket.take() > 0
        refused = ps.person().get("/auth/login/github")
        assert refused.status_code == 303
        assert parse_qs(urlsplit(refused.headers["location"]).query)["error"] == [
            "rate_limited"
        ]
        # the other providers have their own bucket
        assert ps.person().get("/auth/login/google").status_code == 302
        ps.clock.advance(1)
        assert ps.person().get("/auth/login/github").status_code == 302
