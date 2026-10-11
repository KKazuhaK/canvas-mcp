"""The process-wide sign-in start limit is a backstop on pending ceremonies, not a per-client throttle."""

from __future__ import annotations

import pathlib

import pytest

from canvas_mcp.core.selfhost.login.registry import START_BURST, START_REFILL_PER_SECOND

from .stack_providers import provider_stack
from .test_entra_only_golden import account_app

#: What the documented proxy examples allow one address to start in a minute (nginx canvas_signin).
PROXY_PER_IP_PER_MINUTE = 30


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
    with provider_stack(tmp_path, monkeypatch) as ps:
        app = account_app(ps.stack)
        assert app.logins is not None
        bucket = app.logins.start_buckets["github"]
        # The bucket runs on the shared test clock (real time plus an offset); drain it in one go.
        while bucket.take() == 0:
            pass
        assert ps.person().get("/auth/login/github").status_code == 429
        # the other providers have their own bucket
        assert ps.person().get("/auth/login/google").status_code == 302
        ps.clock.advance(1)
        assert ps.person().get("/auth/login/github").status_code == 302
