"""The request-context middleware loads the caller's write-tool switches."""

from __future__ import annotations

import logging
from typing import Any

import pytest

from canvas_mcp.core.credentials import RequestToolPrefs, get_request_tool_prefs
from canvas_mcp.core.selfhost.request_context import SelfhostRequestContextMiddleware

from .conftest import OID_A, OID_B, acct_key
from .test_request_context import (
    SECRET_TOKEN,
    FakeStore,
    Probe,
    _claims,
    _middleware,
    _run,
    _user,
)

KEY_A = acct_key(OID_A)


class FakePrefs:
    def __init__(
        self,
        enabled: dict[str, set[str]] | None = None,
        *,
        fail: Exception | None = None,
    ) -> None:
        self.enabled_by_key = enabled or {}
        self.fail = fail
        self.asked: list[str] = []
        self.versions: list[int] = []

    def enabled(self, principal_key: str, version: int) -> frozenset[str]:
        self.asked.append(principal_key)
        self.versions.append(version)
        if self.fail is not None:
            raise self.fail
        return frozenset(self.enabled_by_key.get(principal_key, set()))


class PrefsProbe(Probe):
    def __init__(self) -> None:
        super().__init__()
        self.prefs: list[RequestToolPrefs | None] = []

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.prefs.append(get_request_tool_prefs())
        await super().__call__(scope, receive, send)


def middleware(app: Probe, prefs: Any) -> SelfhostRequestContextMiddleware:
    return _middleware(app, FakeStore({KEY_A: SECRET_TOKEN}), tool_prefs=prefs)


class TestLoading:
    async def test_the_callers_switches_reach_the_request(self) -> None:
        probe = PrefsProbe()
        prefs = FakePrefs({KEY_A: {"send_message", "mark_module_item_done"}})
        call = await _run(middleware(probe, prefs), user=_user(_claims()))
        assert call.status == 200
        assert probe.prefs == [
            RequestToolPrefs(
                enabled=frozenset({"send_message", "mark_module_item_done"})
            )
        ]
        assert prefs.asked == [KEY_A]
        assert prefs.versions == [1]

    async def test_a_user_without_a_record_has_nothing_enabled(self) -> None:
        probe = PrefsProbe()
        await _run(middleware(probe, FakePrefs()), user=_user(_claims()))
        assert probe.prefs == [RequestToolPrefs(enabled=frozenset(), readable=True)]

    async def test_each_user_gets_their_own_switches(self) -> None:
        prefs = FakePrefs(
            {KEY_A: {"send_message"}, acct_key(OID_B): {"submit_assignment"}}
        )
        a, b = PrefsProbe(), PrefsProbe()
        await _run(middleware(a, prefs), user=_user(_claims()))
        await _run(
            middleware(b, prefs),
            user=_user(_claims(acct=acct_key(OID_B), sub=acct_key(OID_B))),
        )
        assert a.prefs[0] is not None and a.prefs[0].enabled == {"send_message"}
        assert b.prefs[0] is not None and b.prefs[0].enabled == {"submit_assignment"}

    async def test_without_a_preferences_source_nothing_is_enabled(self) -> None:
        probe = PrefsProbe()
        await _run(middleware(probe, None), user=_user(_claims()))
        assert probe.prefs == [RequestToolPrefs()]
        assert probe.prefs[0] is not None and probe.prefs[0].enabled == frozenset()

    async def test_an_unreadable_record_enables_nothing_and_is_logged_without_details(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.ERROR)
        probe = PrefsProbe()
        prefs = FakePrefs(
            {KEY_A: {"send_message"}},
            fail=RuntimeError("secret internals /srv/data.db"),
        )
        call = await _run(middleware(probe, prefs), user=_user(_claims()))
        assert call.status == 200  # the request still goes on: read tools keep working
        assert probe.prefs == [RequestToolPrefs(enabled=frozenset(), readable=False)]
        assert "write-tool preferences unreadable" in caplog.text
        assert (
            "secret internals" not in caplog.text and "/srv/data.db" not in caplog.text
        )

    async def test_the_canvas_credentials_are_still_mounted_when_the_switches_cannot_be_read(
        self,
    ) -> None:
        probe = PrefsProbe()
        await _run(
            middleware(probe, FakePrefs(fail=RuntimeError("x"))), user=_user(_claims())
        )
        creds = probe.seen["creds"]
        assert creds is not None and creds.api_token == SECRET_TOKEN

    async def test_nothing_is_loaded_for_requests_that_are_not_mcp_calls(self) -> None:
        probe = PrefsProbe()
        prefs = FakePrefs({KEY_A: {"send_message"}})
        for path in ("/account", "/healthz"):
            await _run(middleware(probe, prefs), path, user=_user(_claims()))
        assert probe.prefs == [None, None]
        assert prefs.asked == []

    async def test_nothing_is_loaded_for_a_denied_or_unauthenticated_request(
        self,
    ) -> None:
        probe = PrefsProbe()
        prefs = FakePrefs({KEY_A: {"send_message"}})
        denied = await _run(
            middleware(probe, prefs), user=_user(_claims(token_use="refresh"))
        )
        assert denied.status == 403
        await _run(middleware(probe, prefs))
        assert prefs.asked == []

    async def test_the_switches_do_not_outlive_the_request(self) -> None:
        probe = PrefsProbe()
        await _run(
            middleware(probe, FakePrefs({KEY_A: {"send_message"}})),
            user=_user(_claims()),
        )
        assert get_request_tool_prefs() is None

    async def test_a_failure_in_the_app_still_clears_them(self) -> None:
        probe = PrefsProbe()
        probe.raises = RuntimeError("boom")
        mw = middleware(probe, FakePrefs({KEY_A: {"send_message"}}))
        with pytest.raises(RuntimeError):
            await _run(mw, user=_user(_claims()))
        assert get_request_tool_prefs() is None
