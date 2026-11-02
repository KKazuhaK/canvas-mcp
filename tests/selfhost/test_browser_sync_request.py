"""How a request chooses browser data over a token, and what the tool layer does with it."""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from types import MappingProxyType
from typing import Any

import pytest
from dbbackend import make_store
from fastmcp import Client, FastMCP
from mcp.types import ToolAnnotations

from canvas_mcp.core import client as canvas_client
from canvas_mcp.core.credentials import (
    BrowserSource,
    current_principal_key,
    get_browser_source,
    get_request_credentials,
    set_browser_source,
    set_http_request_active,
)
from canvas_mcp.core.credentials import clear_http_request_context as clear_context
from canvas_mcp.core.selfhost.browser_store import BrowserSyncStore, SnapshotItem
from canvas_mcp.core.selfhost.config_snapshot import ConfigSnapshot
from canvas_mcp.core.selfhost.db.settings_repo import TypedSettings
from canvas_mcp.core.selfhost.schools import SchoolPolicy
from canvas_mcp.core.selfhost.server_settings import SETTINGS
from canvas_mcp.core.selfhost.token_store import Keyring, TokenStore
from canvas_mcp.core.tool_results import install_tool_result_contract

from .conftest import OID_A, OID_B, acct_key, make_account
from .test_request_context import (
    CANVAS_HOST,
    SECRET_TOKEN,
    FakeSnapshots,
    FakeStore,
    Probe,
    _claims,
    _middleware,
    _run,
    _user,
    native_snapshot,
)

NOW = 1_800_000_000
KEY_A = acct_key(OID_A)
KEY_B = acct_key(OID_B)
INVALID = {"credential_status": "invalid", "invalid_reason": "canvas_token_rejected"}
NO_TOKEN = {"credential_id": None, "canvas_host": None, "generation": None}


class SettingsSnapshots(FakeSnapshots):
    def __init__(self, schools: SchoolPolicy | None = None, **settings: int) -> None:
        super().__init__(schools)
        self.values = {k: v.default for k, v in SETTINGS.items()} | settings

    def get(self, revision: int) -> ConfigSnapshot:
        base = super().get(revision)
        return replace(base, settings=TypedSettings(MappingProxyType(self.values)))


@pytest.fixture
def db(tmp_path):
    ring = Keyring.parse("k1:" + base64.b64encode(b"1" * 32).decode())
    store: TokenStore = make_store(tmp_path / "request.sqlite3", ring, clock=lambda: NOW)
    store.initialize()
    make_account(store, OID_A)
    make_account(store, OID_B)
    try:
        yield store
    finally:
        store.close()


@pytest.fixture
def browser(db: TokenStore) -> BrowserSyncStore:
    return BrowserSyncStore(db.database, db.keyring, clock=lambda: NOW)


def bind(
    browser: BrowserSyncStore,
    key: str = KEY_A,
    *,
    host: str | None = CANVAS_HOST,
    items: dict[str, Any] | None = None,
    at: int = NOW - 60,
) -> str:
    """A binding with snapshots, made through the real pairing path."""
    code, _ = browser.create_pairing_code(key)
    claimed = browser.claim(code)
    assert claimed is not None
    _, binding_id = claimed
    if host is not None:
        stored = [
            SnapshotItem(path, path, {}, at, 200, body) for path, body in (items or {"/users/self": {"id": 42}}).items()
        ]
        browser.save(binding_id, canvas_host=host, canvas_user_id="42", items=stored)
    return binding_id


class SourceProbe(Probe):
    """Records what a request carries, and reads one Canvas path through the client."""

    def __init__(self, endpoint: str | None = "/users/self") -> None:
        super().__init__()
        self.endpoint = endpoint
        self.answer: Any = None
        self.browser: BrowserSource | None = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.browser = get_browser_source()
        self.key_seen = current_principal_key()
        if self.endpoint is not None:
            self.answer = await canvas_client.make_canvas_request("get", self.endpoint)
        await super().__call__(scope, receive, send)


async def serve(
    store: FakeStore,
    browser: BrowserSyncStore | None,
    *,
    endpoint: str | None = "/users/self",
    settings: SettingsSnapshots | None = None,
) -> SourceProbe:
    probe = SourceProbe(endpoint)
    mw = _middleware(probe, store, browser=browser)
    if settings is not None:
        mw.snapshots = settings
    call = await _run(mw, user=_user(_claims()))
    assert call.status == 200
    return probe


def without_token(**changes: Any) -> FakeStore:
    store = FakeStore()
    store.snapshots[KEY_A] = native_snapshot(**NO_TOKEN, **changes)
    return store


# -- choosing the data source -------------------------------------------------------------------


async def test_no_token_and_a_binding_for_the_school_runs_in_browser_mode(browser):
    bind(browser, items={"/users/self": {"id": 42, "name": "Ada"}})
    probe = await serve(without_token(), browser)
    assert probe.browser is not None and probe.browser.canvas_host == CANVAS_HOST
    assert probe.seen["creds"] is None
    assert probe.answer == {"id": 42, "name": "Ada"}
    assert probe.key_seen.endswith(f"|browser|{CANVAS_HOST}|{probe.browser.binding_id}")


async def test_a_usable_token_is_preferred_and_snapshots_are_ignored(browser):
    bind(browser)
    store = FakeStore({KEY_A: SECRET_TOKEN})
    probe = await serve(store, browser, endpoint=None)
    assert probe.browser is None
    assert probe.seen["creds"] is not None and probe.seen["creds"].api_token == SECRET_TOKEN
    assert "|browser|" not in probe.key_seen


async def test_a_token_Canvas_rejected_hands_over_to_the_binding_of_the_same_school(browser):
    bind(browser)
    store = FakeStore()
    store.snapshots[KEY_A] = native_snapshot(**INVALID)
    probe = await serve(store, browser)
    assert probe.browser is not None and probe.seen["creds"] is None


async def test_a_dead_token_of_another_school_does_not_hand_over(browser):
    bind(browser)
    store = FakeStore()
    store.snapshots[KEY_A] = native_snapshot(canvas_host="other.example.edu", **INVALID)
    probe = await serve(store, browser, endpoint=None)
    assert probe.browser is None and probe.seen["creds"] is None
    assert probe.seen["code"] == "CREDENTIAL_INVALID"


async def test_a_binding_that_has_not_uploaded_yet_does_not_count(browser):
    bind(browser, host=None)
    probe = await serve(without_token(), browser, endpoint=None)
    assert probe.browser is None and probe.seen["code"] == "CREDENTIAL_INVALID"


async def test_a_school_the_server_does_not_offer_does_not_count(browser):
    bind(browser, host="elsewhere.example.edu")
    probe = await serve(without_token(), browser, endpoint=None)
    assert probe.browser is None


async def test_a_revoked_binding_does_not_count(browser):
    bind(browser)
    browser.revoke_account(KEY_A)
    assert (await serve(without_token(), browser, endpoint=None)).browser is None


async def test_another_accounts_binding_is_never_used(browser):
    bind(browser, KEY_B, items={"/users/self": {"id": 99, "name": "Bea"}})
    probe = await serve(without_token(), browser, endpoint="/users/self")
    assert probe.browser is None
    assert "error" in probe.answer


async def test_without_a_snapshot_store_the_server_behaves_as_before(browser):
    bind(browser)
    probe = await serve(without_token(), None, endpoint=None)
    assert probe.browser is None and probe.seen["code"] == "CREDENTIAL_INVALID"


async def test_an_unreadable_store_falls_back_to_the_no_token_answer(browser):
    class Broken:
        def active_binding(self, key: str) -> None:
            raise RuntimeError("database down")

    probe = await serve(without_token(), Broken(), endpoint=None)  # type: ignore[arg-type]
    assert probe.browser is None and probe.seen["code"] == "CREDENTIAL_INVALID"


async def test_the_context_does_not_leak_into_the_next_request(browser):
    bind(browser)
    await serve(without_token(), browser, endpoint=None)
    assert get_browser_source() is None and get_request_credentials() is None


async def test_each_account_reads_only_its_own_snapshots(browser, db):
    bind(browser, KEY_A, items={"/users/self": {"id": 1, "name": "alice"}})
    bind(browser, KEY_B, items={"/users/self": {"id": 2, "name": "bea"}})
    a = FakeStore()
    a.snapshots[KEY_A] = native_snapshot(**NO_TOKEN)
    probe_a = await serve(a, browser)
    assert probe_a.answer["name"] == "alice"


# -- data age, as settings -----------------------------------------------------------------------


async def test_data_older_than_the_limit_is_refused_and_the_limit_is_a_setting(browser):
    import time

    bind(browser, at=int(time.time()) - 5 * 86400)
    default = await serve(without_token(), browser, settings=SettingsSnapshots())
    assert default.answer == {"id": 42}
    assert default.browser is not None and default.browser.max_age_seconds == 14 * 86400
    assert default.browser.fresh_seconds == 12 * 3600
    tuned = await serve(
        without_token(),
        browser,
        settings=SettingsSnapshots(**{"browser_sync.max_age_days": 3, "browser_sync.fresh_hours": 2}),
    )
    assert tuned.browser is not None
    assert (tuned.browser.max_age_seconds, tuned.browser.fresh_seconds) == (3 * 86400, 2 * 3600)
    assert "error" in tuned.answer and "3 days old" in tuned.answer["error"]


# -- the tool result layer ---------------------------------------------------------------------------


def tool_server(source: BrowserSource | None) -> FastMCP:
    mcp = FastMCP("browser-notes")
    install_tool_result_contract(mcp)

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    async def read_quizzes() -> str:
        data = await canvas_client.fetch_all_paginated_results("/courses/5/quizzes")
        if isinstance(data, dict):
            return f"Error fetching quizzes: {data['error']}"
        return f"{len(data)} quizzes"

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    async def read_nothing() -> str:
        return "no canvas call"

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    async def read_missing() -> str:
        data = await canvas_client.fetch_all_paginated_results("/courses/5/pages")
        return f"Error: {data['error']}" if isinstance(data, dict) else "ok"

    return mcp


def source_with(age_seconds: int, *, fresh_hours: int = 12) -> BrowserSource:
    from canvas_mcp.core.browser_source import BrowserSnapshot

    async def load(path: str) -> list[BrowserSnapshot]:
        import time

        if path != "/courses/5/quizzes":
            return []
        return [BrowserSnapshot(path, {}, int(time.time()) - age_seconds, 200, [{"id": 1}, {"id": 2}])]

    return BrowserSource("b1", CANVAS_HOST, load, fresh_seconds=fresh_hours * 3600)


async def call(source: BrowserSource | None, tool: str) -> Any:
    set_http_request_active(True)
    if source is not None:
        set_browser_source(source)
    try:
        async with Client(tool_server(source)) as client:
            return await client.call_tool(tool, {}, raise_on_error=False)
    finally:
        clear_context()


async def test_a_result_from_browser_data_says_how_old_the_data_is():
    result = await call(source_with(600), "read_quizzes")
    texts = [block.text for block in result.content]
    assert texts[0] == "2 quizzes"
    assert texts[-1] == "Data synced from your browser 10 minutes ago."
    assert result.is_error is False


async def test_old_data_carries_the_warning_after_the_threshold():
    fresh = await call(source_with(11 * 3600), "read_quizzes")
    assert "out of date" not in fresh.content[-1].text
    stale = await call(source_with(13 * 3600), "read_quizzes")
    assert stale.content[-1].text == (
        "Data synced from your browser 13 hours ago. It may be out of date; open Canvas in the browser to refresh it."
    )
    shorter = await call(source_with(3 * 3600, fresh_hours=2), "read_quizzes")
    assert "out of date" in shorter.content[-1].text


async def test_a_tool_that_read_nothing_gets_no_note_and_neither_does_a_token_user():
    assert [b.text for b in (await call(source_with(60), "read_nothing")).content] == ["no canvas call"]
    # Without a browser source nothing is appended, whatever the tool does.
    result = await call(None, "read_nothing")
    assert [b.text for b in result.content] == ["no canvas call"]


async def test_a_failure_is_coded_and_carries_no_freshness_note():
    result = await call(source_with(60), "read_missing")
    assert result.is_error is True
    [block] = result.content
    payload = json.loads(block.text)
    assert payload["error"] == "SOURCE_UNAVAILABLE"
    assert "not been synced by the browser extension" in payload["message"]
    assert "Data synced" not in block.text
