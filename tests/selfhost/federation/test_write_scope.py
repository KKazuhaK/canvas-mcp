"""A trusted issuer's scopes narrow what a person's own write-tool choices allow, never widen it."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from canvas_mcp.core.config import reset_config
from canvas_mcp.core.course_policy import reset_policy_cache
from canvas_mcp.server import register_all_tools

from .conftest import Hub, make_hub
from .test_accounts import result_of

WRITE = "mark_module_item_done"


@pytest.fixture
def writable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Hub]:
    monkeypatch.setenv("STUDENT_WRITE_TOOLS", WRITE)
    monkeypatch.setenv("ALLOWED_WRITE_TOOLS", WRITE)
    monkeypatch.delenv("COURSE_AGENT_POLICY_DEFAULT", raising=False)
    reset_config()
    reset_policy_cache()
    yield from make_hub(
        tmp_path,
        monkeypatch,
        {"ACCESS_POLICY": "open"},
        register_tools=lambda mcp: register_all_tools(mcp, role="student"),
    )
    reset_config()
    reset_policy_cache()


def tool_names(hub: Hub, token: str) -> set[str]:
    response = hub.stack.rpc(token, "tools/list")
    assert response.status_code == 200, response.text
    body = response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        body = [ln[5:].strip() for ln in body.splitlines() if ln.startswith("data:")][
            -1
        ]
    return {tool["name"] for tool in json.loads(body)["result"]["tools"]}


def switch_on(hub: Hub, account: str) -> None:
    hub.stack.store.set_tool_prefs(account, [WRITE])
    hub.stack.runtime.tool_prefs.invalidate(account)


def test_without_a_write_scope_configured_the_persons_choice_decides(writable):
    writable.trust()
    token = writable.issuer.mint()
    assert WRITE not in tool_names(writable, token)
    (account,) = writable.accounts()
    switch_on(writable, account)
    assert WRITE in tool_names(writable, token)


def test_a_token_without_the_write_scope_is_read_only(writable):
    from ..authz.stack import ALICE
    from .issuer import ISSUER

    writable.trust(write_scope="canvas:write")
    alice = writable.stack.enroll(
        ALICE
    )  # has a Canvas token, so a call reaches the write check
    writable.federation.store.link(alice, ISSUER, "hub-alice")
    switch_on(writable, alice)  # the person switched the write tool on
    read_only = writable.issuer.mint(sub="hub-alice", scope="canvas:read")
    assert "list_courses" in tool_names(writable, read_only)
    assert WRITE not in tool_names(writable, read_only)
    is_error, answer = result_of(writable.call(read_only, WRITE))
    assert is_error is True and "read-only" in answer
    # With the scope the same call is past the gate (it would go on to Canvas).
    with_scope = writable.issuer.mint(sub="hub-alice", scope="canvas:write")
    assert WRITE in tool_names(writable, with_scope)


def test_the_write_scope_alone_does_not_switch_a_tool_on(writable):
    writable.trust(write_scope="canvas:write")
    token = writable.issuer.mint(scope="canvas:write")
    assert WRITE not in tool_names(writable, token)  # the person has not switched it on
    (account,) = writable.accounts()
    switch_on(writable, account)
    assert WRITE in tool_names(writable, token)
    # And the operator's ceiling still applies: a tool outside ALLOWED_WRITE_TOOLS is not offered.
    assert "create_planner_note" not in tool_names(writable, token)
