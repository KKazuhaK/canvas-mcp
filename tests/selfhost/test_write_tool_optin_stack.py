"""Per-user write-tool opt-in through the whole HTTP stack.

Real tool registry, the operator's ALLOWED_WRITE_TOOLS, the credential gate, the
preference cache and the course policy; only Entra (a static verifier) and Canvas
(respx) are faked.
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import fastmcp
import httpx
import pytest
import respx
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from starlette.testclient import TestClient

from canvas_mcp.core.config import reset_config
from canvas_mcp.core.course_policy import reset_policy_cache
from canvas_mcp.core.selfhost.app import (
    build_selfhost_asgi_app,
    install_selfhost,
    prepare_selfhost,
)
from canvas_mcp.core.selfhost.settings import load_selfhost_settings
from canvas_mcp.core.tool_policy import apply_tool_policy, resolve_tool_policy
from canvas_mcp.server import register_all_tools

from .conftest import CLIENT, OID_A, OID_B, TENANT

BASE = "https://canvas.example.test"
CANVAS = "https://canvas.example.edu"
TOKEN = {OID_A: "canvas-token-for-user-A-0123456789", OID_B: "canvas-token-for-user-B-0123456789"}
KEY = {oid: f"entra:{TENANT}:{oid}".lower() for oid in (OID_A, OID_B)}
STUDENT_WRITES = "mark_module_item_done,send_message,create_planner_note,submit_assignment"
OPERATOR_ALLOWS = "mark_module_item_done,create_planner_note"


def _entra(oid: str) -> dict[str, Any]:
    return {
        "client_id": CLIENT, "scopes": ["Canvas.Access"], "tid": TENANT, "oid": oid, "azp": CLIENT,
        "roles": ["Canvas.User"], "name": f"user {oid[:4]}",
    }


@pytest.fixture
def stack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[SimpleNamespace]:
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path / "fastmcp")
    monkeypatch.setenv("CANVAS_API_URL", CANVAS)
    monkeypatch.setenv("STUDENT_WRITE_TOOLS", STUDENT_WRITES)
    monkeypatch.setenv("ALLOWED_WRITE_TOOLS", OPERATOR_ALLOWS)
    monkeypatch.delenv("COURSE_AGENT_POLICY_DEFAULT", raising=False)
    for name in ("CANVAS_API_TOKEN", "CANVAS_ROLE"):
        monkeypatch.delenv(name, raising=False)
    reset_config()
    reset_policy_cache()

    settings = load_selfhost_settings({
        "PUBLIC_BASE_URL": BASE,
        "ENTRA_TENANT_ID": TENANT,
        "ENTRA_CLIENT_ID": CLIENT,
        "ENTRA_CLIENT_SECRET": "entra-client-secret-0123456789",
        "OAUTH_JWT_SIGNING_KEY": "jwt-signing-key-" + "z" * 40,
        "ACCOUNT_SESSION_SECRET": base64.b64encode(bytes(range(32))).decode(),
        "CANVAS_TOKEN_KEYS": "k1:" + base64.b64encode(bytes(32)).decode(),
        "FASTMCP_HOME": str(tmp_path / "fastmcp"),
        "SELFHOST_DATA_DIR": str(tmp_path / "data"),
    })
    runtime = prepare_selfhost(settings)
    for oid, token in TOKEN.items():
        runtime.store.put(
            tenant_id=TENANT, object_id=oid, api_token=token, canvas_user_id=oid[:2],
            canvas_user_name="n", entra_display_name="n", entra_upn="n@example.test",
            canvas_host="canvas.example.edu",
        )

    from canvas_mcp.core.config import get_config

    config = get_config()
    policy = resolve_tool_policy(config.allowed_write_tools, "http")
    mcp = FastMCP(
        "optin",
        auth=StaticTokenVerifier({"bearer-A": _entra(OID_A), "bearer-B": _entra(OID_B)}, required_scopes=["Canvas.Access"]),
    )
    register_all_tools(mcp, role="student")
    asyncio.run(apply_tool_policy(mcp, policy))
    install_selfhost(mcp, runtime, config, tool_policy=policy)
    app = build_selfhost_asgi_app(mcp, runtime, config)

    state = SimpleNamespace(syllabus="agent_writes: allow", done=False, seen=[], puts=[])

    def canvas(request: httpx.Request) -> httpx.Response:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        state.seen.append((request.method, request.url.path, token))
        path = request.url.path
        if request.method == "GET" and path == "/api/v1/courses/101":
            return httpx.Response(200, json={"id": 101, "name": "Python", "syllabus_body": state.syllabus})
        if request.method == "GET" and path == "/api/v1/courses/101/modules/5/items/9":
            return httpx.Response(200, json={
                "id": 9, "title": "Read me",
                "completion_requirement": {"type": "must_mark_done", "completed": state.done},
            })
        if request.method == "PUT" and path == "/api/v1/courses/101/modules/5/items/9/done":
            state.done = True
            state.puts.append(token)
            return httpx.Response(200, json={})
        if request.method == "GET" and path == "/api/v1/courses":
            return httpx.Response(200, json=[{"id": 101, "name": "Python", "course_code": "ICS 33"}])
        return httpx.Response(404, json={"errors": [{"message": "not found"}]})

    with respx.mock(assert_all_called=False) as router, TestClient(app, base_url=BASE) as client:
        router.route(host="canvas.example.edu").mock(side_effect=canvas)
        yield SimpleNamespace(client=client, runtime=runtime, state=state, mcp=mcp)
    reset_config()
    reset_policy_cache()


def rpc(stack: SimpleNamespace, bearer: str, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {bearer}",
    }
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    response = stack.client.post("/mcp", json=body, headers=headers)
    assert response.status_code == 200, response.text
    text = response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        text = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")][-1]
    payload = json.loads(text)
    assert "error" not in payload, payload
    return payload["result"]


def tool_names(stack: SimpleNamespace, bearer: str) -> set[str]:
    return {tool["name"] for tool in rpc(stack, bearer, "tools/list")["tools"]}


def call(stack: SimpleNamespace, bearer: str, name: str, arguments: dict[str, Any] | None = None) -> tuple[bool, str]:
    result = rpc(stack, bearer, "tools/call", {"name": name, "arguments": arguments or {}})
    return bool(result.get("isError")), "".join(block.get("text", "") for block in result["content"])


MARK = {"course_identifier": "101", "module_id": "5", "item_id": "9"}


def switch_on(stack: SimpleNamespace, oid: str, *names: str, invalidate: bool = True) -> None:
    stack.runtime.store.set_tool_prefs(KEY[oid], names)
    if invalidate:
        stack.runtime.tool_prefs.invalidate(KEY[oid])


class TestDefaultOff:
    def test_a_user_who_changed_nothing_sees_and_can_use_no_write_tool(self, stack):
        names = tool_names(stack, "bearer-A")
        assert "list_courses" in names and "get_my_profile" in names
        assert not names & {"mark_module_item_done", "create_planner_note", "send_message", "submit_assignment"}

    def test_calling_a_write_tool_by_name_is_refused_before_any_canvas_request(self, stack):
        is_error, text = call(stack, "bearer-A", "mark_module_item_done", MARK)
        assert is_error
        assert "'mark_module_item_done' is turned off for your account" in text
        assert "https://canvas.example.test/account" in text
        assert stack.state.seen == []

    def test_read_tools_work_as_before(self, stack):
        is_error, text = call(stack, "bearer-A", "list_courses")
        assert not is_error and "Python" in text


class TestSwitchedOn:
    def test_the_tool_appears_in_the_list_and_runs(self, stack):
        switch_on(stack, OID_A, "mark_module_item_done")
        assert "mark_module_item_done" in tool_names(stack, "bearer-A")
        is_error, text = call(stack, "bearer-A", "mark_module_item_done", MARK)
        assert not is_error and "marked" in text.lower()
        assert stack.state.puts == [TOKEN[OID_A]]

    def test_only_the_user_who_switched_it_on_gets_it(self, stack):
        switch_on(stack, OID_A, "mark_module_item_done")
        assert "mark_module_item_done" not in tool_names(stack, "bearer-B")
        is_error, text = call(stack, "bearer-B", "mark_module_item_done", MARK)
        assert is_error and "turned off" in text
        assert stack.state.puts == []

    def test_switching_on_other_tools_does_not_enable_this_one(self, stack):
        switch_on(stack, OID_A, "create_planner_note")
        assert call(stack, "bearer-A", "mark_module_item_done", MARK)[0]

    def test_a_change_reaches_the_server_after_the_cache_is_dropped(self, stack):
        # The first request caches "nothing switched on".
        assert call(stack, "bearer-A", "mark_module_item_done", MARK)[0]
        switch_on(stack, OID_A, "mark_module_item_done", invalidate=False)
        assert call(stack, "bearer-A", "mark_module_item_done", MARK)[0]  # still cached (at most 30 s)
        stack.runtime.tool_prefs.invalidate(KEY[OID_A])
        assert not call(stack, "bearer-A", "mark_module_item_done", MARK)[0]

    def test_turning_it_off_takes_effect_at_once_when_the_cache_is_dropped(self, stack):
        switch_on(stack, OID_A, "mark_module_item_done")
        assert not call(stack, "bearer-A", "mark_module_item_done", MARK)[0]
        switch_on(stack, OID_A)
        assert call(stack, "bearer-A", "mark_module_item_done", MARK)[0]
        assert "mark_module_item_done" not in tool_names(stack, "bearer-A")


class TestServerCeiling:
    def test_a_tool_the_operator_does_not_allow_stays_unusable_even_if_switched_on(self, stack):
        # send_message and submit_assignment are registered by STUDENT_WRITE_TOOLS
        # but left out of ALLOWED_WRITE_TOOLS.
        switch_on(stack, OID_A, "send_message", "submit_assignment", "create_assignment", "execute_typescript")
        names = tool_names(stack, "bearer-A")
        assert not names & {"send_message", "submit_assignment", "create_assignment", "execute_typescript"}
        for tool in ("send_message", "submit_assignment", "create_assignment", "execute_typescript"):
            is_error, text = call(stack, "bearer-A", tool)
            assert is_error, tool
            assert "not offered on this server" in text, tool
        assert stack.state.seen == []

    def test_switching_on_everything_exposes_exactly_what_the_operator_allows(self, stack):
        from canvas_mcp.core.tool_policy import SIDE_EFFECT_TOOLS

        switch_on(stack, OID_A, *sorted(SIDE_EFFECT_TOOLS))
        names = tool_names(stack, "bearer-A")
        assert names & SIDE_EFFECT_TOOLS == set(OPERATOR_ALLOWS.split(","))


class TestCoursePolicyStillApplies:
    def test_a_course_that_denies_writes_refuses_even_when_the_user_switched_it_on(self, stack):
        stack.state.syllabus = "agent_writes: deny\nnote: No AI writes in this course."
        switch_on(stack, OID_A, "mark_module_item_done")
        is_error, text = call(stack, "bearer-A", "mark_module_item_done", MARK)
        assert "Update blocked" in text and "No AI writes in this course." in text
        assert stack.state.puts == []
        assert is_error or "❌" in text

    def test_a_course_with_no_policy_uses_the_operator_default_deny(self, stack):
        stack.state.syllabus = "Welcome to the course."
        switch_on(stack, OID_A, "mark_module_item_done")
        _is_error, text = call(stack, "bearer-A", "mark_module_item_done", MARK)
        assert "Update blocked" in text and "has not opted in" in text
        assert stack.state.puts == []

    def test_a_course_that_allows_other_tools_only_still_blocks_this_one(self, stack):
        stack.state.syllabus = "agent_writes: allow\nallow_tools: create_planner_note"
        switch_on(stack, OID_A, "mark_module_item_done")
        _is_error, text = call(stack, "bearer-A", "mark_module_item_done", MARK)
        assert "permits agent writes but not 'mark_module_item_done'" in text
        assert stack.state.puts == []


class TestDiscovery:
    def test_search_canvas_tools_does_not_advertise_a_tool_that_is_off(self, stack):
        _error, text = call(stack, "bearer-A", "search_canvas_tools", {"query": "module_item_done", "detail_level": "names"})
        assert "mark_module_item_done" not in text
        switch_on(stack, OID_A, "mark_module_item_done")
        _error, text = call(stack, "bearer-A", "search_canvas_tools", {"query": "module_item_done", "detail_level": "names"})
        assert "mark_module_item_done" in text
        # ... and only for the user who switched it on.
        _error, text = call(stack, "bearer-B", "search_canvas_tools", {"query": "module_item_done", "detail_level": "names"})
        assert "mark_module_item_done" not in text
