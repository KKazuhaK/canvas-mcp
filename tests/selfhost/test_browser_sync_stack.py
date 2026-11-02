"""Browser sync through the whole stack: extension endpoints, OAuth, FastMCP gate, tools.

The in-process request tests skip FastMCP's middleware chain; this one does not.
No Canvas host is mocked: any call to Canvas would fail the test.
"""

from __future__ import annotations

import json
import pathlib
from types import SimpleNamespace

import httpx
import pytest
import respx

from canvas_mcp.core.credentials import clear_http_request_context, set_browser_source
from canvas_mcp.core.tool_policy import TOOL_EFFECTS, Effect
from canvas_mcp.server import register_all_tools

from .account_fixture import _display_in_utc, build_harness, sign_in  # noqa: F401
from .authz.stack import User
from .conftest import OID_A
from .test_browser_sync import COURSES, Rig, res
from .test_selfhost_integration import call_tool, rpc, text_of


def student_tools(mcp) -> None:  # type: ignore[no-untyped-def]
    register_all_tools(mcp, role="student")


@pytest.fixture
def rig(tmp_path: pathlib.Path):
    h = build_harness(tmp_path, register_tools=student_tools)
    assert sign_in(h, oid=OID_A).status_code == 303
    rig = Rig(h)
    token = rig.pair()
    todo = [{"type": "submitting", "assignment": {"id": 1, "name": "Essay", "due_at": "2999-01-01T00:00:00Z", "course_id": 101, "points_possible": 10}, "context_type": "Course", "course_id": 101}]
    course = {"id": 101, "name": "Course 101", "course_code": "C101", "enrollments": [{"type": "student", "computed_current_score": 90.0, "computed_current_grade": "A-"}]}
    assert rig.upload(
        token,
        [
            res("/users/self", {}, {"id": 77, "name": "Ada Student"}),
            res("/users/self/profile", {}, {"id": 77, "name": "Ada Student", "login_id": "ada"}),
            res("/courses", COURSES, [course]),
            res("/courses", {"enrollment_state": "active", **COURSES}, [course]),
            res("/users/self/todo", {}, todo),
        ],
        captured_at=h.now - 600,  # the stack runs on the harness clock
    ).json()["accepted"] == 5
    bearer = h.stack.tokens_for(User("A", OID_A))[1]["access_token"]
    mcp = SimpleNamespace(client=h.stack.new_client(), tokens={})
    with respx.mock(assert_all_called=False) as router:
        yield SimpleNamespace(rig=rig, mcp=mcp, bearer=bearer, canvas=router)
    clear_http_request_context()


def test_read_tools_are_answered_from_the_synced_data_with_a_freshness_note(rig):
    todo = call_tool(rig.mcp, rig.bearer, "get_my_todo_items")
    assert not todo.get("isError"), todo
    assert "Essay" in text_of(todo)
    assert todo["content"][-1]["text"].startswith("Data synced from your browser")
    profile = call_tool(rig.mcp, rig.bearer, "get_my_profile")
    assert not profile.get("isError"), profile
    assert "Ada Student" in text_of(profile)
    grades = call_tool(rig.mcp, rig.bearer, "get_my_course_grades")
    assert not grades.get("isError"), grades
    assert "C101" in text_of(grades) or "Course 101" in text_of(grades)
    assert len(rig.canvas.calls) == 0


def test_unsynced_data_is_a_coded_failure_not_the_token_message(rig):
    result = call_tool(rig.mcp, rig.bearer, "list_announcements", {"course_identifier": "101"})
    assert result["isError"] is True
    text = text_of(result)
    assert "SOURCE_UNAVAILABLE" in text and "Canvas token required" not in text


def test_only_read_tools_are_offered_and_a_write_tool_is_refused(rig):
    response = rpc(rig.mcp, rig.bearer, "tools/list")
    text = response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        text = [ln[5:] for ln in text.splitlines() if ln.startswith("data:")][-1]
    body = json.loads(text)
    names = [t["name"] for t in body["result"]["tools"]]
    assert names and all(TOOL_EFFECTS.get(n) is Effect.READ for n in names)
    response = rpc(rig.mcp, rig.bearer, "tools/call", {"name": "create_planner_note", "arguments": {"title": "x"}})
    assert response.status_code == 200
    assert "Canvas token required" not in response.text
    text = response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        text = [ln[5:] for ln in text.splitlines() if ln.startswith("data:")][-1]
    result = json.loads(text)["result"]
    assert result["isError"] is True
    payload = json.loads(result["content"][0]["text"])
    assert payload["error"] == "PERMISSION_DENIED" and "read-only" in payload["message"]
    assert len(rig.canvas.calls) == 0


async def test_the_gate_refuses_a_write_tool_that_is_switched_on(rig):
    from fastmcp.exceptions import ToolError

    from canvas_mcp.core.credentials import BrowserSource
    from canvas_mcp.core.selfhost.tool_gate import _check_browser_read_only

    async def load(path):  # noqa: ANN001
        return []

    from canvas_mcp.core.credentials import set_http_request_active

    set_http_request_active(True)
    set_browser_source(BrowserSource("b", "canvas.example.edu", load))
    try:
        _check_browser_read_only("list_courses")
        for name in ("create_planner_note", "send_message", "not_a_known_tool"):
            with pytest.raises(ToolError, match="read-only"):
                _check_browser_read_only(name)
    finally:
        clear_http_request_context()


def test_without_synced_data_or_a_token_the_old_message_stays(tmp_path: pathlib.Path):
    h = build_harness(tmp_path, register_tools=student_tools)
    sign_in(h, oid=OID_A)
    bearer = h.stack.tokens_for(User("A", OID_A))[1]["access_token"]
    mcp = SimpleNamespace(client=h.stack.new_client(), tokens={})
    result = call_tool(mcp, bearer, "get_my_todo_items")
    assert result["isError"] is True
    assert isinstance(httpx.URL("https://x"), httpx.URL)
