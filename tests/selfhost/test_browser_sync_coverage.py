"""The sync plan answers the normal call of every student read tool.

Each read tool a student profile registers is run against snapshots built from the
plan itself (fake bodies, same paths and queries the extension would upload). A
tool whose normal call needs data the plan does not carry fails here, so the plan
and the tools cannot drift apart. Tools that need data outside the extension's
allowlist are listed with the reason, and are checked to fail cleanly, offline.
"""

from __future__ import annotations

import datetime as dt
import time
from typing import Any
from unittest.mock import patch

import pytest
from fastmcp import Client, FastMCP

from canvas_mcp.core import browser_source, client
from canvas_mcp.core.browser_source import (
    BrowserMiss,
    BrowserSnapshot,
    normalize_params,
)
from canvas_mcp.core.credentials import (
    BrowserSource,
    clear_http_request_context,
    set_browser_source,
    set_http_request_active,
)
from canvas_mcp.core.selfhost import browser_plan
from canvas_mcp.core.tool_policy import TOOL_EFFECTS, Effect
from canvas_mcp.server import register_all_tools

HOST = "canvas.example.edu"
USER_ID = "77"
COURSES = (101, 102)
NOW = time.time()


def iso(delta_days: float) -> str:
    return (dt.datetime.fromtimestamp(NOW, tz=dt.UTC) + dt.timedelta(days=delta_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def course(i: int) -> dict[str, Any]:
    return {
        "id": i,
        "name": f"Course {i}",
        "course_code": f"CODE {i}",
        "workflow_state": "available",
        "restrict_quantitative_data": False,
        "syllabus_body": "<p>Syllabus</p>",
        "term": {"id": 1, "name": "Fall"},
        "enrollments": [
            {
                "type": "student",
                "role": "StudentEnrollment",
                "enrollment_state": "active",
                "computed_current_score": 91.0,
                "computed_current_grade": "A-",
            }
        ],
        "grading_standard": None,
    }


def assignment(cid: int) -> dict[str, Any]:
    return {
        "id": 1,
        "name": "Homework 1",
        "course_id": cid,
        "due_at": iso(3),
        "points_possible": 10,
        "assignment_group_id": 5,
        "peer_reviews": False,
        "submission_types": ["online_text_entry"],
        "all_dates": [],
        "submission": {"id": 9, "workflow_state": "unsubmitted", "score": None, "user_id": int(USER_ID)},
    }


def body_for(path: str, query: dict[str, list[str]]) -> Any:
    """A plausible Canvas answer for one planned resource."""
    parts = path.strip("/").split("/")
    context = (query.get("context_codes[]") or [""])[0]
    if path == "/users/self":
        return {"id": int(USER_ID), "name": "Ada Student", "login_id": "ada"}
    if path == "/users/self/profile":
        return {"id": int(USER_ID), "name": "Ada Student", "login_id": "ada", "primary_email": "ada@example.edu", "time_zone": "America/Los_Angeles"}
    if path == "/courses":
        return [course(i) for i in COURSES]
    if path == "/users/self/groups":
        return [{"id": 31, "name": "Study group", "context_type": "Course", "course_id": 101, "members_count": 2}]
    if path == "/users/self/todo":
        return [{"type": "submitting", "assignment": assignment(101), "context_type": "Course", "course_id": 101}]
    if path == "/users/self/activity_stream":
        return [{"id": 4, "type": "Message", "title": "News", "message": "hi", "created_at": iso(-1), "course_id": 101}]
    if path == "/users/self/activity_stream/summary":
        return [{"type": "Message", "count": 1, "unread_count": 1, "notification_category": ""}]
    if path == "/planner/items":
        return [
            {
                "plannable_id": 1,
                "plannable_type": "assignment",
                "plannable_date": iso(2),
                "course_id": 101,
                "context_type": "Course",
                "plannable": {"id": 1, "title": "Homework 1", "due_at": iso(2)},
                "submissions": {"submitted": False},
                "planner_override": None,
            }
        ]
    if path == "/planner_notes":
        return [{"id": 6, "title": "Read", "todo_date": iso(1), "course_id": None}]
    if path == "/calendar_events":
        kind = (query.get("type") or ["event"])[0]
        code = context or "course_101"
        return [
            {
                "id": 1 if kind == "event" else 2,
                "title": "Lecture",
                "type": kind,
                "context_code": code,
                "start_at": iso(1),
                "end_at": iso(1.05),
                "description": "d",
                **({"assignment": assignment(101)} if kind == "assignment" else {}),
            }
        ]
    if path == "/announcements":
        return [
            {
                "id": 8,
                "title": "Welcome",
                "message": "<p>hello</p>",
                "context_code": context or "course_101",
                "posted_at": iso(-2),
                "user_name": "Prof",
            }
        ]
    if len(parts) == 3 and parts[0] == "courses":
        what = parts[2]
        if what == "assignments":
            return [assignment(int(parts[1]))]
        if what == "assignment_groups":
            return [{"id": 5, "name": "Homework", "group_weight": 100, "assignments": [assignment(int(parts[1]))]}]
        if what == "quizzes":
            return [{"id": 3, "title": "Quiz 1", "due_at": iso(4), "published": True, "points_possible": 5}]
        if what == "modules":
            return [{"id": 2, "name": "Week 1", "items": [{"id": 1, "title": "Reading", "type": "Page"}], "published": True}]
        if what == "front_page":
            return {"title": "Home", "body": "<p>Welcome</p>", "url": "home"}
        if what == "discussion_topics":
            only = bool(query.get("only_announcements"))
            return [{"id": 8 if only else 7, "title": "Topic", "message": "m", "posted_at": iso(-3), "published": True}]
    raise AssertionError(f"no fake body for {path} {query}")


def snapshots_from_plan() -> list[BrowserSnapshot]:
    plan = browser_plan.build_plan(canvas_host=HOST, canvas_user_id=USER_ID, now=NOW)
    out: list[BrowserSnapshot] = []
    for resource in plan["resources"]:
        ids: tuple[Any, ...] = COURSES if resource.get("perCourse") else (None,)
        for cid in ids:
            fill = (lambda s: s) if cid is None else (lambda s, c=cid: s.replace("{course_id}", str(c)))
            path = fill(resource["path"])
            query = {
                key: [fill(v) for v in (value if isinstance(value, list) else [value])]
                for key, value in resource["query"].items()
            }
            out.append(
                BrowserSnapshot(
                    path=path,
                    query=query,
                    captured_at=int(NOW) - 60,
                    status=200,
                    body=body_for(path, query),
                )
            )
    return out


# -- what the tools are expected to do ------------------------------------------------------------------

#: Normal calls the plan must answer completely.
COVERED: dict[str, dict[str, Any]] = {
    "calculate_grade_scenarios": {"course_identifier": 101},
    "get_assignment_details": {"course_identifier": 101, "assignment_id": 1},
    "get_calendar_event": {"event_id": 1},
    "get_course_details": {"course_identifier": 101},
    "get_course_structure": {"course_identifier": 101},
    "get_discussion_topic_details": {"course_identifier": 101, "topic_id": 7},
    "get_front_page": {"course_identifier": 101},
    "get_my_activity_stream": {},
    "get_my_assignment_scores": {"course_identifier": 101},
    "get_my_course_grades": {},
    "get_my_enrollments": {},
    "get_my_peer_reviews_todo": {},
    "get_my_profile": {},
    "get_my_submission_status": {},
    "get_my_todo_items": {},
    "get_my_upcoming_assignments": {},
    "get_syllabus": {"course_identifier": 101},
    "list_announcements": {"course_identifier": "101"},
    "list_assignments": {"course_identifier": 101},
    "list_calendar_events": {},
    "list_courses": {},
    "list_discussion_topics": {"course_identifier": 101},
    "list_modules": {"course_identifier": 101},
    "list_my_announcements": {},
    "list_my_groups": {},
    "list_planner_notes": {},
    "list_quizzes": {"course_identifier": 101},
}

#: Tools that need data the extension's allowlist cannot carry (or that browser
#: sync deliberately does not store), with the reason. Each must still fail cleanly.
GAPS: dict[str, tuple[dict[str, Any], str]] = {
    "find_message_recipients": ({"course_identifier": 101}, "inbox: /search/recipients"),
    "get_conversation_details": ({"conversation_id": 1}, "inbox: /conversations"),
    "list_conversations": ({}, "inbox: /conversations"),
    "get_unread_count": ({}, "inbox: /conversations"),
    "get_discussion_entry_details": (
        {"course_identifier": 101, "topic_id": 7, "entry_id": 1},
        "discussion entries are other students' posts",
    ),
    "get_discussion_with_replies": (
        {"course_identifier": 101, "topic_id": 7},
        "discussion entries are other students' posts",
    ),
    "list_discussion_entries": (
        {"course_identifier": 101, "topic_id": 7},
        "discussion entries are other students' posts",
    ),
    "get_group_members": ({"group_id": 31}, "group members are not synced"),
    "list_group_files": ({"group_id": 31}, "file listings are not synced"),
    "list_group_discussion_topics": ({"course_identifier": 101}, "group topics are not synced"),
    "get_page_content": ({"course_identifier": 101, "page_url_or_id": "home"}, "pages are outside the allowlist"),
    "get_page_details": ({"course_identifier": 101, "page_url_or_id": "home"}, "pages are outside the allowlist"),
    "list_pages": ({"course_identifier": 101}, "pages are outside the allowlist"),
    "list_course_files": ({"course_identifier": 101}, "file listings are not synced"),
    "read_course_file": ({"course_identifier": 101, "file_id": 5}, "file contents are not synced"),
    "read_course_file_text": ({"course_identifier": 101, "file_id": 5}, "file contents are not synced"),
    "list_module_items": (
        {"course_identifier": 101, "module_id": 2},
        "modules/{id}/items is outside the allowlist",
    ),
    "get_my_submission": (
        {"course_identifier": 101, "assignment_id": 1},
        "submissions/self is outside the allowlist",
    ),
    "get_quiz_details": (
        {"course_identifier": 101, "quiz_id": 3},
        "course permissions and quiz submissions are outside the allowlist",
    ),
    "get_course_content_overview": (
        {"course_identifier": 101},
        "reads pages, which are outside the allowlist",
    ),
}

#: Misses a covered tool's normal call is allowed to have, by tool: group calendars
#: need one request per group, which the extension cannot expand from a plan.
ALLOWED_MISSES: dict[str, str] = {"list_calendar_events": "group_"}

#: Read tools that never ask Canvas for data.
NO_CANVAS_DATA = {"search_canvas_tools"}


def offline() -> Any:
    return patch.object(
        client.httpx.AsyncClient,
        "__init__",
        side_effect=AssertionError("browser mode must never open an HTTP client"),
    )


class Run:
    def __init__(self) -> None:
        self.misses: list[BrowserMiss] = []
        self.asked: list[str] = []


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch) -> Run:
    state = Run()
    real = browser_source.answer_get

    async def recording(source: BrowserSource, endpoint: str, params: Any, **kw: Any) -> Any:
        state.asked.append(endpoint + " " + repr(normalize_params(params)))
        try:
            return await real(source, endpoint, params, **kw)
        except BrowserMiss as miss:
            state.misses.append(BrowserMiss(
                    miss.code, f"{endpoint} {normalize_params(params)}: {miss.message}"
                ))
            raise

    monkeypatch.setattr(browser_source, "answer_get", recording)
    return state


def make_source() -> BrowserSource:
    stored = snapshots_from_plan()

    async def load(path: str) -> list[BrowserSnapshot]:
        return [s for s in stored if s.path == path]

    return BrowserSource("binding", HOST, load)


async def call_tool(name: str, arguments: dict[str, Any]) -> Any:
    mcp = FastMCP("coverage")
    register_all_tools(mcp, role="student")
    set_http_request_active(True)
    set_browser_source(make_source())
    try:
        with offline():
            async with Client(mcp) as c:
                return await c.call_tool(name, arguments, raise_on_error=False)
    finally:
        clear_http_request_context()


async def registered_read_tools() -> set[str]:
    mcp = FastMCP("coverage")
    register_all_tools(mcp, role="student")
    async with Client(mcp) as c:
        return {t.name for t in await c.list_tools() if TOOL_EFFECTS.get(t.name) is Effect.READ}


async def test_every_student_read_tool_is_either_covered_or_a_listed_gap():
    names = await registered_read_tools()
    assert names, "no read tools were registered"
    accounted = set(COVERED) | set(GAPS) | NO_CANVAS_DATA
    assert names - accounted == set(), "classify new read tools as COVERED or GAPS"
    assert accounted - names == set(), "stale entries"
    assert not set(COVERED) & set(GAPS)


@pytest.mark.parametrize("name", sorted(COVERED))
async def test_the_normal_call_of_a_covered_tool_is_answered_from_the_plan(name, run: Run):
    result = await call_tool(name, COVERED[name])
    assert run.asked, "the tool did not read anything"
    allowed = ALLOWED_MISSES.get(name)
    unexpected = [m.message for m in run.misses if allowed is None or allowed not in m.message]
    assert unexpected == [], unexpected
    if allowed is not None:
        # The allowance covers only the contexts named, never the whole answer.
        assert len(run.misses) < len(run.asked)
    text = "\n".join(getattr(block, "text", "") for block in result.content)
    if allowed is None:
        assert "not been synced" not in text
    assert result.is_error is False, text[:300]


@pytest.mark.parametrize("name", sorted(GAPS))
async def test_a_tool_the_plan_cannot_serve_fails_without_touching_canvas(name, run: Run):
    arguments, reason = GAPS[name]
    result = await call_tool(name, arguments)  # `offline()` fails the call if Canvas is contacted
    assert run.misses, f"{name} was expected to need unsynced data ({reason})"
    text = "\n".join(getattr(block, "text", "") for block in result.content)
    assert "Traceback" not in text


async def test_every_planned_resource_is_used_by_some_covered_tool(run: Run):
    """A resource nothing reads is dead weight the extension fetches for nothing."""
    plan_paths = {r["path"] for r in browser_plan.build_plan(canvas_host=HOST, canvas_user_id=USER_ID, now=NOW)["resources"]}
    for name in sorted(COVERED):
        await call_tool(name, COVERED[name])
    asked = {entry.split(" ", 1)[0] for entry in run.asked}

    def covers(path: str) -> bool:
        concrete = path.replace("{course_id}", "101")
        if concrete in asked:
            return True
        # Single objects are answered from their parent list.
        return any(a.rsplit("/", 1)[0] == concrete for a in asked)

    unused = sorted(p for p in plan_paths if not covers(p))
    assert unused == [], unused
