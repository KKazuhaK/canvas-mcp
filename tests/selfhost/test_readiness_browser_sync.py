"""Readiness for an account served by browser sync is judged by the rules ``/mcp`` applies.

``/mcp`` reads only the rows of the binding's plan, refuses a resource Canvas answered with an
error status, refuses data older than ``browser_sync.max_age_days`` and warns about data older
than ``browser_sync.fresh_hours``. Each case asks both endpoints about the same stored data.
"""

from __future__ import annotations

import pathlib
from types import SimpleNamespace
from typing import Any

import pytest
import respx
from sqlalchemy import insert

from canvas_mcp.core import browser_source
from canvas_mcp.core.credentials import clear_http_request_context
from canvas_mcp.core.selfhost.browser_store import SnapshotItem
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.server import register_all_tools

from .account_fixture import _display_in_utc, build_harness, sign_in  # noqa: F401
from .authz.stack import User
from .conftest import OID_A
from .test_browser_sync import BARE, COURSES, Rig, res
from .test_selfhost_integration import call_tool, text_of

PATH = "/api/v1/readiness"
HOUR, DAY = 3600, 86400
ME = {"id": 77, "name": "Ada Student"}
PROFILE = {"id": 77, "name": "Ada Student", "login_id": "ada"}
COURSE = {
    "id": 101,
    "name": "Course 101",
    "course_code": "C101",
    "enrollments": [
        {"type": "student", "computed_current_score": 90.0, "computed_current_grade": "A-"}
    ],
}


def student_tools(mcp: Any) -> None:
    register_all_tools(mcp, role="student")


@pytest.fixture
def env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    h = build_harness(tmp_path, register_tools=student_tools)
    assert sign_in(h, oid=OID_A).status_code == 303
    rig = Rig(h)
    token = rig.pair()
    bearer = h.stack.tokens_for(User("A", OID_A))[1]["access_token"]
    mcp = SimpleNamespace(client=h.stack.new_client(), tokens={})
    # The tools judge age by the wall clock; the stack runs on the harness clock.
    monkeypatch.setattr(browser_source, "time", SimpleNamespace(time=lambda: h.now))
    with respx.mock(assert_all_called=False):
        yield SimpleNamespace(h=h, rig=rig, token=token, bearer=bearer, mcp=mcp)
    clear_http_request_context()


def setting(env: Any, name: str) -> int:
    return int(env.h.stack.runtime.snapshots.current.settings[name])


def put(env: Any, items: list[dict[str, Any]], age: int) -> None:
    accepted = env.rig.upload(env.token, items, captured_at=env.h.now - age).json()["accepted"]
    assert accepted == len(items)


def put_all(env: Any, *, self_age: int, courses_age: int, self_status: int = 200,
            courses_status: int = 200) -> None:
    put(
        env,
        [
            res("/users/self", {}, ME if self_status == 200 else {}, self_status),
            res("/users/self/profile", {}, PROFILE, self_status),
        ],
        self_age,
    )
    put(
        env,
        [
            res("/courses", BARE, [COURSE] if courses_status == 200 else [], courses_status),
            res("/courses", COURSES, [COURSE] if courses_status == 200 else [], courses_status),
        ],
        courses_age,
    )


def readiness(env: Any) -> Any:
    return env.mcp.client.get(
        PATH, headers={"Authorization": f"Bearer {env.bearer}", "Accept": "application/json"}
    )


def state_of(env: Any) -> dict[str, Any]:
    response = readiness(env)
    assert response.status_code == 200, response.text
    return response.json()  # type: ignore[no-any-return]


def mcp_result(env: Any) -> dict[str, Any]:
    return call_tool(env.mcp, env.bearer, "get_my_course_grades")


def test_complete_fresh_data_is_ready_and_mcp_serves_it(env):
    put_all(env, self_age=600, courses_age=600)
    assert state_of(env)["state"] == "ready"
    assert not mcp_result(env).get("isError")


def test_a_users_self_the_school_refuses_is_not_ready(env):
    put_all(env, self_age=600, courses_age=600, self_status=401, courses_status=401)
    body = state_of(env)
    assert body["state"] == "revoked"
    assert "blocks" in body["summary"] or "refus" in body["summary"].lower()
    assert body["action"]["url"].endswith("/account/browser-extension")
    result = mcp_result(env)
    assert result["isError"] is True and "SOURCE_UNAVAILABLE" in text_of(result)


def test_a_courses_list_the_school_refuses_is_not_ready(env):
    put_all(env, self_age=600, courses_age=600, courses_status=403)
    assert state_of(env)["state"] != "ready"
    assert mcp_result(env)["isError"] is True


def test_one_fresh_row_does_not_hide_a_stale_courses_row(env):
    stale = setting(env, "browser_sync.fresh_hours") * HOUR + 2 * HOUR
    put_all(env, self_age=600, courses_age=stale)
    body = state_of(env)
    assert body["state"] == "degraded"
    assert "browser sync" in body["summary"].lower() and "ago" in body["summary"]
    result = mcp_result(env)
    assert not result.get("isError")
    assert "may be out of date" in text_of(result)  # /mcp warns about the same data


def test_a_courses_row_past_the_maximum_age_is_expired(env):
    too_old = setting(env, "browser_sync.max_age_days") * DAY + HOUR
    put_all(env, self_age=600, courses_age=too_old)
    body = state_of(env)
    assert body["state"] == "expired"
    assert body["action"]["url"].endswith("/account/browser-extension")
    result = mcp_result(env)
    assert result["isError"] is True and "days old" in text_of(result)


def test_a_users_self_row_past_the_maximum_age_is_expired(env):
    too_old = setting(env, "browser_sync.max_age_days") * DAY + HOUR
    put_all(env, self_age=too_old, courses_age=600)
    assert state_of(env)["state"] == "expired"


def test_a_leftover_row_outside_the_plan_proves_nothing(env):
    too_old = setting(env, "browser_sync.max_age_days") * DAY + HOUR
    put_all(env, self_age=too_old, courses_age=too_old)
    binding = env.rig.store.active_binding(env.h.stack.account_of(User("A", OID_A)))
    assert binding is not None
    # A fresh row whose key no plan holds (an old course's resource, say).
    item = SnapshotItem(
        "/users/self?leftover=1",
        "/users/self",
        {"leftover": ["1"]},
        int(env.h.now) - 60,
        200,
        ME,
    )
    with env.h.store.database.write() as conn:
        conn.execute(insert(s.browser_snapshots).values(**env.rig.store._seal(binding.id, item)))
    assert any(r.key == "/users/self?leftover=1" for r in env.rig.store.resources(binding.id))
    assert state_of(env)["state"] == "expired"
    assert mcp_result(env)["isError"] is True


def test_nothing_uploaded_is_needs_setup(env):
    body = state_of(env)
    assert body["state"] == "needs_setup"
    assert mcp_result(env)["isError"] is True


def test_the_two_core_resources_only_come_from_the_binding_rows(env):
    # Courses present but /users/self never synced: /mcp cannot show the profile either.
    put(env, [res("/courses", BARE, [COURSE]), res("/courses", COURSES, [COURSE])], 600)
    assert state_of(env)["state"] == "needs_setup"
