"""A fake Canvas for the browser sync demo: a school that disables access tokens.

- Any request with an ``Authorization`` header gets 401, like a school that
  blocks personal access tokens.
- ``/login`` sets a session cookie; ``/api/v1/*`` answers only with that cookie,
  prefixes JSON with ``while(1);`` like Canvas does for session requests, and
  paginates with ``Link`` headers.

Run: python fake_canvas.py --port 8443 --cert cert.pem --key key.pem
"""
from __future__ import annotations

import argparse
import json
import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

SESSIONS: set[str] = set()
REQUEST_LOG: list[dict[str, object]] = []
NOW = datetime.now(UTC).replace(microsecond=0)
USER_ID = 4242


def iso(days: float) -> str:
    return (NOW + timedelta(days=days)).isoformat().replace("+00:00", "Z")


COURSES = [
    {"id": 101, "name": "Data Structures", "course_code": "CS 201", "workflow_state": "available",
     "enrollment_term_id": 1, "term": {"id": 1, "name": "Fall 2026"},
     "enrollments": [{"type": "student", "role": "StudentEnrollment", "enrollment_state": "active",
                      "user_id": USER_ID, "computed_current_score": 91.5, "computed_current_grade": "A-",
                      "computed_final_score": 88.0, "computed_final_grade": "B+"}]},
    {"id": 102, "name": "Linear Algebra", "course_code": "MATH 221", "workflow_state": "available",
     "enrollment_term_id": 1, "term": {"id": 1, "name": "Fall 2026"},
     "enrollments": [{"type": "student", "role": "StudentEnrollment", "enrollment_state": "active",
                      "user_id": USER_ID, "computed_current_score": 84.0, "computed_current_grade": "B",
                      "computed_final_score": 80.0, "computed_final_grade": "B-"}]},
]


def assignment(course_id: int, aid: int, name: str, due_days: float, points: float,
               score: float | None) -> dict[str, object]:
    submitted = score is not None
    return {
        "id": aid, "course_id": course_id, "name": name, "due_at": iso(due_days),
        "points_possible": points, "assignment_group_id": course_id * 10,
        "submission_types": ["online_upload"], "published": True,
        "html_url": f"/courses/{course_id}/assignments/{aid}",
        "submission": {"assignment_id": aid, "user_id": USER_ID, "score": score,
                       "grade": None if score is None else str(score),
                       "submitted_at": iso(due_days - 1) if submitted else None,
                       "workflow_state": "graded" if submitted else "unsubmitted",
                       "late": False, "missing": False},
    }


ASSIGNMENTS = {
    101: [assignment(101, 1001, "Linked lists lab", -10, 20, 19),
          assignment(101, 1002, "Hash table project", 3, 50, None),
          assignment(101, 1003, "Midterm review quiz", 9, 10, None)],
    102: [assignment(102, 2001, "Problem set 4", -3, 30, 25),
          assignment(102, 2002, "Problem set 5", 5, 30, None)],
}


def planner_items() -> list[dict[str, object]]:
    items = []
    for course_id, rows in ASSIGNMENTS.items():
        for a in rows:
            items.append({
                "context_type": "Course", "course_id": course_id, "plannable_id": a["id"],
                "plannable_type": "assignment", "plannable_date": a["due_at"],
                "plannable": {"id": a["id"], "title": a["name"], "due_at": a["due_at"],
                              "points_possible": a["points_possible"]},
                "submissions": {"submitted": a["submission"]["submitted_at"] is not None,  # type: ignore[index]
                                "graded": a["submission"]["score"] is not None},  # type: ignore[index]
                "html_url": a["html_url"], "context_name": next(c["name"] for c in COURSES if c["id"] == course_id),
            })
    return sorted(items, key=lambda i: str(i["plannable_date"]))


ANNOUNCEMENTS = [
    {"id": 501, "title": "Midterm room change", "message": "<p>The midterm is in room 120.</p>",
     "posted_at": iso(-2), "context_code": "course_101", "html_url": "/courses/101/discussion_topics/501"},
    {"id": 502, "title": "Office hours moved", "message": "<p>Thursday 3pm this week.</p>",
     "posted_at": iso(-1), "context_code": "course_102", "html_url": "/courses/102/discussion_topics/502"},
]

CALENDAR = [
    {"id": 701, "title": "CS 201 lecture", "start_at": iso(1), "end_at": iso(1.05),
     "context_code": "course_101", "type": "event", "location_name": "Hall A"},
    {"id": 702, "title": "MATH 221 recitation", "start_at": iso(2), "end_at": iso(2.05),
     "context_code": "course_102", "type": "event", "location_name": "Room 9"},
]


def assignment_groups(course_id: int) -> list[dict[str, object]]:
    return [{"id": course_id * 10, "name": "Homework", "group_weight": 100, "position": 1,
             "rules": {}, "assignments": ASSIGNMENTS[course_id]}]


def modules(course_id: int) -> list[dict[str, object]]:
    return [{"id": course_id * 100 + 1, "name": "Week 1", "position": 1, "state": "completed",
             "items": [{"id": 1, "title": "Syllabus", "type": "Page", "position": 1}]}]


def resolve(path: str) -> object | None:
    parts = [p for p in path.split("/") if p]
    if parts == ["users", "self"]:
        return {"id": USER_ID, "name": "Demo Student", "short_name": "Demo", "sortable_name": "Student, Demo"}
    if parts == ["users", "self", "profile"]:
        return {"id": USER_ID, "name": "Demo Student", "primary_email": "demo@example.edu",
                "login_id": "demo", "time_zone": "America/Los_Angeles", "locale": "en"}
    if parts in (["users", "self", "todo"],):
        return [{"type": "submitting", "assignment": a, "context_type": "Course", "course_id": a["course_id"]}
                for rows in ASSIGNMENTS.values() for a in rows if a["submission"]["score"] is None]  # type: ignore[index]
    if parts == ["users", "self", "groups"]:
        return []
    if parts == ["users", "self", "activity_stream"]:
        return [{"id": 9001, "type": "Announcement", "title": a["title"], "created_at": a["posted_at"],
                 "context_type": "Course", "course_id": int(str(a["context_code"]).split("_")[1])}
                for a in ANNOUNCEMENTS]
    if parts == ["users", "self", "activity_stream", "summary"]:
        return [{"type": "Announcement", "count": 2, "unread_count": 1}]
    if parts == ["courses"]:
        return COURSES
    if len(parts) >= 2 and parts[0] == "courses" and parts[1].isdigit():
        cid = int(parts[1])
        course = next((c for c in COURSES if c["id"] == cid), None)
        if course is None:
            return None
        rest = parts[2:]
        if not rest:
            return course
        if rest == ["assignments"]:
            return ASSIGNMENTS[cid]
        if len(rest) == 2 and rest[0] == "assignments" and rest[1].isdigit():
            return next((a for a in ASSIGNMENTS[cid] if a["id"] == int(rest[1])), None)
        if rest == ["assignment_groups"]:
            return assignment_groups(cid)
        if rest == ["modules"]:
            return modules(cid)
        if rest == ["quizzes"]:
            return [{"id": cid * 1000 + 1, "title": "Weekly quiz", "due_at": iso(6), "points_possible": 5}]
        if rest == ["enrollments"]:
            return course["enrollments"]
        if rest == ["discussion_topics"]:
            return [a for a in ANNOUNCEMENTS if a["context_code"] == f"course_{cid}"]
        if rest == ["front_page"]:
            return {"title": "Welcome", "body": "<p>Welcome to the course.</p>", "url": "welcome"}
        return None
    if parts == ["planner", "items"]:
        return planner_items()
    if parts == ["planner_notes"]:
        return []
    if parts == ["calendar_events"]:
        return CALENDAR
    if parts == ["announcements"]:
        return ANNOUNCEMENTS
    return None


def session_of(request: Request) -> str | None:
    value = request.cookies.get("canvas_session")
    return value if value in SESSIONS else None


async def login_form(request: Request) -> Response:
    return HTMLResponse(
        "<!doctype html><title>Log In to Canvas</title><h1>Fake Canvas</h1>"
        "<form method=post action=/login><input name=username value=demo>"
        "<input name=password type=password value=demo><button id=login>Log in</button></form>"
    )


async def login(request: Request) -> Response:
    token = secrets.token_urlsafe(24)
    SESSIONS.add(token)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie("canvas_session", token, httponly=True, secure=True, samesite="lax")
    return response


async def logout(request: Request) -> Response:
    SESSIONS.discard(request.cookies.get("canvas_session", ""))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("canvas_session")
    return response


async def dashboard(request: Request) -> Response:
    if session_of(request) is None:
        return RedirectResponse("/login", status_code=302)
    return HTMLResponse("<!doctype html><title>Dashboard</title><h1>Dashboard</h1><p>Signed in as Demo Student.</p>")


async def api(request: Request) -> Response:
    path = "/" + request.path_params["path"]
    entry = {"method": request.method, "path": path, "auth_header": "authorization" in request.headers,
             "session": session_of(request) is not None}
    REQUEST_LOG.append(entry)
    if "authorization" in request.headers:
        return JSONResponse({"errors": [{"message": "Personal access tokens are disabled at this school"}]}, 401)
    if session_of(request) is None:
        return JSONResponse({"status": "unauthenticated", "errors": [{"message": "user authorization required"}]}, 401)
    if request.method != "GET":
        return JSONResponse({"errors": [{"message": "demo is read-only"}]}, 405)
    data = resolve(path)
    if data is None:
        return JSONResponse({"errors": [{"message": "The specified resource does not exist."}]}, 404)
    headers: dict[str, str] = {}
    if isinstance(data, list):
        per_page = max(1, min(int(request.query_params.get("per_page", 10)), 100))
        page = max(1, int(request.query_params.get("page", 1)))
        chunk = data[(page - 1) * per_page: page * per_page]
        if page * per_page < len(data):
            query = [(k, v) for k, v in request.query_params.multi_items() if k != "page"]
            query.append(("page", str(page + 1)))
            next_url = f"{request.url.scheme}://{request.url.netloc}{request.url.path}?{urlencode(query)}"
            headers["Link"] = f'<{next_url}>; rel="next"'
        data = chunk
    body = "while(1);" + json.dumps(data)
    return Response(body, media_type="application/json; charset=utf-8", headers=headers)


async def request_log(request: Request) -> Response:
    return JSONResponse(REQUEST_LOG)


app = Starlette(routes=[
    Route("/", dashboard),
    Route("/login", login_form, methods=["GET"]),
    Route("/login", login, methods=["POST"]),
    Route("/logout", logout),
    Route("/__demo/requests", request_log),
    Route("/api/v1/{path:path}", api, methods=["GET", "POST", "PUT", "DELETE"]),
])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port, ssl_certfile=args.cert, ssl_keyfile=args.key,
                log_level="warning")
