"""The server-defined list of Canvas reads the browser extension performs, and upload validation.

The plan is derived from what the student read tools request, so that the normal
call of each tool can be answered from the snapshots (``tests/selfhost/
test_browser_sync_coverage.py`` runs the tools against snapshots built from this
plan and fails on any miss). Every path fits the extension's own allowlist.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from ..browser_source import WINDOW_PARAMS, canonical_query, parse_when

PLAN_VERSION = 1
SCHEMA_VERSION = 1
MAX_PAGES = 50
WINDOW_PAST_DAYS = 60
WINDOW_FUTURE_DAYS = 120
#: The longest date window an upload may carry (plan window plus slack).
MAX_WINDOW_DAYS = 400
MAX_RESOURCES_PER_UPLOAD = 600
#: Distinct courses one binding may name; every one adds a dozen planned resources.
MAX_COURSES_PER_BINDING = 200
#: A course list longer than this is refused without reading it.
MAX_COURSE_LIST_LENGTH = 1000

#: The extension enforces this allowlist regardless of the plan (see the design doc).
ALLOWED_PATH = re.compile(
    r"^/(users/self(/(profile|todo|groups|activity_stream(/summary)?))?"
    r"|courses(/\d+(/(assignments|assignment_groups|modules|quizzes|front_page|discussion_topics))?)?"
    r"|planner/items|planner_notes|calendar_events|announcements)$"
)

COURSE_PLACEHOLDER = "{course_id}"
USER_PLACEHOLDER = "{user_id}"

_COURSE_INCLUDES = [
    "current_grading_period_scores",
    "grading_scheme",
    "restrict_quantitative_data",
    "syllabus_body",
    "teachers",
    "term",
    "total_scores",
    "total_students",
]

#: ``(path, query, paginate, per_course)``; the window placeholder is filled per request.
_WINDOW = {"start_date": "{start}", "end_date": "{end}"}


class Resource:
    def __init__(
        self,
        path: str,
        query: Mapping[str, str | Sequence[str]] | None = None,
        *,
        paginate: bool = False,
        per_course: bool = False,
        needs_user: bool = False,
    ) -> None:
        self.path = path
        self.query = {k: _as_list(v) for k, v in (query or {}).items()}
        self.paginate = paginate
        self.per_course = per_course
        self.needs_user = needs_user

    @property
    def windowed(self) -> bool:
        return "start_date" in self.query


def _as_list(value: str | Sequence[str]) -> list[str]:
    return [value] if isinstance(value, str) else [str(v) for v in value]


_EVENT_EXCLUDES = ["child_events"]

RESOURCES: tuple[Resource, ...] = (
    Resource("/users/self"),
    Resource("/users/self/profile"),
    Resource("/users/self/todo", paginate=True),
    Resource("/users/self/groups", paginate=True),
    Resource(
        "/users/self/activity_stream",
        {"only_active_courses": "true"},
        paginate=True,
    ),
    Resource(
        "/users/self/activity_stream/summary",
        {"only_active_courses": "true"},
        paginate=True,
    ),
    # The course lists come first: the extension expands {course_id} from them.
    Resource("/courses", {"include[]": _COURSE_INCLUDES}, paginate=True),
    Resource(
        "/courses",
        {"enrollment_state": "active", "include[]": _COURSE_INCLUDES},
        paginate=True,
    ),
    Resource(
        "/courses",
        {
            "enrollment_state": "active",
            "include[]": _COURSE_INCLUDES,
            "state[]": ["available"],
        },
        paginate=True,
    ),
    Resource(
        "/courses",
        {
            "enrollment_state": "active",
            "include[]": ["term"],
            "state[]": ["available", "unpublished"],
        },
        paginate=True,
    ),
    Resource("/planner/items", _WINDOW, paginate=True),
    Resource("/planner/items", {"filter": "incomplete_items"}, paginate=True),
    Resource("/planner_notes", _WINDOW, paginate=True),
    Resource(
        "/calendar_events",
        {
            "type": "event",
            "context_codes[]": ["user_" + USER_PLACEHOLDER],
            "excludes[]": _EVENT_EXCLUDES,
            **_WINDOW,
        },
        paginate=True,
        needs_user=True,
    ),
    Resource(
        "/calendar_events",
        {
            "type": "assignment",
            "context_codes[]": ["user_" + USER_PLACEHOLDER],
            "excludes[]": _EVENT_EXCLUDES,
            **_WINDOW,
        },
        paginate=True,
        needs_user=True,
    ),
    Resource(
        "/courses/{course_id}/assignments",
        {"include[]": ["all_dates", "checkpoints", "submission"]},
        paginate=True,
        per_course=True,
    ),
    Resource(
        "/courses/{course_id}/assignment_groups",
        {"include[]": ["assignments", "submission"]},
        paginate=True,
        per_course=True,
    ),
    Resource("/courses/{course_id}/quizzes", paginate=True, per_course=True),
    Resource(
        "/courses/{course_id}/modules",
        {"include[]": ["items"]},
        paginate=True,
        per_course=True,
    ),
    Resource("/courses/{course_id}/front_page", per_course=True),
    Resource("/courses/{course_id}/discussion_topics", paginate=True, per_course=True),
    Resource(
        "/courses/{course_id}/discussion_topics",
        {"only_announcements": "true"},
        paginate=True,
        per_course=True,
    ),
    Resource(
        "/announcements",
        {
            "context_codes[]": ["course_" + COURSE_PLACEHOLDER],
            "active_only": "true",
            **_WINDOW,
        },
        paginate=True,
        per_course=True,
    ),
    Resource(
        "/calendar_events",
        {
            "type": "event",
            "context_codes[]": ["course_" + COURSE_PLACEHOLDER],
            "excludes[]": _EVENT_EXCLUDES,
            **_WINDOW,
        },
        paginate=True,
        per_course=True,
    ),
    Resource(
        "/calendar_events",
        {
            "type": "assignment",
            "context_codes[]": ["course_" + COURSE_PLACEHOLDER],
            "excludes[]": _EVENT_EXCLUDES,
            **_WINDOW,
        },
        paginate=True,
        per_course=True,
    ),
)


def _fill(value: str, *, course: str | None, user: str | None) -> str:
    if course is not None:
        value = value.replace(COURSE_PLACEHOLDER, course)
    if user is not None:
        value = value.replace(USER_PLACEHOLDER, user)
    return value


def resource_key(path: str, query: Mapping[str, Sequence[str]]) -> str:
    """The identity of a resource: its path and its query without the date window.

    The window moves every day; the newest upload of a resource replaces the
    previous one, and the window it covers is stored inside the sealed snapshot.
    """
    rest = {k: v for k, v in query.items() if k not in WINDOW_PARAMS}
    text = canonical_query(rest)
    return f"{path}?{text}" if text else path


def window_bounds(now: float) -> tuple[str, str]:
    day = dt.datetime.fromtimestamp(now, tz=dt.UTC).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    start = day - dt.timedelta(days=WINDOW_PAST_DAYS)
    end = day + dt.timedelta(days=WINDOW_FUTURE_DAYS)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return start.strftime(fmt), end.strftime(fmt)


def build_plan(
    *, canvas_host: str | None, canvas_user_id: str | None, now: float
) -> dict[str, Any]:
    """The plan document served to the extension."""
    start, end = window_bounds(now)
    resources: list[dict[str, Any]] = []
    for resource in RESOURCES:
        if resource.needs_user and canvas_user_id is None:
            # The personal calendar needs the student's id, known after the first upload.
            continue
        query: dict[str, Any] = {}
        for key, values in resource.query.items():
            filled = [
                _fill(v, course=None, user=canvas_user_id)
                .replace("{start}", start)
                .replace("{end}", end)
                for v in values
            ]
            query[key] = filled if key.endswith("[]") else filled[0]
        entry: dict[str, Any] = {"path": resource.path, "query": query}
        if resource.paginate:
            entry["paginate"] = True
        if resource.per_course:
            entry["perCourse"] = True
        resources.append(entry)
    return {
        "planVersion": PLAN_VERSION,
        "canvasHost": canvas_host,
        "maxPages": MAX_PAGES,
        "resources": resources,
    }


def expected_resources(
    course_ids: Iterable[str], canvas_user_id: str | None
) -> dict[str, bool]:
    """Every acceptable resource key after expansion, mapped to "carries a date window"."""
    expected: dict[str, bool] = {}
    for resource in RESOURCES:
        if resource.needs_user and canvas_user_id is None:
            continue
        courses: Iterable[str | None] = course_ids if resource.per_course else (None,)
        for course in courses:
            path = _fill(resource.path, course=course, user=canvas_user_id)
            query = {
                key: [_fill(v, course=course, user=canvas_user_id) for v in values]
                for key, values in resource.query.items()
                if key not in WINDOW_PARAMS
            }
            expected[resource_key(path, query)] = resource.windowed
    return expected


def normalize_upload_query(raw: object) -> dict[str, list[str]] | None:
    """An uploaded ``query`` as ``{key: [values]}``, or None when it is not valid."""
    if not isinstance(raw, dict) or len(raw) > 16:
        return None
    out: dict[str, list[str]] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\[\])?", key):
            return None
        values = value if isinstance(value, list) else [value]
        if len(values) > 64 or not all(
            isinstance(v, str) and 0 < len(v) <= 256 and "\x00" not in v for v in values
        ):
            return None
        out[key] = list(values)
    return out


def valid_window(query: Mapping[str, Sequence[str]]) -> bool:
    """Both bounds present, parseable, in order, and no longer than the plan allows."""
    starts, ends = query.get("start_date"), query.get("end_date")
    if not starts or not ends or len(starts) != 1 or len(ends) != 1:
        return False
    start = parse_when(starts[0], end=False, zone=dt.UTC)
    end = parse_when(ends[0], end=True, zone=dt.UTC)
    if start is None or end is None or end < start:
        return False
    return (end - start).days <= MAX_WINDOW_DAYS
