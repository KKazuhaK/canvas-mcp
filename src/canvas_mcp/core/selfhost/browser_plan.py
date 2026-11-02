"""The server-defined list of Canvas reads the browser extension performs, and upload validation.

The plan is derived from what the student read tools request, so that the normal
call of each tool can be answered from the snapshots (``tests/selfhost/
test_browser_sync_coverage.py`` runs the tools against snapshots built from this
plan and fails on any miss). Every path fits the extension's own allowlist.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from typing import Any

from ..browser_source import WINDOW_PARAMS, canonical_query, parse_when

PLAN_VERSION = 2
#: Upload ``planVersion`` values the server still understands.
ACCEPTED_PLAN_VERSIONS = frozenset({1, 2})
COLD_INTERVAL_HOURS = 12
SCHEMA_VERSION = 1
MAX_PAGES = 50
WINDOW_PAST_DAYS = 30
WINDOW_FUTURE_DAYS = 90
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

#: What each ``/courses`` list carries is what the tools ask of that exact query:
#: the unfiltered list resolves course codes (no includes); the plain active list
#: serves the grade tools and, by id, ``/courses/{id}`` for the syllabus and the
#: grading fields (the heavy ``syllabus_body`` lives only here); ``list_courses``
#: asks teachers, term and the student count on ``state[]=available``;
#: ``get_my_enrollments`` asks only the term.
_GRADE_INCLUDES = [
    "current_grading_period_scores",
    "grading_scheme",
    "restrict_quantitative_data",
    "syllabus_body",
    "total_scores",
]
_LISTING_INCLUDES = ["teachers", "term", "total_students"]

_WINDOW = {"start_date": "{start}", "end_date": "{end}"}

HOT = "hot"
COLD = "cold"
EACH_COURSE = "eachCourse"
COURSE_LIST = "courseList"
#: Canvas caps ``context_codes[]`` on the calendar at ten.
CONTEXT_CHUNK = 10
#: How often the large, slow-changing hot feeds are refetched.
FEED_REFRESH_MINUTES = 60
CALENDAR_REFRESH_MINUTES = 30


class Resource:
    def __init__(
        self,
        path: str,
        query: Mapping[str, str | Sequence[str]] | None = None,
        *,
        tier: str = HOT,
        paginate: bool = False,
        expand: str | None = None,
        chunk: int | None = None,
        needs_user: bool = False,
        course_source: bool = False,
        refresh_minutes: int | None = None,
    ) -> None:
        self.path = path
        self.query = {k: _as_list(v) for k, v in (query or {}).items()}
        self.tier = tier
        self.paginate = paginate
        #: ``eachCourse``: one resource per course. ``courseList``: a ``{course_id}``
        #: query element becomes one element per course, ``chunk`` courses a request.
        self.expand = expand
        self.chunk = chunk
        self.needs_user = needs_user
        #: Its course ids drive the per-course expansion (the active enrollments only).
        self.course_source = course_source
        #: A hot resource is refetched only when its last successful fetch is older
        #: than this many minutes (None: on every sync).
        self.refresh_minutes = refresh_minutes

    @property
    def windowed(self) -> bool:
        return "start_date" in self.query


def _as_list(value: str | Sequence[str]) -> list[str]:
    return [value] if isinstance(value, str) else [str(v) for v in value]


_EVENT_EXCLUDES = ["child_events"]


def _course_events(kind: str, codes: list[str], **extra: Any) -> Resource:
    # An assignment's calendar entry carries the assignment's whole description (the
    # bulk of a calendar chunk). Its id is not numeric, so no tool reads one by id,
    # and the list tools exclude descriptions by default: leave them out here.
    excludes = [*_EVENT_EXCLUDES, "description"] if kind == "assignment" else _EVENT_EXCLUDES
    return Resource(
        "/calendar_events",
        {"type": kind, "context_codes[]": codes, "excludes[]": excludes, **_WINDOW},
        paginate=True,
        # Events change rarely and only in Canvas itself (writes are refused here), and
        # due dates are also in the planner, which refreshes on every sync. The
        # assignment entries nest the whole assignment object, which the tool reads
        # (`Assignment ID`), so their content cannot be trimmed instead.
        refresh_minutes=CALENDAR_REFRESH_MINUTES,
        **extra,
    )


#: The plan, in the order the extension fetches it. Hot resources are fetched on every
#: sync; cold ones only when the extension's last fetch of that expanded key is older
#: than ``COLD_INTERVAL_HOURS``. The course lists come first: they drive the expansion.
RESOURCES: tuple[Resource, ...] = (
    Resource("/users/self"),
    Resource("/users/self/profile"),
    Resource("/users/self/todo", paginate=True),
    Resource("/users/self/groups", paginate=True),
    Resource(
        "/users/self/activity_stream",
        {"only_active_courses": "true"},
        paginate=True,
        refresh_minutes=FEED_REFRESH_MINUTES,
    ),
    Resource(
        "/users/self/activity_stream/summary",
        {"only_active_courses": "true"},
        paginate=True,
        refresh_minutes=FEED_REFRESH_MINUTES,
    ),
    Resource("/courses", paginate=True),
    Resource(
        "/courses",
        {"enrollment_state": "active", "include[]": _GRADE_INCLUDES},
        paginate=True,
        course_source=True,
    ),
    Resource(
        "/courses",
        {
            "enrollment_state": "active",
            "include[]": _LISTING_INCLUDES,
            "state[]": ["available"],
        },
        paginate=True,
        course_source=True,
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
    _course_events("event", ["user_" + USER_PLACEHOLDER], needs_user=True),
    _course_events("assignment", ["user_" + USER_PLACEHOLDER], needs_user=True),
    # Aggregated over all courses: one request per ten courses, whatever their number.
    Resource(
        "/announcements",
        {
            "context_codes[]": ["course_" + COURSE_PLACEHOLDER],
            "active_only": "true",
            **_WINDOW,
        },
        paginate=True,
        expand=COURSE_LIST,
        chunk=CONTEXT_CHUNK,
    ),
    _course_events(
        "event", ["course_" + COURSE_PLACEHOLDER], expand=COURSE_LIST, chunk=CONTEXT_CHUNK
    ),
    _course_events(
        "assignment", ["course_" + COURSE_PLACEHOLDER], expand=COURSE_LIST, chunk=CONTEXT_CHUNK
    ),
    # Per-course content: refreshed at most every ``COLD_INTERVAL_HOURS``.
    Resource(
        "/courses/{course_id}/assignments",
        {"include[]": ["all_dates", "checkpoints", "submission"]},
        tier=COLD,
        paginate=True,
        expand=EACH_COURSE,
    ),
    Resource(
        "/courses/{course_id}/assignment_groups",
        {"include[]": ["assignments", "submission"]},
        tier=COLD,
        paginate=True,
        expand=EACH_COURSE,
    ),
    Resource("/courses/{course_id}/quizzes", tier=COLD, paginate=True, expand=EACH_COURSE),
    Resource(
        "/courses/{course_id}/modules",
        {"include[]": ["items"]},
        tier=COLD,
        paginate=True,
        expand=EACH_COURSE,
    ),
    Resource("/courses/{course_id}/front_page", tier=COLD, expand=EACH_COURSE),
    Resource(
        "/courses/{course_id}/discussion_topics", tier=COLD, paginate=True, expand=EACH_COURSE
    ),
    Resource(
        "/courses/{course_id}/discussion_topics",
        {"only_announcements": "true"},
        tier=COLD,
        paginate=True,
        expand=EACH_COURSE,
    ),
)


#: The most groups one binding may have calendars planned for.
MAX_GROUPS = 200


def usable_course_ids(body: Any) -> set[str]:
    """Course ids of a course-source list that may expand the plan.

    An unpublished course is left out: its sub-resources are forbidden to a student,
    and Canvas rejects a whole ``/calendar_events`` chunk when any one code in it is
    forbidden. The one rule the extension mirrors: ``id`` is an integer and
    ``workflow_state`` is not ``"unpublished"``.
    """
    if not isinstance(body, list):
        return set()
    return {
        str(c["id"])
        for c in body
        if isinstance(c, dict)
        and isinstance(c.get("id"), int)
        and not isinstance(c.get("id"), bool)
        and c.get("workflow_state") != "unpublished"
    }


def group_ids_of(body: Any, course_ids: Collection[str]) -> list[str]:
    """Sorted distinct group ids calendars are planned for ([] when absurdly many).

    A group of a course counts only when that course expands the plan (``course_ids``):
    a group of an unpublished or concluded course is forbidden, and Canvas rejects a
    whole calendar chunk when one of its codes is. Groups of another context (an
    account) stay.
    """
    if not isinstance(body, list):
        return []
    allowed = set(course_ids)
    ids = {
        c["id"]
        for c in body
        if isinstance(c, dict)
        and isinstance(c.get("id"), int)
        and not isinstance(c.get("id"), bool)
        and (c.get("context_type") != "Course" or str(c.get("course_id")) in allowed)
    }
    return [str(i) for i in sorted(ids)] if len(ids) <= MAX_GROUPS else []


def group_calendar_resources(group_ids: Iterable[str]) -> list[Resource]:
    """Plain hot calendar resources with the concrete ``group_<id>`` codes, ten to a request."""
    ids = sorted_course_ids(group_ids)
    return [
        _course_events(kind, [f"group_{g}" for g in ids[start : start + CONTEXT_CHUNK]])
        for start in range(0, len(ids), CONTEXT_CHUNK)
        for kind in ("event", "assignment")
    ]


def course_source_keys() -> frozenset[str]:
    """Resource keys of the course lists that define the per-course expansion."""
    return frozenset(
        resource_key(r.path, r.query) for r in RESOURCES if r.course_source
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
    *,
    canvas_host: str | None,
    canvas_user_id: str | None,
    now: float,
    group_ids: Iterable[str] = (),
) -> dict[str, Any]:
    """The plan document served to the extension."""
    start, end = window_bounds(now)
    resources: list[dict[str, Any]] = []
    groups = group_calendar_resources(group_ids) if canvas_user_id is not None else []
    for resource in [*RESOURCES, *groups]:
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
        entry: dict[str, Any] = {"path": resource.path, "query": query, "tier": resource.tier}
        if resource.paginate:
            entry["paginate"] = True
        if resource.expand is not None:
            entry["expand"] = resource.expand
            if resource.expand == EACH_COURSE:
                # A v1 extension reads this flag (its `{course_id}` expansion); it does not
                # understand `courseList`, which it then rejects locally and visibly.
                entry["perCourse"] = True
        if resource.chunk is not None:
            entry["chunk"] = resource.chunk
        if resource.course_source:
            entry["courseSource"] = True
        if resource.refresh_minutes is not None:
            entry["refreshMinutes"] = resource.refresh_minutes
        resources.append(entry)
    return {
        "planVersion": PLAN_VERSION,
        "canvasHost": canvas_host,
        "maxPages": MAX_PAGES,
        "coldIntervalHours": COLD_INTERVAL_HOURS,
        "resources": resources,
    }


def sorted_course_ids(course_ids: Iterable[str]) -> list[str]:
    """Distinct course ids in ascending numeric order: the one order chunks are cut in."""
    return [str(i) for i in sorted({int(c) for c in course_ids if str(c).isdigit()})]


def expanded_resources(
    course_ids: Iterable[str],
    canvas_user_id: str | None,
    group_ids: Iterable[str] = (),
) -> list[tuple[Resource, str, dict[str, list[str]]]]:
    """Every concrete request of the plan, without date windows: ``(resource, path, query)``.

    ``eachCourse`` gives one request per course. ``courseList`` replaces the query
    element holding ``{course_id}`` with one element per course and cuts the sorted,
    de-duplicated ids into chunks of ``resource.chunk``, one request each. The
    extension does the same, so both sides agree on the chunks.
    """
    ids = sorted_course_ids(course_ids)
    out: list[tuple[Resource, str, dict[str, list[str]]]] = []
    groups = group_calendar_resources(group_ids) if canvas_user_id is not None else []
    for resource in [*RESOURCES, *groups]:
        if resource.needs_user and canvas_user_id is None:
            continue
        base = {
            key: values for key, values in resource.query.items() if key not in WINDOW_PARAMS
        }
        if resource.expand == EACH_COURSE:
            for course in ids:
                out.append(
                    (
                        resource,
                        _fill(resource.path, course=course, user=canvas_user_id),
                        {
                            k: [_fill(v, course=course, user=canvas_user_id) for v in vs]
                            for k, vs in base.items()
                        },
                    )
                )
        elif resource.expand == COURSE_LIST:
            size = resource.chunk or CONTEXT_CHUNK
            for start in range(0, len(ids), size):
                chunk = ids[start : start + size]
                query: dict[str, list[str]] = {}
                for key, values in base.items():
                    expanded: list[str] = []
                    for value in values:
                        if COURSE_PLACEHOLDER in value:
                            expanded.extend(value.replace(COURSE_PLACEHOLDER, c) for c in chunk)
                        else:
                            expanded.append(_fill(value, course=None, user=canvas_user_id))
                    query[key] = expanded
                out.append((resource, resource.path, query))
        else:
            out.append(
                (
                    resource,
                    _fill(resource.path, course=None, user=canvas_user_id),
                    {
                        k: [_fill(v, course=None, user=canvas_user_id) for v in vs]
                        for k, vs in base.items()
                    },
                )
            )
    return out


def expected_resources(
    course_ids: Iterable[str],
    canvas_user_id: str | None,
    group_ids: Iterable[str] = (),
) -> dict[str, bool]:
    """Every acceptable resource key after expansion, mapped to "carries a date window"."""
    return {
        resource_key(path, query): resource.windowed
        for resource, path, query in expanded_resources(course_ids, canvas_user_id, group_ids)
    }


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
