"""Answering Canvas reads from browser snapshots: matching rules and request wiring."""

from __future__ import annotations

import copy
from typing import Any
from unittest.mock import patch

import pytest

from canvas_mcp.core import client
from canvas_mcp.core.browser_source import (
    BrowserMiss,
    BrowserSnapshot,
    answer_get,
    capture_freshness,
    freshness_note,
)
from canvas_mcp.core.credentials import (
    BrowserSource,
    RequestCredentials,
    clear_http_request_context,
    get_browser_source,
    set_browser_source,
    set_http_request_active,
    set_request_credentials,
)
from canvas_mcp.core.error_codes import (
    PERMISSION_DENIED,
    SOURCE_UNAVAILABLE,
    capture_failures,
)

NOW = 1_800_000_000
DAY = 86400
WINDOW = {"start_date": ["2026-09-01T00:00:00Z"], "end_date": ["2027-03-01T00:00:00Z"]}


def snap(
    path: str,
    body: Any,
    query: dict[str, list[str]] | None = None,
    *,
    status: int = 200,
    age: int = 60,
) -> BrowserSnapshot:
    return BrowserSnapshot(
        path=path,
        query=query or {},
        captured_at=NOW - age,
        status=status,
        body=body if status == 200 else None,
    )


def source(
    *snapshots: BrowserSnapshot, max_age_days: int = 14, zone: str | None = "UTC"
) -> BrowserSource:
    """A source over ``snapshots``; ``zone`` is the time zone of the synced profile."""
    everything = list(snapshots)
    if zone is not None:
        everything.append(snap("/users/self/profile", {"id": 1, "time_zone": zone}))

    async def load(path: str) -> list[BrowserSnapshot]:
        return [s for s in everything if s.path == path]

    return BrowserSource(
        binding_id="b1",
        canvas_host="canvas.example.edu",
        load=load,
        max_age_seconds=max_age_days * DAY,
    )


async def ask(
    src: BrowserSource, endpoint: str, params: dict[str, Any] | None = None
) -> Any:
    return await answer_get(src, endpoint, params, now=NOW)


async def miss(
    src: BrowserSource, endpoint: str, params: dict[str, Any] | None = None
) -> BrowserMiss:
    with pytest.raises(BrowserMiss) as caught:
        await ask(src, endpoint, params)
    return caught.value


# -- lists: path, paging, include, other parameters ---------------------------------------


async def test_exact_path_hit_ignores_paging_parameters():
    rows = [{"id": 1}, {"id": 2}]
    src = source(snap("/courses/5/quizzes", rows))
    got = await ask(src, "/courses/5/quizzes", {"per_page": 100, "page": 1})
    assert got == rows


async def test_the_answer_is_a_copy_the_caller_may_change():
    rows = [{"id": 1}]
    src = source(snap("/courses/5/quizzes", rows))
    got = await ask(src, "/courses/5/quizzes")
    got[0]["id"] = 99
    got.append({"id": 3})
    assert rows == [{"id": 1}]


async def test_include_may_be_any_subset_of_the_stored_include():
    src = source(
        snap("/courses/5/assignments", [{"id": 1}], {"include[]": ["all_dates", "submission"]})
    )
    assert await ask(src, "/courses/5/assignments", {"include[]": ["submission"]}) == [{"id": 1}]
    assert await ask(src, "/courses/5/assignments") == [{"id": 1}]
    refused = await miss(src, "/courses/5/assignments", {"include[]": ["submission", "rubric"]})
    assert refused.code == SOURCE_UNAVAILABLE and "not been synced" in refused.message


async def test_a_parameter_the_stored_copy_does_not_have_is_a_miss():
    src = source(snap("/courses/5/modules", [{"id": 1}]))
    assert (await miss(src, "/courses/5/modules", {"search_term": "week"})).code == SOURCE_UNAVAILABLE


async def test_a_filter_the_request_does_not_ask_for_is_a_miss():
    stored = snap("/courses", [{"id": 1}], {"enrollment_state": ["active"]})
    src = source(stored)
    assert await ask(src, "/courses", {"enrollment_state": "active"}) == [{"id": 1}]
    await miss(src, "/courses")
    await miss(src, "/courses", {"enrollment_state": "completed"})


async def test_booleans_compare_the_way_they_go_on_the_wire():
    src = source(snap("/users/self/activity_stream", [{"id": 1}], {"only_active_courses": ["true"]}))
    assert await ask(src, "/users/self/activity_stream", {"only_active_courses": True}) == [{"id": 1}]
    await miss(src, "/users/self/activity_stream", {"only_active_courses": False})


async def test_the_unknown_path_is_a_miss_with_the_not_synced_message():
    err = await miss(source(), "/courses/9/quizzes")
    assert err.code == SOURCE_UNAVAILABLE
    assert "not been synced by the browser extension" in err.message


# -- date windows ----------------------------------------------------------------------------


def planner(*dates: str) -> list[dict[str, Any]]:
    return [{"id": i, "plannable_date": d} for i, d in enumerate(dates, 1)]


async def test_a_covered_window_is_filtered_locally():
    items = planner("2026-08-30T10:00:00Z", "2026-11-05T10:00:00Z", "2026-11-20T10:00:00Z", "2027-04-01T10:00:00Z")
    src = source(snap("/planner/items", items, dict(WINDOW)))
    got = await ask(
        src,
        "/planner/items",
        {"start_date": "2026-11-01T00:00:00Z", "end_date": "2026-11-10T00:00:00Z"},
    )
    assert [i["id"] for i in got] == [2]


async def test_date_only_bounds_cover_the_whole_last_day():
    items = planner("2026-11-10T23:30:00Z", "2026-11-11T00:30:00Z")
    src = source(snap("/planner/items", items, dict(WINDOW)))
    got = await ask(src, "/planner/items", {"start_date": "2026-11-10", "end_date": "2026-11-10"})
    assert [i["id"] for i in got] == [1]


async def test_a_window_outside_the_stored_window_is_a_miss():
    src = source(snap("/planner/items", planner("2026-11-05T10:00:00Z"), dict(WINDOW)))
    await miss(src, "/planner/items", {"start_date": "2026-08-01", "end_date": "2026-09-30"})
    await miss(src, "/planner/items", {"start_date": "2026-10-01", "end_date": "2027-06-01"})


async def test_a_request_without_a_window_is_not_answered_from_a_windowed_copy():
    src = source(snap("/planner/items", planner("2026-11-05T10:00:00Z"), dict(WINDOW)))
    await miss(src, "/planner/items")
    await miss(src, "/planner/items", {"start_date": "2026-11-01"})


async def test_garbage_dates_are_a_miss_not_an_error():
    src = source(snap("/planner/items", planner("2026-11-05T10:00:00Z"), dict(WINDOW)))
    await miss(src, "/planner/items", {"start_date": "soon", "end_date": "later"})


async def test_calendar_events_overlap_the_window():
    events = [
        {"id": 1, "context_code": "course_5", "start_at": "2026-10-30T09:00:00Z", "end_at": "2026-11-02T09:00:00Z"},
        {"id": 2, "context_code": "course_5", "start_at": "2026-12-30T09:00:00Z", "end_at": "2026-12-30T10:00:00Z"},
    ]
    src = source(
        snap(
            "/calendar_events",
            events,
            {"type": ["event"], "context_codes[]": ["course_5"], **WINDOW},
        )
    )
    got = await ask(
        src,
        "/calendar_events",
        {
            "type": "event",
            "context_codes[]": ["course_5"],
            "start_date": "2026-11-01",
            "end_date": "2026-11-07",
        },
    )
    assert [e["id"] for e in got] == [1]


# -- date-only bounds are days in the student's zone -------------------------------------------


def notes() -> list[dict[str, Any]]:
    return [
        {"id": 1, "todo_date": "2026-11-04T02:00:00Z"},  # Nov 3, 6pm in Pacific time
        {"id": 2, "todo_date": "2026-11-03T05:00:00Z"},  # Nov 2, 9pm in Pacific time
        {"id": 3, "todo_date": "2026-11-04T09:00:00Z"},  # Nov 4, 1am in Pacific time
    ]


DAY_3 = {"start_date": "2026-11-03", "end_date": "2026-11-03"}


async def test_a_date_only_day_is_the_students_day_not_the_utc_day():
    pacific = source(snap("/planner_notes", notes(), dict(WINDOW)), zone="America/Los_Angeles")
    got = await ask(pacific, "/planner_notes", DAY_3)
    assert [n["id"] for n in got] == [1]
    utc = source(snap("/planner_notes", notes(), dict(WINDOW)), zone="UTC")
    assert [n["id"] for n in await ask(utc, "/planner_notes", DAY_3)] == [2]
    tokyo = source(snap("/planner_notes", notes(), dict(WINDOW)), zone="Asia/Tokyo")
    assert [n["id"] for n in await ask(tokyo, "/planner_notes", DAY_3)] == [2]


async def test_a_date_only_end_covers_the_whole_local_day_and_no_more():
    items = [
        {"id": 1, "todo_date": "2026-11-04T07:59:59Z"},  # last second of Nov 3, Pacific
        {"id": 2, "todo_date": "2026-11-04T08:00:00Z"},  # first second of Nov 4, Pacific
    ]
    src = source(snap("/planner_notes", items, dict(WINDOW)), zone="America/Los_Angeles")
    got = await ask(src, "/planner_notes", DAY_3)
    assert [n["id"] for n in got] == [1]


async def test_without_a_known_zone_a_date_only_bound_is_a_miss(monkeypatch):
    monkeypatch.setenv("TIMEZONE", "UTC")
    from canvas_mcp.core.config import reset_config

    reset_config()
    stored = snap("/planner_notes", notes(), dict(WINDOW))
    for src in (
        source(stored, zone=None),  # no profile synced
        source(stored, zone="Not/AZone"),  # a name that is no zone
        source(stored, zone=""),
    ):
        assert (await miss(src, "/planner_notes", DAY_3)).code == SOURCE_UNAVAILABLE
    # A bound with its own offset needs no zone.
    got = await ask(
        source(stored, zone=None),
        "/planner_notes",
        {"start_date": "2026-11-03T08:00:00Z", "end_date": "2026-11-04T07:59:59Z"},
    )
    assert [n["id"] for n in got] == [1]


async def test_the_servers_timezone_stands_in_when_the_profile_has_none(monkeypatch):
    monkeypatch.setenv("TIMEZONE", "America/Los_Angeles")
    from canvas_mcp.core.config import reset_config

    reset_config()
    src = source(snap("/planner_notes", notes(), dict(WINDOW)), zone=None)
    assert [n["id"] for n in await ask(src, "/planner_notes", DAY_3)] == [1]
    # The student's own zone wins over the server's.
    tokyo = source(snap("/planner_notes", notes(), dict(WINDOW)), zone="Asia/Tokyo")
    assert [n["id"] for n in await ask(tokyo, "/planner_notes", DAY_3)] == [2]


LA = "America/Los_Angeles"
WIDE = {"start_date": ["2026-10-01T00:00:00Z"], "end_date": ["2027-06-01T00:00:00Z"]}


async def test_the_day_the_clocks_go_back_has_twenty_five_hours():
    # 2026-11-01 in Los Angeles runs from 07:00Z to 08:00Z the next day.
    items = [
        {"id": 1, "todo_date": "2026-11-01T06:59:59Z"},  # Oct 31, 11:59pm PDT
        {"id": 2, "todo_date": "2026-11-01T07:00:00Z"},  # first second of Nov 1
        {"id": 3, "todo_date": "2026-11-02T07:30:00Z"},  # Nov 1, 11:30pm PST: the extra hour
        {"id": 4, "todo_date": "2026-11-02T08:00:00Z"},  # Nov 2, midnight
    ]
    src = source(snap("/planner_notes", items, dict(WIDE)), zone=LA)
    got = await ask(src, "/planner_notes", {"start_date": "2026-11-01", "end_date": "2026-11-01"})
    assert [n["id"] for n in got] == [2, 3]


async def test_the_day_the_clocks_go_forward_has_twenty_three_hours():
    # 2027-03-14 in Los Angeles runs from 08:00Z to 07:00Z the next day.
    items = [
        {"id": 1, "todo_date": "2027-03-14T07:59:59Z"},  # Mar 13, 11:59pm PST
        {"id": 2, "todo_date": "2027-03-14T08:00:00Z"},  # first second of Mar 14
        {"id": 3, "todo_date": "2027-03-15T06:59:59Z"},  # Mar 14, 11:59:59pm PDT
        {"id": 4, "todo_date": "2027-03-15T07:00:00Z"},  # Mar 15, midnight
        {"id": 5, "todo_date": "2027-03-15T07:30:00Z"},  # Mar 15, 12:30am
    ]
    src = source(snap("/planner_notes", items, dict(WIDE)), zone=LA)
    got = await ask(src, "/planner_notes", {"start_date": "2027-03-14", "end_date": "2027-03-14"})
    assert [n["id"] for n in got] == [2, 3]
    # A window of both days is 47 hours long, and starts and ends at local midnights.
    both = await ask(src, "/planner_notes", {"start_date": "2027-03-14", "end_date": "2027-03-15"})
    assert [n["id"] for n in both] == [2, 3, 4, 5]


# -- contexts and types -----------------------------------------------------------------------


def events_in(context: str, *ids: int) -> list[dict[str, Any]]:
    return [
        {"id": i, "context_code": context, "start_at": "2026-11-05T10:00:00Z", "title": "t", "description": "d"}
        for i in ids
    ]


def event_query(code: str, kind: str = "event") -> dict[str, list[str]]:
    return {"type": [kind], "context_codes[]": [code], "excludes[]": ["child_events"], **WINDOW}


async def test_context_codes_are_answered_from_per_course_snapshots():
    src = source(
        snap("/calendar_events", events_in("course_5", 1, 2), event_query("course_5")),
        snap("/calendar_events", events_in("course_6", 3), event_query("course_6")),
    )
    params = {
        "type": "event",
        "context_codes[]": ["course_6", "course_5"],
        "start_date": "2026-11-01",
        "end_date": "2026-11-30",
        "excludes[]": ["child_events"],
    }
    got = await ask(src, "/calendar_events", params)
    assert sorted(e["id"] for e in got) == [1, 2, 3]
    # A context nobody synced makes the whole answer a miss: partial data would look complete.
    await miss(src, "/calendar_events", {**params, "context_codes[]": ["course_5", "group_9"]})


async def test_extra_excludes_are_applied_to_the_stored_items():
    stored = snap("/calendar_events", events_in("course_5", 1), event_query("course_5"))
    src = source(stored)
    params = {
        "type": "event",
        "context_codes[]": ["course_5"],
        "start_date": "2026-11-01",
        "end_date": "2026-11-30",
    }
    # child_events is never stored, so a request that does not exclude it is still answered.
    assert [e["id"] for e in await ask(src, "/calendar_events", params)] == [1]
    got = await ask(src, "/calendar_events", {**params, "excludes[]": ["description", "child_events"]})
    assert got and all("description" not in e for e in got)
    assert all("description" in e for e in stored.body)
    # A stored copy that left something out cannot answer a request that wants it.
    thin = source(
        snap(
            "/calendar_events",
            events_in("course_5", 1),
            {**event_query("course_5"), "excludes[]": ["child_events", "description"]},
        )
    )
    await miss(thin, "/calendar_events", params)


async def test_planner_items_cover_every_context_when_stored_without_codes():
    items = [
        {"id": 1, "course_id": 5, "plannable_date": "2026-11-05T10:00:00Z"},
        {"id": 2, "course_id": 6, "plannable_date": "2026-11-05T10:00:00Z"},
    ]
    src = source(snap("/planner/items", items, dict(WINDOW)))
    got = await ask(
        src,
        "/planner/items",
        {"context_codes[]": ["course_6"], "start_date": "2026-11-01", "end_date": "2026-11-30"},
    )
    assert [i["id"] for i in got] == [2]


async def test_type_is_matched_or_filtered():
    mixed = [
        {"id": 1, "type": "event", "start_at": "2026-11-05T10:00:00Z"},
        {"id": 2, "type": "assignment", "start_at": "2026-11-05T10:00:00Z"},
    ]
    typed = source(snap("/calendar_events", mixed, {"type": ["event"], **WINDOW}))
    params = {"start_date": "2026-11-01", "end_date": "2026-11-30"}
    await miss(typed, "/calendar_events", {**params, "type": "assignment"})
    untyped = source(snap("/calendar_events", mixed, dict(WINDOW)))
    got = await ask(untyped, "/calendar_events", {**params, "type": "assignment"})
    assert [e["id"] for e in got] == [2]


# -- one object by id -------------------------------------------------------------------------


async def test_one_object_is_taken_from_the_stored_list_by_id():
    courses = [{"id": 5, "name": "A", "syllabus_body": "s"}, {"id": 6, "name": "B"}]
    src = source(snap("/courses", courses, {"include[]": ["syllabus_body", "term"]}))
    assert await ask(src, "/courses/5", {"include[]": ["syllabus_body"]}) == courses[0]
    assert await ask(src, "/courses/6") == courses[1]
    assert (await miss(src, "/courses/7")).code == SOURCE_UNAVAILABLE
    assert (await miss(src, "/courses/5", {"include[]": ["total_scores"]})).code == SOURCE_UNAVAILABLE


async def test_an_assignment_by_id_ignores_all_dates_when_the_list_has_it():
    src = source(
        snap("/courses/5/assignments", [{"id": 9, "name": "HW"}], {"include[]": ["all_dates", "submission"]})
    )
    got = await ask(src, "/courses/5/assignments/9", {"all_dates": "true", "include[]": ["submission"]})
    assert got == {"id": 9, "name": "HW"}


async def test_an_exact_snapshot_wins_over_the_parent_list():
    src = source(
        snap("/courses/5", {"id": 5, "name": "exact"}),
        snap("/courses", [{"id": 5, "name": "from list"}]),
    )
    assert (await ask(src, "/courses/5"))["name"] == "exact"


async def test_a_calendar_event_by_id_is_found_in_any_window():
    src = source(
        snap("/calendar_events", events_in("course_5", 1), event_query("course_5")),
        snap("/calendar_events", events_in("course_6", 2), event_query("course_6")),
    )
    assert (await ask(src, "/calendar_events/2"))["id"] == 2


# -- stored statuses and age ------------------------------------------------------------------


async def test_a_stored_failure_status_is_named_in_the_message():
    src = source(snap("/courses", None, status=401))
    err = await miss(src, "/courses")
    assert err.code == SOURCE_UNAVAILABLE
    assert "401" in err.message and "blocks session access" in err.message
    other = await miss(source(snap("/courses/5/front_page", None, status=404)), "/courses/5/front_page")
    assert "404" in other.message and "blocks" not in other.message


async def test_a_good_copy_beats_a_failed_one_for_the_same_request():
    src = source(
        snap("/courses", None, {"enrollment_state": ["active"]}, status=500, age=10),
        snap("/courses", [{"id": 1}], {"enrollment_state": ["active"]}, age=5000),
    )
    assert await ask(src, "/courses", {"enrollment_state": "active"}) == [{"id": 1}]


async def test_data_older_than_the_limit_is_not_used():
    old = snap("/courses/5/quizzes", [{"id": 1}], age=15 * DAY)
    err = await miss(source(old, max_age_days=14), "/courses/5/quizzes")
    assert err.code == SOURCE_UNAVAILABLE and "14 days" in err.message
    fresh = snap("/courses/5/quizzes", [{"id": 1}], age=13 * DAY)
    assert await ask(source(fresh, max_age_days=14), "/courses/5/quizzes") == [{"id": 1}]


async def test_a_second_fresh_copy_rescues_a_stale_one():
    src = source(
        snap("/courses", [{"id": 1}], {"enrollment_state": ["active"]}, age=20 * DAY),
        snap("/courses", [{"id": 2}], {"enrollment_state": ["active"]}, age=60),
    )
    assert await ask(src, "/courses", {"enrollment_state": "active"}) == [{"id": 2}]


# -- freshness ----------------------------------------------------------------------------------


async def test_the_oldest_snapshot_used_is_reported():
    src = source(
        snap("/courses/5/quizzes", [{"id": 1}], age=3600),
        snap("/courses/5/modules", [{"id": 2}], age=7200),
    )
    with capture_freshness() as used:
        await ask(src, "/courses/5/quizzes")
        await ask(src, "/courses/5/modules")
        await miss(src, "/courses/5/pages")
    assert sorted(used) == [NOW - 7200, NOW - 3600]
    assert freshness_note(used, now=NOW) == "Data synced from your browser 2 hours ago."


def test_freshness_note_wording_and_thresholds():
    assert freshness_note([], now=NOW) is None
    assert freshness_note([NOW - 5], now=NOW) == "Data synced from your browser less than a minute ago."
    assert freshness_note([NOW - 600], now=NOW) == "Data synced from your browser 10 minutes ago."
    at_limit = freshness_note([NOW - 12 * 3600], now=NOW)
    assert at_limit is not None and "out of date" not in at_limit
    stale = freshness_note([NOW - 12 * 3600 - 1], now=NOW)
    assert stale is not None and "may be out of date; open Canvas" in stale
    custom = freshness_note([NOW - 3 * 3600], now=NOW, stale_after_seconds=3600)
    assert custom is not None and "out of date" in custom
    assert "3 days ago" in (freshness_note([NOW - 3 * DAY], now=NOW) or "")


# -- the request path (make_canvas_request) ----------------------------------------------------


@pytest.fixture
def http_mode():
    set_http_request_active(True)
    try:
        yield
    finally:
        clear_http_request_context()


def no_network():
    """Any attempt to open an HTTP connection fails the test."""
    return patch.object(
        client.httpx.AsyncClient,
        "__init__",
        side_effect=AssertionError("browser mode must never open an HTTP client"),
    )


async def test_a_write_is_refused_and_nothing_is_sent(http_mode):
    set_browser_source(source(snap("/courses/5/assignments", [])))
    with no_network(), capture_failures() as codes:
        result = await client.make_canvas_request(
            "post", "/courses/5/assignments", data={"assignment": {"name": "x"}}
        )
    assert "read-only" in result["error"]
    assert codes == [PERMISSION_DENIED]
    for method in ("put", "delete"):
        with no_network():
            assert "read-only" in (await client.make_canvas_request(method, "/courses/5"))["error"]


async def test_other_api_roots_are_unavailable(http_mode):
    set_browser_source(source(snap("/courses/5/quizzes", [{"id": 1}])))
    with no_network(), capture_failures() as codes:
        result = await client.make_canvas_request("get", "/courses/5/quizzes", api_root="quiz")
    assert "error" in result and codes == [SOURCE_UNAVAILABLE]


async def test_a_miss_records_the_failure_code(http_mode):
    set_browser_source(source())
    with no_network(), capture_failures() as codes:
        result = await client.make_canvas_request("get", "/users/self/todo")
    assert "not been synced" in result["error"]
    assert codes == [SOURCE_UNAVAILABLE]


async def test_pagination_returns_the_whole_stored_list_without_a_next_link(http_mode):
    rows = [{"id": i} for i in range(250)]
    set_browser_source(source(snap("/courses/5/quizzes", rows)))
    with no_network():
        got = await client.fetch_all_paginated_results("/courses/5/quizzes", {"per_page": 100})
    assert got == rows


async def test_a_single_object_endpoint_inside_fetch_all_is_a_clear_error(http_mode):
    set_browser_source(source(snap("/users/self", {"id": 1})))
    with no_network():
        got = await client.fetch_all_paginated_results("/users/self")
    assert got == {"error": "Invalid paginated response: expected a list"}


async def test_anonymization_runs_exactly_as_for_live_responses(http_mode, monkeypatch):
    monkeypatch.setenv("ENABLE_DATA_ANONYMIZATION", "true")
    from canvas_mcp.core.config import reset_config

    reset_config()
    people = [
        {
            "id": 1,
            "user_id": 77,
            "user": {"id": 77, "name": "Real Student", "sortable_name": "Student, Real", "email": "real@example.edu"},
        }
    ]
    set_browser_source(source(snap("/courses/5/enrollments", copy.deepcopy(people))))
    with no_network():
        got = await client.fetch_all_paginated_results("/courses/5/enrollments")
        raw = await client.fetch_all_paginated_results("/courses/5/enrollments", skip_anonymization=True)
    text = repr(got)
    assert "Real Student" not in text and "real@example.edu" not in text
    assert got[0]["user"]["id"] == 77
    assert raw == people
    expected, _ = client._anonymize_for_endpoint(copy.deepcopy(people), "/courses/5/enrollments")
    assert got == expected


async def test_downloads_have_no_credential_to_use(http_mode):
    set_browser_source(source())
    with pytest.raises(PermissionError, match="Browser sync"):
        async with client.canvas_authenticated_client():
            pass


async def test_a_request_never_has_both_a_token_and_browser_data(http_mode):
    set_request_credentials(RequestCredentials("tok", "https://canvas.example.edu/api/v1"))
    with pytest.raises(RuntimeError):
        set_browser_source(source())
    set_browser_source  # noqa: B018 - the guard above is the assertion
    clear_http_request_context()
    set_http_request_active(True)
    set_browser_source(source())
    assert get_browser_source() is not None
    set_request_credentials(RequestCredentials("tok", "https://canvas.example.edu/api/v1"))
    assert get_browser_source() is None


async def test_without_a_source_an_http_request_still_fails_closed(http_mode):
    with no_network(), capture_failures() as codes:
        result = await client.make_canvas_request("get", "/users/self")
    assert "error" in result and codes
