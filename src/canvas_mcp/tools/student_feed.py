"""Student "what's new" feed: cross-course announcements and activity.

Two read-only tools that answer "what happened in my classes lately?" without
the caller having to walk their courses one at a time:

- ``list_my_announcements`` reads ``GET /api/v1/announcements``, the one Canvas
  endpoint that returns announcements for several courses in a single query
  (``context_codes[]``). The per-course ``list_announcements`` tool is left as
  it is; this one is deliberately cross-course.
- ``get_my_activity_stream`` reads ``GET /api/v1/users/self/activity_stream``
  and its ``/summary`` twin, the feed behind the Canvas dashboard's "Recent
  Activity" view, and groups it by kind (announcements, discussions, inbox
  conversations, grades and submission comments, notifications).

Neither endpoint changes read state, and neither tool writes anything.

Everything Canvas users wrote — titles, bodies, author names, comments — is
fenced at the output boundary (issue 239). Privacy tiers: ``/announcements``
has no sensitive path segment and stays at ``ANONYMIZE_NONE``, the same
treatment as the ``/discussion_topics`` listings it mirrors (instructor-authored
course content). ``/users/self/activity_stream`` carries a ``users`` route
segment and is NOT on the exact self-only allowlist, so it gets the full
anonymization tier when anonymization is enabled; that is correct for a feed
that embeds other people's discussion posts, messages and comments.
"""

import re
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..core.cache import get_course_code, get_course_id
from ..core.client import fetch_all_paginated_results
from ..core.dates import format_date, parse_date
from ..core.untrusted_content import fence_untrusted, fence_untrusted_inline
from ..core.validation import coerce_canvas_id, validate_params
from .courses import strip_html_tags

#: Default look-back window for ``list_my_announcements``. Matches Canvas's own
#: default ``start_date`` for ``/announcements`` ("Defaults to 14 days ago").
DEFAULT_ANNOUNCEMENT_DAYS = 14

#: Course context codes sent per ``/announcements`` request. Canvas documents no
#: limit, but every code lengthens the query string and a student can carry
#: dozens of "active" enrollments, so requests are split into bounded chunks.
CONTEXT_CODE_CHUNK_SIZE = 10

MAX_LIMIT = 200
MAX_PREVIEW_CHARS = 2000

_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CONTEXT_CODE = re.compile(r"^course_(\d+)$")
# A grade Canvas computed from a grading scheme is a short token ("A-", "92.5",
# "complete", "85%"). Anything else is rendered through the inline fence.
_PLAIN_GRADE = re.compile(r"^[A-Za-z0-9.+\-% ]{1,16}$")
_PLAIN_CATEGORY = re.compile(r"^[A-Za-z &/\-]{1,40}$")

#: Activity-stream item ``type`` -> display category, in display order.
_STREAM_CATEGORIES: list[tuple[str, tuple[str, ...]]] = [
    ("Announcements", ("Announcement",)),
    ("Discussions", ("DiscussionTopic", "DiscussionEntry")),
    ("Inbox conversations", ("Conversation",)),
    ("Grades & submission comments", ("Submission",)),
    ("Notifications", ("Message",)),
    ("Peer review requests", ("AssessmentRequest",)),
]
_OTHER_CATEGORY = "Other activity"

_TYPE_FILTERS: dict[str, tuple[str, ...]] = {
    "announcements": ("Announcement",),
    "discussions": ("DiscussionTopic", "DiscussionEntry"),
    "conversations": ("Conversation",),
    "submissions": ("Submission",),
    "notifications": ("Message",),
}

ActivityType = Literal[
    "all", "announcements", "discussions", "conversations", "submissions", "notifications"
]


def _category_for(item_type: Any) -> str:
    for label, types in _STREAM_CATEGORIES:
        if item_type in types:
            return label
    return _OTHER_CATEGORY


def _to_canvas_timestamp(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_window(
    start_date: str | None, end_date: str | None
) -> tuple[datetime, datetime] | str:
    """Turn the optional window bounds into UTC datetimes, or an error string.

    A date-only ``end_date`` covers that whole UTC day; otherwise an
    announcement posted at noon on the end date would fall outside a window
    the caller meant to include it in.
    """
    now = datetime.now(UTC)

    if start_date:
        start = parse_date(start_date)
        if start is None:
            return (
                f"Error: could not parse start_date '{start_date}'. "
                "Use YYYY-MM-DD or ISO 8601 (YYYY-MM-DDTHH:MM:SSZ)."
            )
    else:
        start = now - timedelta(days=DEFAULT_ANNOUNCEMENT_DAYS)

    if end_date:
        end = parse_date(end_date)
        if end is None:
            return (
                f"Error: could not parse end_date '{end_date}'. "
                "Use YYYY-MM-DD or ISO 8601 (YYYY-MM-DDTHH:MM:SSZ)."
            )
        if _DATE_ONLY.match(end_date.strip()):
            end = end + timedelta(days=1) - timedelta(seconds=1)
    else:
        end = now

    if start > end:
        return "Error: start_date must be on or before end_date."
    return start, end


def _preview(text: Any, max_chars: int) -> str:
    """Plain-text preview of Canvas rich text, cut at ``max_chars``."""
    if not isinstance(text, str) or not text:
        return ""
    plain = strip_html_tags(text)
    if len(plain) > max_chars:
        return plain[: max(max_chars - 3, 0)].rstrip() + "..."
    return plain


def _as_count(value: Any) -> int:
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def _grade_label(value: Any) -> str:
    text = str(value)
    if _PLAIN_GRADE.match(text):
        return text
    return fence_untrusted_inline(text, "grade text")


async def _fetch_active_courses() -> list[dict] | str:
    """The caller's active-enrollment courses, or an error string."""
    courses = await fetch_all_paginated_results(
        "/courses", params={"enrollment_state": "active", "per_page": 100}
    )
    if isinstance(courses, dict) and "error" in courses:
        return f"Error fetching your courses: {courses['error']}"
    if not isinstance(courses, list):
        return "Error fetching your courses: unexpected response from Canvas."
    return [c for c in courses if isinstance(c, dict)]


async def _course_label(course_id: Any, codes: dict[str, str]) -> str:
    """Course code for display, never an unvalidated value in a request path."""
    numeric = coerce_canvas_id(course_id) if course_id is not None else None
    if numeric is None:
        return "Unknown course"
    if numeric in codes:
        return codes[numeric]
    code = await get_course_code(numeric)
    return str(code) if code else f"course {numeric}"


def _chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[i:i + size] for i in range(0, len(items), size)]


async def _fetch_announcements(
    context_codes: list[str], window_params: dict[str, Any]
) -> tuple[list[dict], list[tuple[str, str]]]:
    """Fetch announcements for ``context_codes`` in bounded chunks.

    Returns the announcements plus ``(context_code, error)`` for each course
    whose announcements could not be read. When a multi-course chunk fails
    (one unreadable course can fail the whole request), its courses are
    retried one at a time so one bad course does not hide the others.
    """
    found: list[dict] = []
    failures: list[tuple[str, str]] = []

    async def fetch(codes: list[str]) -> list[dict] | str:
        result = await fetch_all_paginated_results(
            "/announcements",
            params={"context_codes[]": codes, **window_params, "per_page": 100},
        )
        if isinstance(result, dict) and "error" in result:
            return str(result["error"])
        if not isinstance(result, list):
            return "unexpected response from Canvas"
        return [a for a in result if isinstance(a, dict)]

    for chunk in _chunks(context_codes, CONTEXT_CODE_CHUNK_SIZE):
        result = await fetch(chunk)
        if not isinstance(result, str):
            found.extend(result)
            continue
        if len(chunk) == 1:
            failures.append((chunk[0], result))
            continue
        for code in chunk:
            single = await fetch([code])
            if isinstance(single, str):
                failures.append((code, single))
            else:
                found.extend(single)
    return found, failures


def _format_announcement(
    announcement: dict, course_display: str, preview_chars: int
) -> str:
    author = announcement.get("author") or {}
    author_name = (
        (author.get("display_name") if isinstance(author, dict) else None)
        or announcement.get("user_name")
        or "Unknown author"
    )
    title = announcement.get("title") or "Untitled announcement"
    posted = format_date(announcement.get("posted_at") or announcement.get("created_at"))
    unread = " [UNREAD]" if announcement.get("read_state") == "unread" else ""

    lines = [
        f"• {course_display} | Posted {posted}{unread}",
        f"  Title: {fence_untrusted_inline(title, 'announcement title')}",
        f"  Author: {fence_untrusted_inline(author_name, 'announcement author')}",
    ]
    ref = f"  ID: {announcement.get('id')}"
    if announcement.get("html_url"):
        ref += f" | Link: {announcement['html_url']}"
    lines.append(ref)
    if preview_chars > 0:
        body = _preview(announcement.get("message"), preview_chars)
        if body:
            lines.append(fence_untrusted(body, "announcement body preview"))
    return "\n".join(lines) + "\n"


def _stream_item_sort_key(item: dict) -> datetime:
    return (
        parse_date(item.get("updated_at") or item.get("created_at"))
        or datetime.min.replace(tzinfo=UTC)
    )


async def _format_stream_item(
    item: dict, codes: dict[str, str], preview_chars: int
) -> str:
    item_type = item.get("type") or "Unknown"
    if item.get("course_id") is not None:
        where = await _course_label(item.get("course_id"), codes)
    elif item.get("group_id") is not None:
        group = coerce_canvas_id(item["group_id"])
        where = f"group {group}" if group else "a group"
    else:
        where = "no course"
    when = format_date(item.get("updated_at") or item.get("created_at"))
    unread = " [UNREAD]" if item.get("read_state") is False else ""
    lines = [f"• {where} | {item_type} | {when}{unread}"]

    if item_type == "Submission":
        assignment = item.get("assignment") if isinstance(item.get("assignment"), dict) else {}
        name = assignment.get("name") or item.get("title") or "Unnamed assignment"
        lines.append(f"  Assignment: {fence_untrusted_inline(name, 'assignment name')}")
        score, grade = item.get("score"), item.get("grade")
        points = assignment.get("points_possible")
        if score is not None or grade is not None:
            parts = []
            if score is not None:
                parts.append(f"{score}/{points}" if points is not None else f"{score}")
            if grade is not None and str(grade) != str(score):
                parts.append(f"grade {_grade_label(grade)}")
            lines.append(f"  Grade: {', '.join(parts)}")
        comments = [
            c for c in (item.get("submission_comments") or []) if isinstance(c, dict)
        ]
        if comments:
            latest = max(
                comments,
                key=lambda c: parse_date(c.get("created_at")) or datetime.min.replace(tzinfo=UTC),
            )
            author = latest.get("author_name") or "Unknown commenter"
            lines.append(
                f"  Comments: {len(comments)} (latest by "
                f"{fence_untrusted_inline(author, 'comment author')}, "
                f"{format_date(latest.get('created_at'))})"
            )
            if preview_chars > 0:
                text = _preview(latest.get("comment"), preview_chars)
                if text:
                    lines.append(fence_untrusted(text, "submission comment preview"))
    else:
        title = item.get("title") or "(no title)"
        lines.append(f"  Title: {fence_untrusted_inline(title, 'activity item title')}")
        if item_type == "Conversation" and item.get("participant_count") is not None:
            lines.append(f"  Participants: {item.get('participant_count')}")
        if item_type == "Message" and item.get("notification_category"):
            category = str(item["notification_category"])
            # Canvas-defined ("Due Date", "Grading"); fenced if it is ever not.
            if not _PLAIN_CATEGORY.match(category):
                category = fence_untrusted_inline(category, "notification category")
            lines.append(f"  Category: {category}")
        if item_type in ("DiscussionTopic", "Announcement"):
            replies = item.get("total_root_discussion_entries")
            if replies is not None:
                lines.append(f"  Replies: {replies}")
            if item.get("require_initial_post") and item.get("user_has_posted") is False:
                lines.append("  You must post before you can see replies.")
        if preview_chars > 0:
            text = _preview(item.get("message"), preview_chars)
            if text:
                lines.append(fence_untrusted(text, "activity item preview"))

    if item.get("html_url"):
        lines.append(f"  Link: {item['html_url']}")
    return "\n".join(lines) + "\n"


def register_student_feed_tools(mcp: FastMCP) -> None:
    """Register the cross-course announcement and activity feed tools."""

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    @validate_params
    async def list_my_announcements(
        course_identifier: str | int | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        limit: int = 50,
        preview_chars: int = 400,
    ) -> str:
        """List announcements across ALL your active courses in one call.

        Cross-course: one query covers every course you are actively enrolled
        in, newest first. For a single course's full announcement history use
        list_announcements instead. Default window: the last 14 days.

        Args:
            course_identifier: Optional course code or Canvas ID to show only
                that course.
            start_date: Earliest post date, YYYY-MM-DD or ISO 8601 (default:
                14 days ago). Date-only values are UTC days.
            end_date: Latest post date, YYYY-MM-DD or ISO 8601 (default: now).
                A date-only end_date includes that whole UTC day.
            limit: Maximum announcements to show (1-200, default 50).
            preview_chars: Characters of body text to preview per
                announcement (0-2000, default 400; 0 shows titles only).
        """
        if not 1 <= limit <= MAX_LIMIT:
            return f"Error: limit must be between 1 and {MAX_LIMIT}."
        if not 0 <= preview_chars <= MAX_PREVIEW_CHARS:
            return f"Error: preview_chars must be between 0 and {MAX_PREVIEW_CHARS}."

        window = _resolve_window(start_date, end_date)
        if isinstance(window, str):
            return window
        start, end = window

        courses = await _fetch_active_courses()
        if isinstance(courses, str):
            return courses

        codes: dict[str, str] = {}
        aliases: dict[str, str] = {}
        course_ids: list[str] = []
        for course in courses:
            cid = coerce_canvas_id(course.get("id")) if course.get("id") is not None else None
            if cid is None or cid in codes:
                continue
            codes[cid] = course.get("course_code") or course.get("name") or f"course {cid}"
            course_ids.append(cid)
            if course.get("course_code"):
                aliases.setdefault(str(course["course_code"]), cid)
            if course.get("sis_course_id"):
                aliases.setdefault(f"sis_course_id:{course['sis_course_id']}", cid)

        filtered = course_identifier is not None and bool(str(course_identifier).strip())
        if filtered:
            wanted = str(course_identifier).strip()
            resolved = await get_course_id(wanted)
            # Only a plain numeric ID may become a context code; a course code
            # or SIS ID that did not resolve must match one of the caller's
            # own active courses.
            target = coerce_canvas_id(resolved) or aliases.get(wanted) or aliases.get(resolved)
            if target is None:
                return (
                    f"Error: '{wanted}' is not one of your active courses. "
                    "Pass its numeric Canvas course ID instead."
                )
            course_ids = [target]
        elif not course_ids:
            return "You have no active courses, so there are no announcements to show."

        window_params = {
            "start_date": _to_canvas_timestamp(start),
            "end_date": _to_canvas_timestamp(end),
            "active_only": True,
        }
        announcements, failures = await _fetch_announcements(
            [f"course_{cid}" for cid in course_ids], window_params
        )

        if failures and len(failures) == len(course_ids):
            detail = "; ".join(f"{code}: {err}" for code, err in failures[:5])
            return f"Error fetching announcements: {detail}"

        # A course listed in two chunks or retried must not show twice.
        unique: dict[str, dict] = {}
        for announcement in announcements:
            key = f"{announcement.get('context_code')}:{announcement.get('id')}"
            unique.setdefault(key, announcement)
        ordered = sorted(
            unique.values(),
            key=lambda a: parse_date(a.get("posted_at") or a.get("created_at"))
            or datetime.min.replace(tzinfo=UTC),
            reverse=True,
        )

        window_text = f"{format_date(_to_canvas_timestamp(start))} to {format_date(_to_canvas_timestamp(end))}"
        scope = (
            await _course_label(course_ids[0], codes)
            if filtered
            else f"{len(course_ids)} active course{'s' if len(course_ids) != 1 else ''}"
        )

        failure_note = ""
        if failures:
            failed = []
            for code, err in failures:
                match = _CONTEXT_CODE.match(code)
                label = await _course_label(match.group(1), codes) if match else code
                failed.append(f"  • {label}: {err}\n")
            failure_note = (
                "\n⚠️  Could not read announcements for:\n" + "".join(failed)
                + "Those courses may have announcements not shown here.\n"
            )

        if not ordered:
            return (
                f"No announcements in {scope} from {window_text}." + failure_note
            )

        lines = [
            f"Announcements across {scope} ({window_text}), newest first: "
            f"{len(ordered)} found\n"
        ]
        for announcement in ordered[:limit]:
            match = _CONTEXT_CODE.match(str(announcement.get("context_code") or ""))
            course_display = (
                await _course_label(match.group(1), codes) if match else "Unknown course"
            )
            lines.append(_format_announcement(announcement, course_display, preview_chars))
        if len(ordered) > limit:
            lines.append(
                f"... {len(ordered) - limit} more not shown. Narrow the date range, "
                "filter by course, or raise limit."
            )
        return "\n".join(lines) + failure_note

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    @validate_params
    async def get_my_activity_stream(
        item_type: ActivityType = "all",
        limit: int = 30,
        include_summary: bool = True,
        preview_chars: int = 300,
    ) -> str:
        """Your recent Canvas activity across all active courses, grouped by kind.

        The dashboard "Recent Activity" feed: announcements, discussions,
        inbox conversations, grades and submission comments, and
        notifications, newest first. Reading it does not mark anything read.

        Args:
            item_type: Show only one kind: "announcements", "discussions",
                "conversations", "submissions" (grades and submission
                comments), "notifications", or "all" (default).
            limit: Maximum items to show (1-200, default 30).
            include_summary: Also show per-kind total and unread counts
                (default True).
            preview_chars: Characters of text to preview per item (0-2000,
                default 300; 0 shows titles only).
        """
        if not 1 <= limit <= MAX_LIMIT:
            return f"Error: limit must be between 1 and {MAX_LIMIT}."
        if not 0 <= preview_chars <= MAX_PREVIEW_CHARS:
            return f"Error: preview_chars must be between 0 and {MAX_PREVIEW_CHARS}."

        items = await fetch_all_paginated_results(
            "/users/self/activity_stream",
            params={"only_active_courses": True, "per_page": 100},
        )
        if isinstance(items, dict) and "error" in items:
            return f"Error fetching your activity stream: {items['error']}"
        if not isinstance(items, list):
            return "Error fetching your activity stream: unexpected response from Canvas."
        items = [i for i in items if isinstance(i, dict)]

        output: list[str] = []
        if include_summary:
            summary = await fetch_all_paginated_results(
                "/users/self/activity_stream/summary",
                params={"only_active_courses": True},
            )
            if isinstance(summary, list):
                totals: dict[str, list[int]] = {}
                for row in summary:
                    if not isinstance(row, dict):
                        continue
                    counts = totals.setdefault(_category_for(row.get("type")), [0, 0])
                    counts[0] += _as_count(row.get("count"))
                    counts[1] += _as_count(row.get("unread_count"))
                output.append("Activity summary (active courses):")
                order = [label for label, _ in _STREAM_CATEGORIES] + [_OTHER_CATEGORY]
                for label in order:
                    if label in totals:
                        total, unread = totals[label]
                        output.append(f"  {label}: {total} ({unread} unread)")
                if not totals:
                    output.append("  No recent activity.")
                output.append("")
            else:
                detail = summary.get("error") if isinstance(summary, dict) else summary
                output.append(f"⚠️  Activity summary unavailable: {detail}\n")

        if item_type != "all":
            wanted = _TYPE_FILTERS[item_type]
            items = [i for i in items if i.get("type") in wanted]

        if not items:
            kind = "" if item_type == "all" else f" {item_type}"
            output.append(f"No recent{kind} activity in your active courses.")
            return "\n".join(output)

        items.sort(key=_stream_item_sort_key, reverse=True)
        shown = items[:limit]

        courses = await _fetch_active_courses()
        codes: dict[str, str] = {}
        if isinstance(courses, list):
            for course in courses:
                cid = coerce_canvas_id(course.get("id")) if course.get("id") is not None else None
                if cid is not None:
                    codes[cid] = course.get("course_code") or course.get("name") or f"course {cid}"

        grouped: dict[str, list[dict]] = {}
        for item in shown:
            grouped.setdefault(_category_for(item.get("type")), []).append(item)

        output.append(
            f"Recent activity, newest first ({len(shown)} of {len(items)} items):"
        )
        order = [label for label, _ in _STREAM_CATEGORIES] + [_OTHER_CATEGORY]
        for label in order:
            group = grouped.get(label)
            if not group:
                continue
            output.append(f"\n## {label} ({len(group)})\n")
            for item in group:
                output.append(await _format_stream_item(item, codes, preview_chars))
        if len(items) > limit:
            output.append(
                f"... {len(items) - limit} older items not shown. Raise limit or "
                "filter with item_type."
            )
        return "\n".join(output)
