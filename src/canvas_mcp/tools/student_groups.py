"""Student group tools: the caller's own Canvas groups and what is inside them.

Everything here is read-only and scoped to groups the caller BELONGS to.

Why membership is checked here rather than left to Canvas
---------------------------------------------------------
Canvas can authorize group reads more widely than membership: course-level
group permissions, self-signup categories (whose rosters students see in
order to pick a group) and public community groups may let a token read a
group it is not in. A 401 from Canvas is therefore not a membership oracle,
and relying on it would let an agent browse other teams' rosters, discussions
and files whenever an institution's settings happen to allow it. Before any group-scoped
request, every tool re-reads ``/users/self/groups`` (the caller's own active
groups) and refuses a group that is not on it. That costs one extra request
per call and fails closed: if the membership list cannot be read, nothing else
is requested.

Privacy (CLAUDE.md "Privacy")
-----------------------------
- ``/groups/{id}/users`` is a roster of classmates. It stays at the client
  layer's ``full`` anonymization tier (``core/client.py``, the ``users``
  segment rule), exactly like every other roster endpoint: with
  ``ENABLE_DATA_ANONYMIZATION`` on, names are pseudonymized and IDs kept. A
  student who wants real names can turn anonymization off for their own
  server. Independently of that setting, ``get_group_members`` prints only the
  member's ID and name — never an email, login ID or SIS ID — because the
  output is built from an explicit field allowlist.
- ``/groups/{id}/discussion_topics/{id}/view`` matches the discussion-content
  rule (``full`` tier), so participant names and the PII in entry bodies
  (including ``new_entries``) are scrubbed. Unlike course topics, the group
  topic records themselves (``/groups/{id}/discussion_topics`` and
  ``.../{topic_id}``) are written by group members, so they have their own
  ``full``-tier rule in ``core/client.py``: the topic ``message`` and author
  fields are scrubbed there. Topic and announcement titles and the group
  description are not free-text fields at that layer, so this module applies
  ``scrub_free_text`` to them when anonymization is on. The topic's author is
  named from the anonymized ``/view`` participant list only.
- ``/users/self/groups`` lands in the ``full`` tier through its ``users``
  segment. Group records carry ``avatar_url``, which used to make the scrubber
  mistake a group for a person and rename it ``Student_<hash>``;
  ``group_category_id`` is now a non-person marker in ``core/anonymization.py``.

All Canvas-authored text (group names and descriptions, topic titles and
bodies, entry bodies, file names, member names) is fenced at the output
boundary (issue 239): group members write most of it.
"""

from __future__ import annotations

import html
import re
from typing import Any

from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..core import cache as course_cache
from ..core.anonymization import scrub_free_text
from ..core.cache import get_course_code, get_course_id, refresh_course_cache
from ..core.client import fetch_all_paginated_results, make_canvas_request
from ..core.config import get_config
from ..core.dates import format_date
from ..core.file_validation import format_file_size
from ..core.untrusted_content import fence_untrusted, fence_untrusted_inline
from ..core.validation import coerce_canvas_id, validate_params

_INVALID_GROUP_ID = (
    "Error: group_id must be a numeric Canvas group ID. "
    "Use list_my_groups to find it."
)
_INVALID_TOPIC_ID = (
    "Error: topic_id must be a numeric Canvas discussion topic ID. "
    "Use list_group_discussion_topics or list_group_announcements to find it."
)

_VALID_FILE_SORTS = frozenset(
    {"name", "size", "created_at", "updated_at", "content_type"}
)

_HTTP_STATUS = re.compile(r"HTTP error: (\d{3})")
_TAG = re.compile(r"<[^>]+>")
# A bare MIME type (type/subtype). Group files are uploaded by classmates and
# Canvas's upload preflight takes a client-supplied content_type, so anything
# that is not a plain MIME token is not printed.
_MIME_TYPE = re.compile(r"^[\w.+-]+/[\w.+-]+$")
_SIS_COURSE_PREFIX = "sis_course_id:"


def _scrub(text: str) -> str:
    """Redact emails/phones/SSNs when data anonymization is on.

    Covers group-member-authored text the client-layer tier does not scrub:
    topic titles and group descriptions (``title`` / ``description`` are not
    free-text fields there, because elsewhere they are instructor content).
    """
    if get_config().enable_data_anonymization:
        return scrub_free_text(text)
    return text


async def _resolve_course_numeric_id(course_identifier: str | int) -> str | None:
    """Resolve any accepted course identifier to a numeric Canvas course ID.

    ``get_course_id`` passes some forms through unresolved (``sis_course_id:``
    values, codes missing from a cold or stale cache, which it may also turn
    into ``sis_course_id:<code>``). Other tools put that value in a URL and
    let Canvas resolve it; list_my_groups compares IDs locally, so it must
    have the number. Returns None when the course cannot be found.
    """
    raw = str(course_identifier).strip()
    resolved = str(await get_course_id(raw)).strip()
    numeric = coerce_canvas_id(resolved)
    if numeric is not None:
        return numeric

    # A course code (with or without underscores): look it up in a fresh cache.
    if not raw.startswith(_SIS_COURSE_PREFIX) and await refresh_course_cache():
        cached = coerce_canvas_id(course_cache.course_code_to_id_cache.get(raw, ""))
        if cached is not None:
            return cached

    # Canvas resolves SIS IDs on GET /courses/:id. Only a single path segment
    # is ever sent.
    if (
        resolved.startswith(_SIS_COURSE_PREFIX)
        and len(resolved) > len(_SIS_COURSE_PREFIX)
        and "/" not in resolved
    ):
        course = await make_canvas_request("get", f"/courses/{resolved}")
        if isinstance(course, dict) and "error" not in course:
            return coerce_canvas_id(course.get("id", ""))
    return None


def _http_status(error: object) -> int | None:
    """The HTTP status embedded in a make_canvas_request error, if any."""
    match = _HTTP_STATUS.search(str(error))
    return int(match.group(1)) if match else None


def _is_error(response: Any) -> bool:
    return isinstance(response, dict) and "error" in response


def _plain_text(markup: object) -> str:
    """Strip HTML tags and decode entities for display. Never sent back to Canvas."""
    if not isinstance(markup, str) or not markup:
        return ""
    return html.unescape(_TAG.sub("", markup)).strip()


def _access_error(action: str, group_id: str, error: object) -> str:
    """A clear message for a failed group-scoped read."""
    status = _http_status(error)
    if status in (401, 403):
        return (
            f"Error: Canvas did not allow you to {action} for group {group_id} "
            f"(HTTP {status}). The group may have this feature turned off, or "
            "your instructor may have restricted it."
        )
    if status == 404:
        return f"Error: Canvas could not find that resource in group {group_id} (HTTP 404)."
    return f"Error: could not {action} for group {group_id}: {error}"


async def _fetch_my_groups(params: dict[str, Any] | None = None) -> list[dict] | dict:
    """GET /users/self/groups — the caller's active groups, all pages."""
    query: dict[str, Any] = {"per_page": 100}
    if params:
        query.update(params)
    groups = await fetch_all_paginated_results("/users/self/groups", query)
    if _is_error(groups):
        return {"error": str(groups.get("error"))}
    if not isinstance(groups, list):
        return {"error": "Unexpected response from Canvas for /users/self/groups"}
    return [g for g in groups if isinstance(g, dict)]


async def _require_membership(raw_group_id: str | int) -> tuple[str, dict | None, str | None]:
    """Validate a group ID and confirm the caller belongs to that group.

    Returns ``(group_id, group, error)``; exactly one of ``group`` / ``error``
    is set. The ID is validated BEFORE any request, and the membership list is
    read fresh on every call so a student who left a group loses access
    immediately. Fails closed when the list cannot be read.
    """
    group_id = coerce_canvas_id(raw_group_id)
    if group_id is None:
        return "", None, _INVALID_GROUP_ID

    groups = await _fetch_my_groups()
    if isinstance(groups, dict):
        return group_id, None, (
            "Error: could not confirm your membership in group "
            f"{group_id}, so nothing was read: {groups.get('error')}"
        )

    for group in groups:
        if str(group.get("id")) == group_id:
            return group_id, group, None

    return group_id, None, (
        f"Error: you are not a member of group {group_id}. These tools only "
        "read groups you belong to; use list_my_groups to see them."
    )


async def _group_label(group: dict) -> str:
    """Fenced group name plus its course code (or parent context name)."""
    name = fence_untrusted_inline(group.get("name") or "Unnamed group", "group name")
    course_id = group.get("course_id")
    if group.get("context_type") == "Course" and course_id:
        course_display = await get_course_code(course_id) or course_id
        return f"{name} in {course_display}"
    context_name = group.get("context_name")
    if context_name:
        return f"{name} in {fence_untrusted_inline(context_name, 'group context name')}"
    return name


def _merge_new_entries(view: list[dict], new_entries: Any) -> list[dict]:
    """Fold /view ``new_entries`` into the entry tree.

    The full-topic view is eventually consistent; entries not yet reflected in
    it come back (with ``include_new_entries=1``) as a flat list in ascending
    ``created_at`` order, each with a ``parent_id``. Each one is attached under
    its parent when the parent is in the tree (including an earlier new entry)
    and at top level otherwise; IDs already in the tree are skipped.
    """
    if not isinstance(new_entries, list) or not new_entries:
        return view

    by_id: dict[str, dict] = {}

    def index(entries: list[Any]) -> None:
        for entry in entries:
            if isinstance(entry, dict):
                by_id[str(entry.get("id"))] = entry
                replies = entry.get("replies")
                if isinstance(replies, list):
                    index(replies)

    index(view)
    merged = list(view)
    for entry in new_entries:
        if not isinstance(entry, dict) or str(entry.get("id")) in by_id:
            continue
        node = dict(entry)
        parent_id = entry.get("parent_id")
        parent = by_id.get(str(parent_id)) if parent_id is not None else None
        if parent is not None:
            replies = parent.get("replies")
            if not isinstance(replies, list):
                replies = []
                parent["replies"] = replies
            replies.append(node)
        else:
            merged.append(node)
        by_id[str(entry.get("id"))] = node
    return merged


def _render_view_entries(
    entries: list[Any], participants: dict[str, str], depth: int = 0
) -> tuple[list[str], int, int]:
    """Render a /view entry tree with each body fenced.

    Returns ``(lines, posts, deleted)``. Canvas omits ``user_id``,
    ``user_name`` and ``message`` on deleted entries, so they get no author
    line; their replies are still rendered.
    """
    lines: list[str] = []
    posts = 0
    deleted = 0
    indent = "    " * depth
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_id = entry.get("id")
        if entry.get("deleted"):
            deleted += 1
            lines.append(f"{indent}Entry {entry_id} [deleted]")
        else:
            posts += 1
            user_id = entry.get("user_id")
            author = participants.get(str(user_id)) if user_id is not None else None
            author_text = (
                fence_untrusted_inline(author, "author name") if author
                else "an unknown participant"
            )
            created = format_date(entry.get("created_at"))
            lines.append(
                f"{indent}Entry {entry_id} by {author_text} (user ID: {user_id}), {created}"
            )
            body = _plain_text(entry.get("message")) or "[No content]"
            lines.append(
                fence_untrusted(body, "group discussion entry by a group member")
            )
        replies = entry.get("replies")
        if isinstance(replies, list) and replies:
            child_lines, child_posts, child_deleted = _render_view_entries(
                replies, participants, depth + 1
            )
            lines.extend(child_lines)
            posts += child_posts
            deleted += child_deleted
    return lines, posts, deleted


def register_student_group_tools(mcp: FastMCP) -> None:
    """Register the read-only student group tools."""

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    @validate_params
    async def list_my_groups(course_identifier: str | int | None = None) -> str:
        """List the Canvas groups you belong to (project teams, study groups).

        Shows each group's name, ID, course, group category ID and member
        count. Use the group ID with get_group_members,
        list_group_discussion_topics, list_group_announcements and
        list_group_files.

        Args:
            course_identifier: Only show your groups in this course
                (course code or Canvas ID). Default: groups in every course.
        """
        params: dict[str, Any] = {}
        course_id: str | None = None
        if course_identifier is not None and str(course_identifier).strip():
            # The filter below compares numeric IDs, so an unresolved code or
            # SIS ID would silently match nothing; fail loudly instead.
            course_id = await _resolve_course_numeric_id(course_identifier)
            if course_id is None:
                return (
                    f"Error: could not find course '{course_identifier}' among "
                    "your Canvas courses. Use a course code from list_courses "
                    "or a numeric Canvas course ID."
                )
            # Documented filter on /users/self/groups. Canvas has no course
            # filter on this endpoint, so the course match is done below.
            params["context_type"] = "Course"

        groups = await _fetch_my_groups(params)
        if isinstance(groups, dict):
            return f"Error fetching your groups: {groups.get('error')}"

        if course_id is not None:
            groups = [g for g in groups if str(g.get("course_id")) == course_id]

        if not groups:
            if course_id is not None:
                course_display = await get_course_code(course_id) or course_identifier
                return f"You are not in any groups in {course_display}."
            return "You are not in any Canvas groups."

        lines = [f"Your groups ({len(groups)}):", ""]
        for group in groups:
            lines.append(f"Group: {await _group_label(group)}")
            lines.append(f"  ID: {group.get('id')}")
            category_id = group.get("group_category_id")
            if category_id is not None:
                lines.append(f"  Group category ID: {category_id}")
            members = group.get("members_count")
            lines.append(
                f"  Members: {members if members is not None else 'unknown'}"
            )
            description = _scrub(_plain_text(group.get("description")))
            if description:
                lines.append("  Description:")
                lines.append(fence_untrusted(description, "group description"))
            lines.append("")
        return "\n".join(lines).rstrip()

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    @validate_params
    async def get_group_members(group_id: str | int) -> str:
        """List the members of one of your groups (names and Canvas user IDs).

        Only works for groups you belong to. Never shows email addresses. When
        the server's data anonymization is on (ENABLE_DATA_ANONYMIZATION),
        classmates' names appear as stable pseudonyms; IDs are real.

        Args:
            group_id: Canvas group ID from list_my_groups
        """
        group_id, group, error = await _require_membership(group_id)
        if error or group is None:
            return error or _INVALID_GROUP_ID

        # exclude_inactive defaults to false: without it, members whose course
        # enrollment was deactivated or dropped are listed as current members.
        members = await fetch_all_paginated_results(
            f"/groups/{group_id}/users", {"per_page": 100, "exclude_inactive": True}
        )
        if _is_error(members):
            return _access_error("list members", group_id, members.get("error"))
        if not isinstance(members, list) or not members:
            return f"No members are listed for group {group_id}."

        lines = [f"Members of {await _group_label(group)} ({len(members)}):", ""]
        for member in members:
            if not isinstance(member, dict):
                continue
            # Explicit allowlist: id and display name only. Email, login_id
            # and SIS identifiers are never printed, whatever Canvas returns
            # and whether or not anonymization is enabled.
            name = member.get("name") or member.get("short_name") or "Unnamed user"
            lines.append(
                f"  - {fence_untrusted_inline(name, 'user name')} (ID: {member.get('id')})"
            )
        if get_config().enable_data_anonymization:
            lines.append("")
            lines.append(
                "Note: data anonymization is on, so classmates' names are pseudonyms."
            )
        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    @validate_params
    async def list_group_discussion_topics(group_id: str | int) -> str:
        """List the discussion topics in one of your groups.

        Group discussions are separate from course discussions. Use
        get_group_discussion with a topic ID to read the posts.

        Args:
            group_id: Canvas group ID from list_my_groups
        """
        group_id, group, error = await _require_membership(group_id)
        if error or group is None:
            return error or _INVALID_GROUP_ID

        topics = await fetch_all_paginated_results(
            f"/groups/{group_id}/discussion_topics", {"per_page": 100}
        )
        if _is_error(topics):
            return _access_error("list discussions", group_id, topics.get("error"))
        if not isinstance(topics, list) or not topics:
            return f"No discussion topics in group {group_id}."

        lines = [f"Discussion topics in {await _group_label(group)}:", ""]
        for topic in topics:
            if not isinstance(topic, dict):
                continue
            title = _scrub(topic.get("title") or "Untitled topic")
            lines.append(f"ID: {topic.get('id')}")
            lines.append(f"Title:\n{fence_untrusted(title, 'group discussion topic title')}")
            lines.append(f"Posted: {format_date(topic.get('posted_at'))}")
            lines.append(f"Last reply: {format_date(topic.get('last_reply_at'))}")
            lines.append(f"Replies: {topic.get('discussion_subentry_count', 0)}")
            if topic.get("locked"):
                lines.append("Locked: yes")
            lines.append("")
        return "\n".join(lines).rstrip()

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    @validate_params
    async def get_group_discussion(group_id: str | int, topic_id: str | int) -> str:
        """Read a group discussion topic (or group announcement) with all its posts.

        Returns the topic title and body, then every entry and reply as a thread.

        Args:
            group_id: Canvas group ID from list_my_groups
            topic_id: Discussion topic ID from list_group_discussion_topics
                or list_group_announcements
        """
        clean_topic_id = coerce_canvas_id(topic_id)
        if clean_topic_id is None:
            return _INVALID_TOPIC_ID
        group_id, group, error = await _require_membership(group_id)
        if error or group is None:
            return error or _INVALID_GROUP_ID

        topic = await make_canvas_request(
            "get", f"/groups/{group_id}/discussion_topics/{clean_topic_id}"
        )
        if _is_error(topic):
            return _access_error("read that discussion topic", group_id, topic.get("error"))
        if not isinstance(topic, dict):
            return f"Error: unexpected response for topic {clean_topic_id}."

        # /view is the documented "full topic" read: all entries with bodies,
        # plus a participants list. It is anonymized at the client layer. The
        # view is eventually consistent; include_new_entries=1 returns the
        # entries not yet reflected in it, which are merged in below.
        view = await make_canvas_request(
            "get",
            f"/groups/{group_id}/discussion_topics/{clean_topic_id}/view",
            params={"include_new_entries": 1},
        )
        view_note: str | None = None
        participants: dict[str, str] = {}
        entries: list[Any] = []
        if _is_error(view):
            view_error = str(view.get("error"))
            status = _http_status(view_error)
            if status == 403 and "require_initial_post" in view_error:
                view_note = (
                    "Replies are hidden until you post in this discussion "
                    "(the topic requires an initial post)."
                )
            elif status == 503:
                view_note = (
                    "Canvas is still preparing this discussion's posts "
                    "(HTTP 503). Try again in a moment."
                )
            else:
                view_note = f"Could not load the posts: {view_error}"
        elif isinstance(view, dict):
            for person in view.get("participants") or []:
                if isinstance(person, dict) and person.get("id") is not None:
                    participants[str(person["id"])] = (
                        person.get("display_name") or "Unknown user"
                    )
            entries = [e for e in view.get("view") or [] if isinstance(e, dict)]
            entries = _merge_new_entries(entries, view.get("new_entries"))

        kind = "Announcement" if topic.get("is_announcement") else "Discussion"
        title = _scrub(topic.get("title") or "Untitled topic")
        author_id = (topic.get("author") or {}).get("id") or topic.get("user_id")
        author_name = participants.get(str(author_id)) if author_id is not None else None

        lines = [
            f"{kind} in {await _group_label(group)}",
            f"Topic ID: {clean_topic_id}",
            f"Title:\n{fence_untrusted(title, 'group discussion topic title')}",
            f"Posted: {format_date(topic.get('posted_at'))}",
        ]
        if author_id is not None:
            shown = (
                fence_untrusted_inline(author_name, "author name") if author_name
                else "name not shown"
            )
            lines.append(f"Author: {shown} (user ID: {author_id})")
        # The client layer already scrubs this record (group topics are in the
        # full tier); scrubbing again after HTML stripping is idempotent and
        # catches addresses split by markup.
        body = _scrub(_plain_text(topic.get("message")))
        if body:
            lines.append(f"Body:\n{fence_untrusted(body, 'group discussion topic body')}")
        lines.append("")

        if view_note:
            lines.append(view_note)
        elif not entries:
            lines.append("No posts yet.")
        else:
            rendered, posts, deleted = _render_view_entries(entries, participants)
            deleted_note = f", plus {deleted} deleted" if deleted else ""
            lines.append(f"Posts ({posts}{deleted_note}):")
            lines.extend(rendered)
        return "\n".join(lines).rstrip()

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    @validate_params
    async def list_group_announcements(group_id: str | int) -> str:
        """List the announcements posted in one of your groups.

        Canvas's /announcements endpoint only accepts courses, so this reads
        the group's discussion topics with only_announcements=true. Use
        get_group_discussion with the ID to read one.

        Args:
            group_id: Canvas group ID from list_my_groups
        """
        group_id, group, error = await _require_membership(group_id)
        if error or group is None:
            return error or _INVALID_GROUP_ID

        announcements = await fetch_all_paginated_results(
            f"/groups/{group_id}/discussion_topics",
            {"only_announcements": True, "per_page": 100},
        )
        if _is_error(announcements):
            return _access_error("list announcements", group_id, announcements.get("error"))
        if not isinstance(announcements, list) or not announcements:
            return f"No announcements in group {group_id}."

        lines = [f"Announcements in {await _group_label(group)}:", ""]
        for item in announcements:
            if not isinstance(item, dict):
                continue
            title = _scrub(item.get("title") or "Untitled announcement")
            lines.append(f"ID: {item.get('id')}")
            lines.append(f"Title:\n{fence_untrusted(title, 'group announcement title')}")
            lines.append(f"Posted: {format_date(item.get('posted_at'))}")
            lines.append("")
        return "\n".join(lines).rstrip()

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    @validate_params
    async def list_group_files(
        group_id: str | int,
        search_term: str | None = None,
        sort: str = "updated_at",
        order: str = "desc",
    ) -> str:
        """List the files stored in one of your groups.

        Args:
            group_id: Canvas group ID from list_my_groups
            search_term: Only files whose name contains this text (2+ characters)
            sort: name, size, created_at, updated_at or content_type (default: updated_at)
            order: "asc" or "desc" (default: desc)
        """
        if sort not in _VALID_FILE_SORTS:
            return (
                f"Error: invalid sort '{sort}'. Use one of: "
                f"{', '.join(sorted(_VALID_FILE_SORTS))}."
            )
        if order not in ("asc", "desc"):
            return f"Error: invalid order '{order}'. Use 'asc' or 'desc'."
        search_term = (search_term or "").strip() or None
        if search_term is not None and len(search_term) < 2:
            # Canvas rejects shorter search terms with a 400.
            return "Error: search_term must be at least 2 characters."

        group_id, group, error = await _require_membership(group_id)
        if error or group is None:
            return error or _INVALID_GROUP_ID

        params: dict[str, Any] = {"per_page": 100, "sort": sort, "order": order}
        if search_term:
            params["search_term"] = search_term

        files = await fetch_all_paginated_results(f"/groups/{group_id}/files", params)
        if _is_error(files):
            return _access_error("list files", group_id, files.get("error"))
        if not isinstance(files, list) or not files:
            if search_term:
                return f"No files in group {group_id} match that search."
            return f"No files in group {group_id}."

        lines = [f"Files in {await _group_label(group)}:", ""]
        for item in files:
            if not isinstance(item, dict):
                continue
            name = item.get("display_name") or item.get("filename") or "unknown"
            size = format_file_size(item.get("size") or 0)
            raw_type = item.get("content-type")
            content_type = (
                raw_type if isinstance(raw_type, str) and _MIME_TYPE.fullmatch(raw_type)
                else "unknown type"
            )
            updated = format_date(item.get("updated_at"))
            lines.append(
                f"  ID: {item.get('id')} | {fence_untrusted_inline(name, 'file name')} "
                f"({size}, {content_type}, updated {updated})"
            )
        lines.append("")
        lines.append(f"Total: {len(files)} file(s)")
        return "\n".join(lines)
