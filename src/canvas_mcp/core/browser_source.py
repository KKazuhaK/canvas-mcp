"""Answer Canvas reads from snapshots uploaded by the student's browser extension.

When a school does not let students create access tokens, the extension reads
Canvas with the student's own browser session and uploads the JSON. A request
whose data source is such a binding never reaches Canvas: ``answer_get`` finds
the stored snapshot that answers the call the tool made, or fails with a
message that says why. See ``deploy/selfhost/BROWSER-SYNC-DESIGN.md``.

Matching is deliberately conservative. A stored snapshot answers a call only
when the data it holds is provably what Canvas would have returned: the same
path, the same filters, a stored ``include[]`` that is a superset of the one
asked for, and (for date windows) a stored window that covers the asked one.
Anything else is a miss, never a guess.
"""

from __future__ import annotations

import copy
import datetime as dt
import re
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .credentials import BrowserSource
from .error_codes import PERMISSION_DENIED, SOURCE_UNAVAILABLE

#: Parameters that only choose how a list is cut into pages. The stored list is whole.
IGNORED_PARAMS = frozenset({"per_page", "page"})
INCLUDE = "include[]"
EXCLUDES = "excludes[]"
CONTEXT_CODES = "context_codes[]"
WINDOW_PARAMS = ("start_date", "end_date")
ALWAYS_EXCLUDED = frozenset({"child_events"})

#: The field that places an item inside a date window, per Canvas path.
DATE_FIELDS: Mapping[str, str] = {
    "/planner/items": "plannable_date",
    "/calendar_events": "start_at",
    "/announcements": "posted_at",
    "/planner_notes": "todo_date",
}
#: These return items of every context the student can see when no
#: ``context_codes[]`` is given, so a stored copy covers any code asked for.
ALL_CONTEXT_PATHS = frozenset({"/planner/items", "/planner_notes"})

_NUMERIC_ID = re.compile(r"^[0-9]+$")

READ_ONLY_MESSAGE = "Browser sync is read-only: this request would change Canvas, so it was not sent."
NOT_SYNCED_MESSAGE = (
    "This data has not been synced by the browser extension yet. "
    "Open Canvas in the browser with the extension installed to sync it."
)
UNSUPPORTED_ROOT_MESSAGE = (
    "Browser sync only serves the standard Canvas REST API, not this part of Canvas."
)


@dataclass(frozen=True)
class BrowserSnapshot:
    """One stored Canvas response."""

    path: str
    #: Every value is a list of strings, in the order the extension sent them.
    query: Mapping[str, list[str]]
    captured_at: int
    status: int
    body: Any


class BrowserMiss(Exception):
    """The request cannot be answered from browser data."""

    def __init__(self, code: str, message: str, *, stored_status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        #: Set when the miss is a Canvas status stored for the data asked for.
        self.stored_status = stored_status


# -- freshness -------------------------------------------------------------------------

_used_captures: ContextVar[list[int] | None] = ContextVar("browser_used_captures", default=None)


@contextmanager
def capture_freshness() -> Iterator[list[int]]:
    """Collect the ``captured_at`` of every snapshot used while one tool call runs."""
    used: list[int] = []
    token = _used_captures.set(used)
    try:
        yield used
    finally:
        _used_captures.reset(token)


def _note_used(captured_at: int) -> None:
    used = _used_captures.get()
    if used is not None:
        used.append(captured_at)


def freshness_note(
    used: Sequence[int], *, now: float | None = None, stale_after_seconds: int = 24 * 3600
) -> str | None:
    """The line appended to a tool result that was answered from browser data."""
    if not used:
        return None
    age = max(0, int((time.time() if now is None else now) - min(used)))
    note = f"Data synced from your browser {_ago(age)}."
    if age > stale_after_seconds:
        note += " It may be out of date; open Canvas in the browser to refresh it."
    return note


def _ago(seconds: int) -> str:
    if seconds < 90:
        return "less than a minute ago" if seconds < 60 else "1 minute ago"
    minutes = seconds // 60
    if minutes < 90:
        return f"{minutes} minutes ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours} hours ago"
    return f"{hours // 24} days ago"


# -- parameter normalisation --------------------------------------------------------------


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def normalize_params(params: Mapping[str, Any] | None) -> dict[str, list[str]]:
    """Request parameters the way httpx would put them on the wire: strings, lists for repeats."""
    out: dict[str, list[str]] = {}
    for key, value in (params or {}).items():
        if value is None:
            continue
        if isinstance(value, (list, tuple, set, frozenset)):
            values = [_scalar(item) for item in value if item is not None]
        else:
            values = [_scalar(value)]
        if key.endswith("[]") or values:
            out[key] = values
    return out


def canonical_query(query: Mapping[str, Sequence[str]]) -> str:
    """The stable text form of a query: keys sorted, repeated values sorted."""
    from urllib.parse import urlencode

    pairs: list[tuple[str, str]] = []
    for key in sorted(query):
        pairs.extend((key, value) for value in sorted(query[key]))
    return urlencode(pairs)


# -- dates -----------------------------------------------------------------------------------


#: The zone date-only bounds are read in for the request being answered.
_date_zone: ContextVar[dt.tzinfo | None] = ContextVar("browser_date_zone", default=None)


def parse_when(
    value: str, *, end: bool, zone: dt.tzinfo | None = None
) -> dt.datetime | None:
    """A Canvas ``start_date`` or ``end_date`` as an aware datetime, or None.

    A date-only bound is a day in the student's Canvas time zone (Canvas applies
    ``beginning_of_day`` / ``end_of_day`` there), and the end covers its whole
    day. With no zone known it cannot be placed on the timeline: None.
    """
    text = value.strip()
    if not text:
        return None
    try:
        if len(text) == 10:
            local = zone or _date_zone.get()
            if local is None:
                return None
            day = dt.date.fromisoformat(text)
            if end:
                # The instant before the next local midnight: a day is 23 or 25 hours on
                # a DST change, so this cannot be "midnight plus 24 hours".
                following = dt.datetime.combine(day + dt.timedelta(days=1), dt.time(), tzinfo=local)
                return following.astimezone(dt.UTC) - dt.timedelta(microseconds=1)
            return dt.datetime.combine(day, dt.time(), tzinfo=local).astimezone(dt.UTC)
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


def _item_time(item: Any, field: str) -> dt.datetime | None:
    if not isinstance(item, dict):
        return None
    value = item.get(field)
    if not isinstance(value, str):
        return None
    return parse_when(value, end=False, zone=dt.UTC)


def _window(query: Mapping[str, Sequence[str]]) -> tuple[dt.datetime, dt.datetime] | None:
    starts, ends = query.get("start_date"), query.get("end_date")
    if not starts or not ends or len(starts) != 1 or len(ends) != 1:
        return None
    start, end = parse_when(starts[0], end=False), parse_when(ends[0], end=True)
    if start is None or end is None or end < start:
        return None
    return start, end


def _in_window(path: str, item: Any, start: dt.datetime, end: dt.datetime) -> bool:
    field = DATE_FIELDS[path]
    begins = _item_time(item, field)
    if begins is None:
        return False
    if path == "/calendar_events":
        finishes = _item_time(item, "end_at") or begins
        return begins <= end and finishes >= start
    return start <= begins <= end


# -- contexts ----------------------------------------------------------------------------------


def _context_of(item: Any) -> str | None:
    if not isinstance(item, dict):
        return None
    code = item.get("context_code")
    if isinstance(code, str) and code:
        return code
    for key, prefix in (("course_id", "course"), ("group_id", "group")):
        value = item.get(key)
        if value not in (None, ""):
            return f"{prefix}_{value}"
    plannable = item.get("plannable")
    if isinstance(plannable, dict):
        for key, prefix in (("course_id", "course"), ("group_id", "group")):
            value = plannable.get(key)
            if value not in (None, ""):
                return f"{prefix}_{value}"
    return None


def _item_in_context(item: Any, code: str) -> bool:
    context = _context_of(item)
    if context is None:
        # Nothing names a course or group: a personal item.
        return code.startswith("user_")
    return context == code


# -- matching ---------------------------------------------------------------------------------


@dataclass
class _Fit:
    """How one stored snapshot answers one request."""

    snapshot: BrowserSnapshot
    window: tuple[dt.datetime, dt.datetime] | None = None
    type_filter: str | None = None
    extra_excludes: tuple[str, ...] = ()
    covers: frozenset[str] | None = None  # None: every context asked for


def _fit(
    snapshot: BrowserSnapshot,
    wanted: Mapping[str, list[str]],
    *,
    lenient: bool,
) -> _Fit | None:
    """The way ``snapshot`` can answer ``wanted``, or None if it cannot."""
    stored = snapshot.query
    path = snapshot.path

    stored_include = set(stored.get(INCLUDE, ()))
    if not set(wanted.get(INCLUDE, ())) <= stored_include:
        return None

    # ``child_events`` carries other students' appointment reservations. Browser
    # sync never stores them, whether or not the request asks to leave them out.
    stored_excludes = set(stored.get(EXCLUDES, ())) - ALWAYS_EXCLUDED
    wanted_excludes = set(wanted.get(EXCLUDES, ())) - ALWAYS_EXCLUDED
    if not stored_excludes <= wanted_excludes:
        return None
    extra_excludes = tuple(sorted(wanted_excludes - stored_excludes))

    handled = {INCLUDE, EXCLUDES, CONTEXT_CODES, "type", *WINDOW_PARAMS}
    # ``all_dates`` only asks for an include the stored copy already has.
    if "all_dates" in stored_include or lenient:
        handled.add("all_dates")

    keys = (set(wanted) | set(stored)) - handled - IGNORED_PARAMS
    for key in keys:
        if key not in wanted:
            if lenient:
                continue
            return None
        if key not in stored or sorted(wanted[key]) != sorted(stored[key]):
            return None

    fit = _Fit(snapshot, extra_excludes=extra_excludes)

    if "type" in wanted:
        if "type" in stored:
            if sorted(wanted["type"]) != sorted(stored["type"]):
                return None
        else:
            if len(wanted["type"]) != 1:
                return None
            fit.type_filter = wanted["type"][0]
    elif "type" in stored and not lenient:
        return None

    stored_window = _window(stored)
    wanted_window = _window(wanted)
    stored_has = any(key in stored for key in WINDOW_PARAMS)
    wanted_has = any(key in wanted for key in WINDOW_PARAMS)
    if stored_has or wanted_has:
        if lenient and stored_has and not wanted_has:
            pass
        elif (
            stored_window is None
            or wanted_window is None
            or path not in DATE_FIELDS
            or wanted_window[0] < stored_window[0]
            or wanted_window[1] > stored_window[1]
        ):
            return None
        else:
            fit.window = wanted_window

    if CONTEXT_CODES in wanted:
        if CONTEXT_CODES in stored:
            fit.covers = frozenset(stored[CONTEXT_CODES])
        elif path in ALL_CONTEXT_PATHS:
            fit.covers = None
        else:
            return None
    elif CONTEXT_CODES in stored and not lenient:
        return None
    return fit


def _filtered(fit: _Fit, body: Any, code: str | None) -> Any:
    """The stored body cut down to what the request asked for."""
    if not isinstance(body, list):
        return body
    items = body
    if fit.type_filter is not None:
        items = [
            item
            for item in items
            if isinstance(item, dict) and item.get("type") == fit.type_filter
        ]
    if fit.window is not None:
        start, end = fit.window
        items = [item for item in items if _in_window(fit.snapshot.path, item, start, end)]
    if code is not None:
        items = [item for item in items if _item_in_context(item, code)]
    if fit.extra_excludes:
        items = [
            {k: v for k, v in item.items() if k not in fit.extra_excludes}
            if isinstance(item, dict)
            else item
            for item in items
        ]
    return items


def _usable(snapshots: Sequence[BrowserSnapshot], source: BrowserSource, now: float) -> list[BrowserSnapshot]:
    """Raise a miss when every candidate is too old; otherwise keep the fresh ones."""
    fresh = [s for s in snapshots if now - s.captured_at <= source.max_age_seconds]
    if snapshots and not fresh:
        days = max(1, source.max_age_seconds // 86400)
        raise BrowserMiss(
            SOURCE_UNAVAILABLE,
            f"The data synced from your browser is more than {days} days old, so it "
            "was not used. Open Canvas in the browser with the extension installed to refresh it.",
        )
    return fresh


def _status_miss(snapshot: BrowserSnapshot) -> BrowserMiss:
    return BrowserMiss(
        SOURCE_UNAVAILABLE,
        f"Canvas answered the browser extension with HTTP {snapshot.status} for this data. "
        + (
            "This school blocks session access to the Canvas API, so browser sync cannot read it."
            if snapshot.status in (401, 403)
            else "It is not available to browser sync."
        ),
        stored_status=snapshot.status,
    )


async def _session_works(source: BrowserSource) -> bool:
    """Whether Canvas answered the extension's own ``/users/self`` read with data."""
    return any(s.status == 200 for s in await source.load("/users/self"))


async def answer_get(
    source: BrowserSource,
    endpoint: str,
    params: Mapping[str, Any] | None,
    *,
    now: float | None = None,
) -> Any:
    """The body a Canvas ``GET endpoint?params`` would return, from stored snapshots.

    Raises :class:`BrowserMiss` when stored data cannot answer it.
    """
    clock = time.time() if now is None else now
    wanted = normalize_params(params)
    path = endpoint.split("?", 1)[0].rstrip("/") or "/"

    zone = None
    if any(len(v.strip()) == 10 for key in WINDOW_PARAMS for v in wanted.get(key, ())):
        zone = await _student_zone(source)
    marker = _date_zone.set(zone)
    try:
        return await _answer(source, path, wanted, clock)
    except BrowserMiss as miss:
        # A refusal of one resource says nothing about the school when the student's
        # own profile was read fine: only claim "the school blocks" when nothing was.
        if miss.stored_status in (401, 403) and await _session_works(source):
            raise BrowserMiss(
                SOURCE_UNAVAILABLE,
                f"Canvas refused access to this data (HTTP {miss.stored_status}).",
                stored_status=miss.stored_status,
            ) from None
        raise
    finally:
        _date_zone.reset(marker)


async def _student_zone(source: BrowserSource) -> dt.tzinfo | None:
    """The student's Canvas time zone: their profile, else the server's ``TIMEZONE``, else None."""
    profiles = sorted(
        await source.load("/users/self/profile"), key=lambda s: -s.captured_at
    )
    for snapshot in profiles:
        name = snapshot.body.get("time_zone") if isinstance(snapshot.body, dict) else None
        if snapshot.status == 200 and isinstance(name, str) and name:
            try:
                return ZoneInfo(name)
            except (ZoneInfoNotFoundError, ValueError, OSError):
                break
    from .dates import output_timezone

    configured = output_timezone()
    return None if configured is dt.UTC else configured


async def _answer(
    source: BrowserSource, path: str, wanted: dict[str, list[str]], clock: float
) -> Any:
    exact = await source.load(path)
    if exact:
        return _answer_list(source, exact, wanted, clock, path=path, lenient=False)

    last = path.rsplit("/", 1)[-1]
    if _NUMERIC_ID.fullmatch(last):
        parent = path.rsplit("/", 1)[0] or "/"
        parents = await source.load(parent)
        if parents:
            return _answer_object(source, parents, wanted, clock, path=parent, object_id=last)
    raise BrowserMiss(SOURCE_UNAVAILABLE, NOT_SYNCED_MESSAGE)


def _candidates(
    snapshots: Sequence[BrowserSnapshot],
    wanted: Mapping[str, list[str]],
    lenient: bool,
) -> list[_Fit]:
    fits = [fit for s in snapshots if (fit := _fit(s, wanted, lenient=lenient))]
    # A successful copy beats a failed one; among equals the newest wins.
    fits.sort(key=lambda f: (f.snapshot.status != 200, -f.snapshot.captured_at))
    return fits


def _answer_list(
    source: BrowserSource,
    snapshots: Sequence[BrowserSnapshot],
    wanted: Mapping[str, list[str]],
    now: float,
    *,
    path: str,
    lenient: bool,
) -> Any:
    fresh = _usable(snapshots, source, now)
    fits = _candidates(fresh, wanted, lenient)
    if not fits:
        raise BrowserMiss(SOURCE_UNAVAILABLE, NOT_SYNCED_MESSAGE)

    codes = wanted.get(CONTEXT_CODES)
    if not codes:
        best = fits[0]
        if best.snapshot.status != 200:
            raise _status_miss(best.snapshot)
        _note_used(best.snapshot.captured_at)
        return copy.deepcopy(_filtered(best, best.snapshot.body, None))

    merged: list[Any] = []
    seen: set[tuple[str, str]] = set()
    for code in dict.fromkeys(codes):
        chosen = next(
            (f for f in fits if f.covers is None or code in f.covers), None
        )
        if chosen is None:
            raise BrowserMiss(SOURCE_UNAVAILABLE, NOT_SYNCED_MESSAGE)
        if chosen.snapshot.status != 200:
            raise _status_miss(chosen.snapshot)
        _note_used(chosen.snapshot.captured_at)
        body = chosen.snapshot.body
        if not isinstance(body, list):
            raise BrowserMiss(SOURCE_UNAVAILABLE, NOT_SYNCED_MESSAGE)
        for item in _filtered(chosen, body, code):
            key = (code, str(item.get("id")) if isinstance(item, dict) else repr(item))
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
    return copy.deepcopy(merged)


def _answer_object(
    source: BrowserSource,
    snapshots: Sequence[BrowserSnapshot],
    wanted: Mapping[str, list[str]],
    now: float,
    *,
    path: str,
    object_id: str,
) -> Any:
    """One object, found by id in a stored list at its parent path."""
    fresh = _usable(snapshots, source, now)
    # Window, context and type narrow a list; they say nothing about one object.
    own = {k: v for k, v in wanted.items() if k not in (*WINDOW_PARAMS, CONTEXT_CODES, "type")}
    fits = _candidates(fresh, own, True)
    if not fits:
        raise BrowserMiss(SOURCE_UNAVAILABLE, NOT_SYNCED_MESSAGE)
    failed: BrowserSnapshot | None = None
    for fit in fits:
        snapshot = fit.snapshot
        if snapshot.status != 200:
            failed = failed or snapshot
            continue
        body = snapshot.body
        if not isinstance(body, list):
            continue
        for item in body:
            if isinstance(item, dict) and str(item.get("id")) == object_id:
                _note_used(snapshot.captured_at)
                extra = fit.extra_excludes
                found = {k: v for k, v in item.items() if k not in extra} if extra else item
                return copy.deepcopy(found)
    if failed is not None:
        raise _status_miss(failed)
    raise BrowserMiss(
        SOURCE_UNAVAILABLE,
        "That item was not found in the data synced by the browser extension. "
        "It may be new; open Canvas in the browser to sync again.",
    )


def refusal_for(method: str, api_root: str) -> BrowserMiss | None:
    """Why a request can never be answered from browser data, or None."""
    if method.lower() != "get":
        return BrowserMiss(PERMISSION_DENIED, READ_ONLY_MESSAGE)
    if api_root != "rest":
        return BrowserMiss(SOURCE_UNAVAILABLE, UNSUPPORTED_ROOT_MESSAGE)
    return None
