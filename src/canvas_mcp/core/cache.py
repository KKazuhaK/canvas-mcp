"""Course caching system for Canvas API."""

from collections.abc import Iterable, Mapping
from typing import Any

from .client import fetch_all_paginated_results, make_canvas_request
from .logging import log_error, log_info
from .validation import coerce_canvas_id, validate_params

# Global cache for course codes to IDs
course_code_to_id_cache: dict[str, str] = {}
id_to_course_code_cache: dict[str, str] = {}
# Every course from the last refresh as (id, course_code, name, sis_course_id),
# so resolve_numeric_course_id can also find a course by name or SIS ID.
CourseRecord = tuple[str, str, str, str]
course_records_cache: list[CourseRecord] = []

SIS_COURSE_PREFIX = "sis_course_id:"
# A SIS token is sent as one path segment, so nothing that could end the
# segment, start a query or fragment, or be decoded into one is allowed.
_SIS_TOKEN_FORBIDDEN = frozenset("/\\?#%")


async def refresh_course_cache() -> bool:
    """Refresh the global course cache."""
    global course_code_to_id_cache, id_to_course_code_cache, course_records_cache

    log_info("Refreshing course cache")
    courses = await fetch_all_paginated_results("/courses", {"per_page": 100})

    if isinstance(courses, dict) and "error" in courses:
        log_error("Error building course cache", error=courses.get("error"))
        return False

    # Build caches for bidirectional lookups
    course_code_to_id_cache = {}
    id_to_course_code_cache = {}
    course_records_cache = course_records(courses)

    for course in courses:
        course_id = str(course.get("id"))
        course_code = course.get("course_code")

        if course_code and course_id:
            course_code_to_id_cache[course_code] = course_id
            id_to_course_code_cache[course_id] = course_code

    log_info(f"Cached {len(course_code_to_id_cache)} course codes")
    return True


@validate_params
async def get_course_id(course_identifier: str | int) -> str:
    """Get course ID from either course code or ID, with caching.

    Args:
        course_identifier: The course identifier, which can be:
                          - A course code (e.g., 'badm_554_120251_246794')
                          - A numeric course ID (as string or int)
                          - A SIS ID format (e.g., 'sis_course_id:xxx')

    Returns:
        The course ID as a string
    """
    global course_code_to_id_cache, id_to_course_code_cache

    # Convert to string for consistent handling
    course_str = str(course_identifier)

    # If it looks like a numeric ID
    if course_str.isdigit():
        return course_str

    # If it's a SIS ID format
    if course_str.startswith("sis_course_id:"):
        return course_str

    # If it's in our cache, return the ID
    if course_str in course_code_to_id_cache:
        return course_code_to_id_cache[course_str]

    # If it looks like a course code (contains underscores)
    if "_" in course_str:
        # Try to refresh cache if it's not there
        if not course_code_to_id_cache:
            await refresh_course_cache()
            if course_str in course_code_to_id_cache:
                return course_code_to_id_cache[course_str]

        # Return SIS format as a fallback
        return f"sis_course_id:{course_str}"

    # Last resort, return as is
    return course_str


async def get_course_code(course_id: str | int) -> str | None:
    """Get course code from ID, with caching."""
    global id_to_course_code_cache, course_code_to_id_cache

    course_id = str(course_id)

    # If it's already a code-like string with underscores
    if "_" in course_id:
        return course_id

    # If it's in our cache, return the code
    if course_id in id_to_course_code_cache:
        return id_to_course_code_cache[course_id]

    # Try to refresh cache if it's not there
    if not id_to_course_code_cache:
        await refresh_course_cache()
        if course_id in id_to_course_code_cache:
            return id_to_course_code_cache[course_id]

    # If we can't find a code, try to fetch the course directly
    response = await make_canvas_request("get", f"/courses/{course_id}")
    if "error" not in response and "course_code" in response:
        code: str | None = response.get("course_code", "")
        # Update our cache
        if code:
            id_to_course_code_cache[course_id] = code
            course_code_to_id_cache[code] = course_id
        return code

    # Last resort, return the ID
    return course_id


def course_records(courses: Iterable[Any]) -> list[CourseRecord]:
    """Canvas course objects as the records ``resolve_numeric_course_id`` matches."""
    records: list[CourseRecord] = []
    for course in courses:
        if not isinstance(course, dict):
            continue
        course_id = coerce_canvas_id(course.get("id", ""))
        if course_id is None:
            continue
        records.append((
            course_id,
            str(course.get("course_code") or ""),
            str(course.get("name") or ""),
            str(course.get("sis_course_id") or ""),
        ))
    return records


def _alias_key(value: object) -> str:
    """A course alias compared case-insensitively, ignoring surrounding whitespace."""
    return str(value).strip().casefold()


def _match_course(
    identifier: str,
    records: Iterable[CourseRecord],
    codes: Mapping[str, str] | None = None,
) -> tuple[str | None, str | None]:
    """Find one course by course code, then SIS ID, then name.

    Returns ``(course_id, None)`` for a single match, ``(None, error)`` when
    the first alias kind that matches at all matches more than one course, and
    ``(None, None)`` when nothing matches.
    """
    key = _alias_key(identifier)
    by_code: set[str] = set()
    by_sis: set[str] = set()
    by_name: set[str] = set()
    for course_id, code, name, sis in records:
        if code and _alias_key(code) == key:
            by_code.add(course_id)
        if sis and key in (_alias_key(sis), _alias_key(SIS_COURSE_PREFIX + sis)):
            by_sis.add(course_id)
        if name and _alias_key(name) == key:
            by_name.add(course_id)
    for code, cached_id in (codes or {}).items():
        numeric = coerce_canvas_id(cached_id)
        if numeric is not None and _alias_key(code) == key:
            by_code.add(numeric)
    for matches in (by_code, by_sis, by_name):
        if len(matches) == 1:
            return next(iter(matches)), None
        if matches:
            ids = ", ".join(sorted(matches, key=int))
            return None, (
                f"Could not find course {identifier}: it matches more than one of "
                f"your courses (IDs {ids}). Pass the numeric Canvas course ID."
            )
    return None, None


def is_safe_sis_course_form(identifier: str) -> bool:
    """True for ``sis_course_id:<token>`` whose token is one plain path segment."""
    if not identifier.startswith(SIS_COURSE_PREFIX):
        return False
    token = identifier[len(SIS_COURSE_PREFIX):]
    return (
        bool(token)
        and ".." not in token
        and not any(
            ch in _SIS_TOKEN_FORBIDDEN or ch.isspace() or not ch.isprintable()
            for ch in token
        )
    )


async def resolve_numeric_course_id(
    course_identifier: str | int,
    *,
    courses: Iterable[Any] | None = None,
) -> tuple[str | None, str | None]:
    """Resolve any accepted course identifier to a numeric Canvas course ID.

    Returns ``(course_id, None)`` or ``(None, error)``; the error always
    starts with ``Could not find course``. Unlike ``get_course_id`` this never
    hands back an unresolved string, so its result is safe in a request path,
    a ``course_<id>`` context code, or a numeric comparison.

    - A numeric ID is returned unchanged, with no request.
    - ``sis_course_id:<token>`` is looked up with ``GET /courses/<form>``, but
      only when the token is a single plain path segment (no ``/``, backslash,
      ``?``, ``#``, ``%``, ``..``, whitespace or control characters). Any
      other SIS form is refused without a request.
    - Anything else (a course code such as ``COMPSCI 161``, a course name, or
      a bare SIS ID) is matched case-insensitively, ignoring surrounding
      whitespace, against the caller's courses: course code first, then SIS
      ID, then name. On a miss the course cache is refreshed once and searched
      again, whether it was cold or warm. The identifier is never sent to
      Canvas.

    Args:
        course_identifier: The identifier the caller gave.
        courses: Canvas course objects to match against instead of the course
            cache; no refresh is made. Numeric and SIS forms behave as above.
    """
    raw = str(course_identifier).strip()
    not_found = f"Could not find course {course_identifier}"
    not_listed = (
        f"{not_found} among your Canvas courses. Use a course code or name from "
        "list_courses, or a numeric Canvas course ID."
    )
    if not raw:
        return None, not_listed

    numeric = coerce_canvas_id(raw)
    if numeric is not None:
        return numeric, None

    if raw.startswith(SIS_COURSE_PREFIX):
        if not is_safe_sis_course_form(raw):
            return None, (
                f"{not_found}: the value after sis_course_id: must be a single "
                "SIS ID without slashes, backslashes, ?, #, %, .. or spaces."
            )
        course = await make_canvas_request("get", f"/courses/{raw}")
        if not isinstance(course, dict) or "error" in course:
            detail = course.get("error") if isinstance(course, dict) else course
            return None, f"{not_found}: {detail}"
        found = coerce_canvas_id(course.get("id", ""))
        return (found, None) if found is not None else (None, not_found)

    if courses is not None:
        found, error = _match_course(raw, course_records(courses))
        return (found, None) if found is not None else (None, error or not_listed)

    found, error = _match_course(raw, course_records_cache, course_code_to_id_cache)
    if found is not None or error:
        return found, error
    if not await refresh_course_cache():
        return None, f"{not_found}: your course list could not be loaded from Canvas."
    found, error = _match_course(raw, course_records_cache, course_code_to_id_cache)
    if found is not None or error:
        return found, error
    return None, not_listed
