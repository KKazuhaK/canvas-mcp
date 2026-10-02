"""Reaching course files when the Files tab is hidden, and fetching their bytes.

Two student problems this module solves:

1. Many instructors hide the course Files tab and hand out slides through
   modules instead. For a student, ``GET /courses/:id/files`` (and possibly
   ``GET /courses/:id/files/:id``) is then refused with 401/403, even though
   every file linked from a module is readable. ``list_files_via_modules`` and
   ``fetch_module_linked_file`` recover those files through the Modules API.
   The fallback only ever reaches files the course itself links from a module,
   so it never widens access beyond what Canvas already shows the student.

2. Downloading a file means following Canvas's download URL, which redirects
   to a storage host (S3 / Instructure file service). ``download_file_bytes``
   sends the Canvas token only to the configured Canvas origin and follows each
   redirect hop by hand, so a hop to any other host goes out without
   credentials and over HTTPS only. This does not rely on the HTTP library's
   redirect-header policy, and avoids the pattern in
   ``client.upload_file_to_storage``, which follows a ``Location`` with the
   authenticated client.
"""

import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx

from .client import (
    canvas_authenticated_client,
    fetch_all_paginated_results,
    make_canvas_request,
)
from .config import get_config
from .credentials import get_request_credentials
from .validation import coerce_canvas_id

#: Canvas statuses that mean "you may not list/see this through this route".
ACCESS_DENIED_STATUSES = frozenset({401, 403})

#: Redirect hops followed by ``download_file_bytes`` before giving up. A Canvas
#: download normally takes one (Canvas -> storage).
MAX_DOWNLOAD_REDIRECTS = 5

_HTTP_STATUS = re.compile(r"^HTTP error: (\d{3})\b")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def canvas_error_status(response: Any) -> int | None:
    """HTTP status carried by a ``make_canvas_request`` error dict, if any."""
    if not isinstance(response, dict):
        return None
    error = response.get("error")
    if not isinstance(error, str):
        return None
    match = _HTTP_STATUS.match(error)
    return int(match.group(1)) if match else None


def is_access_denied(response: Any) -> bool:
    """True when Canvas refused the request with 401 or 403."""
    return canvas_error_status(response) in ACCESS_DENIED_STATUSES


async def list_files_via_modules(course_id: str) -> list[dict[str, Any]] | dict[str, Any]:
    """Files linked from the course's modules, de-duplicated by file ID.

    Returns a list of ``{"id", "title", "modules"}`` in module order, or a
    Canvas error dict. ``title`` is the module item title (instructor-authored,
    not necessarily the file's display name); ``modules`` names every module
    the file appears in.

    Canvas may omit ``items`` from a module it deems too large to inline, so
    those modules are read through the List Module Items endpoint.
    """
    modules = await fetch_all_paginated_results(
        f"/courses/{course_id}/modules", {"per_page": 100, "include[]": ["items"]}
    )
    if isinstance(modules, dict) and "error" in modules:
        return modules

    files: dict[str, dict[str, Any]] = {}
    for module in modules or []:
        if not isinstance(module, dict):
            continue
        module_name = module.get("name") or "Unnamed module"
        items = module.get("items")
        if items is None:
            module_id = coerce_canvas_id(module.get("id", ""))
            if module_id is None:
                continue
            items = await fetch_all_paginated_results(
                f"/courses/{course_id}/modules/{module_id}/items", {"per_page": 100}
            )
            if isinstance(items, dict) and "error" in items:
                return items
        for item in items or []:
            if not isinstance(item, dict) or item.get("type") != "File":
                continue
            file_id = coerce_canvas_id(item.get("content_id", ""))
            if file_id is None:
                continue
            entry = files.setdefault(
                file_id,
                {"id": file_id, "title": item.get("title") or "Untitled", "modules": []},
            )
            if module_name not in entry["modules"]:
                entry["modules"].append(module_name)
    return list(files.values())


async def fetch_module_linked_file(
    course_id: str, file_id: str, denied: dict[str, Any]
) -> tuple[Any, str | None]:
    """Fallback metadata lookup after the course-scoped file GET was refused.

    Only a file the course links from a module is fetched, through the
    context-free ``GET /files/:id`` route; anything else returns the original
    refusal. Returns ``(file_info_or_error, note)`` where ``note`` explains the
    route taken and is ``None`` when no file was found.
    """
    module_files = await list_files_via_modules(course_id)
    if isinstance(module_files, dict):
        return (
            {
                "error": (
                    f"{denied.get('error')}; module fallback also failed: "
                    f"{module_files.get('error')}"
                )
            },
            None,
        )

    match = next((f for f in module_files if f["id"] == file_id), None)
    if match is None:
        return (
            {
                "error": (
                    f"{denied.get('error')}. The course file is not readable through "
                    f"the course Files route and is not linked from any module "
                    f"in this course."
                )
            },
            None,
        )

    file_info = await make_canvas_request("get", f"/files/{file_id}")
    if isinstance(file_info, dict) and "error" in file_info:
        return file_info, None
    note = (
        "Canvas refused the course Files route (the Files tab is probably hidden), "
        "so this file was read through the module that links it."
    )
    return file_info, note


def _origin(url: httpx.URL) -> tuple[str, str, int | None]:
    return (url.scheme, url.host, url.port or _DEFAULT_PORTS.get(url.scheme))


def _canvas_origin() -> tuple[str, str, int | None] | None:
    """Origin of the Canvas instance the current caller's token belongs to."""
    creds = get_request_credentials()
    base = creds.api_url if creds else get_config().canvas_api_url
    try:
        return _origin(httpx.URL(base))
    except (httpx.InvalidURL, TypeError):
        return None


@asynccontextmanager
async def _unauthenticated_client() -> AsyncIterator[httpx.AsyncClient]:
    """A client that carries no Canvas credentials, for non-Canvas hops."""
    async with httpx.AsyncClient(timeout=get_config().api_timeout) as client:
        yield client


async def download_file_bytes(url: str, max_bytes: int) -> bytes | dict[str, str]:
    """Download a Canvas file URL into memory, never leaking the token.

    Each hop is fetched with ``follow_redirects=False``. A hop on the Canvas
    origin uses the fail-closed authenticated client; any other hop uses a
    client with no credentials and must be HTTPS. The body is capped at
    ``max_bytes`` (checked against Content-Length first, then while streaming).
    Error messages carry only the status, never the URL, because download
    URLs embed verifiers and signed storage tokens.
    """
    try:
        current = httpx.URL(url)
    except (httpx.InvalidURL, TypeError):
        return {"error": "Canvas returned an invalid download URL"}

    canvas_origin = _canvas_origin()
    for _ in range(MAX_DOWNLOAD_REDIRECTS + 1):
        if current.scheme not in _DEFAULT_PORTS:
            return {"error": f"Refusing to download over the '{current.scheme}' scheme"}
        on_canvas = canvas_origin is not None and _origin(current) == canvas_origin
        if not on_canvas and current.scheme != "https":
            return {"error": "Refusing a non-HTTPS download from a non-Canvas host"}
        client_cm = canvas_authenticated_client() if on_canvas else _unauthenticated_client()

        try:
            async with client_cm as client:
                async with client.stream("GET", str(current), follow_redirects=False) as response:
                    status = response.status_code
                    if 300 <= status < 400:
                        location = response.headers.get("Location")
                        if not location:
                            return {"error": f"HTTP {status} redirect without a Location header"}
                        try:
                            current = current.join(location)
                        except httpx.InvalidURL:
                            return {"error": "Download redirected to an invalid URL"}
                        continue
                    if status >= 400:
                        return {"error": f"HTTP {status} while downloading the file"}

                    declared = response.headers.get("Content-Length")
                    if declared and declared.isdigit() and int(declared) > max_bytes:
                        return {"error": "File exceeds the size limit (declared Content-Length)"}

                    buffer = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(buffer) + len(chunk) > max_bytes:
                            return {"error": "File exceeds the size limit during download"}
                        buffer.extend(chunk)
                    return bytes(buffer)
        except PermissionError as exc:
            return {"error": str(exc)}
        except httpx.HTTPError as exc:
            return {"error": f"Download failed: {type(exc).__name__}"}

    return {"error": f"Too many redirects (more than {MAX_DOWNLOAD_REDIRECTS})"}
