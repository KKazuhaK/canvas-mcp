"""File-related MCP tools for Canvas API.

Provides tools for uploading, downloading, reading, and listing files in Canvas courses.
Uploaded files can be used with other tools like add_module_item (for adding
files to modules) and send_conversation (for attaching files to messages).

The Canvas file upload process uses a 3-step protocol:
1. Request upload URL from Canvas API
2. Upload file to external storage (S3/Instructure)
3. Confirm upload and get final file object

This module handles all three steps transparently.
"""

import asyncio
import base64
import io
import mimetypes
import os
import re
import tempfile
from typing import Any

from fastmcp import FastMCP
from fastmcp.tools import ToolResult
from mcp.types import (
    BlobResourceContents,
    ContentBlock,
    EmbeddedResource,
    ImageContent,
    TextContent,
    ToolAnnotations,
)

from ..core.cache import get_course_code, get_course_id
from ..core.client import (
    canvas_authenticated_client,
    fetch_all_paginated_results,
    make_canvas_request,
    upload_file_to_storage,
)
from ..core.config import get_config
from ..core.course_files import (
    canvas_error_status,
    download_file_bytes,
    fetch_module_linked_file,
    is_access_denied,
    list_files_via_modules,
)
from ..core.credentials import is_http_request_active
from ..core.document_text import SUPPORTED_FORMATS, DocumentTextError, detect_kind
from ..core.file_validation import (
    FileValidationResult,
    format_file_size,
    sanitize_filename,
    validate_file_for_upload,
)
from ..core.mcp_client import client_mishandles_file_blobs
from ..core.tool_results import FULL_CONTENT_TOOL_META
from ..core.untrusted_content import fence_untrusted_inline
from ..core.validation import coerce_canvas_id, validate_params
from .file_text import (
    EXTRACTION_SLOTS,
    extract_document,
    format_document_text,
    shown_content_type,
)

#: Image types a model is shown inline (MCP ImageContent). Claude accepts
#: exactly these; any other image type travels as a file like everything else.
INLINE_IMAGE_TYPES = frozenset({"image/png", "image/jpeg", "image/gif", "image/webp"})

#: Leading bytes that identify a file regardless of what the uploader claimed.
_MAGIC_TYPES: tuple[tuple[bytes, str], ...] = (
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)

#: Content types that say nothing about the bytes; the file extension decides.
_GENERIC_TYPES = frozenset(
    {"unrecognized", "application/octet-stream", "binary/octet-stream", "application/unknown"}
)

_SAFE_EXTENSION = re.compile(r"\.[a-z0-9]{1,8}")

_EXTENSION_FOR_TYPE = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/zip": ".zip",
    "application/json": ".json",
    "text/plain": ".txt",
    "text/csv": ".csv",
    "text/html": ".html",
    "text/markdown": ".md",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
}

#: Shown with the extracted-text fallback for clients that cannot take a file.
_FALLBACK_LEAD_NOTE = (
    "This app cannot receive files from tools, so this is the file's complete "
    "extracted text. Figures, layout and scanned pages are not included; to see "
    "them, download the file from Canvas and attach it to the chat."
)
_FALLBACK_SEE_PAGES = (
    "To see those pages, download the file from Canvas and attach it to the chat."
)


def _file_mime_type(data: bytes, content_type: Any, filename: str) -> str:
    """The MIME type to declare for the returned file.

    The Canvas ``content-type`` comes from the uploader on API uploads, so the
    bytes themselves decide when they carry a known signature; then a clean
    Canvas type; then the file extension; then ``application/octet-stream``.
    """
    for magic, mime in _MAGIC_TYPES:
        if data.startswith(magic):
            return mime
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    declared = shown_content_type(content_type if isinstance(content_type, str) else None)
    if declared not in _GENERIC_TYPES and declared not in INLINE_IMAGE_TYPES:
        # A declared inline image type without the matching signature is not
        # sent as ImageContent: the client would fail to decode it.
        return declared
    guessed, _ = mimetypes.guess_type(filename)
    if guessed and guessed not in INLINE_IMAGE_TYPES:
        return guessed
    return "application/octet-stream"


def _file_resource_uri(file_id: str, mime: str) -> str:
    """Resource URI for the returned file, built only from values we control.

    Claude Code shows the URI to the model, so the uploader-chosen file name
    is never part of it.
    """
    # A fixed table first: mimetypes' answer varies by platform (and the
    # Windows registry), and the extension decides how a client opens the file.
    extension = _EXTENSION_FOR_TYPE.get(mime) or mimetypes.guess_extension(mime) or ""
    if not _SAFE_EXTENSION.fullmatch(extension):
        extension = ""
    return f"canvas://files/{file_id}{extension}"


def _count_pdf_pages(data: bytes) -> int | None:
    try:
        from pypdf import PdfReader
    except ImportError:
        return None
    with EXTRACTION_SLOTS:
        try:
            return len(PdfReader(io.BytesIO(data)).pages)
        except Exception:
            return None


async def _pdf_page_count(data: bytes) -> int | None:
    """Page count when pypdf is installed and can read the file, else None."""
    return await asyncio.to_thread(_count_pdf_pages, data)


async def _file_as_text_fallback(
    data: bytes,
    mime: str,
    filename: str,
    shown_name: str,
    course_display: str | int,
    route_note: str | None,
) -> str:
    """Complete extracted text, for a client that cannot receive the file."""
    kind = detect_kind(mime, filename)
    if kind is None:
        return (
            f"Error: {shown_name} ({mime}) cannot be shown here. This app cannot "
            f"receive files from tools, and text can only be extracted from "
            f"{SUPPORTED_FORMATS}. Download the file from Canvas and attach it to "
            "the chat to view it."
        )
    try:
        doc = await extract_document(data, kind, filename)
    except DocumentTextError as exc:
        return f"Error reading {shown_name}: {exc}"
    return format_document_text(
        shown_name=shown_name,
        course_display=course_display,
        kind=kind,
        shown_type=mime,
        size_bytes=len(data),
        doc=doc,
        route_note=route_note,
        see_pages_hint=_FALLBACK_SEE_PAGES,
        lead_notes=(_FALLBACK_LEAD_NOTE,),
    )


async def _get_file_info(course_id: str, file_id: str) -> tuple[Any, str | None]:
    """File metadata via the course route, falling back to module links.

    Returns ``(file_info_or_error, note)``. ``note`` is set only when the
    course Files route was refused (401/403, typically a hidden Files tab) and
    the file was found through a module instead.
    """
    file_info = await make_canvas_request("get", f"/courses/{course_id}/files/{file_id}")
    if is_access_denied(file_info):
        return await fetch_module_linked_file(course_id, file_id, file_info)
    return file_info, None


def _invalid_file_id(file_id: str | int) -> str:
    return f"Error: file_id must be a numeric Canvas file ID (got {file_id!r})."


def register_shared_file_tools(mcp: FastMCP) -> None:
    """Register file tools accessible to both students and educators."""

    # Writes a new file on the server's filesystem, so it is not read-only. It
    # opens with O_EXCL and never replaces an existing path (additive), and a
    # repeat fails without writing (idempotent).
    @mcp.tool(annotations=ToolAnnotations(
        read_only_hint=False, destructive_hint=False, idempotent_hint=True
    ))
    @validate_params
    async def download_course_file(
        course_identifier: str | int,
        file_id: str | int,
        save_directory: str | None = None,
    ) -> str:
        """Download a file from a Canvas course to the local filesystem.

        Only available on a local (stdio) server. Use read_course_file to get
        file content back in the response instead.

        Use list_course_files or list_module_items to find file IDs.

        Args:
            course_identifier: Course code or Canvas ID
            file_id: Canvas file ID
            save_directory: Local directory to save to (default: system temp dir, must exist)
        """
        # This tool writes to the *server's* filesystem. On a local stdio server
        # that is the caller's own machine; on a shared HTTP one it is somebody
        # else's host, and the caller picks both the destination directory and
        # (via the Canvas file they choose) the filename and bytes — an arbitrary
        # write primitive against the service account. There is also no reason a
        # remote caller would want it: they cannot read what lands there.
        if is_http_request_active():
            return (
                "Error: 'download_course_file' writes to the server's filesystem and is "
                "only available on a local (stdio) server. On this hosted server, use "
                "read_course_file instead, which returns the content in the response."
            )

        file_key = coerce_canvas_id(file_id)
        if file_key is None:
            return _invalid_file_id(file_id)

        course_id = await get_course_id(course_identifier)

        # Get file metadata, falling back to module links if Files is hidden
        file_info, route_note = await _get_file_info(course_id, file_key)

        if isinstance(file_info, dict) and "error" in file_info:
            return f"Error getting file info: {file_info['error']}"

        raw_filename = file_info.get("display_name") or file_info.get("filename", f"file_{file_id}")
        filename = sanitize_filename(raw_filename)
        download_url = file_info.get("url")
        content_type = file_info.get("content-type", "unknown")

        if not download_url:
            return "Error: No download URL available for this file. Check permissions."

        # Determine save path with symlink resolution
        from pathlib import Path
        save_dir = Path(save_directory or tempfile.gettempdir()).resolve()
        if not save_dir.is_dir():
            return f"Error: Directory does not exist: {save_directory}"

        save_path = (save_dir / filename).resolve()
        if not save_path.is_relative_to(save_dir):
            return "Error: Invalid filename - path outside allowed directory"

        # Create the destination exclusively. Canvas controls the filename, so a
        # plain 'wb' open lets a course file named e.g. ".zshrc" silently truncate
        # a real file in whatever directory was chosen. O_EXCL refuses an existing
        # path (including a pre-planted symlink) and O_NOFOLLOW refuses to follow
        # one, closing the swap race between the containment check and the write.
        # O_NOFOLLOW is POSIX-only; on Windows the attribute does not exist at
        # all, so naming it directly would raise AttributeError before os.open
        # runs and break every local download there. O_EXCL alone still refuses
        # an existing path, including a pre-planted symlink, which is the bulk
        # of the protection.
        # The 0o600 mode is owner-only on POSIX. Windows has no permission bits:
        # the mode only sets the read-only attribute, and access follows the ACL
        # inherited from save_dir (the default, the per-user temp dir, is
        # private to that user).
        open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(save_path, open_flags, 0o600)
        except FileExistsError:
            return (
                f"Error: '{save_path}' already exists. Refusing to overwrite it — "
                f"remove it first or pass a different save_directory."
            )
        except OSError as e:
            return f"Error creating destination file: {e}"

        # Wrap the descriptor immediately so it is closed even if the network call
        # below fails before the first write, and download by streaming to handle
        # large files efficiently.
        try:
            total_bytes = 0
            with os.fdopen(fd, 'wb') as f:
                async with canvas_authenticated_client() as client:
                    async with client.stream(
                        "GET", download_url, follow_redirects=True
                    ) as response:
                        response.raise_for_status()

                        async for chunk in response.aiter_bytes(chunk_size=8192):
                            f.write(chunk)
                            total_bytes += len(chunk)
        except Exception as e:
            # We created this path, so a failed download leaves a truncated or
            # empty file that a later reader could mistake for real content.
            try:
                os.unlink(save_path)
            except OSError:
                pass
            return f"Error downloading file: {str(e)}"

        size_str = format_file_size(total_bytes)
        course_display = await get_course_code(course_id) or course_identifier

        # Filename is uploader-controlled (issue 239); the on-disk path uses
        # the sanitized value, only the display is fenced.
        result = f"Downloaded: {fence_untrusted_inline(filename, 'file name')}\n"
        result += f"  Path: {save_path}\n"
        result += f"  Size: {size_str}\n"
        result += f"  Type: {content_type}\n"
        result += f"  Course: {course_display}\n"
        if route_note:
            result += f"  Note: {route_note}\n"
        return result

    @mcp.tool(
        annotations=ToolAnnotations(read_only_hint=True),
        # The result mixes text with the file itself; it has no JSON shape.
        output_schema=None,
        meta=FULL_CONTENT_TOOL_META,
    )
    @validate_params
    async def read_course_file(
        course_identifier: str | int,
        file_id: str | int,
        max_size_mb: float = 25.0,
    ) -> str | ToolResult:
        """Open a course file exactly as a person sees it: returns the original file.

        Use this to look at lecture slides, PDFs, handouts, worksheets, or
        images the way a student would, with layout, figures, diagrams,
        equations, handwriting, and scanned pages intact. It returns the file
        itself, like a file attached to the chat, not a text conversion:

        - Claude Code saves the file and gives its path: open that path with
          the Read tool to view it (a PDF arrives as page images plus text).
        - Images (PNG, JPEG, GIF, WebP) are shown directly.
        - Claude Desktop chat cannot receive files from tools, so there it
          returns the file's complete extracted text instead.

        For the words only (quicker, smaller), use read_course_file_text. Use
        list_course_files or list_module_items to find file IDs. Works for
        files linked from modules even when the course Files tab is hidden.

        Args:
            course_identifier: Course code or Canvas ID
            file_id: Canvas file ID
            max_size_mb: Maximum file size in MB to read (default: 25). Clamped server-side to
                READ_FILE_MAX_SIZE_MB (default 100). Larger files are refused before
                anything is downloaded.
        """
        if max_size_mb <= 0:
            return (
                f"Error: max_size_mb must be positive (got {max_size_mb}). "
                f"Pass a value like 25 for a 25 MB limit."
            )

        server_max_mb = get_config().read_file_max_size_mb
        effective_max_mb = min(float(max_size_mb), server_max_mb)
        max_size_bytes = int(effective_max_mb * 1024 * 1024)

        file_key = coerce_canvas_id(file_id)
        if file_key is None:
            return _invalid_file_id(file_id)

        course_id = await get_course_id(course_identifier)

        # Get file metadata, falling back to module links if Files is hidden
        file_info, route_note = await _get_file_info(course_id, file_key)

        if isinstance(file_info, dict) and "error" in file_info:
            return f"Error getting file info: {file_info['error']}"
        if not isinstance(file_info, dict):
            return "Error getting file info: unexpected response from Canvas."

        # Uploader-controlled (issue 239): only ever shown inside a fence, and
        # never written anywhere (the resource URI uses the file ID).
        filename = str(
            file_info.get("display_name") or file_info.get("filename") or f"file_{file_key}"
        )
        shown_name = fence_untrusted_inline(filename, "file name")
        reported_size = file_info.get("size") or 0

        if file_info.get("locked_for_user"):
            explanation = file_info.get("lock_explanation") or "Canvas reports it as locked."
            return (
                f"Error: {shown_name} is locked for you: "
                f"{fence_untrusted_inline(explanation, 'lock explanation')}"
            )

        download_url = file_info.get("url")
        if not download_url:
            return "Error: No download URL available for this file. Check permissions."

        # Refuse an oversized file before a single byte is downloaded.
        if isinstance(reported_size, int) and reported_size > max_size_bytes:
            return (
                f"Error: File {shown_name} is {format_file_size(reported_size)}, "
                f"which exceeds the {effective_max_mb:g} MB limit. Nothing was downloaded. "
                f"Use download_course_file on a local server for large files."
            )

        # The token goes to the Canvas origin only; storage hops get none.
        data = await download_file_bytes(download_url, max_size_bytes)
        if isinstance(data, dict):
            error = data["error"]
            if "size limit" in error:
                return (
                    f"Error: File {shown_name} exceeds the {effective_max_mb:g} MB limit "
                    f"during download. Use download_course_file on a local server for "
                    f"large files."
                )
            return f"Error downloading {shown_name}: {error}"

        mime = _file_mime_type(data, file_info.get("content-type"), filename)
        course_display = await get_course_code(course_id) or course_identifier

        if mime not in INLINE_IMAGE_TYPES and client_mishandles_file_blobs():
            return await _file_as_text_fallback(
                data, mime, filename, shown_name, course_display, route_note
            )

        lines = [
            f"File: {shown_name}",
            f"  Course: {course_display}",
            f"  Type: {mime}",
            f"  Size: {format_file_size(len(data))}",
        ]
        if mime == "application/pdf":
            pages = await _pdf_page_count(data)
            if pages is not None:
                lines.append(f"  Pages: {pages}")
        if route_note:
            lines.append(f"  Note: {route_note}")

        encoded = base64.b64encode(data).decode("ascii")
        content: list[ContentBlock]
        if mime in INLINE_IMAGE_TYPES:
            lines.append("The image follows.")
            content = [
                TextContent(type="text", text="\n".join(lines)),
                ImageContent(type="image", data=encoded, mime_type=mime),
            ]
        else:
            hint = (
                "Claude Code saves this file; open the saved path with Read to view "
                "it like an attached file."
            )
            if mime != "application/pdf" and not mime.startswith("text/"):
                hint += " If Read cannot open this type, read_course_file_text returns its text."
            lines.append(hint)
            content = [
                TextContent(type="text", text="\n".join(lines)),
                EmbeddedResource(
                    type="resource",
                    resource=BlobResourceContents(
                        uri=_file_resource_uri(file_key, mime),
                        mime_type=mime,
                        blob=encoded,
                    ),
                ),
            ]
        return ToolResult(content=content)

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    @validate_params
    async def list_course_files(
        course_identifier: str | int,
        search_term: str | None = None,
        sort: str = "updated_at",
        order: str = "desc",
    ) -> str:
        """List files in a Canvas course with optional search.

        If Canvas refuses the course file list (401/403, usually because the
        Files tab is hidden for students), lists the files linked from the
        course modules instead and says so in the output.

        Args:
            course_identifier: Course code or Canvas ID
            search_term: Filter files by name
            sort: Sort field: name, size, created_at, updated_at, content_type (default: updated_at)
            order: "asc" or "desc" (default: desc)
        """
        # Validate sort and order parameters
        valid_sort_fields = {"name", "size", "created_at", "updated_at", "content_type"}
        if sort not in valid_sort_fields:
            return f"Invalid sort field: '{sort}'. Must be one of: {', '.join(sorted(valid_sort_fields))}"

        if order not in ("asc", "desc"):
            return f"Invalid order: '{order}'. Must be 'asc' or 'desc'."

        course_id = await get_course_id(course_identifier)

        params = {
            "per_page": 100,
            "sort": sort,
            "order": order,
        }
        if search_term:
            params["search_term"] = search_term

        files = await fetch_all_paginated_results(
            f"/courses/{course_id}/files",
            params
        )

        if is_access_denied(files):
            # Students get 401/403 here when the course Files tab is hidden,
            # yet files linked from modules stay readable. List those instead.
            return await _list_module_linked_files(
                course_id, course_identifier, files, search_term, sort, order
            )

        if isinstance(files, dict) and "error" in files:
            return f"Error listing files: {files['error']}"

        if not files:
            msg = "No files found"
            if search_term:
                msg += f" matching '{search_term}'"
            return msg

        course_display = await get_course_code(course_id) or course_identifier
        result = f"Files in {course_display}:\n\n"

        for f in files:
            fid = f.get("id", "?")
            name = f.get("display_name") or f.get("filename", "unknown")
            size = format_file_size(f.get("size", 0))
            ctype = f.get("content-type", "unknown")
            result += f"  ID: {fid} | {fence_untrusted_inline(name, 'file name')} ({size}, {ctype})\n"

        result += f"\nTotal: {len(files)} file(s)"
        return result


async def _list_module_linked_files(
    course_id: str,
    course_identifier: str | int,
    denied: dict[str, Any],
    search_term: str | None,
    sort: str,
    order: str,
) -> str:
    """``list_course_files`` output built from module File items."""
    module_files = await list_files_via_modules(course_id)
    if isinstance(module_files, dict):
        return (
            f"Error listing files: {denied.get('error')}; listing files through "
            f"modules also failed: {module_files.get('error')}"
        )

    if search_term:
        needle = search_term.lower()
        module_files = [f for f in module_files if needle in str(f["title"]).lower()]

    notice = (
        f"Note: Canvas refused the course file list (HTTP {canvas_error_status(denied)}); "
        "the Files tab is probably hidden for students. Showing files linked from "
        "modules instead. Files not placed in any module are not listed, names are "
        "module item titles, and size/type are not shown here (read_course_file_text "
        "and read_course_file report them).\n"
    )
    if sort == "name":
        module_files = sorted(
            module_files, key=lambda f: str(f["title"]).lower(), reverse=order == "desc"
        )
    else:
        notice += (
            f"Sort '{sort}' is not available for module-linked files; "
            "shown in module order.\n"
        )

    if not module_files:
        msg = "No files found in modules"
        if search_term:
            msg += f" matching '{search_term}'"
        return f"{notice}\n{msg}"

    course_display = await get_course_code(course_id) or course_identifier
    result = f"{notice}\nFiles linked from modules in {course_display}:\n\n"
    for f in module_files:
        modules = ", ".join(
            fence_untrusted_inline(name, "module name") for name in f["modules"]
        )
        title = fence_untrusted_inline(f["title"], "module item title")
        result += f"  ID: {f['id']} | {title} (module: {modules})\n"
    result += f"\nTotal: {len(module_files)} file(s)"
    return result


def register_educator_file_tools(mcp: FastMCP) -> None:
    """Register educator-only file tools (upload)."""

    @mcp.tool(annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=False))
    @validate_params
    async def upload_course_file(
        course_identifier: str | int,
        file_path: str,
        folder_path: str | None = None,
        display_name: str | None = None,
        on_duplicate: str = "rename"
    ) -> str:
        """Upload a file to Canvas course storage.

        Uploads a local file to a Canvas course. The returned file ID can be used with
        add_module_item (item_type='File') or send_conversation (attachment_ids).

        Args:
            course_identifier: Course code or Canvas ID
            file_path: Absolute path to the local file to upload
            folder_path: Canvas folder path (default: "course files" root)
            display_name: Override the filename shown in Canvas
            on_duplicate: "rename" (default) or "overwrite"
        """
        # 'file_path' reads the *server's* filesystem. On a local stdio server that
        # is the caller's own machine; on a shared HTTP one a remote caller could
        # name any file the service account can read and upload it into their own
        # Canvas course. Refused outright over HTTP, matching the student upload
        # path in student_write.py, which already blocks the same hole.
        if is_http_request_active():
            return (
                "Error: 'file_path' reads files from the server and is only "
                "available on a local (stdio) server. On this hosted server, "
                "upload the file through Canvas directly."
            )

        # Validate on_duplicate parameter
        if on_duplicate not in ("rename", "overwrite"):
            return f"Invalid on_duplicate value: '{on_duplicate}'. Must be 'rename' or 'overwrite'."

        # Step 0: Validate the file locally first
        validation: FileValidationResult = validate_file_for_upload(file_path)

        if not validation.valid:
            return f"❌ File validation failed: {validation.error}"

        # Get course ID for API calls
        course_id = await get_course_id(course_identifier)

        # Determine the filename to use in Canvas
        upload_filename = display_name if display_name else validation.sanitized_name

        # Step 1: Request upload URL from Canvas API
        upload_request_params = {
            "name": upload_filename,
            "size": validation.file_size,
            "content_type": validation.mime_type,
            "on_duplicate": on_duplicate,
        }

        # Canvas expects the folder path relative to course files. ALWAYS send
        # it: omitting parent_folder_path does not mean "root", it means Canvas
        # creates and uses a folder literally named "unfiled" (issue #198,
        # reproduced live — A/B: no param -> "course files/unfiled";
        # parent_folder_path="" -> "course files"). Empty string is the root, and
        # costs no extra request, unlike looking up /folders/root for its id.
        upload_request_params["parent_folder_path"] = folder_path or ""

        # Request the upload slot
        step1_response = await make_canvas_request(
            "post",
            f"/courses/{course_id}/files",
            data=upload_request_params,
            use_form_data=True
        )

        if isinstance(step1_response, dict) and "error" in step1_response:
            return f"❌ Failed to request upload URL: {step1_response['error']}"

        # Extract upload URL and parameters
        upload_url = step1_response.get("upload_url")
        upload_params = step1_response.get("upload_params", {})

        if not upload_url:
            return "❌ Canvas API did not return an upload URL. Check API permissions."

        # Step 2: Upload file to external storage
        step2_response = await upload_file_to_storage(
            upload_url=upload_url,
            upload_params=upload_params,
            file_path=file_path,
            filename=upload_filename,
            content_type=validation.mime_type
        )

        if isinstance(step2_response, dict) and "error" in step2_response:
            error_msg = step2_response.get("error", "Unknown error")
            details = step2_response.get("details", "")
            if details:
                return f"❌ File upload failed: {error_msg}\nDetails: {details}"
            return f"❌ File upload failed: {error_msg}"

        # Step 3: Extract file information from response
        # The response could be from:
        # - Direct storage response (200/201)
        # - Redirect confirmation from Canvas API

        file_id = step2_response.get("id")
        file_name = step2_response.get("display_name") or step2_response.get("filename") or upload_filename
        file_url = step2_response.get("url", "")
        file_folder_id = step2_response.get("folder_id")

        # If we got a success but no file ID, the file might need confirmation
        # This can happen with some storage backends
        if not file_id and step2_response.get("success"):
            # Try to find the file by name in the course
            # This is a fallback for edge cases
            return (
                "⚠️ Upload appears successful but file ID not returned. "
                "The file may need manual verification in Canvas."
            )

        if not file_id:
            return (
                "❌ Upload completed but no file ID received. "
                f"Response: {step2_response}"
            )

        # Format success response
        course_display = await get_course_code(course_id) or course_identifier
        file_size_str = format_file_size(validation.file_size)

        result = "✅ File uploaded successfully!\n\n"
        result += f"**{file_name}**\n"
        result += f"  File ID: {file_id}\n"
        result += f"  Course: {course_display}\n"
        result += f"  Size: {file_size_str}\n"
        result += f"  Type: {validation.mime_type}\n"

        if file_folder_id:
            result += f"  Folder ID: {file_folder_id}\n"

        if folder_path:
            result += f"  Folder Path: {folder_path}\n"

        result += "\n**Next steps:**\n"
        result += f"  - Add to module: add_module_item(..., item_type='File', content_id={file_id})\n"
        result += f"  - Attach to message: send_conversation(..., attachment_ids=['{file_id}'])\n"

        if file_url:
            result += f"  - Direct URL: {file_url}\n"

        return result
