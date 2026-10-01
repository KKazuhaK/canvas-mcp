"""Read a course file (lecture slides, PDFs, handouts) as text.

``read_course_file`` returns raw bytes as base64, which a model cannot read
for a PDF or a slide deck. This tool downloads the file, extracts its text
(PDF pages, PPTX slide titles/text/speaker notes, DOCX paragraphs and tables,
plain text/Markdown/CSV/JSON, HTML), and returns it with page or slide markers
inside an untrusted-content fence.

It shares the module fallback of the other file tools: when the course Files
tab is hidden, a file linked from a module is still readable.
"""

import asyncio

from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..core.cache import get_course_code, get_course_id
from ..core.client import make_canvas_request
from ..core.config import get_config
from ..core.course_files import (
    download_file_bytes,
    fetch_module_linked_file,
    is_access_denied,
)
from ..core.document_text import (
    KIND_LABELS,
    SUPPORTED_FORMATS,
    DocumentTextError,
    ExtractedDocument,
    detect_kind,
    extract_text,
)
from ..core.file_validation import format_file_size
from ..core.untrusted_content import fence_untrusted, fence_untrusted_inline
from ..core.validation import coerce_canvas_id, validate_params

#: Largest file this tool downloads, before the server's READ_FILE_MAX_SIZE_MB
#: clamp. Lecture decks are usually well under this; video is not a target.
TEXT_READ_MAX_SIZE_MB = 50.0

DEFAULT_MAX_CHARS = 40000
#: Upper bound on ``max_chars`` so one call cannot flood the model context.
MAX_CHARS_LIMIT = 200000


def _render_sections(doc: ExtractedDocument, max_chars: int) -> tuple[str, int | None, bool]:
    """Join sections with markers and cut at ``max_chars``.

    Returns ``(text, resume_at, truncated)``. ``resume_at`` is the page/slide
    to pass as ``start_page`` to continue: the first one not shown in full.
    """
    label = (doc.unit or "").capitalize()
    pieces: list[str] = []
    length = 0
    for index, section in enumerate(doc.sections):
        if section.number is not None:
            body = section.text or f"[no text on this {doc.unit}]"
            piece = f"--- {label} {section.number} ---\n{body}"
        else:
            piece = section.text
        separator = "\n\n" if pieces else ""
        if length + len(separator) + len(piece) > max_chars:
            room = max_chars - length - len(separator)
            if room > 0:
                pieces.append(separator + piece[:room])
            return "".join(pieces), section.number, True
        pieces.append(separator + piece)
        length += len(separator) + len(piece)
        if doc.stopped_early and index == len(doc.sections) - 1:
            # Extraction stopped on budget: everything shown is complete, more
            # exists after it.
            next_unit = section.number + 1 if section.number is not None else None
            return "".join(pieces), next_unit, True
    return "".join(pieces), None, False


def register_file_text_tools(mcp: FastMCP) -> None:
    """Register the course-file text extraction tool."""

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    @validate_params
    async def read_course_file_text(
        course_identifier: str | int,
        file_id: str | int,
        max_chars: int = DEFAULT_MAX_CHARS,
        start_page: int | None = None,
        end_page: int | None = None,
    ) -> str:
        """Read a course file (PDF, slides, Word doc, text) as plain text.

        Extracts PDF page text, PowerPoint slide titles/text/speaker notes,
        Word paragraphs and tables, and plain text/Markdown/CSV/JSON/HTML.
        Output carries page or slide markers. Works for files linked from
        modules even when the course Files tab is hidden. Scanned PDFs have
        no extractable text (no OCR). For raw bytes use read_course_file.

        Use list_course_files or list_module_items to find file IDs.

        Args:
            course_identifier: Course code or Canvas ID
            file_id: Canvas file ID
            max_chars: Maximum characters of text to return (default 40000, max 200000)
            start_page: First page (PDF) or slide (PPTX) to read, 1-based
            end_page: Last page or slide to read, inclusive
        """
        file_key = coerce_canvas_id(file_id)
        if file_key is None:
            return f"Error: file_id must be a numeric Canvas file ID (got {file_id!r})."
        if max_chars < 1:
            return f"Error: max_chars must be positive (got {max_chars})."
        max_chars = min(max_chars, MAX_CHARS_LIMIT)
        if start_page is not None and start_page < 1:
            return f"Error: start_page must be 1 or greater (got {start_page})."
        if end_page is not None and end_page < 1:
            return f"Error: end_page must be 1 or greater (got {end_page})."
        if start_page is not None and end_page is not None and start_page > end_page:
            return (
                f"Error: start_page ({start_page}) must not be greater than "
                f"end_page ({end_page})."
            )

        course_id = await get_course_id(course_identifier)

        file_info = await make_canvas_request("get", f"/courses/{course_id}/files/{file_key}")
        route_note = None
        if is_access_denied(file_info):
            file_info, route_note = await fetch_module_linked_file(
                course_id, file_key, file_info
            )
        if isinstance(file_info, dict) and "error" in file_info:
            return f"Error getting file info: {file_info['error']}"
        if not isinstance(file_info, dict):
            return "Error getting file info: unexpected response from Canvas."

        filename = file_info.get("display_name") or file_info.get("filename") or f"file_{file_key}"
        shown_name = fence_untrusted_inline(filename, "file name")
        content_type = file_info.get("content-type") or "unknown"
        reported_size = file_info.get("size") or 0

        if file_info.get("locked_for_user"):
            explanation = file_info.get("lock_explanation") or "Canvas reports it as locked."
            return (
                f"Error: {shown_name} is locked for you: "
                f"{fence_untrusted_inline(explanation, 'lock explanation')}"
            )

        kind = detect_kind(content_type, filename)
        if kind is None:
            return (
                f"Error: cannot extract text from {shown_name} ({content_type}). "
                f"Supported formats: {SUPPORTED_FORMATS}. Use read_course_file for raw bytes."
            )

        effective_max_mb = min(TEXT_READ_MAX_SIZE_MB, get_config().read_file_max_size_mb)
        max_bytes = int(effective_max_mb * 1024 * 1024)
        if isinstance(reported_size, int) and reported_size > max_bytes:
            return (
                f"Error: {shown_name} is {format_file_size(reported_size)}, over the "
                f"{effective_max_mb:g} MB limit for text extraction. Nothing was downloaded."
            )

        download_url = file_info.get("url")
        if not download_url:
            return "Error: No download URL available for this file. Check permissions."

        data = await download_file_bytes(download_url, max_bytes)
        if isinstance(data, dict):
            return f"Error downloading {shown_name}: {data['error']}"

        try:
            doc = await asyncio.to_thread(
                extract_text,
                data,
                kind,
                filename=filename,
                start=start_page,
                end=end_page,
                budget=max_chars + 1,
            )
        except DocumentTextError as exc:
            return f"Error reading {shown_name}: {exc}"

        text, resume_at, truncated = _render_sections(doc, max_chars)
        course_display = await get_course_code(course_id) or course_identifier

        result = f"File: {shown_name}\n"
        result += f"  Course: {course_display}\n"
        result += f"  Type: {KIND_LABELS[kind]} ({content_type})\n"
        result += f"  Size: {format_file_size(len(data))}\n"
        if doc.unit and doc.total_units is not None:
            numbers = [s.number for s in doc.sections if s.number is not None]
            if numbers:
                result += (
                    f"  {doc.unit.capitalize()}s: {numbers[0]}-{numbers[-1]} "
                    f"of {doc.total_units}\n"
                )
            else:
                result += f"  {doc.unit.capitalize()}s: 0\n"
        if route_note:
            result += f"  Note: {route_note}\n"
        for note in doc.notes:
            result += f"  Note: {note}\n"

        if not text.strip():
            result += "\n(No text could be extracted from this file.)\n"
            return result

        result += "\n" + fence_untrusted(text, "course file text") + "\n"
        if truncated:
            result += f"\n[Truncated at {max_chars} characters."
            if resume_at is not None and doc.unit:
                result += f" Continue with start_page={resume_at}."
            else:
                result += " Raise max_chars to read more."
            result += "]\n"
        return result
