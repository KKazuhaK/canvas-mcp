"""Read a course file (lecture slides, PDFs, handouts) as text, complete.

This tool downloads the file, extracts its text (PDF pages, PPTX slide
titles/text/speaker notes, DOCX paragraphs and tables, plain
text/Markdown/CSV/JSON, HTML), and returns ALL of it with page or slide markers
inside an untrusted-content fence. Nothing is cut: a caller who wants less asks
for a page range. Claude Code is told (``FULL_CONTENT_TOOL_META``) that the
result may be large, so it delivers it whole or saves it to a file the model
reads, rather than shortening it.

To see a file the way a person does (layout, figures, scanned pages), use
``read_course_file``, which returns the file itself. ``read_course_file`` also
uses the helpers here to fall back to text for clients that cannot receive a
file from a tool.

It shares the module fallback of the other file tools: when the course Files
tab is hidden, a file linked from a module is still readable.
"""

import asyncio
import re
import threading

from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..core.cache import get_course_code, resolve_numeric_course_id
from ..core.client import make_canvas_request
from ..core.config import get_config
from ..core.course_files import (
    download_file_bytes,
    fetch_module_linked_file,
    is_access_denied,
)
from ..core.document_text import (
    KIND_DOCX,
    KIND_LABELS,
    PAGED_KINDS,
    SUPPORTED_FORMATS,
    DocumentTextError,
    ExtractedDocument,
    detect_kind,
    extract_text,
)
from ..core.file_validation import format_file_size
from ..core.tool_results import (
    FULL_CONTENT_TOOL_META,
    MAX_WIRE_MESSAGE_BYTES,
    text_wire_bytes,
)
from ..core.untrusted_content import fence_untrusted, fence_untrusted_inline
from ..core.validation import coerce_canvas_id, validate_params

#: Largest file this tool downloads, before the server's READ_FILE_MAX_SIZE_MB
#: clamp. Lecture decks are usually well under this; video is not a target.
TEXT_READ_MAX_SIZE_MB = 50.0

#: Largest text result, as serialized JSON, either file tool returns. The rest
#: of the 16 MiB message limit is headroom for the header and the envelope.
TEXT_RESULT_MAX_BYTES = MAX_WIRE_MESSAGE_BYTES - 1024 * 1024

#: Parses running at once. Office parsing holds a whole document's XML tree in
#: memory and cannot be cancelled once started, so concurrent calls queue here
#: (in the worker thread, not on the event loop) instead of stacking up.
MAX_CONCURRENT_EXTRACTIONS = 2
EXTRACTION_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_EXTRACTIONS)

#: How ``read_course_file_text`` tells the model to see pages that have no
#: text (scans, figures, handwriting).
SEE_PAGES_WITH_READ_COURSE_FILE = (
    "Call read_course_file on this file to see the pages as images, the way a "
    "person would."
)

#: A MIME type as Canvas should report it (type/subtype, no parameters).
_MIME_TOKEN = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}")


def shown_content_type(content_type: str | None) -> str:
    """The Canvas content-type as safe to print, or ``"unrecognized"``.

    Canvas takes ``content_type`` from the uploader on API uploads, so the
    raw value is uploader-controlled. Only a plain ``type/subtype`` token is
    shown; anything else (newlines, prose, injection text) is replaced.
    """
    base = (content_type or "").split(";", 1)[0].strip().lower()
    if base and _MIME_TOKEN.fullmatch(base):
        return base
    return "unrecognized"


def _extract_bounded(
    data: bytes,
    kind: str,
    filename: str,
    start: int | None,
    end: int | None,
) -> ExtractedDocument:
    """``extract_text`` of the whole range, holding an extraction slot."""
    with EXTRACTION_SLOTS:
        return extract_text(data, kind, filename=filename, start=start, end=end)


async def extract_document(
    data: bytes,
    kind: str,
    filename: str,
    start_page: int | None = None,
    end_page: int | None = None,
) -> ExtractedDocument:
    """All text of ``data`` (or of the page range), parsed in a worker thread.

    Raises ``DocumentTextError`` (including ``MissingDependencyError``, whose
    message carries the documents-extra install hint).
    """
    return await asyncio.to_thread(
        _extract_bounded, data, kind, filename, start_page, end_page
    )


def _join_sections(doc: ExtractedDocument) -> str:
    label = (doc.unit or "").capitalize()
    pieces: list[str] = []
    for section in doc.sections:
        if section.number is None:
            pieces.append(section.text)
        else:
            body = section.text or f"[no text on this {doc.unit}]"
            pieces.append(f"--- {label} {section.number} ---\n{body}")
    return "\n\n".join(pieces)


def format_document_text(
    *,
    shown_name: str,
    course_display: str | int,
    kind: str,
    shown_type: str,
    size_bytes: int,
    doc: ExtractedDocument,
    route_note: str | None,
    see_pages_hint: str,
    lead_notes: tuple[str, ...] = (),
) -> str:
    """The complete text result: header lines, then every section, fenced.

    ``shown_name`` must already be fenced. ``see_pages_hint`` tells the
    caller how to see pages or slides that carry no text (scans, figures).
    """
    result = f"File: {shown_name}\n"
    result += f"  Course: {course_display}\n"
    result += f"  Type: {KIND_LABELS[kind]} ({shown_type})\n"
    result += f"  Size: {format_file_size(size_bytes)}\n"

    unit = (doc.unit or "").capitalize()
    numbered = [s for s in doc.sections if s.number is not None]
    if doc.unit and doc.total_units is not None:
        if numbered:
            result += (
                f"  {unit}s: {numbered[0].number}-{numbered[-1].number} "
                f"of {doc.total_units}\n"
            )
        else:
            result += f"  {unit}s: 0\n"

    text = _join_sections(doc)
    if doc.unit is None and text:
        result += f"  Characters: {len(text)} (complete)\n"

    for note in lead_notes:
        result += f"  Note: {note}\n"
    if route_note:
        result += f"  Note: {route_note}\n"
    for note in doc.notes:
        result += f"  Note: {note}\n"

    blank = [s.number for s in numbered if not s.text.strip()]
    if blank and len(blank) < len(numbered):
        listed = ", ".join(str(n) for n in blank)
        result += f"  Note: {unit}s with no extractable text: {listed}. {see_pages_hint}\n"

    if not text.strip() or (numbered and len(blank) == len(numbered)):
        result += "\n(No text could be extracted from this file.)"
        if kind in PAGED_KINDS or kind == KIND_DOCX:
            result += f" {see_pages_hint}"
        return result + "\n"

    return result + "\n" + fence_untrusted(text, "course file text") + "\n"


def oversized_text_error(
    result: str,
    *,
    shown_name: str,
    doc: ExtractedDocument,
    range_tool: str | None = None,
) -> str | None:
    """An error when ``result`` is too big for one MCP message, else None.

    Claude Code drops the server connection on a message over 16 MiB rather
    than cutting or saving it, so text that would serialize past
    ``TEXT_RESULT_MAX_BYTES`` is refused, never cut. For a paged document the
    error proposes a page range that fits; ``range_tool`` names the tool that
    takes one when it is not the caller.
    """
    size = text_wire_bytes(result)
    if size <= TEXT_RESULT_MAX_BYTES:
        return None
    error = (
        f"Error: the text of {shown_name} is {format_file_size(size)}, more than "
        f"the {TEXT_RESULT_MAX_BYTES // (1024 * 1024)} MB one result can carry "
        "(MCP clients disconnect on a result over 16 MB). Nothing was cut or returned."
    )
    numbered = [s for s in doc.sections if s.number is not None]
    if doc.unit and numbered:
        # Assume text is spread evenly; aim for 80% of the budget.
        fits = max(1, int(len(numbered) * TEXT_RESULT_MAX_BYTES * 0.8 / size))
        first = numbered[0].number or 1
        last = min(first + fits - 1, numbered[-1].number or first)
        how = f"call {range_tool} with" if range_tool else "pass"
        error += (
            f" Read it in parts: {how} start_page and end_page, for example "
            f"start_page={first}, end_page={last} ({doc.total_units} {doc.unit}s in all)."
        )
    else:
        error += (
            " This format has no pages to select. On a local server, "
            "download_course_file saves the file to disk."
        )
    return error


def register_file_text_tools(mcp: FastMCP) -> None:
    """Register the course-file text extraction tool."""

    @mcp.tool(
        annotations=ToolAnnotations(read_only_hint=True),
        meta=FULL_CONTENT_TOOL_META,
    )
    @validate_params
    async def read_course_file_text(
        course_identifier: str | int,
        file_id: str | int,
        start_page: int | None = None,
        end_page: int | None = None,
    ) -> str:
        """Read ALL the text of a course file (PDF, slides, Word doc, text).

        Returns the complete extracted text, never cut: PDF page text,
        PowerPoint slide titles/text/speaker notes, Word paragraphs and
        tables, and text files (plain text, Markdown, CSV, JSON, HTML, XML,
        LaTeX, notebooks, source code), with page or slide markers. Works for
        files linked from modules even when the course Files tab is hidden.
        Text too large for one response (over 15 MB) is refused, not cut:
        read a PDF or deck in parts with start_page/end_page.

        Text extraction misses layout, figures, equations drawn as images,
        and scanned pages (no OCR). To see the file the way a person does,
        call read_course_file, which returns the original file.

        Use list_course_files or list_module_items to find file IDs.

        Args:
            course_identifier: Course code or Canvas ID
            file_id: Canvas file ID
            start_page: Optional first page (PDF) or slide (PPTX) to read, 1-based
            end_page: Optional last page or slide to read, inclusive
        """
        file_key = coerce_canvas_id(file_id)
        if file_key is None:
            return f"Error: file_id must be a numeric Canvas file ID (got {file_id!r})."
        if start_page is not None and start_page < 1:
            return f"Error: start_page must be 1 or greater (got {start_page})."
        if end_page is not None and end_page < 1:
            return f"Error: end_page must be 1 or greater (got {end_page})."
        if start_page is not None and end_page is not None and start_page > end_page:
            return (
                f"Error: start_page ({start_page}) must not be greater than "
                f"end_page ({end_page})."
            )

        course_id, course_error = await resolve_numeric_course_id(course_identifier)
        if course_id is None:
            return f"Error: {course_error}"

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
        content_type = file_info.get("content-type") or ""
        shown_type = shown_content_type(content_type)
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
                f"Error: cannot extract text from {shown_name} ({shown_type}). "
                f"Supported formats: {SUPPORTED_FORMATS}. Use read_course_file to "
                "open the file itself."
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
            doc = await extract_document(data, kind, filename, start_page, end_page)
        except DocumentTextError as exc:
            return f"Error reading {shown_name}: {exc}"

        course_display = await get_course_code(course_id) or course_identifier
        result = format_document_text(
            shown_name=shown_name,
            course_display=course_display,
            kind=kind,
            shown_type=shown_type,
            size_bytes=len(data),
            doc=doc,
            route_note=route_note,
            see_pages_hint=SEE_PAGES_WITH_READ_COURSE_FILE,
        )
        return oversized_text_error(result, shown_name=shown_name, doc=doc) or result
