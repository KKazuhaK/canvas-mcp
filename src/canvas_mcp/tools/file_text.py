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
import re
import threading
from dataclasses import dataclass

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
    PAGED_KINDS,
    SUPPORTED_FORMATS,
    DocumentTextError,
    ExtractedDocument,
    TextSection,
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


#: Parses running at once. Office parsing holds a whole document's XML tree in
#: memory and cannot be cancelled once started, so concurrent calls queue here
#: (in the worker thread, not on the event loop) instead of stacking up.
MAX_CONCURRENT_EXTRACTIONS = 2
_EXTRACTION_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_EXTRACTIONS)

#: A MIME type as Canvas should report it (type/subtype, no parameters).
_MIME_TOKEN = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}")


def _shown_content_type(content_type: str | None) -> str:
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
    budget: int,
) -> ExtractedDocument:
    """``extract_text`` holding one of the extraction slots (worker thread)."""
    with _EXTRACTION_SLOTS:
        return extract_text(
            data, kind, filename=filename, start=start, end=end, budget=budget
        )


@dataclass
class _Rendered:
    text: str
    truncated: bool = False
    #: Page/slide to pass as ``start_page`` to continue, if any remain.
    resume_at: int | None = None
    #: First and last page/slide that appear in ``text`` (fully or partly).
    first_shown: int | None = None
    last_shown: int | None = None
    #: The page/slide shown only in part, if the cut fell inside one.
    partial: int | None = None
    #: True when ``partial`` is the first page/slide shown: it alone is over
    #: ``max_chars``, so the caller must raise ``max_chars`` or skip past it.
    oversized: bool = False


def _render_sections(doc: ExtractedDocument, max_chars: int) -> _Rendered:
    """Join sections with markers and cut at ``max_chars``.

    The continuation point always moves forward: when the very first
    page/slide does not fit, ``resume_at`` is the one after it (and
    ``oversized`` is set) rather than the same page again.
    """
    label = (doc.unit or "").capitalize()
    out = _Rendered("")
    pieces: list[str] = []
    length = 0
    for index, section in enumerate(doc.sections):
        header = ""
        if section.number is not None:
            body = section.text or f"[no text on this {doc.unit}]"
            header = f"--- {label} {section.number} ---\n"
            piece = header + body
        else:
            piece = section.text
        separator = "\n\n" if pieces else ""
        if length + len(separator) + len(piece) > max_chars:
            out.truncated = True
            room = max_chars - length - len(separator)
            first = not pieces
            # A later section is only shown if at least one character of its
            # body fits; a bare (or cut) marker would claim a page that is
            # not there.
            if room > 0 and (first or room > len(header)):
                pieces.append(separator + piece[:room])
                if section.number is not None:
                    out.partial = section.number
                    out.last_shown = section.number
                    if out.first_shown is None:
                        out.first_shown = section.number
            if section.number is None:
                break
            if first:
                out.oversized = True
                more = index < len(doc.sections) - 1 or doc.stopped_early
                out.resume_at = section.number + 1 if more else None
            else:
                out.resume_at = section.number
            break
        pieces.append(separator + piece)
        length += len(separator) + len(piece)
        if section.number is not None:
            out.last_shown = section.number
            if out.first_shown is None:
                out.first_shown = section.number
        if doc.stopped_early and index == len(doc.sections) - 1:
            # Extraction stopped on budget: everything shown is complete, more
            # exists after it.
            out.truncated = True
            out.resume_at = section.number + 1 if section.number is not None else None
    out.text = "".join(pieces)
    return out


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
        start_char: int = 0,
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
            start_char: For files without pages (DOCX, text, HTML), the 0-based character offset to start from
        """
        file_key = coerce_canvas_id(file_id)
        if file_key is None:
            return f"Error: file_id must be a numeric Canvas file ID (got {file_id!r})."
        if max_chars < 1:
            return f"Error: max_chars must be positive (got {max_chars})."
        requested_max_chars = max_chars
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
        if start_char < 0:
            return f"Error: start_char must be 0 or greater (got {start_char})."

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
        content_type = file_info.get("content-type") or ""
        shown_type = _shown_content_type(content_type)
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
                f"Supported formats: {SUPPORTED_FORMATS}. Use read_course_file for raw bytes."
            )
        if start_char and kind in PAGED_KINDS:
            return (
                f"Error: start_char applies only to files without pages (Word, text, "
                f"HTML). {shown_name} is a {KIND_LABELS[kind]} file: use start_page instead."
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
                _extract_bounded,
                data,
                kind,
                filename,
                start_page,
                end_page,
                # Unpaged extraction (DOCX) must also gather the skipped prefix.
                start_char + max_chars + 1,
            )
        except DocumentTextError as exc:
            return f"Error reading {shown_name}: {exc}"

        full_chars: int | None = None
        if doc.unit is None and doc.sections:
            full_text = doc.sections[0].text
            if start_char and start_char >= len(full_text):
                return (
                    f"Error: start_char {start_char} is past the end of {shown_name} "
                    f"({len(full_text)} characters of text)."
                )
            if not doc.stopped_early:
                full_chars = len(full_text)
            doc.sections[0] = TextSection(None, full_text[start_char:])

        rendered = _render_sections(doc, max_chars)
        text = rendered.text
        course_display = await get_course_code(course_id) or course_identifier

        result = f"File: {shown_name}\n"
        result += f"  Course: {course_display}\n"
        result += f"  Type: {KIND_LABELS[kind]} ({shown_type})\n"
        result += f"  Size: {format_file_size(len(data))}\n"
        unit = (doc.unit or "").capitalize()
        if doc.unit and doc.total_units is not None:
            if rendered.first_shown is not None:
                # The range shown, not the range extracted: a page gathered
                # but cut away entirely is not claimed here.
                result += (
                    f"  {unit}s: {rendered.first_shown}-{rendered.last_shown} "
                    f"of {doc.total_units}"
                )
                if rendered.partial is not None:
                    result += f" ({doc.unit} {rendered.partial} cut short)"
                result += "\n"
            else:
                result += f"  {unit}s: 0\n"
        elif text and (start_char or rendered.truncated):
            end_char = start_char + len(text)
            of = f" of {full_chars}" if full_chars is not None else ""
            result += f"  Characters: {start_char}-{end_char}{of}\n"
        if route_note:
            result += f"  Note: {route_note}\n"
        for note in doc.notes:
            result += f"  Note: {note}\n"

        if not text.strip() and not rendered.truncated:
            # A whitespace-only slice mid-file still gets its continuation hint.
            result += "\n(No text could be extracted from this file.)\n"
            return result

        result += "\n" + fence_untrusted(text, "course file text") + "\n"
        if rendered.truncated:
            result += f"\n[Truncated at {max_chars} characters"
            if requested_max_chars > max_chars:
                result += f" (max_chars is capped at {MAX_CHARS_LIMIT})"
            result += "."
            if doc.unit and rendered.oversized:
                result += (
                    f" {unit} {rendered.partial} alone is longer than that, so only "
                    "its first part is shown"
                )
                if max_chars < MAX_CHARS_LIMIT:
                    result += "; raise max_chars to read all of it"
                if rendered.resume_at is not None:
                    result += f"; continue with start_page={rendered.resume_at}"
                result += "."
            elif doc.unit and rendered.resume_at is not None:
                result += f" Continue with start_page={rendered.resume_at}."
            elif doc.unit is None:
                result += f" Continue with start_char={start_char + len(text)}."
            result += "]\n"
        return result
