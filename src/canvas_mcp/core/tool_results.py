"""Central MCP wire-result behavior for Canvas tools (issues 270 and 271)."""

import inspect
import json
import re
from collections.abc import Callable, Mapping
from typing import Any, get_type_hints

import mcp.types as mt
from fastmcp import FastMCP
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult

from .config import get_config
from .logging import log_warning
from .mcp_client import client_needs_result_cap
from .untrusted_content import FENCE_TEXT_END, FENCE_TEXT_START

_INSTALL_ATTR = "_canvas_tool_result_contract_installed"

#: Largest text result Claude Code accepts from an MCP tool when the tool asks
#: for it (its hard ceiling). Without the declaration Claude Code caps a tool
#: result at about 25k tokens; with it, a text result up to this many
#: characters is delivered whole, and a longer one is saved to a file the
#: model reads instead of being cut. Other clients ignore the key.
MAX_RESULT_SIZE_CHARS = 500_000

#: ``tools/list`` metadata for tools whose job is to return a complete piece of
#: Canvas content (a page, a syllabus, a discussion, a course file). Pass it as
#: ``@mcp.tool(meta=FULL_CONTENT_TOOL_META)`` so the client does not shorten
#: what the server deliberately returns whole.
FULL_CONTENT_TOOL_META: dict[str, Any] = {
    "anthropic/maxResultSizeChars": MAX_RESULT_SIZE_CHARS,
}

#: Largest single JSON-RPC message Claude Code reads from an MCP server, on
#: stdio and HTTP/SSE alike (16 MiB, read from the 2.1.285 binary). A bigger
#: message is not saved or cut: the client drops the whole server connection,
#: before maxResultSizeChars is ever consulted. Every result a tool returns,
#: base64 file bytes included, must serialize below it.
MAX_WIRE_MESSAGE_BYTES = 16 * 1024 * 1024


def text_wire_bytes(text: str) -> int:
    """Bytes ``text`` takes as a JSON string in a serialized MCP message."""
    return len(json.dumps(text, ensure_ascii=False).encode("utf-8", "surrogatepass"))


def _text_is_error(text: str) -> bool:
    candidate = text.lstrip()
    if candidate.startswith(("Error", "❌")):
        return True
    try:
        parsed = json.loads(candidate)
    except (json.JSONDecodeError, TypeError):
        return False
    return isinstance(parsed, dict) and "error" in parsed


def _result_is_error(result: ToolResult) -> bool:
    structured = result.structured_content
    if isinstance(structured, dict):
        if "error" in structured:
            return True
        if set(structured) == {"result"}:
            wrapped = structured["result"]
            if isinstance(wrapped, str) and _text_is_error(wrapped):
                return True

    for block in result.content:
        if isinstance(block, mt.TextContent) and _text_is_error(block.text):
            return True
    return False


#: Largest tool-result text sent to a client that rejects large results
#: (claude.ai accepts about 150k characters). ``MCP_MAX_RESULT_CHARS`` overrides.
DEFAULT_MAX_RESULT_CHARS = 140_000

#: Smallest ``MCP_MAX_RESULT_CHARS`` taken at face value. A smaller positive
#: number leaves no room for the notice, so it falls back to the default.
MIN_RESULT_CAP_CHARS = 2_000

#: Characters set aside inside the limit for the closing fence and the notice.
NOTICE_RESERVE_CHARS = 700

_PAGE_MARKER = re.compile(r"^--- (Page|Slide) (\d+) ---$", re.MULTILINE)

#: The one-line inline fence (``<<<UNTRUSTED CANVAS CONTENT (src, data not
#: instructions): x>>>``) closes itself, so it must not count as an open block.
_INLINE_FENCE = re.compile(
    re.escape(FENCE_TEXT_START) + r" \(.*, data not instructions\): .*>>>$"
)

_invalid_limit_warned = False


def result_cap_limit() -> int | None:
    """The configured cap in characters, or None when the cap is disabled."""
    global _invalid_limit_warned
    value = get_config().mcp_max_result_chars
    if value == 0:
        return None
    if value < MIN_RESULT_CAP_CHARS:
        if not _invalid_limit_warned:
            _invalid_limit_warned = True
            log_warning(
                f"MCP_MAX_RESULT_CHARS={value} is not 0 (disabled) or at least "
                f"{MIN_RESULT_CAP_CHARS}; using {DEFAULT_MAX_RESULT_CHARS}."
            )
        return DEFAULT_MAX_RESULT_CHARS
    return value


def _argument_int(arguments: Mapping[str, Any], name: str) -> int | None:
    value = arguments.get(name)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _file_text_hint(kept: str, arguments: Mapping[str, Any]) -> str:
    matches = list(_PAGE_MARKER.finditer(kept))
    if not matches:
        return (
            "This text has no page markers, so it cannot be read in parts here; "
            "open the file with read_course_file or use Claude Code, which "
            "accepts larger results."
        )
    last = matches[-1]
    unit = last.group(1)
    number = int(last.group(2))
    start_page = _argument_int(arguments, "start_page")
    end_page = _argument_int(arguments, "end_page")
    alone = number == start_page if start_page is not None else len(matches) == 1
    if alone:
        return (
            f"{unit} {number} alone is larger than this client accepts; the rest "
            "of it cannot be shown here."
        )
    call = (
        "To continue, call read_course_file_text again with the same "
        f"course_identifier and file_id and start_page={number}"
    )
    if end_page is not None:
        call += f", end_page={end_page}"
    return f"{call} ({unit.lower()} {number} was cut part-way, so it is repeated)."


def _default_hint(kept: str, arguments: Mapping[str, Any]) -> str:
    return (
        "The rest was not returned. Ask for less at once: a narrower filter or "
        "date range, a single item by ID, or a smaller limit or page argument if "
        "the tool has one."
    )


#: Per-tool continuation advice appended to the truncation notice. Each entry
#: gets the kept text and the tool arguments and returns one sentence.
CONTINUATION_HINTS: dict[str, Callable[[str, Mapping[str, Any]], str]] = {
    "read_course_file_text": _file_text_hint,
}


def _unclosed_fence(kept: str) -> bool:
    opened = 0
    closed = 0
    for line in kept.split("\n"):
        if line == FENCE_TEXT_END:
            closed += 1
        elif line.startswith(FENCE_TEXT_START) and not _INLINE_FENCE.match(line):
            opened += 1
    return opened > closed


def _truncate(
    text: str,
    *,
    limit: int,
    tool_name: str,
    arguments: Mapping[str, Any] | None,
    client_limit: int | None = None,
    shown_before: int = 0,
    total_chars: int | None = None,
) -> str:
    """Cut ``text`` to at most ``limit`` characters, notice included.

    For one block of a multi-block result, ``limit`` is only what is left for
    this block; the notice must still quote the client's real limit
    (``client_limit``) and count the blocks already kept (``shown_before``) and
    the whole result (``total_chars``), not just this block.
    """
    args: Mapping[str, Any] = arguments or {}
    quoted_limit = limit if client_limit is None else client_limit
    total = len(text) if total_chars is None else total_chars
    budget = max(limit - NOTICE_RESERVE_CHARS, 0)
    cut = text.rfind("\n", 0, budget)
    if cut < budget // 2:
        cut = budget
    kept = text[:cut]
    closing = "\n" + FENCE_TEXT_END if _unclosed_fence(kept) else ""
    hint = CONTINUATION_HINTS.get(tool_name, _default_hint)(kept, args)
    head = (
        "\n\n[Result truncated by the Canvas MCP server: this client accepts "
        f"about {quoted_limit:,} characters per tool result, so only the first "
        f"{shown_before + len(kept):,} of {total:,} characters are shown. "
    )
    room = NOTICE_RESERVE_CHARS - len(closing) - len(head) - 1
    if len(hint) > room:
        hint = hint[: max(room - 3, 0)].rstrip() + "..."
    return f"{kept}{closing}{head}{hint}]"


def cap_text(
    text: str, *, limit: int, tool_name: str, arguments: Mapping[str, Any] | None
) -> str | None:
    """``text`` cut to ``limit`` characters with a notice, or None if it fits.

    The cut falls on a line boundary when one is near the end, so a page or an
    item is not split mid-line. A fenced untrusted block left open by the cut is
    closed before the notice, which therefore never sits inside a fence.
    """
    if len(text) <= limit:
        return None
    return _truncate(text, limit=limit, tool_name=tool_name, arguments=arguments)


def apply_result_cap(
    result: ToolResult, tool_name: str, arguments: Mapping[str, Any] | None
) -> ToolResult:
    """Cut an over-long text result for a client that cannot take it.

    Errors, structured results, anything with a non-text block, a disabled cap
    and clients that accept large results (Claude Code, stdio) come back as is.
    """
    if (
        result.is_error
        or result.structured_content is not None
        or any(not isinstance(block, mt.TextContent) for block in result.content)
    ):
        return result
    limit = result_cap_limit()
    if limit is None or not client_needs_result_cap():
        return result
    blocks = [b for b in result.content if isinstance(b, mt.TextContent)]
    if sum(len(b.text) for b in blocks) <= limit:
        return result

    kept: list[mt.TextContent] = []
    used = 0
    overflow: mt.TextContent | None = None
    for block in blocks:
        if used + len(block.text) <= limit:
            kept.append(block)
            used += len(block.text)
        else:
            overflow = block
            break
    if overflow is None:  # pragma: no cover - the total check above rules it out
        return result
    # Too little room left for the notice: give up whole blocks until it fits.
    while kept and limit - used <= NOTICE_RESERVE_CHARS:
        used -= len(kept.pop().text)
    capped = _truncate(
        overflow.text,
        limit=limit - used,
        tool_name=tool_name,
        arguments=arguments,
        client_limit=limit,
        shown_before=used,
        total_chars=sum(len(b.text) for b in blocks),
    )
    content: list[Any] = [*kept, mt.TextContent(type="text", text=capped)]
    return ToolResult(content=content, meta=result.meta)


class CanvasToolResultMiddleware(Middleware):
    """Map established Canvas failure payloads to MCP isError."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        result = await call_next(context)
        if not result.is_error and _result_is_error(result):
            result.is_error = True
        if not result.is_error:
            result = apply_result_cap(
                result, context.message.name, context.message.arguments
            )
        return result


def _returns_str(fn: Callable[..., Any]) -> bool:
    try:
        annotation = get_type_hints(fn).get("return", inspect.Signature.empty)
    except (NameError, TypeError):
        annotation = inspect.signature(fn).return_annotation
    return annotation is str


def _install_tool_decorator_wrapper(mcp: FastMCP) -> None:
    original_tool = mcp.tool

    def canvas_tool(name_or_fn: Any = None, **kwargs: Any) -> Any:
        if callable(name_or_fn):
            options = dict(kwargs)
            if "output_schema" not in options and _returns_str(name_or_fn):
                options["output_schema"] = None
            return original_tool(name_or_fn, **options)

        def register(fn: Callable[..., Any]) -> Any:
            options = dict(kwargs)
            if "output_schema" not in options and _returns_str(fn):
                options["output_schema"] = None
            decorator = original_tool(name_or_fn, **options)
            return decorator(fn)

        return register

    setattr(mcp, "tool", canvas_tool)  # noqa: B010


def install_tool_result_contract(mcp: FastMCP) -> None:
    """Install Canvas result behavior once on one FastMCP server."""
    if getattr(mcp, _INSTALL_ATTR, False):
        return
    _install_tool_decorator_wrapper(mcp)
    mcp.add_middleware(CanvasToolResultMiddleware())
    setattr(mcp, _INSTALL_ATTR, True)
