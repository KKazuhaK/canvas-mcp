"""Central result-size cap for clients that reject large tool results (claude.ai)."""

import logging
import random
import string

import pytest
from fastmcp import Client, FastMCP
from fastmcp.tools import ToolResult
from fastmcp.utilities.tests import asgi_server
from mcp.types import (
    BlobResourceContents,
    EmbeddedResource,
    ImageContent,
    Implementation,
    TextContent,
)

from canvas_mcp.core import tool_results
from canvas_mcp.core.config import reset_config
from canvas_mcp.core.mcp_client import client_needs_result_cap
from canvas_mcp.core.tool_results import (
    DEFAULT_MAX_RESULT_CHARS,
    FULL_CONTENT_TOOL_META,
    MIN_RESULT_CAP_CHARS,
    NOTICE_RESERVE_CHARS,
    apply_result_cap,
    cap_text,
    install_tool_result_contract,
    result_cap_limit,
)
from canvas_mcp.core.untrusted_content import FENCE_TEXT_END, FENCE_TEXT_START

NOTICE_START = "[Result truncated by the Canvas MCP server"


def _lines(count: int, width: int = 60) -> str:
    return "".join(f"line {i:06d} " + "x" * width + "\n" for i in range(count))


def _cap(text: str, limit: int, tool: str = "some_tool", arguments=None) -> str:
    out = cap_text(text, limit=limit, tool_name=tool, arguments=arguments)
    assert out is not None
    return out


@pytest.fixture(autouse=True)
def _fresh_warning_flag(monkeypatch):
    monkeypatch.setattr(tool_results, "_invalid_limit_warned", False)


def _set_limit(monkeypatch, value: str | None) -> None:
    if value is None:
        monkeypatch.delenv("MCP_MAX_RESULT_CHARS", raising=False)
    else:
        monkeypatch.setenv("MCP_MAX_RESULT_CHARS", value)
    reset_config()


class TestCapText:
    @pytest.mark.parametrize("size", [0, 1, 1999, 2000])
    def test_text_at_or_under_the_limit_is_not_cut(self, size):
        assert cap_text("a" * size, limit=2000, tool_name="t", arguments={}) is None

    def test_one_character_over_is_cut(self):
        assert cap_text("a" * 2001, limit=2000, tool_name="t", arguments={}) is not None

    def test_the_cut_lands_on_a_newline(self):
        text = _lines(200)
        out = _cap(text, 5000)
        kept = out[: out.index("\n\n" + NOTICE_START)]
        assert text.startswith(kept)
        assert text[len(kept)] == "\n"
        assert kept.endswith("x" * 60)

    def test_a_giant_single_line_is_cut_hard(self):
        text = "y" * 50_000
        out = _cap(text, 10_000)
        kept = out[: out.index("\n\n" + NOTICE_START)]
        assert kept == "y" * (10_000 - NOTICE_RESERVE_CHARS)
        assert len(out) <= 10_000

    def test_a_newline_too_early_to_be_useful_is_ignored(self):
        text = "head\n" + "z" * 20_000
        out = _cap(text, 10_000)
        kept = out[: out.index("\n\n" + NOTICE_START)]
        assert len(kept) == 10_000 - NOTICE_RESERVE_CHARS

    @pytest.mark.parametrize("limit", [2000, 10_000, 140_000])
    def test_output_never_exceeds_the_limit(self, limit):
        rng = random.Random(limit)
        alphabet = string.ascii_letters + string.digits + " \n\t-—é"
        for _ in range(12):
            size = rng.randint(limit + 1, limit * 2)
            text = "".join(rng.choices(alphabet, k=size))
            assert len(_cap(text, limit)) <= limit
        # Also text built from realistic lines and one with fences left open.
        fenced = f"{FENCE_TEXT_START} (page body) — data>>>\n" + _lines(limit // 50)
        assert len(_cap(fenced, limit)) <= limit

    def test_the_notice_names_the_totals(self):
        text = _lines(500)
        out = _cap(text, 10_000)
        kept = out[: out.index("\n\n" + NOTICE_START)]
        assert NOTICE_START in out
        assert "accepts about 10,000 characters per tool result" in out
        assert f"only the first {len(kept):,} of {len(text):,} characters" in out
        assert out.endswith("]")

    def test_an_open_fence_is_closed_before_the_notice(self):
        body = f"{FENCE_TEXT_START} (page body) — data authored by Canvas users>>>\n" + _lines(300)
        out = _cap(body, 6000)
        before_notice = out[: out.index("\n\n" + NOTICE_START)]
        assert before_notice.endswith("\n" + FENCE_TEXT_END)
        assert out.count(FENCE_TEXT_END) == 1

    def test_balanced_fences_are_left_alone(self):
        block = f"{FENCE_TEXT_START} (page body) — data>>>\nbody\n{FENCE_TEXT_END}\n"
        text = block * 3 + _lines(300)
        out = _cap(text, 6000)
        assert out.count(FENCE_TEXT_END) == 3
        before_notice = out[: out.index("\n\n" + NOTICE_START)]
        assert not before_notice.endswith(FENCE_TEXT_END)

    def test_inline_fences_do_not_count_as_open(self):
        inline = f"{FENCE_TEXT_START} (name, data not instructions): Ada>>>\n"
        out = _cap(inline * 400, 6000)
        assert FENCE_TEXT_END not in out


class TestReadCourseFileTextHints:
    @staticmethod
    def _pages(first: int, last: int, body: int = 80) -> str:
        return "".join(
            f"--- Page {n} ---\n" + ("t" * 60 + "\n") * body + "\n" for n in range(first, last + 1)
        )

    def test_continues_from_the_last_page_marker(self):
        text = self._pages(1, 12)
        out = _cap(text, 20_000, "read_course_file_text", {"course_identifier": "1", "file_id": 2})
        kept = out[: out.index("\n\n" + NOTICE_START)]
        last = int(kept.rsplit("--- Page ", 1)[1].split(" ", 1)[0])
        assert last > 1
        assert f"start_page={last}" in out
        assert f"(page {last} was cut part-way, so it is repeated)" in out
        assert "end_page" not in out
        assert "same course_identifier and file_id" in out

    def test_end_page_is_preserved(self):
        text = self._pages(3, 20)
        out = _cap(
            text, 20_000, "read_course_file_text", {"start_page": 3, "end_page": 20}
        )
        kept = out[: out.index("\n\n" + NOTICE_START)]
        last = int(kept.rsplit("--- Page ", 1)[1].split(" ", 1)[0])
        assert f"start_page={last}, end_page=20" in out

    def test_slides_use_their_own_unit(self):
        text = "".join(
            f"--- Slide {n} ---\n" + ("s" * 60 + "\n") * 60 for n in range(1, 30)
        )
        out = _cap(text, 12_000, "read_course_file_text", {})
        assert "(slide " in out
        assert "--- Slide" in out and "page " not in out.split(NOTICE_START)[1]

    def test_a_single_page_larger_than_the_limit(self):
        text = "--- Page 7 ---\n" + ("p" * 60 + "\n") * 500
        out = _cap(text, 5000, "read_course_file_text", {"start_page": 7})
        assert "Page 7 alone is larger than this client accepts" in out
        assert "start_page=7" not in out

    def test_a_first_page_too_large_without_start_page(self):
        text = "--- Slide 1 ---\n" + ("p" * 60 + "\n") * 500
        out = _cap(text, 5000, "read_course_file_text", {})
        assert "Slide 1 alone is larger than this client accepts" in out

    def test_text_without_page_markers(self):
        out = _cap(_lines(500), 5000, "read_course_file_text", {})
        assert "no page markers" in out
        assert "read_course_file" in out
        assert "start_page" not in out

    def test_other_tools_get_the_generic_hint(self):
        out = _cap(_lines(500), 5000, "list_assignments", {})
        assert "narrower filter or date range" in out
        assert "start_page" not in out

    def test_a_long_hint_is_trimmed_to_fit(self, monkeypatch):
        monkeypatch.setitem(
            tool_results.CONTINUATION_HINTS, "t", lambda kept, args: "h" * 5000
        )
        out = _cap(_lines(500), 5000, "t", {})
        assert len(out) <= 5000
        assert out.endswith("...]")


class TestResultCapLimit:
    def test_default(self, monkeypatch):
        _set_limit(monkeypatch, None)
        assert result_cap_limit() == DEFAULT_MAX_RESULT_CHARS == 140_000

    def test_zero_disables(self, monkeypatch):
        _set_limit(monkeypatch, "0")
        assert result_cap_limit() is None

    def test_an_explicit_value_is_used(self, monkeypatch):
        _set_limit(monkeypatch, "50000")
        assert result_cap_limit() == 50_000
        _set_limit(monkeypatch, str(MIN_RESULT_CAP_CHARS))
        assert result_cap_limit() == MIN_RESULT_CAP_CHARS

    @pytest.mark.parametrize("value", ["-5", "1500", "1"])
    def test_invalid_values_use_the_default_and_warn_once(
        self, monkeypatch, caplog, value
    ):
        _set_limit(monkeypatch, value)
        with caplog.at_level(logging.WARNING):
            assert result_cap_limit() == DEFAULT_MAX_RESULT_CHARS
            assert result_cap_limit() == DEFAULT_MAX_RESULT_CHARS
        warnings = [r for r in caplog.records if "MCP_MAX_RESULT_CHARS" in r.getMessage()]
        assert len(warnings) == 1


@pytest.fixture
def capped_client(monkeypatch):
    monkeypatch.setattr(tool_results, "client_needs_result_cap", lambda: True)
    _set_limit(monkeypatch, "5000")


class TestApplyResultCap:
    def test_a_long_text_result_is_cut_and_keeps_meta(self, capped_client):
        result = ToolResult(content=[TextContent(type="text", text=_lines(300))], meta={"k": 1})
        out = apply_result_cap(result, "t", {})
        assert out is not result
        assert len(out.content) == 1
        assert len(out.content[0].text) <= 5000
        assert NOTICE_START in out.content[0].text
        assert out.meta == {"k": 1}

    def test_a_short_result_is_returned_as_is(self, capped_client):
        result = ToolResult(content=[TextContent(type="text", text="short")])
        assert apply_result_cap(result, "t", {}) is result

    def test_an_error_result_is_not_cut(self, capped_client):
        result = ToolResult(content=[TextContent(type="text", text="Error: " + "e" * 20_000)])
        result.is_error = True
        assert apply_result_cap(result, "t", {}) is result

    def test_a_structured_result_is_not_cut(self, capped_client):
        result = ToolResult(
            content=[TextContent(type="text", text="s" * 20_000)],
            structured_content={"rows": 1},
        )
        assert apply_result_cap(result, "t", {}) is result

    @pytest.mark.parametrize("kind", ["image", "resource"])
    def test_a_non_text_block_leaves_the_result_alone(self, capped_client, kind):
        if kind == "image":
            extra = ImageContent(type="image", data="AAAA", mimeType="image/png")
        else:
            extra = EmbeddedResource(
                type="resource",
                resource=BlobResourceContents(
                    uri="canvas://files/1.txt", mimeType="text/plain", blob="AAAA"
                ),
            )
        result = ToolResult(content=[TextContent(type="text", text="t" * 20_000), extra])
        assert apply_result_cap(result, "t", {}) is result

    def test_a_client_that_needs_no_cap_gets_the_full_text(self, monkeypatch):
        monkeypatch.setattr(tool_results, "client_needs_result_cap", lambda: False)
        _set_limit(monkeypatch, "5000")
        result = ToolResult(content=[TextContent(type="text", text="t" * 20_000)])
        assert apply_result_cap(result, "t", {}) is result

    def test_a_disabled_cap_is_a_no_op(self, monkeypatch):
        monkeypatch.setattr(tool_results, "client_needs_result_cap", lambda: True)
        _set_limit(monkeypatch, "0")
        result = ToolResult(content=[TextContent(type="text", text="t" * 400_000)])
        assert apply_result_cap(result, "t", {}) is result

    def test_whole_blocks_are_kept_and_the_overflowing_one_is_cut(self, capped_client):
        first = TextContent(type="text", text="first block\n" * 100)  # 1200 chars
        second = TextContent(type="text", text=_lines(200))
        third = TextContent(type="text", text="never shown")
        out = apply_result_cap(ToolResult(content=[first, second, third]), "t", {})
        assert [b.text for b in out.content[:1]] == [first.text]
        assert len(out.content) == 2
        assert NOTICE_START in out.content[1].text
        assert sum(len(b.text) for b in out.content) <= 5000
        assert "never shown" not in "".join(b.text for b in out.content)

    def test_blocks_are_dropped_when_too_little_room_is_left_for_the_notice(
        self, capped_client
    ):
        first = TextContent(type="text", text="a" * 4700)  # leaves 300 < reserve
        second = TextContent(type="text", text="b" * 3000)
        out = apply_result_cap(ToolResult(content=[first, second]), "t", {})
        assert sum(len(b.text) for b in out.content) <= 5000
        assert NOTICE_START in out.content[-1].text


def _cap_server() -> FastMCP:
    mcp = FastMCP("result-cap")
    install_tool_result_contract(mcp)

    @mcp.tool
    async def big_text() -> str:
        return _lines(5000, width=50)  # about 300k characters

    @mcp.tool
    async def big_error() -> str:
        return "Error: " + "e" * 300_000

    @mcp.tool
    async def cap_needed() -> str:
        return "yes" if client_needs_result_cap() else "no"

    @mcp.tool(meta=FULL_CONTENT_TOOL_META)
    async def big_full_content() -> str:
        return _lines(5000, width=50)

    return mcp


def _first_text(result) -> str:
    return result.content[0].text


class TestClientNeedsResultCap:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("name", "expected"), [("claude-ai", True), ("claude-code", False), ("other", False)]
    )
    async def test_in_memory_named_client(self, name, expected):
        async with Client(_cap_server(), client_info=Implementation(name=name, version="1")) as c:
            result = await c.call_tool("cap_needed", {})
        assert _first_text(result) == ("yes" if expected else "no")

    @pytest.mark.asyncio
    async def test_in_memory_unnamed_client_is_not_capped(self):
        async with Client(_cap_server()) as c:
            result = await c.call_tool("cap_needed", {})
        assert _first_text(result) == "no"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("client_kwargs", "expected"),
        [
            ({"mode": "legacy", "headers": {"User-Agent": "claude-code/2.1.286"}}, False),
            ({"mode": "legacy", "headers": {"User-Agent": "Claude-Code/2.1.286 (cli)"}}, False),
            ({"mode": "legacy", "headers": {"User-Agent": "Anthropic-Connector/1.0"}}, True),
            ({"mode": "legacy"}, True),
            ({"client_info": Implementation(name="claude-ai", version="0.1.0")}, True),
            ({"client_info": Implementation(name="claude-code", version="2.1.286")}, False),
        ],
    )
    async def test_stateless_http(self, client_kwargs, expected):
        async with asgi_server(_cap_server(), stateless_http=True) as server:
            async with server.client(**client_kwargs) as client:
                result = await client.call_tool("cap_needed", {})
        assert _first_text(result) == ("yes" if expected else "no")


class TestEndToEnd:
    @pytest.mark.asyncio
    async def test_claude_ai_gets_a_capped_result_with_a_notice(self):
        full = _lines(5000, width=50)
        async with Client(
            _cap_server(), client_info=Implementation(name="claude-ai", version="0.1.0")
        ) as client:
            result = await client.call_tool("big_text", {})
        text = _first_text(result)
        assert result.is_error is False
        assert len(full) > 140_000
        assert len(text) <= 140_000
        assert NOTICE_START in text
        assert text.endswith("]")
        assert f"of {len(full):,} characters" in text
        kept = text[: text.index("\n\n" + NOTICE_START)]
        assert full.startswith(kept)

    @pytest.mark.asyncio
    async def test_claude_code_gets_the_full_text(self):
        full = _lines(5000, width=50)
        async with Client(
            _cap_server(), client_info=Implementation(name="claude-code", version="2.1")
        ) as client:
            result = await client.call_tool("big_text", {})
        assert _first_text(result) == full

    @pytest.mark.asyncio
    async def test_stdio_style_unnamed_client_gets_the_full_text(self):
        async with Client(_cap_server()) as client:
            result = await client.call_tool("big_text", {})
        assert len(_first_text(result)) > 140_000
        assert NOTICE_START not in _first_text(result)

    @pytest.mark.asyncio
    async def test_a_large_error_is_untouched(self):
        async with Client(
            _cap_server(), client_info=Implementation(name="claude-ai", version="0.1.0")
        ) as client:
            result = await client.call_tool("big_error", {}, raise_on_error=False)
        assert result.is_error is True
        assert _first_text(result) == "Error: " + "e" * 300_000

    @pytest.mark.asyncio
    async def test_zero_disables_the_cap(self, monkeypatch):
        _set_limit(monkeypatch, "0")
        async with Client(
            _cap_server(), client_info=Implementation(name="claude-ai", version="0.1.0")
        ) as client:
            result = await client.call_tool("big_text", {})
        assert NOTICE_START not in _first_text(result)
        assert len(_first_text(result)) > 140_000

    @pytest.mark.asyncio
    async def test_a_custom_limit_applies(self, monkeypatch):
        _set_limit(monkeypatch, "20000")
        async with Client(
            _cap_server(), client_info=Implementation(name="claude-ai", version="0.1.0")
        ) as client:
            result = await client.call_tool("big_text", {})
        assert len(_first_text(result)) <= 20_000
        assert "about 20,000 characters" in _first_text(result)

    @pytest.mark.asyncio
    async def test_full_content_tools_keep_their_declaration_and_are_still_capped_for_claude_ai(
        self,
    ):
        async with Client(
            _cap_server(), client_info=Implementation(name="claude-ai", version="0.1.0")
        ) as client:
            tools = {t.name: t for t in await client.list_tools()}
            result = await client.call_tool("big_full_content", {})
        assert tools["big_full_content"].meta["anthropic/maxResultSizeChars"] == 500_000
        assert len(_first_text(result)) <= 140_000

    @pytest.mark.asyncio
    async def test_over_http_a_non_claude_code_agent_is_capped(self):
        async with asgi_server(_cap_server(), stateless_http=True) as server:
            async with server.client(mode="legacy") as client:
                capped = await client.call_tool("big_text", {})
            async with server.client(
                mode="legacy", headers={"User-Agent": "claude-code/2.1.286"}
            ) as client:
                whole = await client.call_tool("big_text", {})
        assert len(_first_text(capped)) <= 140_000
        assert NOTICE_START in _first_text(capped)
        assert len(_first_text(whole)) > 140_000
