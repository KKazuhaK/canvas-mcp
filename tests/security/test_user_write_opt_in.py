"""The per-user write-tool layer can only narrow what the operator allows.

The effective set is ``registered ∩ ALLOWED_WRITE_TOOLS ∩ user-enabled`` (and the
course policy at call time). These tests pin the properties that matter for
prompt injection: nothing a user (or a stored record) says can widen the server
ceiling, nothing is on by default, and no MCP tool can read or change the switches.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastmcp import Client, FastMCP
from fastmcp.server.auth import AccessToken
from selfhost.conftest import acct_key

import canvas_mcp.core.config as config_module
from canvas_mcp.core.config import STUDENT_WRITE_TOOL_NAMES
from canvas_mcp.core.credentials import (
    RequestCredentials,
    RequestPrincipal,
    RequestToolPrefs,
    clear_http_request_context,
    set_request_credentials,
    set_request_principal,
    set_request_tool_prefs,
)
from canvas_mcp.core.selfhost import tool_gate
from canvas_mcp.core.selfhost.tool_gate import SelfhostCredentialGate
from canvas_mcp.core.selfhost.tool_prefs import (
    WriteDecision,
    decide,
    effective_write_tools,
    offered_write_tools,
)
from canvas_mcp.core.tool_policy import (
    SIDE_EFFECT_TOOLS,
    TOOL_EFFECTS,
    Effect,
    apply_tool_policy,
    resolve_tool_policy,
)
from canvas_mcp.server import register_all_tools

OID = "aaaaaaaa-0000-4000-8000-00000000000a"
TENANT = "11111111-2222-3333-4444-555555555555"
SRC = Path(__file__).resolve().parents[2] / "src" / "canvas_mcp"
READ = {name for name, effect in TOOL_EFFECTS.items() if effect is Effect.READ}


@pytest.fixture(autouse=True)
def _request(monkeypatch: pytest.MonkeyPatch):
    clear_http_request_context()
    monkeypatch.setattr(
        tool_gate,
        "get_access_token",
        lambda: AccessToken(token="t", client_id="c", scopes=[], claims={"oid": OID}),
    )
    set_request_principal(
        RequestPrincipal(
            key=acct_key(OID), tenant_id=TENANT, object_id=OID, display_name="",
            upn="", roles=frozenset({"Canvas.User"}), is_owner=False,
        )
    )
    set_request_credentials(RequestCredentials(api_token="x" * 30, api_url="https://c.example.test/api/v1"))
    yield
    clear_http_request_context()


@pytest.fixture
def all_flags_on(monkeypatch):
    monkeypatch.setenv("EXECUTE_TYPESCRIPT_ENABLED", "true")
    monkeypatch.setenv("STUDENT_WRITE_TOOLS", ",".join(sorted(STUDENT_WRITE_TOOL_NAMES)))
    monkeypatch.delenv("ALLOWED_WRITE_TOOLS", raising=False)
    monkeypatch.setattr(config_module, "_config", None, raising=False)
    yield
    monkeypatch.setattr(config_module, "_config", None, raising=False)


async def _stack(allowed: str, enabled: set[str]) -> tuple[FastMCP, frozenset[str]]:
    """The real registry under an operator policy, behind the gate, for a user with these switches."""
    mcp = FastMCP("opt-in")
    register_all_tools(mcp, role="all")
    policy = resolve_tool_policy(allowed, "http")
    await apply_tool_policy(mcp, policy)
    mcp.add_middleware(SelfhostCredentialGate(write_ceiling=policy.allowed))
    set_request_tool_prefs(RequestToolPrefs(enabled=frozenset(enabled)))
    return mcp, policy.allowed


async def _visible(mcp: FastMCP) -> set[str]:
    async with Client(mcp) as client:
        return {tool.name for tool in await client.list_tools()}


class TestCeilingIsAHardLimit:
    @pytest.mark.parametrize("name", sorted(SIDE_EFFECT_TOOLS))
    def test_a_stored_switch_never_beats_a_missing_operator_allowance(self, name: str) -> None:
        # The user's record names every write tool; the operator allows none.
        verdict = decide(name, enabled=SIDE_EFFECT_TOOLS, ceiling=frozenset())
        assert verdict is WriteDecision.NOT_OFFERED

    @pytest.mark.parametrize("allowed", sorted(SIDE_EFFECT_TOOLS - {"execute_typescript"}))
    def test_one_allowed_tool_opens_exactly_that_tool(self, allowed: str) -> None:
        for name in SIDE_EFFECT_TOOLS:
            verdict = decide(name, enabled=SIDE_EFFECT_TOOLS, ceiling={allowed})
            assert (verdict is WriteDecision.ALLOWED) == (name == allowed), name

    def test_code_execution_is_never_user_enableable(self) -> None:
        everything = frozenset(TOOL_EFFECTS)
        assert decide("execute_typescript", enabled=everything, ceiling=everything) is WriteDecision.NOT_OFFERED
        assert "execute_typescript" not in offered_write_tools(everything, everything)

    def test_the_effective_set_is_a_subset_of_both_inputs(self) -> None:
        offered = offered_write_tools(TOOL_EFFECTS, {"send_message", "create_assignment"})
        for enabled in (set(), {"send_message"}, set(SIDE_EFFECT_TOOLS), {"ghost"}):
            got = effective_write_tools(offered, enabled)
            assert got <= offered and got <= enabled

    def test_nothing_is_on_by_default(self) -> None:
        for name in SIDE_EFFECT_TOOLS - {"execute_typescript"}:
            assert decide(name, enabled=frozenset(), ceiling=None) is WriteDecision.NOT_ENABLED
            assert decide(name, enabled=frozenset(), ceiling=SIDE_EFFECT_TOOLS) is WriteDecision.NOT_ENABLED
        # Code execution is not something a user can turn on at all.
        assert decide("execute_typescript", enabled=frozenset(), ceiling=None) is WriteDecision.NOT_OFFERED


class TestRealRegistry:
    async def test_by_default_a_user_sees_only_read_tools_even_when_the_operator_allows_writes(
        self, all_flags_on
    ) -> None:
        mcp, _ = await _stack("all", set())
        visible = await _visible(mcp)
        assert visible, "no tools registered; the check would pass vacuously"
        assert visible <= READ

    async def test_the_visible_writes_are_exactly_allowed_and_switched_on(self, all_flags_on) -> None:
        allowed = "send_message,submit_assignment,create_assignment,mark_module_item_done"
        enabled = {"send_message", "create_assignment", "delete_page", "execute_typescript"}
        mcp, ceiling = await _stack(allowed, enabled)
        visible = await _visible(mcp)
        assert visible - READ == {"send_message", "create_assignment"}
        assert visible - READ == (ceiling & enabled)

    async def test_switching_on_every_write_tool_cannot_exceed_the_allowlist(self, all_flags_on) -> None:
        mcp, ceiling = await _stack("send_message", set(SIDE_EFFECT_TOOLS))
        assert (await _visible(mcp)) - READ == {"send_message"} == set(ceiling)

    async def test_a_hidden_or_unallowed_tool_is_refused_when_called_by_name(self, all_flags_on) -> None:
        mcp, _ = await _stack("send_message", {"submit_assignment", "delete_page"})
        async with Client(mcp) as client:
            for name in ("send_message", "submit_assignment", "delete_page", "execute_typescript"):
                result = await client.call_tool(name, {}, raise_on_error=False)
                assert result.is_error, name

    async def test_the_operator_ceiling_all_still_leaves_code_execution_out(self, all_flags_on) -> None:
        mcp, _ = await _stack("all", set(SIDE_EFFECT_TOOLS))
        assert "execute_typescript" not in await _visible(mcp)


class TestNoToolCanChangeTheSwitches:
    def test_no_registered_tool_module_touches_the_preferences(self) -> None:
        pattern = re.compile(r"set_tool_prefs|get_tool_prefs|ToolPrefsCache|user_tool_prefs|enabled_write_tools")
        offenders = [
            str(path.relative_to(SRC))
            for path in sorted((SRC / "tools").rglob("*.py"))
            if pattern.search(path.read_text(encoding="utf-8"))
        ]
        assert offenders == []

    def test_only_the_account_pages_write_the_switches(self) -> None:
        writers = sorted(
            str(path.relative_to(SRC)).replace("\\", "/")
            for path in SRC.rglob("*.py")
            if "set_tool_prefs(" in path.read_text(encoding="utf-8")
            or "set_tool_prefs," in path.read_text(encoding="utf-8")
        )
        assert writers == ["core/selfhost/account_web.py", "core/selfhost/token_store.py"]

    def test_the_account_pages_are_the_only_route_that_saves_them(self) -> None:
        text = (SRC / "core" / "selfhost" / "account_web.py").read_text(encoding="utf-8")
        assert text.count("self.store.set_tool_prefs") == 1
        assert "async def save_write_tools" in text
        # Behind the same guard as every other POST: session, Origin, CSRF.
        body = text[text.index("async def save_write_tools") :]
        assert "self._guard_post(request" in body.split("self.store.set_tool_prefs")[0]

    async def test_no_registered_tool_is_about_preferences(self, all_flags_on) -> None:
        mcp = FastMCP("names")
        register_all_tools(mcp, role="all")
        for tool in await mcp.list_tools(run_middleware=False):
            haystack = f"{tool.name} {tool.description or ''}".lower()
            assert "preference" not in haystack and "write_tools" not in haystack, tool.name
