"""SELFHOST_DISABLED_TOOLS: the operator removes named tools at startup.

Three layers: the setting parser, the startup wiring through ``main()``, and the
whole HTTP stack (real tool registry, credential gate, token store) proving that a
disabled tool is neither listed nor callable, for a read tool and a write tool alike.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import fastmcp
import httpx
import pytest
import respx
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from starlette.testclient import TestClient

from canvas_mcp import server as server_module
from canvas_mcp.core import config as config_module
from canvas_mcp.core.config import reset_config
from canvas_mcp.core.course_policy import reset_policy_cache
from canvas_mcp.core.selfhost.app import (
    apply_disabled_tools,
    build_selfhost_asgi_app,
    install_selfhost,
    prepare_selfhost,
)
from canvas_mcp.core.selfhost.settings import (
    DISABLED_TOOLS_ENV,
    SelfhostConfigError,
    load_selfhost_settings,
)
from canvas_mcp.core.tool_policy import (
    TOOL_EFFECTS,
    Effect,
    apply_tool_policy,
    resolve_tool_policy,
)
from canvas_mcp.server import register_all_tools

from .conftest import CLIENT, OID_A, TENANT
from .test_startup import HTTP, SECRETS, _run_main, entra_env  # noqa: F401 - fixture

BASE = "https://canvas.example.test"
CANVAS = "https://canvas.example.edu"
STUDENT_WRITES = "mark_module_item_done,create_planner_note,send_message"
OPERATOR_ALLOWS = "mark_module_item_done,create_planner_note"
READ_TOOL = "read_course_file_text"
WRITE_TOOL = "create_planner_note"
KEY_A = f"entra:{TENANT}:{OID_A}".lower()
TOKEN_A = "canvas-token-for-user-A-0123456789"


def _env(**overrides: str) -> dict[str, str]:
    env = {
        "PUBLIC_BASE_URL": BASE,
        "ENTRA_TENANT_ID": TENANT,
        "ENTRA_CLIENT_ID": CLIENT,
        "ENTRA_CLIENT_SECRET": "entra-client-secret-0123456789",
        "OAUTH_JWT_SIGNING_KEY": "jwt-signing-key-" + "z" * 40,
        "ACCOUNT_SESSION_SECRET": base64.b64encode(bytes(range(32))).decode(),
        "CANVAS_TOKEN_KEYS": "k1:" + base64.b64encode(bytes(32)).decode(),
        "FASTMCP_HOME": "/data/fastmcp",
    }
    env.update(overrides)
    return env


def _problems(raw: str) -> list[str]:
    with pytest.raises(SelfhostConfigError) as info:
        load_selfhost_settings(_env(SELFHOST_DISABLED_TOOLS=raw))
    return info.value.problems


class TestSetting:
    def test_the_variable_name(self):
        assert DISABLED_TOOLS_ENV == "SELFHOST_DISABLED_TOOLS"

    def test_unset_and_blank_remove_nothing(self):
        assert load_selfhost_settings(_env()).disabled_tools == ()
        for blank in ("", "  ", ",", " , ,"):
            assert load_selfhost_settings(_env(SELFHOST_DISABLED_TOOLS=blank)).disabled_tools == ()

    def test_names_are_trimmed_lowercased_deduplicated_and_sorted(self):
        settings = load_selfhost_settings(
            _env(SELFHOST_DISABLED_TOOLS=" read_course_file_text, LIST_USERS ,read_course_file_text,send_message,")
        )
        assert settings.disabled_tools == ("list_users", "read_course_file_text", "send_message")

    def test_read_and_write_tools_are_both_accepted(self):
        raw = f"{READ_TOOL},{WRITE_TOOL},execute_typescript"
        settings = load_selfhost_settings(_env(SELFHOST_DISABLED_TOOLS=raw))
        assert set(settings.disabled_tools) == {READ_TOOL, WRITE_TOOL, "execute_typescript"}

    def test_every_known_tool_name_is_accepted(self):
        raw = ",".join(sorted(TOOL_EFFECTS))
        loaded = load_selfhost_settings(_env(SELFHOST_DISABLED_TOOLS=raw)).disabled_tools
        assert set(loaded) == set(TOOL_EFFECTS)

    def test_an_unknown_name_stops_startup_and_the_message_lists_only_the_unknown_names(self):
        problems = _problems(f"{READ_TOOL},read_course_file_txt,no_such_tool")
        assert len(problems) == 1
        assert "SELFHOST_DISABLED_TOOLS" in problems[0]
        assert "no_such_tool" in problems[0] and "read_course_file_txt" in problems[0]
        assert READ_TOOL not in problems[0].replace("read_course_file_txt", "")

    def test_an_entry_that_is_not_shaped_like_a_tool_name_is_counted_not_echoed(self):
        secret = "Bearer-s3cr3t/Token+value=="
        problems = _problems(f"{READ_TOOL},{secret}, two words ")
        assert len(problems) == 1
        assert "2 entries" in problems[0]
        assert "s3cr3t" not in problems[0] and "words" not in problems[0]

    def test_it_is_reported_together_with_other_problems(self):
        with pytest.raises(SelfhostConfigError) as info:
            load_selfhost_settings(_env(ENTRA_CLIENT_SECRET="short", SELFHOST_DISABLED_TOOLS="nope"))
        text = "; ".join(info.value.problems)
        assert "ENTRA_CLIENT_SECRET" in text and "SELFHOST_DISABLED_TOOLS" in text

    def test_the_summary_for_config_lists_the_tools(self):
        settings = load_selfhost_settings(_env(SELFHOST_DISABLED_TOOLS=f"{WRITE_TOOL},{READ_TOOL}"))
        lines = server_module._selfhost_summary(settings)
        assert f"  Disabled tools: {WRITE_TOOL}, {READ_TOOL}" in lines
        none = server_module._selfhost_summary(load_selfhost_settings(_env()))
        assert "  Disabled tools: none" in none


class TestApply:
    @staticmethod
    def _server(role: str = "student") -> FastMCP:
        mcp = FastMCP("disable")
        register_all_tools(mcp, role=role)
        return mcp

    @staticmethod
    def _names(mcp: FastMCP) -> set[str]:
        return {tool.name for tool in asyncio.run(mcp.list_tools(run_middleware=False))}

    def test_a_named_read_tool_is_removed_and_the_rest_stay(self):
        mcp = self._server()
        before = self._names(mcp)
        assert READ_TOOL in before
        removed = asyncio.run(apply_disabled_tools(mcp, {READ_TOOL}))
        assert removed == [READ_TOOL]
        assert self._names(mcp) == before - {READ_TOOL}

    def test_an_empty_list_changes_nothing(self):
        mcp = self._server()
        before = self._names(mcp)
        assert asyncio.run(apply_disabled_tools(mcp, ())) == []
        assert self._names(mcp) == before

    def test_it_can_only_remove_never_add(self):
        mcp = self._server("student")
        before = self._names(mcp)
        # A tool that is not registered for the student profile: naming it neither
        # registers it nor fails.
        absent = next(
            name for name, effect in TOOL_EFFECTS.items() if name not in before and effect is Effect.READ
        )
        assert asyncio.run(apply_disabled_tools(mcp, {absent})) == []
        assert self._names(mcp) == before

    def test_a_write_tool_the_operator_never_allowed_is_not_brought_back(self):
        mcp = self._server()
        asyncio.run(apply_tool_policy(mcp, resolve_tool_policy(None, "http")))
        before = self._names(mcp)
        assert WRITE_TOOL not in before
        assert asyncio.run(apply_disabled_tools(mcp, {WRITE_TOOL})) == []
        assert self._names(mcp) == before


class TestStartup:
    def test_main_removes_the_tools_and_logs_the_count(self, entra_env, caplog):  # noqa: F811
        import canvas_mcp.core.selfhost.app as app_module

        mp = entra_env["monkeypatch"]
        mp.setenv("CANVAS_ROLE", "student")
        mp.setenv("SELFHOST_DISABLED_TOOLS", f"{READ_TOOL}, list_users")
        caplog.set_level(logging.INFO)
        seen: dict[str, Any] = {}
        real_install = app_module.install_selfhost

        def spy(mcp, runtime, config, **kwargs):
            seen["names"] = {tool.name for tool in asyncio.run(mcp.list_tools(run_middleware=False))}
            return real_install(mcp, runtime, config, **kwargs)

        mp.setattr(app_module, "install_selfhost", spy)
        mp.setattr(server_module, "_run_selfhost_http_server", lambda app, host, port: None)
        mp.setattr("sys.argv", ["canvas-mcp-server", *HTTP])
        config_module.reset_config()
        try:
            server_module.main()
        finally:
            config_module.reset_config()
        assert "list_courses" in seen["names"]
        assert READ_TOOL not in seen["names"] and "list_users" not in seen["names"]
        assert "disabled_tools" in caplog.text

    def test_an_unknown_name_exits_1_and_names_only_the_unknown_tool(self, entra_env, caplog):  # noqa: F811
        mp = entra_env["monkeypatch"]
        mp.setenv("SELFHOST_DISABLED_TOOLS", f"{READ_TOOL},read_course_file_txt")
        assert _run_main(mp, *HTTP).code == 1
        assert "read_course_file_txt" in caplog.text
        assert "SELFHOST_DISABLED_TOOLS" in caplog.text
        for secret in SECRETS.values():
            assert secret not in caplog.text
        assert f"unknown tools: {READ_TOOL}" not in caplog.text

    def test_an_unknown_name_also_stops_the_config_command(self, entra_env):  # noqa: F811
        entra_env["monkeypatch"].setenv("SELFHOST_DISABLED_TOOLS", "no_such_tool")
        assert _run_main(entra_env["monkeypatch"], *HTTP, "--config").code == 1

    def test_config_shows_the_list_without_secrets(self, entra_env, capsys):  # noqa: F811
        entra_env["monkeypatch"].setenv("SELFHOST_DISABLED_TOOLS", f"{WRITE_TOOL},{READ_TOOL}")
        assert _run_main(entra_env["monkeypatch"], *HTTP, "--config").code == 0
        out = capsys.readouterr().err
        assert f"Disabled tools: {WRITE_TOOL}, {READ_TOOL}" in out
        for secret in SECRETS.values():
            assert secret not in out


@pytest.fixture
def stack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[SimpleNamespace]:
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path / "fastmcp")
    monkeypatch.setenv("CANVAS_API_URL", CANVAS)
    monkeypatch.setenv("STUDENT_WRITE_TOOLS", STUDENT_WRITES)
    monkeypatch.setenv("ALLOWED_WRITE_TOOLS", OPERATOR_ALLOWS)
    monkeypatch.delenv("COURSE_AGENT_POLICY_DEFAULT", raising=False)
    for name in ("CANVAS_API_TOKEN", "CANVAS_ROLE"):
        monkeypatch.delenv(name, raising=False)
    reset_config()
    reset_policy_cache()

    settings = load_selfhost_settings(_env(
        FASTMCP_HOME=str(tmp_path / "fastmcp"),
        SELFHOST_DATA_DIR=str(tmp_path / "data"),
        SELFHOST_DISABLED_TOOLS=f"{READ_TOOL},{WRITE_TOOL}",
    ))
    runtime = prepare_selfhost(settings)
    runtime.store.put(
        tenant_id=TENANT, object_id=OID_A, api_token=TOKEN_A, canvas_user_id="1",
        canvas_user_name="n", entra_display_name="n", entra_upn="n@example.test",
        canvas_host="canvas.example.edu",
    )
    # The user switched both the allowed write tools on.
    runtime.store.set_tool_prefs(KEY_A, ["mark_module_item_done", WRITE_TOOL])

    from canvas_mcp.core.config import get_config

    config = get_config()
    policy = resolve_tool_policy(config.allowed_write_tools, "http")
    mcp = FastMCP(
        "disabled",
        auth=StaticTokenVerifier(
            {"bearer-A": {
                "client_id": CLIENT, "scopes": ["Canvas.Access"], "tid": TENANT, "oid": OID_A,
                "azp": CLIENT, "roles": ["Canvas.User"], "name": "user A",
            }},
            required_scopes=["Canvas.Access"],
        ),
    )
    register_all_tools(mcp, role="student")
    asyncio.run(apply_tool_policy(mcp, policy))
    asyncio.run(apply_disabled_tools(mcp, settings.disabled_tools))
    install_selfhost(mcp, runtime, config, tool_policy=policy)
    app = build_selfhost_asgi_app(mcp, runtime, config)

    seen: list[tuple[str, str]] = []

    def canvas(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path == "/api/v1/courses":
            return httpx.Response(200, json=[{"id": 101, "name": "Python", "course_code": "ICS 33"}])
        return httpx.Response(404, json={"errors": [{"message": "not found"}]})

    with respx.mock(assert_all_called=False) as router, TestClient(app, base_url=BASE) as client:
        router.route(host="canvas.example.edu").mock(side_effect=canvas)
        yield SimpleNamespace(client=client, seen=seen)
    reset_config()
    reset_policy_cache()


def _rpc(stack: SimpleNamespace, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Authorization": "Bearer bearer-A",
    }
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    response = stack.client.post("/mcp", json=body, headers=headers)
    assert response.status_code == 200, response.text
    text = response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        text = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")][-1]
    return json.loads(text)


def _tool_names(stack: SimpleNamespace) -> set[str]:
    return {tool["name"] for tool in _rpc(stack, "tools/list")["result"]["tools"]}


def _refused(stack: SimpleNamespace, name: str) -> str:
    """The refusal text of a call, whether the server reports it as a result or an error."""
    payload = _rpc(stack, "tools/call", {"name": name, "arguments": {}})
    if "error" in payload:
        return str(payload["error"]["message"])
    result = payload["result"]
    assert result.get("isError"), f"{name} was not refused: {result}"
    return "".join(block.get("text", "") for block in result["content"])


class TestWholeStack:
    def test_a_disabled_read_tool_is_absent_from_the_list_and_refused_on_call(self, stack):
        names = _tool_names(stack)
        assert READ_TOOL not in names
        assert "list_courses" in names and "read_course_file" in names
        text = _refused(stack, READ_TOOL)
        assert "unknown" in text.lower() or "not found" in text.lower()
        assert stack.seen == []

    def test_a_disabled_write_tool_stays_gone_even_when_allowed_and_switched_on(self, stack):
        names = _tool_names(stack)
        assert WRITE_TOOL not in names
        assert "mark_module_item_done" in names  # allowed, switched on, not disabled
        _refused(stack, WRITE_TOOL)
        assert stack.seen == []

    def test_search_canvas_tools_does_not_advertise_a_disabled_tool(self, stack):
        payload = _rpc(stack, "tools/call", {
            "name": "search_canvas_tools", "arguments": {"query": "read_course_file", "detail_level": "names"},
        })
        text = "".join(block.get("text", "") for block in payload["result"]["content"])
        assert "read_course_file" in text
        assert READ_TOOL not in text

    def test_the_other_tools_still_work(self, stack):
        payload = _rpc(stack, "tools/call", {"name": "list_courses", "arguments": {}})
        assert not payload["result"].get("isError")
        assert "Python" in "".join(block.get("text", "") for block in payload["result"]["content"])
