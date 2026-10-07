"""Tests for the credential gate on tool calls and resource reads."""

import logging
from typing import Any

import pytest
from fastmcp import Client, FastMCP
from fastmcp.server.auth import AccessToken

from canvas_mcp.core.credentials import (
    RequestCredentials,
    set_missing_credentials_message,
    set_request_credentials,
    set_request_principal,
)
from canvas_mcp.core.selfhost import tool_gate
from canvas_mcp.core.selfhost.request_context import not_enrolled_message
from canvas_mcp.core.selfhost.tool_gate import SelfhostCredentialGate

from .conftest import OID_A, OID_B, make_principal

ACCOUNT_URL = "https://mcp.example.test/account"


class Body:
    """Counts how often the tool or resource body really ran."""

    runs = 0


@pytest.fixture
def server() -> FastMCP:
    Body.runs = 0
    mcp = FastMCP("gate-test")
    mcp.add_middleware(SelfhostCredentialGate())

    @mcp.tool()
    def whoami() -> str:
        """Dummy tool."""
        Body.runs += 1
        return "ran"

    @mcp.resource("data://thing")
    def thing() -> str:
        Body.runs += 1
        return "resource body"

    @mcp.prompt()
    def instructions() -> str:
        """Dummy prompt."""
        return "how to enroll"

    return mcp


def _verified_token(oid: str | None) -> AccessToken | None:
    if oid is None:
        return None
    return AccessToken(token="t", client_id="c", scopes=[], claims={"oid": oid})


@pytest.fixture
def verified_oid(monkeypatch: pytest.MonkeyPatch):
    """Control which oid the (verified) access token carries."""

    def use(oid: str | None) -> None:
        monkeypatch.setattr(tool_gate, "get_access_token", lambda: _verified_token(oid))

    return use


def _enrol(oid: str = OID_A, token: str = "canvas-token-1234567890abcdef") -> None:
    set_request_principal(make_principal(oid))
    set_request_credentials(RequestCredentials(api_token=token, api_url="https://canvas.example.test/api/v1"))


async def _call(server: FastMCP) -> Any:
    async with Client(server) as client:
        return await client.call_tool("whoami", {}, raise_on_error=False)


def _text(result: Any) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


class TestToolCalls:
    async def test_unenrolled_user_gets_the_account_message_and_the_body_never_runs(self, server, verified_oid):
        verified_oid(OID_A)
        set_request_principal(make_principal(OID_A))
        set_missing_credentials_message(not_enrolled_message(ACCOUNT_URL))
        result = await _call(server)
        assert result.is_error
        assert ACCOUNT_URL in _text(result)
        assert Body.runs == 0

    async def test_enrolled_user_passes(self, server, verified_oid):
        verified_oid(OID_A)
        _enrol(OID_A)
        result = await _call(server)
        assert not result.is_error
        assert _text(result) == "ran"
        assert Body.runs == 1

    async def test_no_principal_is_refused(self, server, verified_oid):
        verified_oid(OID_A)
        set_request_credentials(RequestCredentials(api_token="x" * 30, api_url="https://c.example.test/api/v1"))
        result = await _call(server)
        assert result.is_error
        assert _text(result) == "Not signed in."
        assert Body.runs == 0

    async def test_principal_and_token_oid_mismatch_is_refused(self, server, verified_oid, caplog):
        caplog.set_level(logging.ERROR)
        verified_oid(OID_B)
        _enrol(OID_A)
        result = await _call(server)
        assert result.is_error
        assert _text(result) == "Identity check failed; reconnect the connector."
        assert Body.runs == 0
        assert "identity mismatch" in caplog.text
        assert OID_A not in caplog.text and OID_B not in caplog.text

    async def test_missing_access_token_is_refused(self, server, verified_oid):
        verified_oid(None)
        _enrol(OID_A)
        result = await _call(server)
        assert result.is_error
        assert _text(result) == "Identity check failed; reconnect the connector."
        assert Body.runs == 0

    async def test_token_oid_is_compared_case_insensitively(self, server, verified_oid):
        verified_oid(OID_A.upper())
        _enrol(OID_A)
        assert not (await _call(server)).is_error

    async def test_default_missing_message_is_the_legacy_text(self, server, verified_oid):
        verified_oid(OID_A)
        set_request_principal(make_principal(OID_A))
        result = await _call(server)
        assert result.is_error
        assert _text(result) == "Canvas token required for HTTP request"


class TestResources:
    async def test_unenrolled_read_is_refused(self, server, verified_oid):
        verified_oid(OID_A)
        set_request_principal(make_principal(OID_A))
        set_missing_credentials_message(not_enrolled_message(ACCOUNT_URL))
        async with Client(server) as client:
            with pytest.raises(Exception, match="account"):
                await client.read_resource("data://thing")
        assert Body.runs == 0

    async def test_enrolled_read_passes(self, server, verified_oid):
        verified_oid(OID_A)
        _enrol(OID_A)
        async with Client(server) as client:
            contents = await client.read_resource("data://thing")
        assert contents[0].text == "resource body"
        assert Body.runs == 1

    async def test_mismatch_read_is_refused(self, server, verified_oid):
        verified_oid(OID_B)
        _enrol(OID_A)
        async with Client(server) as client:
            with pytest.raises(Exception, match="Identity check failed"):
                await client.read_resource("data://thing")
        assert Body.runs == 0


class TestNotGated:
    async def test_listing_and_prompts_work_without_credentials(self, server, verified_oid):
        verified_oid(OID_A)
        set_request_principal(make_principal(OID_A))
        async with Client(server) as client:
            tools = await client.list_tools()
            prompt = await client.get_prompt("instructions")
        assert [t.name for t in tools] == ["whoami"]
        assert prompt.messages
        assert Body.runs == 0
