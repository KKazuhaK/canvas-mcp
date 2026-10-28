"""Failure codes, /healthz and the HTTP-mode contract a platform relies on.

A platform that injects each user's Canvas token as ``X-Canvas-Token`` needs
three things from this server: a machine-readable reason when a tool call fails,
a liveness probe that needs no credentials, and a tool list it can classify.
"""

import asyncio
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from fastmcp import Client, FastMCP
from starlette.testclient import TestClient

from canvas_mcp import __version__
from canvas_mcp.core import error_codes, token_health
from canvas_mcp.core.client import make_canvas_request
from canvas_mcp.core.credentials import (
    RequestCredentials,
    RequestTokenState,
    clear_request_credentials,
    set_request_credentials,
    set_request_token_state,
)
from canvas_mcp.core.tool_results import install_tool_result_contract

CANVAS = "https://canvas.test/api/v1"
DEAD_BODY = {"errors": [{"message": "Invalid access token."}]}


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    """A 429 is retried with a sleep; the tests do not wait for it."""
    monkeypatch.setattr("canvas_mcp.core.client.asyncio.sleep", AsyncMock())


def _server() -> FastMCP:
    mcp = FastMCP("codes")
    install_tool_result_contract(mcp)

    @mcp.tool
    async def fetch(path: str) -> str:
        """Call Canvas with a caller token and report failures as tools do."""
        set_request_credentials(RequestCredentials("tok-123", CANVAS))
        set_request_token_state(RequestTokenState())
        try:
            result = await make_canvas_request("get", path)
        finally:
            clear_request_credentials()
            set_request_token_state(None)
        if isinstance(result, dict) and "error" in result:
            return f"Error: {result['error']}"
        return "fine"

    @mcp.tool
    async def validate(title: str) -> str:
        """Refuse before calling Canvas."""
        return "Error: title cannot be empty."

    @mcp.tool
    async def boom() -> str:
        """Raise instead of returning."""
        raise RuntimeError("kaboom")

    return mcp


async def _call(name: str, args: dict):
    async with Client(_server()) as client:
        return await client.call_tool(name, args, raise_on_error=False)


def _payload(result) -> dict:
    assert result.is_error is True
    assert len(result.content) == 1
    payload = json.loads(result.content[0].text)
    assert set(payload) == {"error", "message"}
    assert payload["error"] in error_codes.ERROR_CODES
    return payload


class TestErrorCodes:
    @pytest.mark.asyncio
    @respx.mock
    async def test_confirmed_dead_token_is_credential_invalid(self):
        respx.get(f"{CANVAS}/courses").respond(
            401, headers={"WWW-Authenticate": "Bearer"}, json={"errors": [{"message": "Invalid access token."}]}
        )
        probe = respx.get(f"{CANVAS}/users/self").respond(401, json=DEAD_BODY)

        payload = _payload(await _call("fetch", {"path": "/courses"}))

        assert payload["error"] == "CREDENTIAL_INVALID"
        assert "rejected the API token" in payload["message"]
        assert probe.call_count == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_401_the_probe_does_not_confirm_is_permission_denied(self):
        respx.get(f"{CANVAS}/courses/9").respond(
            401, headers={"WWW-Authenticate": "Bearer"}, json={"status": "unauthorized"}
        )
        respx.get(f"{CANVAS}/users/self").respond(200, json={"id": 1})

        payload = _payload(await _call("fetch", {"path": "/courses/9"}))

        assert payload["error"] == "PERMISSION_DENIED"
        assert "HTTP error: 401" in payload["message"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_plain_401_is_not_probed_and_is_permission_denied(self):
        respx.get(f"{CANVAS}/courses/9").respond(401, json={"status": "unauthorized"})
        probe = respx.get(f"{CANVAS}/users/self").respond(401, json=DEAD_BODY)

        payload = _payload(await _call("fetch", {"path": "/courses/9"}))

        assert payload["error"] == "PERMISSION_DENIED"
        assert probe.call_count == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_403_is_permission_denied(self):
        respx.get(f"{CANVAS}/courses/9/users").respond(403, json={"status": "unauthorized"})

        payload = _payload(await _call("fetch", {"path": "/courses/9/users"}))

        assert payload["error"] == "PERMISSION_DENIED"
        assert "HTTP error: 403" in payload["message"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_429_after_retries_is_rate_limited(self):
        route = respx.get(f"{CANVAS}/courses").respond(429)

        payload = _payload(await _call("fetch", {"path": "/courses"}))

        assert payload["error"] == "RATE_LIMITED"
        assert route.call_count > 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_canvas_403_rate_limit_text_is_rate_limited(self):
        respx.get(f"{CANVAS}/courses").respond(403, text="403 Forbidden (Rate Limit Exceeded)")

        assert _payload(await _call("fetch", {"path": "/courses"}))["error"] == "RATE_LIMITED"

    @pytest.mark.asyncio
    @respx.mock
    @pytest.mark.parametrize("status", [400, 404, 422])
    async def test_client_errors_are_invalid_argument(self, status):
        respx.get(f"{CANVAS}/courses/0").respond(status, json={"errors": []})

        assert _payload(await _call("fetch", {"path": "/courses/0"}))["error"] == "INVALID_ARGUMENT"

    @pytest.mark.asyncio
    @respx.mock
    @pytest.mark.parametrize("status", [500, 502, 503])
    async def test_server_errors_are_source_unavailable(self, status):
        respx.get(f"{CANVAS}/courses").respond(status)

        assert _payload(await _call("fetch", {"path": "/courses"}))["error"] == "SOURCE_UNAVAILABLE"

    @pytest.mark.asyncio
    @respx.mock
    async def test_network_failure_is_source_unavailable(self):
        respx.get(f"{CANVAS}/courses").mock(side_effect=httpx.ConnectError("no route"))

        payload = _payload(await _call("fetch", {"path": "/courses"}))

        assert payload["error"] == "SOURCE_UNAVAILABLE"
        assert "no route" in payload["message"]

    @pytest.mark.asyncio
    async def test_a_refusal_before_canvas_is_invalid_argument(self):
        payload = _payload(await _call("validate", {"title": ""}))

        assert payload == {"error": "INVALID_ARGUMENT", "message": "Error: title cannot be empty."}

    @pytest.mark.asyncio
    async def test_arguments_that_do_not_fit_the_schema_are_invalid_argument(self):
        assert _payload(await _call("validate", {}))["error"] == "INVALID_ARGUMENT"

    @pytest.mark.asyncio
    async def test_an_unexpected_exception_is_source_unavailable(self):
        assert _payload(await _call("boom", {}))["error"] == "SOURCE_UNAVAILABLE"

    @pytest.mark.asyncio
    @respx.mock
    async def test_success_is_untouched(self):
        respx.get(f"{CANVAS}/courses").respond(200, json=[])
        async with Client(_server()) as client:
            result = await client.call_tool("fetch", {"path": "/courses"})

        assert result.is_error is False
        assert result.content[0].text == "fine"

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_dead_token_is_probed_once_per_request(self):
        """Later calls of the same request stop at the remembered verdict."""
        respx.get(f"{CANVAS}/courses").respond(401, headers={"WWW-Authenticate": "Bearer"})
        probe = respx.get(f"{CANVAS}/users/self").respond(401, json=DEAD_BODY)
        mcp = FastMCP("twice")
        install_tool_result_contract(mcp)

        @mcp.tool
        async def twice() -> str:
            """Two calls with one token."""
            set_request_credentials(RequestCredentials("tok", CANVAS))
            set_request_token_state(RequestTokenState())
            try:
                await make_canvas_request("get", "/courses")
                second = await make_canvas_request("get", "/courses")
            finally:
                clear_request_credentials()
                set_request_token_state(None)
            return f"Error: {second['error']}"

        async with Client(mcp) as client:
            result = await client.call_tool("twice", {}, raise_on_error=False)

        assert _payload(result)["error"] == "CREDENTIAL_INVALID"
        assert probe.call_count == 1

    def test_codes_for_statuses(self):
        assert error_codes.code_for_status(409) == "INVALID_ARGUMENT"
        assert error_codes.code_for_status(418) == "SOURCE_UNAVAILABLE"

    def test_a_tool_that_reports_a_status_without_the_client_still_gets_a_code(self):
        from fastmcp.tools import ToolResult

        from canvas_mcp.core.tool_results import with_error_code

        coded = with_error_code(ToolResult(content="Error: HTTP error: 403, Text: nope"), [])

        assert json.loads(coded.content[0].text)["error"] == "PERMISSION_DENIED"
        assert coded.is_error is True


class _Config:
    canvas_api_url = CANVAS
    mcp_access_keys = frozenset({"secret-key"})
    entra_auth_enabled = False
    mcp_entra_allowed_oids = frozenset()
    access_request_enabled = False


async def _run(middleware, scope):
    sent = []

    async def send(message):
        sent.append(message)

    with patch("canvas_mcp.server.get_config", return_value=_Config()):
        await middleware(scope, AsyncMock(), send)
    return sent


class TestHealthz:
    @pytest.fixture
    def middleware(self):
        from canvas_mcp.server import CanvasCredentialMiddleware

        self.inner = AsyncMock()
        return CanvasCredentialMiddleware(self.inner)

    @pytest.mark.asyncio
    async def test_bypasses_the_access_key_gate_and_the_token_check(self, middleware):
        sent = await _run(middleware, {"type": "http", "method": "GET", "path": "/healthz", "headers": []})

        assert sent[0]["status"] == 200
        assert json.loads(sent[1]["body"]) == {"ok": True, "version": __version__}
        headers = dict(sent[0]["headers"])
        assert headers[b"content-type"] == b"application/json"
        assert headers[b"cache-control"] == b"no-store"
        self.inner.assert_not_called()

    @pytest.mark.asyncio
    async def test_head_has_no_body(self, middleware):
        sent = await _run(middleware, {"type": "http", "method": "HEAD", "path": "/healthz", "headers": []})

        assert sent[0]["status"] == 200
        assert sent[1]["body"] == b""

    @pytest.mark.asyncio
    async def test_other_methods_are_refused(self, middleware):
        sent = await _run(middleware, {"type": "http", "method": "POST", "path": "/healthz", "headers": []})

        assert sent[0]["status"] == 405

    @pytest.mark.asyncio
    async def test_other_paths_still_need_credentials(self, middleware):
        sent = await _run(middleware, {"type": "http", "method": "GET", "path": "/healthz/x", "headers": []})

        assert sent[0]["status"] == 401
        self.inner.assert_not_called()

    def test_the_real_app_serves_it_without_credentials(self, monkeypatch):
        """Through the real ASGI stack: no token, no access key, nothing else leaks."""
        from canvas_mcp.server import CanvasCredentialMiddleware, create_server

        monkeypatch.setenv("CANVAS_API_URL", CANVAS)
        monkeypatch.setenv("MCP_ACCESS_KEYS", "secret-key")
        from canvas_mcp.core.config import reset_config

        reset_config()
        try:
            app = CanvasCredentialMiddleware(create_server().http_app(stateless_http=True))
            with TestClient(app) as client:
                health = client.get("/healthz")
                assert health.status_code == 200
                assert health.json() == {"ok": True, "version": __version__}
                assert client.post("/mcp", json={}).status_code == 401
        finally:
            reset_config()


class TestProbeStrictness:
    """Only a probe that says "this token is dead" makes CREDENTIAL_INVALID."""

    @pytest.mark.asyncio
    @respx.mock
    @pytest.mark.parametrize(
        ("headers", "body"),
        [
            ({"WWW-Authenticate": 'Bearer error="insufficient_scope"'}, {"errors": [{"message": "Insufficient scopes on access token."}]}),
            ({}, {"errors": [{"message": "Insufficient scopes on access token."}]}),
            ({"WWW-Authenticate": "Bearer realm=canvas"}, {"errors": [{"message": "user authorization required"}]}),
            ({}, {}),
        ],
    )
    async def test_a_probe_401_that_is_not_about_a_dead_token_is_permission_denied(self, headers, body):
        respx.get(f"{CANVAS}/courses").respond(
            401, headers={"WWW-Authenticate": "Bearer"}, json=DEAD_BODY
        )
        probe = respx.get(f"{CANVAS}/users/self").respond(401, headers=headers, json=body)

        payload = _payload(await _call("fetch", {"path": "/courses"}))

        assert probe.call_count == 1
        assert payload["error"] == "PERMISSION_DENIED"

    @pytest.mark.asyncio
    @respx.mock
    async def test_an_original_401_about_scope_is_not_even_probed(self):
        respx.get(f"{CANVAS}/courses").respond(
            401,
            headers={"WWW-Authenticate": 'Bearer error="insufficient_scope"'},
            json={"errors": [{"message": "Insufficient scopes on access token."}]},
        )
        probe = respx.get(f"{CANVAS}/users/self").respond(401, json=DEAD_BODY)

        payload = _payload(await _call("fetch", {"path": "/courses"}))

        assert payload["error"] == "PERMISSION_DENIED"
        assert probe.call_count == 0

    @pytest.mark.asyncio
    @respx.mock
    @pytest.mark.parametrize(
        ("headers", "body"),
        [
            ({"WWW-Authenticate": 'Bearer error="invalid_token"'}, {}),
            ({}, {"errors": [{"message": "Invalid access token."}]}),
            ({}, {"errors": [{"message": "The access token expired."}]}),
        ],
    )
    async def test_each_dead_token_marker_confirms(self, headers, body):
        respx.get(f"{CANVAS}/courses").respond(401, headers={"WWW-Authenticate": "Bearer"}, json=DEAD_BODY)
        respx.get(f"{CANVAS}/users/self").respond(401, headers=headers, json=body)

        assert _payload(await _call("fetch", {"path": "/courses"}))["error"] == "CREDENTIAL_INVALID"


class TestStdioEnvToken:
    """One stdio server per user, the token in CANVAS_API_TOKEN."""

    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch):
        from canvas_mcp.core.config import reset_config

        monkeypatch.setenv("CANVAS_API_TOKEN", "env-token-xyz")
        monkeypatch.setenv("CANVAS_API_URL", CANVAS)
        reset_config()
        yield
        reset_config()

    def _stdio_server(self) -> FastMCP:
        mcp = FastMCP("stdio")
        install_tool_result_contract(mcp)

        @mcp.tool
        async def fetch(path: str) -> str:
            """Call Canvas with the env token (no per-request credentials)."""
            result = await make_canvas_request("get", path)
            return f"Error: {result['error']}" if isinstance(result, dict) and "error" in result else "fine"

        return mcp

    async def _call_stdio(self, path: str):
        from canvas_mcp.core.client import cleanup_http_client

        await cleanup_http_client()
        async with Client(self._stdio_server()) as client:
            return await client.call_tool("fetch", {"path": path}, raise_on_error=False)

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_revoked_env_token_is_credential_invalid(self):
        route = respx.get(f"{CANVAS}/courses").respond(
            401, headers={"WWW-Authenticate": "Bearer"}, json=DEAD_BODY
        )
        probe = respx.get(f"{CANVAS}/users/self").respond(401, json=DEAD_BODY)

        payload = _payload(await self._call_stdio("/courses"))

        assert payload["error"] == "CREDENTIAL_INVALID"
        assert route.calls[0].request.headers["authorization"] == "Bearer env-token-xyz"
        assert probe.calls[0].request.headers["authorization"] == "Bearer env-token-xyz"

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_live_env_token_with_a_401_stays_permission_denied(self):
        respx.get(f"{CANVAS}/courses/9").respond(401, headers={"WWW-Authenticate": "Bearer"}, json=DEAD_BODY)
        respx.get(f"{CANVAS}/users/self").respond(200, json={"id": 1})

        assert _payload(await self._call_stdio("/courses/9"))["error"] == "PERMISSION_DENIED"

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_second_failure_reuses_the_verdict(self):
        respx.get(f"{CANVAS}/courses").respond(401, headers={"WWW-Authenticate": "Bearer"}, json=DEAD_BODY)
        probe = respx.get(f"{CANVAS}/users/self").respond(401, json=DEAD_BODY)

        await self._call_stdio("/courses")
        assert _payload(await self._call_stdio("/courses"))["error"] == "CREDENTIAL_INVALID"
        assert probe.call_count == 1


class TestProbeCoalescing:
    @pytest.mark.asyncio
    @respx.mock
    async def test_concurrent_failures_of_one_token_share_one_probe(self):
        respx.get(f"{CANVAS}/courses").respond(
            401, headers={"WWW-Authenticate": "Bearer"}, json=DEAD_BODY
        )

        async def slow_probe(request):
            await asyncio.sleep(0.05)
            return httpx.Response(401, json=DEAD_BODY)

        probe = respx.get(f"{CANVAS}/users/self").mock(side_effect=slow_probe)
        mcp = FastMCP("burst")
        install_tool_result_contract(mcp)

        @mcp.tool
        async def burst() -> str:
            """Eight parallel calls, no shared per-request state."""
            set_request_credentials(RequestCredentials("tok-burst", CANVAS))
            try:
                results = await asyncio.gather(*(make_canvas_request("get", "/courses") for _ in range(8)))
            finally:
                clear_request_credentials()
            return "Error: " + results[0]["error"]

        async with Client(mcp) as client:
            result = await client.call_tool("burst", {}, raise_on_error=False)

        assert _payload(result)["error"] == "CREDENTIAL_INVALID"
        assert probe.call_count == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_an_alive_verdict_is_cached_for_a_minute_then_rechecked(self, monkeypatch):
        now = [1000.0]
        monkeypatch.setattr(token_health, "_clock", lambda: now[0])
        respx.get(f"{CANVAS}/courses").respond(401, headers={"WWW-Authenticate": "Bearer"}, json=DEAD_BODY)
        probe = respx.get(f"{CANVAS}/users/self").respond(200, json={"id": 1})

        await _call("fetch", {"path": "/courses"})
        await _call("fetch", {"path": "/courses"})
        assert probe.call_count == 1

        now[0] += token_health.PROBE_CACHE_SECONDS + 1
        await _call("fetch", {"path": "/courses"})
        assert probe.call_count == 2

    def test_the_cache_key_is_not_the_token(self):
        key = token_health._token_key(RequestCredentials("super-secret-token", CANVAS))

        assert "super-secret-token" not in key
        assert len(key) == 64

    @pytest.mark.asyncio
    @respx.mock
    async def test_different_tokens_are_probed_separately(self):
        respx.get(f"{CANVAS}/courses").respond(401, headers={"WWW-Authenticate": "Bearer"}, json=DEAD_BODY)
        probe = respx.get(f"{CANVAS}/users/self").respond(200, json={"id": 1})
        for token in ("tok-a", "tok-b"):
            set_request_credentials(RequestCredentials(token, CANVAS))
            await make_canvas_request("get", "/courses")
        clear_request_credentials()

        assert probe.call_count == 2


class TestLegacyHttpThroughTheRealMiddleware:
    """X-Canvas-Token in, a coded tool result out, nothing mocked but Canvas."""

    def _app(self, monkeypatch):
        from canvas_mcp.core.config import reset_config
        from canvas_mcp.server import CanvasCredentialMiddleware

        monkeypatch.setenv("CANVAS_API_URL", CANVAS)
        monkeypatch.setenv("MCP_ACCESS_KEYS", "k")
        monkeypatch.delenv("CANVAS_API_TOKEN", raising=False)
        reset_config()
        mcp = FastMCP("legacy")
        install_tool_result_contract(mcp)

        @mcp.tool
        async def courses() -> str:
            """List courses with the caller's token."""
            result = await make_canvas_request("get", "/courses")
            return f"Error: {result['error']}" if isinstance(result, dict) and "error" in result else "fine"

        return CanvasCredentialMiddleware(mcp.http_app(stateless_http=True))

    def _call(self, client, token: str):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "X-MCP-Access-Key": "k",
            "X-Canvas-Token": token,
        }
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "courses", "arguments": {}}}
        response = client.post("/mcp", json=body, headers=headers)
        assert response.status_code == 200, response.text
        text = response.text
        if text.startswith("event:"):
            text = next(line[5:] for line in text.splitlines() if line.startswith("data:"))
        return json.loads(text)["result"]

    @respx.mock
    def test_a_dead_token_comes_back_credential_invalid(self, monkeypatch):
        from canvas_mcp.core.config import reset_config

        seen = []

        def courses(request):
            seen.append(request.headers["authorization"])
            return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"}, json=DEAD_BODY)

        respx.get(f"{CANVAS}/courses").mock(side_effect=courses)
        respx.get(f"{CANVAS}/users/self").respond(401, json=DEAD_BODY)
        try:
            with TestClient(self._app(monkeypatch)) as client:
                result = self._call(client, "revoked-user-token")
        finally:
            reset_config()

        assert result["isError"] is True
        payload = json.loads(result["content"][0]["text"])
        assert payload["error"] == "CREDENTIAL_INVALID"
        assert seen == ["Bearer revoked-user-token"]

    @respx.mock
    def test_a_permission_401_with_a_live_token_is_permission_denied(self, monkeypatch):
        from canvas_mcp.core.config import reset_config

        respx.get(f"{CANVAS}/courses").respond(401, headers={"WWW-Authenticate": "Bearer"}, json=DEAD_BODY)
        respx.get(f"{CANVAS}/users/self").respond(200, json={"id": 1})
        try:
            with TestClient(self._app(monkeypatch)) as client:
                result = self._call(client, "live-user-token")
        finally:
            reset_config()

        assert json.loads(result["content"][0]["text"])["error"] == "PERMISSION_DENIED"


# Messages as tools produce them, with the code a platform should see.
LOCAL_REFUSALS = [
    ("Error: Course 99 not found.", "INVALID_ARGUMENT"),
    ("Error: Could not find course 60366", "INVALID_ARGUMENT"),
    ("Error: could not resolve a numeric Canvas course ID.", "INVALID_ARGUMENT"),
    ("Error: You do not have permission to view this resource.", "PERMISSION_DENIED"),
    ("Error: not authorized to read these submissions.", "PERMISSION_DENIED"),
    ("Error: No download URL available for this file. Check permissions.", "PERMISSION_DENIED"),
    ("Error: Canvas token is invalid.", "PERMISSION_DENIED"),
    (
        "Error: 'download_course_file' writes to the server's filesystem and is only available on a local (stdio) server.",
        "INVALID_ARGUMENT",
    ),
    ("Error: Creating a local identity map is only available on a local (stdio) server. No file was written.", "INVALID_ARGUMENT"),
    # Wording alone never makes CREDENTIAL_INVALID.
    ("Authentication required", "INVALID_ARGUMENT"),
    ("Error: no Canvas token configured", "INVALID_ARGUMENT"),
    ("Canvas token required for HTTP request", "INVALID_ARGUMENT"),
    ("Error: Request failed: ConnectTimeout", "SOURCE_UNAVAILABLE"),
    ("Error: Max retries exceeded", "SOURCE_UNAVAILABLE"),
    ("Error: something nobody anticipated", "INVALID_ARGUMENT"),
]


class TestLocalRefusals:
    @pytest.mark.parametrize(("message", "code"), LOCAL_REFUSALS)
    def test_wording_fallback_table(self, message, code):
        assert error_codes.code_for_text(message) == code

    @pytest.mark.parametrize(("message", "code"), LOCAL_REFUSALS[:2] + LOCAL_REFUSALS[3:8])
    def test_through_the_middleware_an_unrecorded_refusal_is_never_source_unavailable(self, message, code):
        from fastmcp.tools import ToolResult

        from canvas_mcp.core.tool_results import with_error_code

        coded = with_error_code(ToolResult(content=message), [])

        assert json.loads(coded.content[0].text) == {"error": code, "message": message}

    def test_an_unexpected_exception_is_never_guessed_from_wording(self):
        from fastmcp.tools import ToolResult

        from canvas_mcp.core.tool_results import with_error_code

        coded = with_error_code(ToolResult(content="Error calling tool 'x': Course not found"), [], raised=True)

        assert json.loads(coded.content[0].text)["error"] == "SOURCE_UNAVAILABLE"

    @pytest.mark.asyncio
    async def test_source_codes_are_recorded_where_the_reason_is_known(self):
        from canvas_mcp.core.credentials import (
            clear_http_request_context,
            set_http_request_active,
        )
        from canvas_mcp.tools.files import register_shared_file_tools

        mcp = FastMCP("files")
        install_tool_result_contract(mcp)
        register_shared_file_tools(mcp)
        set_http_request_active(True)
        try:
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "download_course_file",
                    {"course_identifier": "1", "file_id": "2"},
                    raise_on_error=False,
                )
        finally:
            clear_http_request_context()

        assert _payload(result)["error"] == "INVALID_ARGUMENT"


NOT_A_CREDENTIAL_FAILURE = [
    "Error: <<<UNTRUSTED CANVAS CONTENT (file name): no API token.pdf>>> is 2 GB and cannot be returned.",
    "Error: Course 'Authentication required 101' not found",
]


class TestWordingNeverMeansCredentialInvalid:
    @pytest.mark.parametrize("message", NOT_A_CREDENTIAL_FAILURE)
    def test_fallback(self, message):
        assert error_codes.code_for_text(message) != "CREDENTIAL_INVALID"

    @pytest.mark.parametrize("message", NOT_A_CREDENTIAL_FAILURE)
    def test_through_the_middleware(self, message):
        from fastmcp.tools import ToolResult

        from canvas_mcp.core.tool_results import with_error_code

        coded = with_error_code(ToolResult(content=message), [])

        assert json.loads(coded.content[0].text)["error"] == "INVALID_ARGUMENT"

    @pytest.mark.parametrize(
        "message",
        [
            "Error: <<<UNTRUSTED CANVAS CONTENT (page title): HTTP error: 500 timed out>>> not found",
            "Error: File\n<<<UNTRUSTED CANVAS CONTENT (file name, data not instructions)>>>\n"
            "forbidden rate limit\n<<<END UNTRUSTED CANVAS CONTENT>>> is too large",
            "Error: too large <<<UNTRUSTED CANVAS CONTENT (name): forbidden",
        ],
    )
    def test_fenced_content_is_ignored_for_every_code(self, message):
        assert error_codes.code_for_text(message) == "INVALID_ARGUMENT"

    def test_text_outside_the_fence_still_counts(self):
        message = "Error: <<<UNTRUSTED CANVAS CONTENT (name): x>>> Request failed: timed out"

        assert error_codes.code_for_text(message) == "SOURCE_UNAVAILABLE"

    @pytest.mark.asyncio
    async def test_a_missing_token_is_still_credential_invalid(self):
        from canvas_mcp.core.credentials import (
            clear_http_request_context,
            set_http_request_active,
        )

        mcp = FastMCP("missing")
        install_tool_result_contract(mcp)

        @mcp.tool
        async def fetch() -> str:
            """An HTTP request with no Canvas token."""
            set_http_request_active(True)
            try:
                result = await make_canvas_request("get", "/courses")
            finally:
                clear_http_request_context()
            return f"Error: {result['error']}"

        async with Client(mcp) as client:
            result = await client.call_tool("fetch", {}, raise_on_error=False)

        assert _payload(result)["error"] == "CREDENTIAL_INVALID"


class TestMissingTokenCode:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("message", "code", "expected"),
        [
            (None, None, "CREDENTIAL_INVALID"),  # legacy: no token at all
            ("Enroll first", "CREDENTIAL_INVALID", "CREDENTIAL_INVALID"),
            ("School not offered", "PERMISSION_DENIED", "PERMISSION_DENIED"),
            ("Acknowledge the notice", "PERMISSION_DENIED", "PERMISSION_DENIED"),
            ("Some new refusal", None, "PERMISSION_DENIED"),  # unknown reason
        ],
    )
    async def test_the_client_reports_the_refusal_reason(self, message, code, expected):
        from canvas_mcp.core.credentials import (
            clear_http_request_context,
            set_http_request_active,
            set_missing_credentials_message,
        )

        mcp = FastMCP("refusal")
        install_tool_result_contract(mcp)

        @mcp.tool
        async def fetch() -> str:
            """An HTTP request that was admitted without Canvas credentials."""
            set_http_request_active(True)
            set_missing_credentials_message(message, code)
            try:
                result = await make_canvas_request("get", "/courses")
            finally:
                clear_http_request_context()
            return f"Error: {result['error']}"

        async with Client(mcp) as client:
            result = await client.call_tool("fetch", {}, raise_on_error=False)

        assert _payload(result)["error"] == expected


def test_fenced_content_with_a_newline_does_not_hide_the_text_after_it():
    message = "Error: <<<UNTRUSTED CANVAS CONTENT (file name): a\nb>>> download timed out"

    assert error_codes.code_for_text(message) == "SOURCE_UNAVAILABLE"
