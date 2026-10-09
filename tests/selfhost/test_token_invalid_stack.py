"""A dead Canvas token through the whole stack: FastMCP auth, our middleware, the gate,
the encrypted store and the real Canvas client. Only Entra and Canvas are faked."""

from __future__ import annotations

import base64
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import fastmcp
import httpx
import pytest
import respx
from dbbackend import raw_connection, stack_env
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from starlette.testclient import TestClient

from canvas_mcp.core.selfhost.app import (
    build_selfhost_asgi_app,
    install_selfhost,
    prepare_selfhost,
)
from canvas_mcp.core.selfhost.request_context import (
    token_rejected_message,
    token_revoked_message,
    unreadable_token_message,
)
from canvas_mcp.core.selfhost.settings import load_selfhost_settings
from canvas_mcp.core.selfhost.token_store import (
    REASON_CANVAS_TOKEN_REJECTED,
    REASON_DECRYPT_FAILED,
    REASON_REVOKED_BY_ADMIN,
    STATUS_ACTIVE,
    STATUS_INVALID,
)
from canvas_mcp.tools import register_course_tools

from .conftest import CLIENT, OID_A, OID_B, TENANT, acct_key, store_put
from .test_selfhost_integration import TOKENS, call_tool, text_of

BASE = "https://canvas.example.test"
CANVAS = "https://canvas.example.edu"
ACCOUNT_URL = f"{BASE}/account"
TOKEN_A = "canvas-token-for-user-A-0123456789"
TOKEN_B = "canvas-token-for-user-B-0123456789"
NEW_TOKEN_A = "canvas-token-for-user-A-fresh-0123"
KEY_A = acct_key(OID_A)
KEY_B = acct_key(OID_B)
COURSES = {
    TOKEN_A: [{"id": 101, "name": "Intermediate Python", "course_code": "ICS 33"}],
    TOKEN_B: [{"id": 202, "name": "Single Variable Calculus", "course_code": "MATH 2B"}],
    NEW_TOKEN_A: [{"id": 101, "name": "Intermediate Python", "course_code": "ICS 33"}],
}
DEAD_HEADERS = {"WWW-Authenticate": 'Bearer realm="canvas-lms"'}


class FakeCanvas:
    """A Canvas that can kill tokens, deny permission, and counts every request."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []
        self.dead: set[str] = set()
        self.permission_denied: set[str] = set()
        self.permission_challenge = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        path = request.url.path
        self.seen.append((path, token))
        if token in self.dead:
            return httpx.Response(
                401, json={"errors": [{"message": "Invalid access token."}]}, headers=DEAD_HEADERS
            )
        if token not in COURSES:
            return httpx.Response(401, json={"errors": [{"message": "Invalid access token."}]})
        if path == "/api/v1/users/self":
            return httpx.Response(200, json={"id": 42, "name": "Ada"})
        if token in self.permission_denied:
            return httpx.Response(
                401,
                json={"errors": [{"message": "user not authorized to perform that action"}]},
                headers=DEAD_HEADERS if self.permission_challenge else None,
            )
        if path == "/api/v1/courses":
            return httpx.Response(200, json=COURSES[token])
        return httpx.Response(404, json={"errors": [{"message": "not found"}]})

    def probes(self) -> list[tuple[str, str]]:
        return [seen for seen in self.seen if seen[0] == "/api/v1/users/self"]

    def data_calls(self) -> list[tuple[str, str]]:
        return [seen for seen in self.seen if seen[0] != "/api/v1/users/self"]


@pytest.fixture
def stack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[SimpleNamespace]:
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path / "fastmcp")
    monkeypatch.setenv("CANVAS_API_URL", CANVAS)
    for name in ("CANVAS_API_TOKEN", "CANVAS_ROLE"):
        monkeypatch.delenv(name, raising=False)
    from canvas_mcp.core.config import reset_config

    reset_config()
    settings = load_selfhost_settings({
        "PUBLIC_BASE_URL": BASE,
        "ENTRA_TENANT_ID": TENANT,
        "ENTRA_CLIENT_ID": CLIENT,
        "ENTRA_CLIENT_SECRET": "entra-client-secret-0123456789",
        "OAUTH_JWT_SIGNING_KEY": "jwt-signing-key-" + "z" * 40,
        "ACCOUNT_SESSION_SECRET": base64.b64encode(bytes(range(32))).decode(),
        "CANVAS_TOKEN_KEYS": "k1:" + base64.b64encode(bytes(32)).decode(),
        "FASTMCP_HOME": str(tmp_path / "fastmcp"),
        "SELFHOST_DATA_DIR": str(tmp_path / "data"),
        **stack_env(),
    })
    runtime = prepare_selfhost(settings)

    def enroll(oid: str, token: str) -> None:
        store_put(runtime.store,
            tenant_id=TENANT, object_id=oid, api_token=token, canvas_user_id="42",
            canvas_user_name="n", entra_display_name="n", entra_upn="n@example.test",
            canvas_host="canvas.example.edu",
        )

    enroll(OID_A, TOKEN_A)
    enroll(OID_B, TOKEN_B)

    config: Any = SimpleNamespace(canvas_api_url=f"{CANVAS}/api/v1")
    mcp = FastMCP("integration", auth=StaticTokenVerifier(TOKENS, required_scopes=["Canvas.Access"]))
    register_course_tools(mcp)
    install_selfhost(mcp, runtime, config)
    app = build_selfhost_asgi_app(mcp, runtime, config)
    canvas = FakeCanvas()

    with respx.mock(assert_all_called=False) as router, TestClient(app, base_url=BASE) as client:
        router.route(host="canvas.example.edu").mock(side_effect=canvas)
        yield SimpleNamespace(
            client=client, runtime=runtime, canvas=canvas, enroll=enroll, store=runtime.store
        )
    reset_config()


def status_of(stack: SimpleNamespace, key: str = KEY_A) -> Any:
    info = stack.store.info(key)
    assert info is not None
    return info


class TestDeadTokenEndToEnd:
    def test_a_rejected_token_is_confirmed_once_and_then_costs_no_requests(self, stack):
        assert call_tool(stack, "bearer-A", "list_courses")["isError"] is False
        stack.canvas.seen.clear()
        stack.canvas.dead.add(TOKEN_A)

        first = call_tool(stack, "bearer-A", "list_courses")

        # The tool reports the Canvas failure as its text; the message names the fix.
        assert token_rejected_message(ACCOUNT_URL) in text_of(first)
        assert [path for path, _ in stack.canvas.data_calls()] == ["/api/v1/courses"]
        assert [token for _, token in stack.canvas.probes()] == [TOKEN_A]
        info = status_of(stack)
        assert info.status == STATUS_INVALID
        assert info.invalid_reason == REASON_CANVAS_TOKEN_REJECTED

        stack.canvas.seen.clear()
        second = call_tool(stack, "bearer-A", "list_courses")
        third = call_tool(stack, "bearer-A", "get_course_details", {"course_identifier": "101"})

        assert second["isError"] is True and third["isError"] is True
        assert token_rejected_message(ACCOUNT_URL) in text_of(second)
        assert token_rejected_message(ACCOUNT_URL) in text_of(third)
        assert stack.canvas.seen == []  # not one Canvas request for a dead token

    def test_other_users_are_not_affected(self, stack):
        stack.canvas.dead.add(TOKEN_A)
        call_tool(stack, "bearer-A", "list_courses")
        assert status_of(stack, KEY_B).status == STATUS_ACTIVE
        result = call_tool(stack, "bearer-B", "list_courses")
        assert result["isError"] is False and "MATH 2B" in text_of(result)

    def test_enrolling_a_new_token_restores_access(self, stack):
        stack.canvas.dead.add(TOKEN_A)
        call_tool(stack, "bearer-A", "list_courses")
        assert status_of(stack).status == STATUS_INVALID

        stack.enroll(OID_A, NEW_TOKEN_A)  # what the account page does on a successful save

        info = status_of(stack)
        assert info.status == STATUS_ACTIVE and info.invalid_reason is None and info.invalid_since is None
        result = call_tool(stack, "bearer-A", "list_courses")
        assert result["isError"] is False and "ICS 33" in text_of(result)
        assert stack.canvas.seen[-1] == ("/api/v1/courses", NEW_TOKEN_A)

    def test_a_permission_401_stays_a_permission_error(self, stack):
        stack.canvas.permission_denied.add(TOKEN_A)
        result = call_tool(stack, "bearer-A", "list_courses")
        assert "401" in text_of(result)
        assert token_rejected_message(ACCOUNT_URL) not in text_of(result)
        assert status_of(stack).status == STATUS_ACTIVE
        assert stack.canvas.probes() == []  # nothing about it looks like a dead token
        # And the token keeps working for what it may do.
        stack.canvas.permission_denied.clear()
        assert call_tool(stack, "bearer-A", "list_courses")["isError"] is False

    def test_a_suspicious_401_that_the_probe_clears_is_a_permission_error(self, stack):
        stack.canvas.permission_denied.add(TOKEN_A)
        stack.canvas.permission_challenge = True  # looks like a dead token at first sight
        result = call_tool(stack, "bearer-A", "list_courses")
        assert "401" in text_of(result)
        assert token_rejected_message(ACCOUNT_URL) not in text_of(result)
        # The probe ran, succeeded, and so the 401 was a permission problem.
        assert len(stack.canvas.probes()) == 1
        assert status_of(stack).status == STATUS_ACTIVE
        # The user is not locked out: the next call is sent.
        stack.canvas.seen.clear()
        call_tool(stack, "bearer-A", "list_courses")
        assert [path for path, _ in stack.canvas.data_calls()] == ["/api/v1/courses"]

    def test_a_successful_call_records_the_last_verified_time(self, stack):
        before = status_of(stack).last_verified_at
        assert before is not None
        # Make the stored time old enough for the rate limit to allow a write.
        with raw_connection(stack.runtime.store) as conn:
            conn.execute("UPDATE canvas_tokens SET last_verified_at = 1")
        call_tool(stack, "bearer-A", "list_courses")
        assert status_of(stack).last_verified_at > 1


class TestMarkedInvalidBeforeTheCall:
    def test_an_admin_marked_row_makes_no_canvas_request(self, stack):
        assert stack.store.mark_invalid(KEY_A, reason=REASON_REVOKED_BY_ADMIN) is True
        stack.canvas.seen.clear()

        result = call_tool(stack, "bearer-A", "list_courses")

        assert result["isError"] is True
        assert token_revoked_message(ACCOUNT_URL) in text_of(result)
        assert stack.canvas.seen == []

    def test_a_rejected_row_makes_no_canvas_request(self, stack):
        stack.store.mark_invalid(KEY_A, reason=REASON_CANVAS_TOKEN_REJECTED)
        stack.canvas.seen.clear()
        result = call_tool(stack, "bearer-A", "list_courses")
        assert result["isError"] is True
        assert token_rejected_message(ACCOUNT_URL) in text_of(result)
        assert stack.canvas.seen == []

    def test_listing_tools_still_works_so_the_user_can_read_the_instructions(self, stack):
        stack.store.mark_invalid(KEY_A, reason=REASON_CANVAS_TOKEN_REJECTED)
        from .test_selfhost_integration import result_of, rpc

        names = {tool["name"] for tool in result_of(rpc(stack, "bearer-A", "tools/list"))["tools"]}
        assert "list_courses" in names


class TestDecryptFailure:
    def test_an_unreadable_row_is_marked_invalid_and_stays_that_way(self, stack):
        with raw_connection(stack.runtime.store) as conn:
            conn.execute("UPDATE canvas_tokens SET ciphertext = ? WHERE principal_key = ?", (b"x" * 40, acct_key(OID_A)))

        first = call_tool(stack, "bearer-A", "list_courses")

        assert first["isError"] is True
        assert unreadable_token_message(ACCOUNT_URL) in text_of(first)
        info = status_of(stack)
        assert info.status == STATUS_INVALID and info.invalid_reason == REASON_DECRYPT_FAILED
        since = info.invalid_since

        second = call_tool(stack, "bearer-A", "list_courses")
        assert unreadable_token_message(ACCOUNT_URL) in text_of(second)
        assert status_of(stack).invalid_since == since  # the first mark is kept
        assert stack.canvas.seen == []

    def test_saving_a_new_token_clears_the_mark(self, stack):
        with raw_connection(stack.runtime.store) as conn:
            conn.execute("UPDATE canvas_tokens SET ciphertext = ? WHERE principal_key = ?", (b"x" * 40, acct_key(OID_A)))
        call_tool(stack, "bearer-A", "list_courses")
        stack.enroll(OID_A, NEW_TOKEN_A)
        assert status_of(stack).status == STATUS_ACTIVE
        assert call_tool(stack, "bearer-A", "list_courses")["isError"] is False
