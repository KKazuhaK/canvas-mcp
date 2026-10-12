"""Native Local AS → MCP → Canvas integration, with only outside providers faked."""

import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx
from dbbackend import raw_connection

from canvas_mcp.tools import register_course_tools

from .account_fixture import _display_in_utc, build_harness, put_row  # noqa: F401
from .authz.stack import User
from .conftest import OID_A, OID_B, acct_key

BASE = "https://canvas.example.test"
CANVAS = "https://canvas.example.edu"
OID_C = "cccccccc-0000-4000-8000-00000000000c"
CANVAS_TOKEN = {
    OID_A: "canvas-token-for-user-A-0123456789",
    OID_B: "canvas-token-for-user-B-0123456789",
}
COURSES = {
    CANVAS_TOKEN[OID_A]: [
        {"id": 101, "name": "Intermediate Python", "course_code": "ICS 33"}
    ],
    CANVAS_TOKEN[OID_B]: [
        {"id": 202, "name": "Single Variable Calculus", "course_code": "MATH 2B"}
    ],
}


@pytest.fixture(params=["request_local", "per_principal"])
def stack(
    request: pytest.FixtureRequest, tmp_path: Path, real_course_list: None
) -> Iterator[SimpleNamespace]:
    h = build_harness(
        tmp_path,
        runtime_env={"SELFHOST_COURSE_STATE": request.param},
        register_tools=register_course_tools,
    )
    tokens = {}
    users = {
        label: User(label, oid)
        for label, oid in (("A", OID_A), ("B", OID_B), ("C", OID_C))
    }
    for label, user in users.items():
        tokens["bearer-" + label] = h.stack.tokens_for(user)[1]["access_token"]
    for oid, token in CANVAS_TOKEN.items():
        put_row(h.store, oid, token=token, name="n", canvas_user_id=oid[:2])

    seen: list[tuple[str, str]] = []

    def canvas(request: httpx.Request) -> httpx.Response:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        seen.append((request.url.path, token))
        if token not in COURSES:
            return httpx.Response(401, json={"errors": [{"message": "bad token"}]})
        if request.url.path == "/api/v1/courses":
            return httpx.Response(200, json=COURSES[token])
        return httpx.Response(404, json={"errors": [{"message": "not found"}]})

    with respx.mock(assert_all_called=False) as router:
        router.route(host="canvas.example.edu").mock(side_effect=canvas)
        yield SimpleNamespace(
            client=h.client,
            runtime=h.stack.runtime,
            seen=seen,
            course_state=request.param,
            tokens=tokens,
            native=h.stack,
            users=users,
        )


def rpc(
    stack: SimpleNamespace,
    bearer: str | None,
    method: str,
    params: dict[str, Any] | None = None,
) -> httpx.Response:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if bearer:
        headers["Authorization"] = f"Bearer {stack.tokens.get(bearer, bearer)}"
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    return stack.client.post("/mcp", json=body, headers=headers)


def result_of(response: httpx.Response) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    text = response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        data = [
            line[5:].strip() for line in text.splitlines() if line.startswith("data:")
        ]
        text = data[-1]
    payload = json.loads(text)
    assert "error" not in payload, payload
    return payload["result"]


def call_tool(
    stack: SimpleNamespace,
    bearer: str,
    name: str,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return result_of(
        rpc(stack, bearer, "tools/call", {"name": name, "arguments": arguments or {}})
    )


def text_of(result: dict[str, Any]) -> str:
    return "".join(block.get("text", "") for block in result["content"])


class TestAuthentication:
    def test_root_opens_account_ui_without_a_bearer(self, stack):
        response = stack.client.get("/", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/account/"
        assert response.headers["cache-control"] == "no-store"

    def test_no_bearer_is_401_with_a_bearer_challenge(self, stack):
        response = rpc(stack, None, "tools/list")
        assert response.status_code == 401
        assert response.headers["www-authenticate"].startswith("Bearer")
        assert stack.seen == []

    def test_unknown_bearer_is_401(self, stack):
        assert rpc(stack, "bearer-nobody", "tools/list").status_code == 401

    @pytest.mark.parametrize("bearer", ["bearer-W", "bearer-N", "bearer-X"])
    def test_external_bearer_is_not_a_local_access_token(self, stack, bearer):
        response = rpc(
            stack, bearer, "tools/call", {"name": "list_courses", "arguments": {}}
        )
        assert response.status_code == 401
        assert stack.seen == []


class TestEnrollment:
    def test_listing_tools_works_without_enrollment(self, stack):
        names = {
            tool["name"]
            for tool in result_of(rpc(stack, "bearer-C", "tools/list"))["tools"]
        }
        assert "list_courses" in names

    def test_a_call_without_enrollment_gets_the_account_message(self, stack):
        result = call_tool(stack, "bearer-C", "list_courses")
        assert result["isError"] is True
        assert f"{BASE}/account" in text_of(result)
        assert "never paste it into this chat" in text_of(result)
        assert stack.seen == []  # no Canvas request, and no server credential tried

    def test_deleting_the_enrollment_stops_tool_calls_immediately(self, stack):
        assert call_tool(stack, "bearer-A", "list_courses")["isError"] is False
        assert stack.runtime.store.delete(acct_key(OID_A)) is True
        result = call_tool(stack, "bearer-A", "list_courses")
        assert result["isError"] is True
        assert f"{BASE}/account" in text_of(result)

    def test_an_unreadable_stored_token_gets_the_enroll_again_message(self, stack):
        with raw_connection(stack.runtime.store) as conn:
            conn.execute(
                "UPDATE canvas_credentials SET ciphertext = ? WHERE account_id = ?",
                (b"x" * 40, acct_key(OID_A)),
            )
        response = rpc(
            stack, "bearer-A", "tools/call", {"name": "list_courses", "arguments": {}}
        )
        assert response.status_code == 503
        assert "could not be read" in response.json()["error"]
        assert stack.seen == []


class TestDisablement:
    """An administrator's disablement is checked on every request, before Canvas is reached."""

    @staticmethod
    def _disable(stack, oid: str = OID_A) -> None:
        from canvas_mcp.core.selfhost.token_store import (
            DISABLE_REASON_OPERATOR,
            OPERATOR,
        )

        stack.runtime.store.disable_principal(
            acct_key(oid), actor=OPERATOR, reason=DISABLE_REASON_OPERATOR
        )

    def test_a_disabled_user_is_refused_on_every_request_and_canvas_is_never_called(
        self, stack
    ):
        assert call_tool(stack, "bearer-A", "list_courses")["isError"] is False
        stack.seen.clear()
        self._disable(stack)
        for method, params in (
            ("tools/call", {"name": "list_courses", "arguments": {}}),
            ("tools/list", {}),
            ("initialize", {}),
        ):
            response = rpc(stack, "bearer-A", method, params)
            assert response.status_code == 401, method
        assert stack.seen == []

    def test_other_users_keep_working(self, stack):
        self._disable(stack, OID_A)
        assert call_tool(stack, "bearer-B", "list_courses")["isError"] is False

    def test_removing_the_enrollment_of_a_disabled_user_changes_nothing(self, stack):
        self._disable(stack)
        assert stack.runtime.store.delete(acct_key(OID_A)) is True
        response = rpc(
            stack, "bearer-A", "tools/call", {"name": "list_courses", "arguments": {}}
        )
        assert response.status_code == 401

    def test_a_change_without_cache_invalidation_is_noticed_on_the_next_request(
        self, stack
    ):
        from canvas_mcp.core.selfhost.token_store import (
            DISABLE_REASON_OPERATOR,
            OPERATOR,
        )

        assert call_tool(stack, "bearer-A", "list_courses")["isError"] is False
        stack.runtime.store.disable_principal(
            acct_key(OID_A), actor=OPERATOR, reason=DISABLE_REASON_OPERATOR
        )
        stack.seen.clear()
        assert rpc(stack, "bearer-A", "tools/list").status_code == 401
        assert stack.seen == []

    def test_enabling_requires_a_new_grant_and_keeps_the_enrollment(self, stack):
        from canvas_mcp.core.selfhost.token_store import OPERATOR

        self._disable(stack)
        stack.runtime.store.enable_principal(acct_key(OID_A), actor=OPERATOR)
        assert rpc(stack, "bearer-A", "tools/list").status_code == 401
        stack.tokens["bearer-A"] = stack.native.tokens_for(stack.users["A"])[1][
            "access_token"
        ]
        assert call_tool(stack, "bearer-A", "list_courses")["isError"] is False


class TestPerUserCredentialsAndIsolation:
    def test_each_user_reaches_canvas_with_their_own_token(self, stack):
        text_a = text_of(call_tool(stack, "bearer-A", "list_courses"))
        text_b = text_of(call_tool(stack, "bearer-B", "list_courses"))
        assert "ICS 33" in text_a and "MATH 2B" not in text_a
        assert "MATH 2B" in text_b and "ICS 33" not in text_b
        assert [token for path, token in stack.seen if path == "/api/v1/courses"] == [
            CANVAS_TOKEN[OID_A],
            CANVAS_TOKEN[OID_B],
        ]

    def test_a_course_cached_for_one_user_does_not_resolve_for_another(self, stack):
        call_tool(stack, "bearer-A", "list_courses")
        stack.seen.clear()
        result = call_tool(
            stack, "bearer-B", "get_course_details", {"course_identifier": "ICS 33"}
        )
        assert not any("/courses/101" in path for path, _ in stack.seen)
        assert not any(token == CANVAS_TOKEN[OID_A] for _, token in stack.seen)
        assert "Intermediate Python" not in text_of(result)

    def test_the_account_holder_reads_back_their_own_course_by_code(self, stack):
        call_tool(stack, "bearer-A", "list_courses")
        stack.seen.clear()
        call_tool(
            stack, "bearer-A", "get_course_details", {"course_identifier": "ICS 33"}
        )
        assert ("/api/v1/courses/101", CANVAS_TOKEN[OID_A]) in stack.seen

    def test_last_used_is_recorded_for_the_caller_only(self, stack):
        call_tool(stack, "bearer-A", "list_courses")
        info_a = stack.runtime.store.info(acct_key(OID_A))
        info_b = stack.runtime.store.info(acct_key(OID_B))
        assert info_a is not None and info_a.last_used_at is not None
        assert info_b is not None and info_b.last_used_at is None

    def test_the_canvas_token_never_appears_in_a_response(self, stack):
        for bearer in ("bearer-A", "bearer-B", "bearer-C"):
            response = rpc(
                stack, bearer, "tools/call", {"name": "list_courses", "arguments": {}}
            )
            for token in CANVAS_TOKEN.values():
                assert token not in response.text
