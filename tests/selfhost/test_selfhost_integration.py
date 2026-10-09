"""End to end through the real HTTP stack: FastMCP auth, our middleware, the gate,
the encrypted token store and the Canvas client, with only Entra and Canvas faked."""

import base64
import json
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

pytest.importorskip("canvas_mcp.core.selfhost.token_store")
pytest.importorskip("canvas_mcp.core.selfhost.account_web")

from canvas_mcp.core.selfhost.app import (  # noqa: E402
    build_selfhost_asgi_app,
    install_selfhost,
    prepare_selfhost,
)
from canvas_mcp.core.selfhost.settings import load_selfhost_settings  # noqa: E402
from canvas_mcp.tools import register_course_tools  # noqa: E402

from .conftest import CLIENT, OID_A, OID_B, TENANT  # noqa: E402

BASE = "https://canvas.example.test"
CANVAS = "https://canvas.example.edu"
OID_C = "cccccccc-0000-4000-8000-00000000000c"  # allowed, never enrolled
OID_W = "dddddddd-0000-4000-8000-00000000000d"  # wrong tenant
OID_N = "eeeeeeee-0000-4000-8000-00000000000e"  # no role
OID_X = "ffffffff-0000-4000-8000-00000000000f"  # wrong client
CANVAS_TOKEN = {OID_A: "canvas-token-for-user-A-0123456789", OID_B: "canvas-token-for-user-B-0123456789"}
COURSES = {
    CANVAS_TOKEN[OID_A]: [{"id": 101, "name": "Intermediate Python", "course_code": "ICS 33"}],
    CANVAS_TOKEN[OID_B]: [{"id": 202, "name": "Single Variable Calculus", "course_code": "MATH 2B"}],
}


def _entra(oid: str, *, tid: str = TENANT, azp: str = CLIENT, roles: list[str] | None = None) -> dict[str, Any]:
    return {
        "client_id": azp, "scopes": ["Canvas.Access"], "tid": tid, "oid": oid, "azp": azp,
        "roles": ["Canvas.User"] if roles is None else roles, "name": f"user {oid[:4]}",
    }


TOKENS = {
    "bearer-A": _entra(OID_A),
    "bearer-B": _entra(OID_B),
    "bearer-C": _entra(OID_C),
    "bearer-W": _entra(OID_W, tid="99999999-9999-9999-9999-999999999999"),
    "bearer-N": _entra(OID_N, roles=[]),
    "bearer-X": _entra(OID_X, azp="12345678-1234-1234-1234-123456789012"),
}


@pytest.fixture(params=["request_local", "per_principal"])
def stack(
    request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, real_course_list: None
) -> Iterator[SimpleNamespace]:
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
        "SELFHOST_COURSE_STATE": request.param,
    })
    runtime = prepare_selfhost(settings)
    for oid, token in CANVAS_TOKEN.items():
        runtime.store.put(
            tenant_id=TENANT, object_id=oid, api_token=token, canvas_user_id=oid[:2],
            canvas_user_name="n", entra_display_name="n", entra_upn="n@example.test",
        )

    config: Any = SimpleNamespace(canvas_api_url=f"{CANVAS}/api/v1")
    mcp = FastMCP("integration", auth=StaticTokenVerifier(TOKENS, required_scopes=["Canvas.Access"]))
    register_course_tools(mcp)
    install_selfhost(mcp, runtime, config)
    app = build_selfhost_asgi_app(mcp, runtime, config)

    seen: list[tuple[str, str]] = []

    def canvas(request: httpx.Request) -> httpx.Response:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        seen.append((request.url.path, token))
        if token not in COURSES:
            return httpx.Response(401, json={"errors": [{"message": "bad token"}]})
        if request.url.path == "/api/v1/courses":
            return httpx.Response(200, json=COURSES[token])
        return httpx.Response(404, json={"errors": [{"message": "not found"}]})

    with respx.mock(assert_all_called=False) as router, TestClient(app, base_url=BASE) as client:
        router.route(host="canvas.example.edu").mock(side_effect=canvas)
        yield SimpleNamespace(client=client, runtime=runtime, seen=seen, course_state=request.param)
    reset_config()


def rpc(stack: SimpleNamespace, bearer: str | None, method: str, params: dict[str, Any] | None = None) -> httpx.Response:
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    return stack.client.post("/mcp", json=body, headers=headers)


def result_of(response: httpx.Response) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    text = response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        data = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
        text = data[-1]
    payload = json.loads(text)
    assert "error" not in payload, payload
    return payload["result"]


def call_tool(stack: SimpleNamespace, bearer: str, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    return result_of(rpc(stack, bearer, "tools/call", {"name": name, "arguments": arguments or {}}))


def text_of(result: dict[str, Any]) -> str:
    return "".join(block.get("text", "") for block in result["content"])


class TestAuthentication:
    def test_no_bearer_is_401_with_a_bearer_challenge(self, stack):
        response = rpc(stack, None, "tools/list")
        assert response.status_code == 401
        assert response.headers["www-authenticate"].startswith("Bearer")
        assert stack.seen == []

    def test_unknown_bearer_is_401(self, stack):
        assert rpc(stack, "bearer-nobody", "tools/list").status_code == 401

    @pytest.mark.parametrize("bearer", ["bearer-W", "bearer-N", "bearer-X"])
    def test_wrong_tenant_role_or_client_is_403_and_nothing_runs(self, stack, bearer):
        response = rpc(stack, bearer, "tools/call", {"name": "list_courses", "arguments": {}})
        assert response.status_code == 403
        assert response.json()["error"]
        assert stack.seen == []


class TestEnrollment:
    def test_listing_tools_works_without_enrollment(self, stack):
        names = {tool["name"] for tool in result_of(rpc(stack, "bearer-C", "tools/list"))["tools"]}
        assert "list_courses" in names

    def test_a_call_without_enrollment_gets_the_account_message(self, stack):
        result = call_tool(stack, "bearer-C", "list_courses")
        assert result["isError"] is True
        assert f"{BASE}/account" in text_of(result)
        assert "never paste it into this chat" in text_of(result)
        assert stack.seen == []  # no Canvas request, and no server credential tried

    def test_deleting_the_enrollment_stops_tool_calls_immediately(self, stack):
        assert call_tool(stack, "bearer-A", "list_courses")["isError"] is False
        assert stack.runtime.store.delete(TENANT, OID_A) is True
        result = call_tool(stack, "bearer-A", "list_courses")
        assert result["isError"] is True
        assert f"{BASE}/account" in text_of(result)

    def test_an_unreadable_stored_token_gets_the_enroll_again_message(self, stack):
        import sqlite3

        with sqlite3.connect(stack.runtime.settings.token_db_path) as conn:
            conn.execute("UPDATE canvas_tokens SET ciphertext = ? WHERE object_id = ?", (b"x" * 40, OID_A))
        result = call_tool(stack, "bearer-A", "list_courses")
        assert result["isError"] is True
        assert "could not be read" in text_of(result)
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
            TENANT, oid, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR
        )
        stack.runtime.access.invalidate()

    def test_a_disabled_user_is_refused_on_every_request_and_canvas_is_never_called(self, stack):
        assert call_tool(stack, "bearer-A", "list_courses")["isError"] is False
        stack.seen.clear()
        self._disable(stack)
        for method, params in (
            ("tools/call", {"name": "list_courses", "arguments": {}}),
            ("tools/list", {}),
            ("initialize", {}),
        ):
            response = rpc(stack, "bearer-A", method, params)
            assert response.status_code == 403, method
            assert "disabled by an administrator" in response.json()["error"]
        assert stack.seen == []

    def test_other_users_keep_working(self, stack):
        self._disable(stack, OID_A)
        assert call_tool(stack, "bearer-B", "list_courses")["isError"] is False

    def test_removing_the_enrollment_of_a_disabled_user_changes_nothing(self, stack):
        self._disable(stack)
        assert stack.runtime.store.delete(TENANT, OID_A) is True
        response = rpc(stack, "bearer-A", "tools/call", {"name": "list_courses", "arguments": {}})
        assert response.status_code == 403

    def test_a_change_from_another_process_is_noticed_within_the_cache_ttl(self, stack, monkeypatch):
        from canvas_mcp.core.selfhost.token_store import (
            DISABLE_REASON_OPERATOR,
            OPERATOR,
        )

        clock = {"now": 1000.0}
        monkeypatch.setattr(stack.runtime.access, "_clock", lambda: clock["now"])
        assert call_tool(stack, "bearer-A", "list_courses")["isError"] is False
        # The operator CLI is a second process: it cannot invalidate our cache.
        stack.runtime.store.disable_principal(
            TENANT, OID_A, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR
        )
        clock["now"] += 1
        assert call_tool(stack, "bearer-A", "list_courses")["isError"] is False  # inside the bound
        clock["now"] += 10
        response = rpc(stack, "bearer-A", "tools/call", {"name": "list_courses", "arguments": {}})
        assert response.status_code == 403

    def test_enabling_restores_the_kept_enrollment(self, stack):
        from canvas_mcp.core.selfhost.token_store import OPERATOR

        self._disable(stack)
        stack.runtime.store.enable_principal(TENANT, OID_A, actor=OPERATOR)
        stack.runtime.access.invalidate()
        assert call_tool(stack, "bearer-A", "list_courses")["isError"] is False


class TestPerUserCredentialsAndIsolation:
    def test_each_user_reaches_canvas_with_their_own_token(self, stack):
        text_a = text_of(call_tool(stack, "bearer-A", "list_courses"))
        text_b = text_of(call_tool(stack, "bearer-B", "list_courses"))
        assert "ICS 33" in text_a and "MATH 2B" not in text_a
        assert "MATH 2B" in text_b and "ICS 33" not in text_b
        assert [token for path, token in stack.seen if path == "/api/v1/courses"] == [
            CANVAS_TOKEN[OID_A], CANVAS_TOKEN[OID_B],
        ]

    def test_a_course_cached_for_one_user_does_not_resolve_for_another(self, stack):
        call_tool(stack, "bearer-A", "list_courses")
        stack.seen.clear()
        result = call_tool(stack, "bearer-B", "get_course_details", {"course_identifier": "ICS 33"})
        assert not any("/courses/101" in path for path, _ in stack.seen)
        assert not any(token == CANVAS_TOKEN[OID_A] for _, token in stack.seen)
        assert "Intermediate Python" not in text_of(result)

    def test_the_account_holder_reads_back_their_own_course_by_code(self, stack):
        call_tool(stack, "bearer-A", "list_courses")
        stack.seen.clear()
        call_tool(stack, "bearer-A", "get_course_details", {"course_identifier": "ICS 33"})
        assert ("/api/v1/courses/101", CANVAS_TOKEN[OID_A]) in stack.seen

    def test_last_used_is_recorded_for_the_caller_only(self, stack):
        call_tool(stack, "bearer-A", "list_courses")
        info_a = stack.runtime.store.info(TENANT, OID_A)
        info_b = stack.runtime.store.info(TENANT, OID_B)
        assert info_a is not None and info_a.last_used_at is not None
        assert info_b is not None and info_b.last_used_at is None

    def test_the_canvas_token_never_appears_in_a_response(self, stack):
        for bearer in ("bearer-A", "bearer-B", "bearer-C"):
            response = rpc(stack, bearer, "tools/call", {"name": "list_courses", "arguments": {}})
            for token in CANVAS_TOKEN.values():
                assert token not in response.text
