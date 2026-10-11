"""Native Local AS and React enrollment through the real MCP and Canvas clients.

Provider cryptography/PKCE and Canvas are offline fakes. Retired proxy/HTML
assertions are replaced by native authorization, JSON lifecycle and confirmation
checks; legacy HTTP and stdio regression coverage remains below.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx
from dbbackend import raw_connection
from fastmcp import FastMCP
from selfhost.account_fixture import _display_in_utc, build_harness  # noqa: F401
from selfhost.authz.stack import AUDIENCE, CLAUDE_REDIRECT, Browser, User
from selfhost.conftest import acct_key
from starlette.testclient import TestClient

from canvas_mcp.core import cache
from canvas_mcp.core.config import reset_config
from canvas_mcp.core.selfhost.token_store import OPERATOR
from canvas_mcp.core.tool_policy import TOOL_EFFECTS, Effect
from canvas_mcp.core.write_confirmation import (
    ConfirmationGuard,
    preview_with_token,
    redeem_confirmation,
)
from canvas_mcp.server import CanvasCredentialMiddleware
from canvas_mcp.tools import register_course_tools

BASE = "https://canvas.example.test"
CANVAS_HOST = "canvas.example.edu"
CANVAS = f"https://{CANVAS_HOST}"
TENANT = "11111111-2222-3333-4444-555555555555"
OTHER_TENANT = "99999999-8888-7777-6666-555555555555"
ORIGIN = {"Origin": BASE}
ACK = {"acknowledged": True, "notice_version": 1}


@dataclass(frozen=True)
class EntraUser:
    name: str
    oid: str
    roles: tuple[str, ...] = ("Canvas.User",)
    tenant: str = TENANT  # tid claim AND issuer tenant, as Entra would issue it
    canvas_token: str = ""
    courses: tuple[dict[str, Any], ...] = ()

    @property
    def upn(self) -> str:
        return f"{self.name.lower()}@example.test"


USER_A = EntraUser(
    "Alice",
    "aaaaaaaa-0000-4000-8000-00000000000a",
    canvas_token="canvas-pat-for-alice-0123456789abcdef",
    courses=({"id": 101, "name": "Intermediate Python", "course_code": "ICS 33"},),
)
USER_B = EntraUser(
    "Bob",
    "bbbbbbbb-0000-4000-8000-00000000000b",
    canvas_token="canvas-pat-for-bob-0123456789abcdefgh",
    courses=(
        {"id": 202, "name": "Single Variable Calculus", "course_code": "MATH 2B"},
    ),
)
USER_C = EntraUser("Carol", "cccccccc-0000-4000-8000-00000000000c", roles=())  # no role
USER_D = EntraUser("Dave", "dddddddd-0000-4000-8000-00000000000d", tenant=OTHER_TENANT)


ENROLLED_TOKENS = {USER_A.canvas_token: USER_A, USER_B.canvas_token: USER_B}


def native_user(user: EntraUser) -> User:
    return User(user.name, user.oid, user.roles, user.canvas_token)


@dataclass
class FakeCanvas:
    seen: list[tuple[str, str]] = field(default_factory=list)  # (path, bearer token)

    def handle(self, request: httpx.Request) -> httpx.Response:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        self.seen.append((request.url.path, token))
        user = ENROLLED_TOKENS.get(token)
        if user is None:
            return httpx.Response(
                401, json={"errors": [{"message": "Invalid access token."}]}
            )
        if request.url.path == "/api/v1/users/self":
            return httpx.Response(
                200, json={"id": 1000 + len(user.name), "name": user.name}
            )
        if request.url.path == "/api/v1/courses":
            return httpx.Response(200, json=list(user.courses))
        for course in user.courses:
            if request.url.path == f"/api/v1/courses/{course['id']}":
                return httpx.Response(200, json=course)
        return httpx.Response(
            404,
            json={"errors": [{"message": "The specified resource does not exist."}]},
        )

    def tokens_used(self) -> set[str]:
        return {token for _, token in self.seen}

    def calls_with(self, path_prefix: str) -> list[str]:
        return [token for path, token in self.seen if path.startswith(path_prefix)]


def rpc(
    client: TestClient,
    bearer: str | None,
    method: str,
    params: dict[str, Any] | None = None,
    **headers: str,
) -> httpx.Response:
    request_headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        **headers,
    }
    if bearer:
        request_headers["Authorization"] = f"Bearer {bearer}"
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    return client.post("/mcp", json=body, headers=request_headers)


def result_of(response: httpx.Response) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    text = response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        text = [
            line[5:].strip() for line in text.splitlines() if line.startswith("data:")
        ][-1]
    payload = json.loads(text)
    assert "error" not in payload, payload
    return payload["result"]


def call_tool(
    client: TestClient, bearer: str, name: str, arguments: dict[str, Any] | None = None
) -> dict[str, Any]:
    return result_of(
        rpc(client, bearer, "tools/call", {"name": name, "arguments": arguments or {}})
    )


def text_of(result: dict[str, Any]) -> str:
    return "".join(block.get("text", "") for block in result["content"])


_WIDGET_GUARD = ConfirmationGuard(nothing_done="Nothing was deleted.")


def _register_widget_tool(mcp: FastMCP, deleted: list[str]) -> None:
    """A write tool guarded exactly like the repo's delete tools (preview + token)."""

    @mcp.tool()
    async def delete_widget(
        widget_id: str, confirmation_token: str | None = None
    ) -> str:
        """Delete a widget after a confirmed preview."""
        fingerprint = _WIDGET_GUARD.fingerprint("delete_widget", widget_id)
        if not confirmation_token:
            return preview_with_token(
                _WIDGET_GUARD,
                fingerprint,
                "delete_widget",
                f"Delete widget {widget_id}",
            )
        error = redeem_confirmation(_WIDGET_GUARD, confirmation_token, fingerprint)
        if error:
            return error
        deleted.append(widget_id)
        return f"Deleted widget {widget_id}"


def api(
    world: SimpleNamespace,
    method: str,
    path: str,
    body: Any = None,
    *,
    origin: str | None = BASE,
    csrf: bool | str = True,
) -> httpx.Response:
    headers = {}
    if origin is not None:
        headers["Origin"] = origin
    if csrf is True:
        shown = world.client.get("/api/v1/me")
        assert shown.status_code == 200, shown.text
        headers["X-CSRF-Token"] = shown.json()["csrf_token"]
    elif isinstance(csrf, str):
        headers["X-CSRF-Token"] = csrf
    return world.client.request(method, "/api/v1" + path, json=body, headers=headers)


def signin(world: SimpleNamespace, user: EntraUser) -> httpx.Response:
    world.client.cookies.clear()
    return Browser(world.native, client=world.client).sign_in(
        native_user(user), tid=user.tenant
    )


def enroll(
    world: SimpleNamespace, user: EntraUser, token: str | None = None
) -> httpx.Response:
    assert signin(world, user).status_code == 303
    return api(
        world,
        "PUT",
        "/me/canvas-token",
        {"canvas_token": token or user.canvas_token, "custody": ACK},
    )


def bearer(world: SimpleNamespace, user: EntraUser) -> str:
    return world.native.tokens_for(native_user(user))[1]["access_token"]


@pytest.fixture(params=["request_local", "per_principal"])
def world(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_course_list: None,
) -> Iterator[SimpleNamespace]:
    monkeypatch.setitem(TOOL_EFFECTS, "delete_widget", Effect.CANVAS_WRITE)
    monkeypatch.setenv("ALLOWED_WRITE_TOOLS", "delete_widget")
    _WIDGET_GUARD.reset()
    deleted: list[str] = []

    def register(mcp: FastMCP) -> None:
        register_course_tools(mcp)
        _register_widget_tool(mcp, deleted)

    h = build_harness(
        tmp_path,
        runtime_env={
            "SELFHOST_COURSE_STATE": request.param,
            "REFRESH_REUSE_GRACE_S": "0",
        },
        register_tools=register,
    )
    h.core._canvas_whoami = h.core._default_whoami
    canvas = FakeCanvas()
    with respx.mock(assert_all_called=False) as router:
        router.route(host=CANVAS_HOST).mock(side_effect=canvas.handle)
        yield SimpleNamespace(
            client=h.client,
            native=h.stack,
            runtime=h.stack.runtime,
            h=h,
            canvas=canvas,
            deleted=deleted,
            course_state=request.param,
        )


@pytest.fixture
def enrolled(world: SimpleNamespace) -> SimpleNamespace:
    for user in (USER_A, USER_B):
        saved = enroll(world, user)
        assert saved.status_code == 200, saved.text
    world.canvas.seen.clear()
    return world


class TestNativeEnrollment:
    def test_each_browser_saves_only_its_own_encrypted_credential(self, enrolled):
        store = enrolled.runtime.store
        assert store.count() == 2
        for user in (USER_A, USER_B):
            assert store.get(acct_key(user.oid)).api_token == user.canvas_token
        with raw_connection(store) as conn:
            sealed = b"".join(
                bytes(value)
                for row in conn.execute(
                    "SELECT nonce, ciphertext FROM canvas_credentials"
                )
                for value in row
            )
        assert all(
            user.canvas_token.encode() not in sealed for user in (USER_A, USER_B)
        )

    def test_account_api_and_page_do_not_return_the_pat(self, enrolled):
        signin(enrolled, USER_A)
        response = enrolled.client.get("/api/v1/me")
        assert response.status_code == 200
        page = enrolled.client.get("/account")
        assert page.status_code == 200 and "no-store" in page.headers["cache-control"]
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
        assert USER_A.canvas_token not in page.text + response.text

    @pytest.mark.parametrize(
        ("origin", "csrf"),
        [(None, True), ("https://evil.example", True), (BASE, "wrong")],
    )
    def test_enrollment_requires_origin_and_real_csrf(self, world, origin, csrf):
        signin(world, USER_A)
        response = api(
            world,
            "PUT",
            "/me/canvas-token",
            {"canvas_token": USER_A.canvas_token, "custody": ACK},
            origin=origin,
            csrf=csrf,
        )
        assert response.status_code == 403
        assert world.runtime.store.count() == 0 and world.canvas.seen == []

    def test_enrollment_requires_custody_acknowledgement(self, world):
        signin(world, USER_A)
        response = api(
            world, "PUT", "/me/canvas-token", {"canvas_token": USER_A.canvas_token}
        )
        assert response.status_code == 422
        assert world.runtime.store.count() == 0 and world.canvas.seen == []

    def test_rejected_canvas_pat_is_never_stored(self, world):
        assert (
            enroll(world, USER_A, "not-a-real-canvas-token-0123456789").status_code
            == 422
        )
        assert world.runtime.store.count() == 0

    @pytest.mark.parametrize("user", [USER_C, USER_D])
    def test_admission_refusal_creates_no_signed_in_account(self, world, user):
        response = signin(world, user)
        assert response.status_code == 303
        assert world.client.get("/api/v1/me").status_code == 401
        assert world.canvas.seen == []


class TestNativeMcp:
    def test_both_callers_use_their_own_pat_and_course_cache(self, enrolled):
        a, b = bearer(enrolled, USER_A), bearer(enrolled, USER_B)
        assert "ICS 33" in text_of(call_tool(enrolled.client, a, "list_courses"))
        enrolled.canvas.seen.clear()
        foreign = call_tool(
            enrolled.client, b, "get_course_details", {"course_identifier": "ICS 33"}
        )
        assert "Intermediate Python" not in text_of(foreign)
        assert USER_A.canvas_token not in enrolled.canvas.tokens_used()
        assert "MATH 2B" in text_of(call_tool(enrolled.client, b, "list_courses"))

    def test_course_state_lifetime_matches_the_configured_mode(self, enrolled):
        a = bearer(enrolled, USER_A)
        call_tool(
            enrolled.client, a, "get_course_details", {"course_identifier": "ICS 33"}
        )
        assert any(key.startswith(acct_key(USER_A.oid)) for key in cache._STATES) is (
            enrolled.course_state == "per_principal"
        )

    def test_disable_and_enable_cannot_revive_an_existing_grant(self, enrolled):
        a = bearer(enrolled, USER_A)
        store = enrolled.runtime.store
        store.disable_principal(
            acct_key(USER_A.oid), actor=OPERATOR, reason="operator_disabled"
        )
        assert rpc(enrolled.client, a, "tools/list").status_code == 401
        store.enable_principal(acct_key(USER_A.oid), actor=OPERATOR)
        assert rpc(enrolled.client, a, "tools/list").status_code == 401
        fresh = bearer(enrolled, USER_A)
        assert "ICS 33" in text_of(call_tool(enrolled.client, fresh, "list_courses"))

    def test_disconnect_keeps_the_grant_but_refuses_tools_until_reenrollment(
        self, enrolled
    ):
        a = bearer(enrolled, USER_A)
        signin(enrolled, USER_A)
        assert api(enrolled, "DELETE", "/me/canvas-token").status_code == 204
        refused = call_tool(enrolled.client, a, "list_courses")
        assert refused["isError"] and BASE + "/account" in text_of(refused)
        assert enroll(enrolled, USER_A).status_code == 200
        assert "ICS 33" in text_of(call_tool(enrolled.client, a, "list_courses"))

    def test_refresh_is_local_and_rotation_refuses_replay(self, enrolled):
        client_id, tokens = enrolled.native.tokens_for(native_user(USER_A))
        calls = enrolled.native.idp.token_requests
        fresh = enrolled.native.refresh(client_id, tokens["refresh_token"])
        assert fresh.status_code == 200
        assert enrolled.native.idp.token_requests == calls
        assert (
            rpc(enrolled.client, fresh.json()["access_token"], "tools/list").status_code
            == 200
        )
        assert (
            enrolled.native.refresh(client_id, tokens["refresh_token"]).status_code
            == 401
        )

    def test_code_is_bound_to_pkce_client_and_one_redemption(self, enrolled):
        native = enrolled.native
        client_id, verifier, code, _ = native.code_for(native_user(USER_A))
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": CLAUDE_REDIRECT,
            "resource": AUDIENCE,
        }
        assert native.token(**data, code_verifier="wrong" * 16).status_code == 401
        assert native.token(**data, code_verifier=verifier).status_code == 200
        assert native.token(**data, code_verifier=verifier).status_code == 401

    def test_unsigned_external_bearer_and_easy_auth_header_grant_nothing(self, world):
        assert (
            rpc(world.client, "external-entra-bearer", "tools/list").status_code == 401
        )
        response = rpc(
            world.client, None, "tools/list", **{"X-MS-CLIENT-PRINCIPAL": "spoof"}
        )
        assert response.status_code == 401
        assert "resource_metadata" in response.headers["www-authenticate"]

    def test_foreign_host_is_refused_and_health_is_public(self, world):
        assert (
            world.client.get("/healthz", headers={"Host": "evil.example"}).status_code
            == 421
        )
        health = world.client.get("/healthz")
        assert health.status_code == 200
        assert USER_A.canvas_token not in health.text


class TestNativeConfirmation:
    @staticmethod
    def preview(world, token):
        world.runtime.store.set_tool_prefs(acct_key(USER_A.oid), ["delete_widget"])
        result = text_of(
            call_tool(world.client, token, "delete_widget", {"widget_id": "w1"})
        )
        match = re.search(r"Confirmation token: (\S+)", result)
        assert match, result
        return match.group(1)

    def test_another_account_cannot_spend_a_preview(self, enrolled):
        a, b = bearer(enrolled, USER_A), bearer(enrolled, USER_B)
        preview = self.preview(enrolled, a)
        enrolled.runtime.store.set_tool_prefs(acct_key(USER_B.oid), ["delete_widget"])
        result = call_tool(
            enrolled.client,
            b,
            "delete_widget",
            {"widget_id": "w1", "confirmation_token": preview},
        )
        assert "Deleted widget" not in text_of(result)
        assert enrolled.deleted == []
        # Authentic mismatches burn the preview; Alice must review a fresh one.
        spent = call_tool(
            enrolled.client,
            a,
            "delete_widget",
            {"widget_id": "w1", "confirmation_token": preview},
        )
        assert "already used" in text_of(spent)
        fresh_preview = self.preview(enrolled, a)
        done = call_tool(
            enrolled.client,
            a,
            "delete_widget",
            {"widget_id": "w1", "confirmation_token": fresh_preview},
        )
        assert "Deleted widget w1" in text_of(done)
        assert enrolled.deleted == ["w1"]

    def test_replacement_invalidates_pending_confirmation(self, enrolled):
        a = bearer(enrolled, USER_A)
        preview = self.preview(enrolled, a)
        assert enroll(enrolled, USER_A).status_code == 200
        result = call_tool(
            enrolled.client,
            a,
            "delete_widget",
            {"widget_id": "w1", "confirmation_token": preview},
        )
        assert "does not match" in text_of(result)
        assert enrolled.deleted == []

    def test_disable_enable_invalidates_confirmation_with_a_new_grant(self, enrolled):
        a = bearer(enrolled, USER_A)
        preview = self.preview(enrolled, a)
        store = enrolled.runtime.store
        store.disable_principal(
            acct_key(USER_A.oid), actor=OPERATOR, reason="operator_disabled"
        )
        store.enable_principal(acct_key(USER_A.oid), actor=OPERATOR)
        fresh = bearer(enrolled, USER_A)
        result = call_tool(
            enrolled.client,
            fresh,
            "delete_widget",
            {"widget_id": "w1", "confirmation_token": preview},
        )
        assert "does not match" in text_of(result)
        assert enrolled.deleted == []

    def test_widget_optin_is_changed_in_the_authenticated_browser(self, enrolled):
        a = bearer(enrolled, USER_A)
        before = call_tool(enrolled.client, a, "delete_widget", {"widget_id": "w1"})
        assert before["isError"]
        signin(enrolled, USER_A)
        saved = api(enrolled, "PUT", "/me/write-tools", {"enabled": ["delete_widget"]})
        assert saved.status_code == 200, saved.text
        assert "Confirmation token:" in text_of(
            call_tool(enrolled.client, a, "delete_widget", {"widget_id": "w1"})
        )


@pytest.fixture
def canvas_only(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeCanvas]:
    monkeypatch.setenv("CANVAS_API_URL", CANVAS)
    monkeypatch.delenv("MCP_AUTH_MODE", raising=False)
    for name in ("MCP_ACCESS_KEYS", "ENTRA_AUTH_ENABLED", "MCP_ALLOW_UNAUTHENTICATED"):
        monkeypatch.delenv(name, raising=False)
    reset_config()
    canvas = FakeCanvas()
    with respx.mock(assert_all_called=False) as router:
        router.route(host=CANVAS_HOST).mock(side_effect=canvas.handle)
        yield canvas
    reset_config()


class TestLegacyHttpModeUnchanged:
    """The upstream per-request ``X-Canvas-Token`` mode still works, and no longer shares caches."""

    @pytest.fixture
    def legacy(self, canvas_only: FakeCanvas) -> Iterator[SimpleNamespace]:
        mcp = FastMCP("legacy")
        register_course_tools(mcp)
        app = CanvasCredentialMiddleware(mcp.http_app(stateless_http=True))
        with TestClient(app, base_url="http://127.0.0.1:8819") as client:
            yield SimpleNamespace(client=client, canvas=canvas_only)

    def test_the_header_token_is_used_and_nothing_else(self, legacy):
        a = call_tool_headers(legacy.client, USER_A.canvas_token, "list_courses")
        b = call_tool_headers(legacy.client, USER_B.canvas_token, "list_courses")
        assert "ICS 33" in text_of(a) and "MATH 2B" not in text_of(a)
        assert "MATH 2B" in text_of(b) and "ICS 33" not in text_of(b)
        assert legacy.canvas.calls_with("/api/v1/courses") == [
            USER_A.canvas_token,
            USER_B.canvas_token,
        ]

    def test_a_request_without_a_token_is_refused(self, legacy):
        response = legacy.client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={
                "Accept": "application/json, text/event-stream",
            },
        )
        assert response.status_code == 401
        assert legacy.canvas.seen == []

    def test_header_tokens_no_longer_share_a_course_cache(self, legacy):
        call_tool_headers(legacy.client, USER_A.canvas_token, "list_courses")
        legacy.canvas.seen.clear()
        result = call_tool_headers(
            legacy.client,
            USER_B.canvas_token,
            "get_course_details",
            {"course_identifier": "ICS 33"},
        )
        assert "Intermediate Python" not in text_of(result)
        assert USER_A.canvas_token not in legacy.canvas.tokens_used()


def call_tool_headers(
    client: TestClient,
    canvas_token: str,
    name: str,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        },
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "X-Canvas-Token": canvas_token,
        },
    )
    return result_of(response)


class TestStdioModeUnchanged:
    async def test_the_server_token_is_used_and_state_is_local(
        self, canvas_only, monkeypatch
    ):
        from fastmcp import Client

        from canvas_mcp.core import client as canvas_client
        from canvas_mcp.core.cache import current_cache_state, reset_course_cache
        from canvas_mcp.core.credentials import (
            current_principal_key,
            is_http_request_active,
        )

        monkeypatch.setenv("CANVAS_API_TOKEN", USER_A.canvas_token)
        reset_config()
        reset_course_cache()
        await canvas_client.cleanup_http_client()

        mcp = FastMCP("stdio")
        register_course_tools(mcp)
        try:
            async with Client(mcp) as client:
                result = await client.call_tool("list_courses", {})
            assert "ICS 33" in "".join(
                getattr(block, "text", "") for block in result.content
            )
            assert canvas_only.calls_with("/api/v1/courses") == [USER_A.canvas_token]
            assert current_principal_key() == "local"
            assert is_http_request_active() is False
            assert current_cache_state().code_to_id == {
                "ICS 33": "101"
            }  # the single local state
        finally:
            reset_course_cache()
            await canvas_client.cleanup_http_client()
            reset_config()
