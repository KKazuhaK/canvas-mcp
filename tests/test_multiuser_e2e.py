"""End-to-end, in-process test of the self-hosted multi-user mode.

Nothing is stubbed on our side: the real FastMCP ``AzureProvider`` (OAuth proxy),
our request-context middleware, credential gate, the /account pages, the encrypted
token store and the Canvas client all run. Only the two outside parties are faked:

* Entra ID: locally generated RSA keys sign every token, and a fake serves the
  discovery document, the JWKS and the token endpoint.
* Canvas: a fake API that answers according to the bearer token it is given.

Every user goes through the real flow: dynamic client registration, ``/authorize``,
the consent page, the Entra callback and ``/token`` for the MCP side; the Entra
sign-in, CSRF-protected enrollment form and session cookie for ``/account``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
import urllib.parse
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import fastmcp
import httpx
import httpx2
import pytest
import respx
from fastmcp import FastMCP
from joserfc import jwt
from joserfc.jwk import RSAKey
from starlette.testclient import TestClient

from canvas_mcp.core.config import reset_config
from canvas_mcp.core.selfhost.app import (
    build_selfhost_asgi_app,
    install_selfhost,
    prepare_selfhost,
)
from canvas_mcp.core.selfhost.oauth import build_entra_auth_provider
from canvas_mcp.core.selfhost.settings import load_selfhost_settings
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
ENTRA_HOST = "login.microsoftonline.com"
TENANT = "11111111-2222-3333-4444-555555555555"
OTHER_TENANT = "99999999-8888-7777-6666-555555555555"
CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
ORIGIN = {"Origin": BASE}


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
    "Alice", "aaaaaaaa-0000-4000-8000-00000000000a",
    canvas_token="canvas-pat-for-alice-0123456789abcdef",
    courses=({"id": 101, "name": "Intermediate Python", "course_code": "ICS 33"},),
)
USER_B = EntraUser(
    "Bob", "bbbbbbbb-0000-4000-8000-00000000000b",
    canvas_token="canvas-pat-for-bob-0123456789abcdefgh",
    courses=({"id": 202, "name": "Single Variable Calculus", "course_code": "MATH 2B"},),
)
USER_C = EntraUser("Carol", "cccccccc-0000-4000-8000-00000000000c", roles=())  # no role
USER_D = EntraUser("Dave", "dddddddd-0000-4000-8000-00000000000d", tenant=OTHER_TENANT)
OWNER = EntraUser("Olive", "eeeeeeee-0000-4000-8000-00000000000e", roles=("Canvas.Owner",))
ENROLLED_TOKENS = {USER_A.canvas_token: USER_A, USER_B.canvas_token: USER_B}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# --------------------------------------------------------------------------- Entra


@dataclass
class _Grant:
    user: EntraUser
    nonce: str | None = None


@dataclass
class FakeEntra:
    """Discovery, JWKS and the token endpoint, signing with a local RSA key."""

    key: RSAKey = field(default_factory=lambda: RSAKey.generate_key(2048, parameters={"kid": "e2e-key", "use": "sig"}))
    grants: dict[str, _Grant] = field(default_factory=dict)
    refresh_tokens: dict[str, EntraUser] = field(default_factory=dict)
    token_requests: list[dict[str, str]] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)

    def sign(self, claims: Mapping[str, Any]) -> str:
        return jwt.encode({"alg": "RS256", "kid": "e2e-key", "typ": "JWT"}, dict(claims), self.key)

    def issue_code(self, user: EntraUser, nonce: str | None = None) -> str:
        code = "entra-code-" + secrets.token_urlsafe(12)
        self.grants[code] = _Grant(user, nonce)
        return code

    def _base_claims(self, user: EntraUser, audience: str) -> dict[str, Any]:
        now = int(time.time())
        return {
            "iss": f"https://{ENTRA_HOST}/{user.tenant}/v2.0",
            "aud": audience,
            "iat": now, "nbf": now, "exp": now + 3600,
            "tid": user.tenant, "oid": user.oid, "sub": "sub-" + user.oid[:8],
            "name": user.name, "preferred_username": user.upn, "ver": "2.0",
            "roles": list(user.roles),
        }

    def access_token(self, user: EntraUser) -> str:
        claims = self._base_claims(user, f"api://{CLIENT_ID}")
        claims.update(azp=CLIENT_ID, azpacr="1", scp="Canvas.Access")
        if not user.roles:
            claims.pop("roles")  # Entra omits the claim when nothing is assigned
        return self.sign(claims)

    def id_token(self, grant: _Grant) -> str:
        claims = self._base_claims(grant.user, CLIENT_ID)
        if grant.nonce:
            claims["nonce"] = grant.nonce
        if not grant.user.roles:
            claims.pop("roles")
        return self.sign(claims)

    def handle(
        self, method: str, url: str, body: bytes, authorization: str = ""
    ) -> tuple[int, dict[str, Any]]:
        path = urllib.parse.urlsplit(url).path
        if method == "GET" and path.endswith("/discovery/v2.0/keys"):
            return 200, {"keys": [self.key.as_dict(private=False)]}
        if method == "GET" and path.endswith("/.well-known/openid-configuration"):
            tenant = path.split("/")[1]
            return 200, {
                "issuer": f"https://{ENTRA_HOST}/{tenant}/v2.0",
                "authorization_endpoint": f"https://{ENTRA_HOST}/{tenant}/oauth2/v2.0/authorize",
                "token_endpoint": f"https://{ENTRA_HOST}/{tenant}/oauth2/v2.0/token",
                "jwks_uri": f"https://{ENTRA_HOST}/{tenant}/discovery/v2.0/keys",
            }
        if method == "POST" and path.endswith("/oauth2/v2.0/token"):
            return self._token(urllib.parse.parse_qs(body.decode(), keep_blank_values=True), authorization)
        self.unexpected.append(f"{method} {url}")
        return 404, {"error": "not_found"}

    def _token(self, form: dict[str, list[str]], authorization: str) -> tuple[int, dict[str, Any]]:
        params = {k: v[0] for k, v in form.items()}
        if authorization.lower().startswith("basic "):  # client_secret_basic, as the OAuth proxy sends
            user, _, secret = base64.b64decode(authorization[6:]).decode("latin-1").partition(":")
            params.setdefault("client_id", urllib.parse.unquote_plus(user))
            params.setdefault("client_secret", urllib.parse.unquote_plus(secret))
        self.token_requests.append({k: v for k, v in params.items() if k != "client_secret"})
        if params.get("client_id") != CLIENT_ID or not params.get("client_secret"):
            return 401, {"error": "invalid_client"}
        grant_type = params.get("grant_type")
        if grant_type == "authorization_code":
            grant = self.grants.pop(params.get("code", ""), None)
            if grant is None or not params.get("code_verifier"):  # both flows use PKCE
                return 400, {"error": "invalid_grant"}
        elif grant_type == "refresh_token":
            user = self.refresh_tokens.get(params.get("refresh_token", ""))
            if user is None:
                return 400, {"error": "invalid_grant"}
            grant = _Grant(user)
        else:
            return 400, {"error": "unsupported_grant_type"}
        refresh = "entra-refresh-" + secrets.token_urlsafe(16)
        self.refresh_tokens[refresh] = grant.user
        return 200, {
            "token_type": "Bearer",
            "scope": f"api://{CLIENT_ID}/Canvas.Access openid profile",
            "expires_in": 3600,
            "access_token": self.access_token(grant.user),
            "refresh_token": refresh,
            "id_token": self.id_token(grant),
        }


# -------------------------------------------------------------------------- Canvas


@dataclass
class FakeCanvas:
    seen: list[tuple[str, str]] = field(default_factory=list)  # (path, bearer token)

    def handle(self, request: httpx.Request) -> httpx.Response:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        self.seen.append((request.url.path, token))
        user = ENROLLED_TOKENS.get(token)
        if user is None:
            return httpx.Response(401, json={"errors": [{"message": "Invalid access token."}]})
        if request.url.path == "/api/v1/users/self":
            return httpx.Response(200, json={"id": 1000 + len(user.name), "name": user.name})
        if request.url.path == "/api/v1/courses":
            return httpx.Response(200, json=list(user.courses))
        for course in user.courses:
            if request.url.path == f"/api/v1/courses/{course['id']}":
                return httpx.Response(200, json=course)
        return httpx.Response(404, json={"errors": [{"message": "The specified resource does not exist."}]})

    def tokens_used(self) -> set[str]:
        return {token for _, token in self.seen}

    def calls_with(self, path_prefix: str) -> list[str]:
        return [token for path, token in self.seen if path.startswith(path_prefix)]


# ------------------------------------------------------------------------- browser


class Browser:
    """What a person's browser and MCP client do, step by step, against the app."""

    def __init__(self, client: TestClient, entra: FakeEntra) -> None:
        self.client = client
        self.entra = entra
        self._dcr_client_id: str | None = None

    def fresh_session(self) -> None:
        self.client.cookies.clear()

    # ----- MCP side: DCR + authorize + consent + Entra callback + token

    def register(self) -> str:
        if self._dcr_client_id is None:
            response = self.client.post("/register", json={
                "client_name": "claude.ai test connector",
                "redirect_uris": [CLAUDE_CALLBACK],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            })
            assert response.status_code == 201, response.text
            self._dcr_client_id = response.json()["client_id"]
        return self._dcr_client_id

    def mcp_authorize(self, user: EntraUser) -> tuple[str | None, httpx.Response]:
        """Run the OAuth dance for ``user``. Returns (FastMCP bearer or None, last response)."""
        self.fresh_session()
        client_id = self.register()
        verifier = secrets.token_urlsafe(48)
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        state = secrets.token_urlsafe(8)
        authorize = self.client.get("/authorize", params={
            "response_type": "code", "client_id": client_id, "redirect_uri": CLAUDE_CALLBACK,
            "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
            "scope": "Canvas.Access", "resource": f"{BASE}/mcp",
        }, follow_redirects=False)
        assert authorize.status_code == 302, authorize.text
        consent_url = authorize.headers["location"]
        assert urllib.parse.urlsplit(consent_url).path == "/consent"

        consent_page = self.client.get(consent_url)
        assert consent_page.status_code == 200
        txn_id = re.search(r'name="txn_id"\s+value="([^"]+)"', consent_page.text)
        csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', consent_page.text)
        assert txn_id and csrf, "consent form fields not found"
        approve = self.client.post("/consent", data={
            "txn_id": txn_id.group(1), "csrf_token": csrf.group(1), "action": "approve",
        }, follow_redirects=False)
        assert approve.status_code == 302, approve.text

        entra_url = urllib.parse.urlsplit(approve.headers["location"])
        assert entra_url.netloc == ENTRA_HOST and entra_url.path == f"/{TENANT}/oauth2/v2.0/authorize"
        query = dict(urllib.parse.parse_qsl(entra_url.query))
        assert query["client_id"] == CLIENT_ID
        assert query["redirect_uri"] == f"{BASE}/auth/callback"
        assert f"api://{CLIENT_ID}/Canvas.Access" in query["scope"]
        assert query["code_challenge_method"] == "S256"

        callback = self.client.get("/auth/callback", params={
            "code": self.entra.issue_code(user), "state": query["state"],
        }, follow_redirects=False)
        if callback.status_code != 302 or not callback.headers.get("location", "").startswith(CLAUDE_CALLBACK):
            return None, callback
        redirect = urllib.parse.urlsplit(callback.headers["location"])
        returned = dict(urllib.parse.parse_qsl(redirect.query))
        assert returned["state"] == state
        token = self.client.post("/token", data={
            "grant_type": "authorization_code", "code": returned["code"], "client_id": client_id,
            "redirect_uri": CLAUDE_CALLBACK, "code_verifier": verifier,
        })
        if token.status_code != 200:
            return None, token
        return token.json()["access_token"], token

    def bearer_for(self, user: EntraUser) -> str:
        bearer, response = self.mcp_authorize(user)
        assert bearer, response.text
        return bearer

    # ----- /account side

    def account_sign_in(self, user: EntraUser) -> httpx.Response:
        self.fresh_session()
        login = self.client.get("/account/login", follow_redirects=False)
        assert login.status_code == 302
        location = urllib.parse.urlsplit(login.headers["location"])
        assert location.netloc == ENTRA_HOST and location.path == f"/{TENANT}/oauth2/v2.0/authorize"
        query = dict(urllib.parse.parse_qsl(location.query))
        assert query["redirect_uri"] == f"{BASE}/account/callback"
        assert query["code_challenge_method"] == "S256" and query["response_mode"] == "query"
        code = self.entra.issue_code(user, nonce=query["nonce"])
        return self.client.get(
            "/account/callback", params={"code": code, "state": query["state"]}, follow_redirects=False
        )

    def csrf(self, path: str = "/account") -> str:
        page = self.client.get(path)
        assert page.status_code == 200, page.text
        match = re.search(r'name="csrf"\s+value="([^"]+)"', page.text)
        assert match, "no csrf field on the page"
        return match.group(1)

    def enroll(self, user: EntraUser, canvas_token: str | None = None) -> httpx.Response:
        signed_in = self.account_sign_in(user)
        assert signed_in.status_code == 303, signed_in.text
        return self.client.post(
            "/account/token",
            data={"csrf": self.csrf(), "canvas_token": canvas_token or user.canvas_token},
            headers=ORIGIN, follow_redirects=False,
        )


# --------------------------------------------------------------------- MCP helpers


def rpc(client: TestClient, bearer: str | None, method: str, params: dict[str, Any] | None = None, **headers: str) -> httpx.Response:
    request_headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json", **headers}
    if bearer:
        request_headers["Authorization"] = f"Bearer {bearer}"
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    return client.post("/mcp", json=body, headers=request_headers)


def result_of(response: httpx.Response) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    text = response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        text = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")][-1]
    payload = json.loads(text)
    assert "error" not in payload, payload
    return payload["result"]


def call_tool(client: TestClient, bearer: str, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    return result_of(rpc(client, bearer, "tools/call", {"name": name, "arguments": arguments or {}}))


def text_of(result: dict[str, Any]) -> str:
    return "".join(block.get("text", "") for block in result["content"])


# ------------------------------------------------------------------------- fixtures

_WIDGET_GUARD = ConfirmationGuard(nothing_done="Nothing was deleted.")


def _register_widget_tool(mcp: FastMCP, deleted: list[str]) -> None:
    """A write tool guarded exactly like the repo's delete tools (preview + token)."""

    @mcp.tool()
    async def delete_widget(widget_id: str, confirmation_token: str | None = None) -> str:
        """Delete a widget after a confirmed preview."""
        fingerprint = _WIDGET_GUARD.fingerprint("delete_widget", widget_id)
        if not confirmation_token:
            return preview_with_token(_WIDGET_GUARD, fingerprint, "delete_widget", f"Delete widget {widget_id}")
        error = redeem_confirmation(_WIDGET_GUARD, confirmation_token, fingerprint)
        if error:
            return error
        deleted.append(widget_id)
        return f"Deleted widget {widget_id}"


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[SimpleNamespace]:
    monkeypatch.setattr(fastmcp.settings, "test_mode", True)  # cheap key stretching only
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path / "fastmcp")
    monkeypatch.setenv("CANVAS_API_URL", CANVAS)
    for name in ("CANVAS_API_TOKEN", "CANVAS_ROLE", "MCP_ACCESS_KEYS"):
        monkeypatch.delenv(name, raising=False)
    reset_config()
    _WIDGET_GUARD.reset()

    settings = load_selfhost_settings({
        "PUBLIC_BASE_URL": BASE,
        "ENTRA_TENANT_ID": TENANT,
        "ENTRA_CLIENT_ID": CLIENT_ID,
        "ENTRA_CLIENT_SECRET": "entra-client-secret-0123456789",
        "OAUTH_JWT_SIGNING_KEY": "jwt-signing-key-" + "z" * 40,
        "ACCOUNT_SESSION_SECRET": base64.b64encode(bytes(range(32))).decode(),
        "CANVAS_TOKEN_KEYS": "k1:" + base64.b64encode(bytes(range(32, 64))).decode(),
        "FASTMCP_HOME": str(tmp_path / "fastmcp"),
        "SELFHOST_DATA_DIR": str(tmp_path / "data"),
    })
    runtime = prepare_selfhost(settings)
    config: Any = SimpleNamespace(canvas_api_url=f"{CANVAS}/api/v1")

    mcp = FastMCP("e2e", auth=build_entra_auth_provider(settings))
    register_course_tools(mcp)
    deleted: list[str] = []
    _register_widget_tool(mcp, deleted)
    install_selfhost(mcp, runtime, config)
    app = build_selfhost_asgi_app(mcp, runtime, config)

    entra = FakeEntra()
    canvas = FakeCanvas()

    # FastMCP talks to Entra through httpx2: hand every client a MockTransport.
    def entra_transport(request: httpx2.Request) -> httpx2.Response:
        if request.url.host != ENTRA_HOST:
            entra.unexpected.append(f"{request.method} {request.url}")
            return httpx2.Response(599, json={"error": "blocked"})
        status, payload = entra.handle(
            request.method, str(request.url), request.content, request.headers.get("authorization", "")
        )
        return httpx2.Response(status, json=payload)

    real_async_client = httpx2.AsyncClient

    class MockedEntraClient(real_async_client):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs.pop("mounts", None)
            kwargs["transport"] = httpx2.MockTransport(entra_transport)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx2, "AsyncClient", MockedEntraClient)

    def entra_httpx(request: httpx.Request) -> httpx.Response:
        status, payload = entra.handle(
            request.method, str(request.url), request.content, request.headers.get("authorization", "")
        )
        return httpx.Response(status, json=payload)

    with respx.mock(assert_all_called=False) as router, TestClient(app, base_url=BASE) as client:
        router.route(host=ENTRA_HOST).mock(side_effect=entra_httpx)
        router.route(host=CANVAS_HOST).mock(side_effect=canvas.handle)
        yield SimpleNamespace(
            client=client, browser=Browser(client, entra), entra=entra, canvas=canvas,
            runtime=runtime, deleted=deleted, mcp=mcp,
        )
    assert entra.unexpected == [], "the app called an endpoint the fake Entra does not serve"
    reset_config()


@pytest.fixture
def enrolled(world: SimpleNamespace) -> SimpleNamespace:
    """A and B enrolled through /account, each with their own Canvas token."""
    for user in (USER_A, USER_B):
        response = world.browser.enroll(user)
        assert response.status_code == 303 and response.headers["location"] == "/account", response.text
    world.canvas.seen.clear()
    return world


# ----------------------------------------------------------------------------- tests


class TestEnrollmentThroughAccount:
    def test_each_user_enrolls_a_different_token_and_it_is_stored_encrypted(self, world):
        for user in (USER_A, USER_B):
            assert world.browser.enroll(user).status_code == 303
        store = world.runtime.store
        stored_a = store.get(TENANT, USER_A.oid)
        stored_b = store.get(TENANT, USER_B.oid)
        assert stored_a is not None and stored_a.api_token == USER_A.canvas_token
        assert stored_b is not None and stored_b.api_token == USER_B.canvas_token
        assert store.count() == 2
        raw = world.runtime.settings.token_db_path.read_bytes()
        assert USER_A.canvas_token.encode() not in raw and USER_B.canvas_token.encode() not in raw
        # The token was checked against the pinned Canvas with the user's own token.
        assert world.canvas.calls_with("/api/v1/users/self") == [USER_A.canvas_token, USER_B.canvas_token]

    def test_the_page_shows_the_enrollment_but_never_the_token(self, enrolled):
        enrolled.browser.account_sign_in(USER_A)
        page = enrolled.client.get("/account")
        assert page.status_code == 200
        assert USER_A.name in page.text
        assert USER_A.canvas_token not in page.text
        assert "no-store" in page.headers["cache-control"]
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]

    def test_enrollment_needs_the_csrf_token_and_a_matching_origin(self, world):
        assert world.browser.account_sign_in(USER_A).status_code == 303
        csrf = world.browser.csrf()
        form = {"canvas_token": USER_A.canvas_token}
        assert world.client.post("/account/token", data={**form, "csrf": "wrong"}, headers=ORIGIN).status_code == 403
        assert world.client.post("/account/token", data={**form, "csrf": csrf}).status_code == 403
        evil = {"Origin": "https://evil.example"}
        assert world.client.post("/account/token", data={**form, "csrf": csrf}, headers=evil).status_code == 403
        assert world.runtime.store.count() == 0
        assert world.canvas.seen == []

    def test_a_token_canvas_rejects_is_not_stored(self, world):
        response = world.browser.enroll(USER_A, canvas_token="not-a-real-canvas-token-0123456789")
        assert response.status_code == 400
        assert world.runtime.store.count() == 0

    def test_users_outside_the_group_or_tenant_cannot_sign_in_to_account(self, world):
        no_role = world.browser.account_sign_in(USER_C)
        assert no_role.status_code == 403
        assert not any(c.startswith("__Host-cmcp_session") for c in no_role.headers.get_list("set-cookie")
                       if "Max-Age=0" not in c)
        other_tenant = world.browser.account_sign_in(USER_D)
        assert other_tenant.status_code in (400, 403)
        assert world.client.get("/account").status_code == 200  # signed-out page, not an error
        assert "Sign in" in world.client.get("/account").text
        assert world.runtime.store.count() == 0


class TestMcpAsTwoUsers:
    def test_a_tool_call_reaches_canvas_with_only_that_users_token(self, enrolled):
        bearer_a = enrolled.browser.bearer_for(USER_A)
        bearer_b = enrolled.browser.bearer_for(USER_B)
        assert bearer_a != bearer_b

        text_a = text_of(call_tool(enrolled.client, bearer_a, "list_courses"))
        assert "ICS 33" in text_a and "MATH 2B" not in text_a
        assert enrolled.canvas.calls_with("/api/v1/courses") == [USER_A.canvas_token]

        text_b = text_of(call_tool(enrolled.client, bearer_b, "list_courses"))
        assert "MATH 2B" in text_b and "ICS 33" not in text_b
        assert enrolled.canvas.calls_with("/api/v1/courses") == [USER_A.canvas_token, USER_B.canvas_token]
        # Neither the FastMCP bearer nor any Entra token ever reached Canvas.
        assert enrolled.canvas.tokens_used() <= set(ENROLLED_TOKENS)
        assert enrolled.entra.unexpected == []

    def test_the_course_cache_and_resolution_do_not_leak_between_users(self, enrolled):
        bearer_a = enrolled.browser.bearer_for(USER_A)
        bearer_b = enrolled.browser.bearer_for(USER_B)
        call_tool(enrolled.client, bearer_a, "list_courses")  # fills A's cache
        enrolled.canvas.seen.clear()

        result = call_tool(enrolled.client, bearer_b, "get_course_details", {"course_identifier": "ICS 33"})
        assert "Intermediate Python" not in text_of(result)
        assert "101" not in text_of(result)
        assert not any(path.startswith("/api/v1/courses/101") for path, _ in enrolled.canvas.seen)
        assert USER_A.canvas_token not in enrolled.canvas.tokens_used()

        # A resolves their own course by code, from their own cache, with their own token.
        enrolled.canvas.seen.clear()
        mine = call_tool(enrolled.client, bearer_a, "get_course_details", {"course_identifier": "ICS 33"})
        assert "Intermediate Python" in text_of(mine)
        assert ("/api/v1/courses/101", USER_A.canvas_token) in enrolled.canvas.seen

    def test_write_confirmation_state_does_not_leak_between_users(self, enrolled):
        bearer_a = enrolled.browser.bearer_for(USER_A)
        bearer_b = enrolled.browser.bearer_for(USER_B)
        # Write tools are off until each user turns them on; this test is about
        # the confirmation state, so both users have switched the widget tool on.
        for user in (USER_A, USER_B):
            enrolled.runtime.store.set_tool_prefs(f"entra:{TENANT}:{user.oid}".lower(), ["delete_widget"])
        preview = text_of(call_tool(enrolled.client, bearer_a, "delete_widget", {"widget_id": "w1"}))
        token = re.search(r"Confirmation token: (\S+)", preview)
        assert token, preview

        stolen = text_of(call_tool(enrolled.client, bearer_b, "delete_widget", {
            "widget_id": "w1", "confirmation_token": token.group(1),
        }))
        assert enrolled.deleted == []
        assert "Deleted widget" not in stolen
        # B's attempt burned the token: even A has to preview again.
        again = text_of(call_tool(enrolled.client, bearer_a, "delete_widget", {
            "widget_id": "w1", "confirmation_token": token.group(1),
        }))
        assert enrolled.deleted == [] and "Deleted widget" not in again

        fresh = text_of(call_tool(enrolled.client, bearer_a, "delete_widget", {"widget_id": "w1"}))
        fresh_token = re.search(r"Confirmation token: (\S+)", fresh)
        assert fresh_token
        done = text_of(call_tool(enrolled.client, bearer_a, "delete_widget", {
            "widget_id": "w1", "confirmation_token": fresh_token.group(1),
        }))
        assert "Deleted widget w1" in done and enrolled.deleted == ["w1"]

    def test_a_write_tool_works_only_after_its_owner_turns_it_on_in_the_browser(self, enrolled):
        bearer_a = enrolled.browser.bearer_for(USER_A)
        bearer_b = enrolled.browser.bearer_for(USER_B)

        def names(bearer: str) -> set[str]:
            return {tool["name"] for tool in result_of(rpc(enrolled.client, bearer, "tools/list"))["tools"]}

        assert "delete_widget" not in names(bearer_a)
        refused = call_tool(enrolled.client, bearer_a, "delete_widget", {"widget_id": "w1"})
        assert refused["isError"] is True
        assert "turned off for your account" in text_of(refused)
        assert "/account" in text_of(refused)

        # The only way to turn it on: the signed-in /account page (session, CSRF, Origin).
        assert enrolled.browser.account_sign_in(USER_A).status_code == 303
        csrf = enrolled.browser.csrf()
        saved = enrolled.client.post(
            "/account/write-tools", data={"csrf": csrf, "tool.delete_widget": "1"},
            headers=ORIGIN, follow_redirects=False,
        )
        assert saved.status_code == 200 and "Write-tool settings saved." in saved.text

        assert "delete_widget" in names(bearer_a)
        assert "Confirmation token" in text_of(call_tool(enrolled.client, bearer_a, "delete_widget", {"widget_id": "w1"}))
        assert "delete_widget" not in names(bearer_b)
        assert call_tool(enrolled.client, bearer_b, "delete_widget", {"widget_id": "w1"})["isError"] is True

        # Turning it off again takes effect at once for the next request.
        off = enrolled.client.post(
            "/account/write-tools", data={"csrf": csrf, "disable_all": "1"},
            headers=ORIGIN, follow_redirects=False,
        )
        assert off.status_code == 200
        assert "delete_widget" not in names(bearer_a)
        assert call_tool(enrolled.client, bearer_a, "delete_widget", {"widget_id": "w1"})["isError"] is True

    def test_the_last_used_time_is_recorded_for_the_caller_only(self, enrolled):
        call_tool(enrolled.client, enrolled.browser.bearer_for(USER_A), "list_courses")
        info_a = enrolled.runtime.store.info(TENANT, USER_A.oid)
        info_b = enrolled.runtime.store.info(TENANT, USER_B.oid)
        assert info_a is not None and info_a.last_used_at is not None
        assert info_b is not None and info_b.last_used_at is None

    def test_a_signed_in_user_without_an_enrolled_token_gets_the_account_hint(self, world):
        bearer = world.browser.bearer_for(USER_A)  # allowed, but not enrolled yet
        tools = result_of(rpc(world.client, bearer, "tools/list"))["tools"]
        assert "list_courses" in {tool["name"] for tool in tools}  # the connector still connects
        result = call_tool(world.client, bearer, "list_courses")
        assert result["isError"] is True
        assert f"{BASE}/account" in text_of(result)
        assert world.canvas.seen == []  # no Canvas call, and no server credential tried

        assert world.browser.enroll(USER_A).status_code == 303  # enrolling fixes it at once
        assert call_tool(world.client, bearer, "list_courses")["isError"] is False

    def test_removing_an_enrollment_stops_tool_calls_until_the_user_enrolls_again(self, enrolled):
        bearer_a = enrolled.browser.bearer_for(USER_A)
        assert call_tool(enrolled.client, bearer_a, "list_courses")["isError"] is False

        assert enrolled.browser.account_sign_in(OWNER).status_code == 303
        admin = enrolled.client.get("/account/admin")
        assert admin.status_code == 200
        assert USER_A.oid in admin.text and USER_B.oid in admin.text
        assert USER_A.canvas_token not in admin.text and USER_B.canvas_token not in admin.text
        revoke = enrolled.client.post("/account/admin/remove", data={
            "csrf": enrolled.browser.csrf("/account/admin"), "tenant_id": TENANT, "object_id": USER_A.oid,
        }, headers=ORIGIN, follow_redirects=False)
        assert revoke.status_code == 303

        result = call_tool(enrolled.client, bearer_a, "list_courses")
        assert result["isError"] is True and f"{BASE}/account" in text_of(result)
        bearer_b = enrolled.browser.bearer_for(USER_B)
        assert call_tool(enrolled.client, bearer_b, "list_courses")["isError"] is False

    def test_disabling_a_user_is_an_access_decision_that_deleting_rows_cannot_undo(self, enrolled):
        """The reported sequence, end to end through the real OAuth, MCP and /account stack."""
        user_a_key = f"entra:{TENANT}:{USER_A.oid}"
        bearer_a = enrolled.browser.bearer_for(USER_A)
        assert call_tool(enrolled.client, bearer_a, "list_courses")["isError"] is False
        # User A has a sealed /account session that is still valid.
        assert enrolled.browser.account_sign_in(USER_A).status_code == 303
        a_session = enrolled.client.cookies.get("__Host-cmcp_session")
        assert a_session

        # The owner disables A and also removes the stored token.
        assert enrolled.browser.account_sign_in(OWNER).status_code == 303
        csrf = enrolled.browser.csrf("/account/admin")
        disable = enrolled.client.post("/account/admin/disable", data={
            "csrf": csrf, "principal_key": user_a_key,
        }, headers=ORIGIN, follow_redirects=False)
        assert disable.status_code == 303
        remove = enrolled.client.post("/account/admin/remove", data={
            "csrf": csrf, "tenant_id": TENANT, "object_id": USER_A.oid,
        }, headers=ORIGIN, follow_redirects=False)
        assert remove.status_code == 303
        assert enrolled.runtime.store.info(user_a_key) is None
        enrolled.canvas.seen.clear()

        # The MCP token A already holds is refused, on every kind of request, at once.
        for method, params in (("tools/call", {"name": "list_courses", "arguments": {}}), ("tools/list", None)):
            refused = rpc(enrolled.client, bearer_a, method, params)
            assert refused.status_code == 403, refused.text
            assert "disabled by an administrator" in refused.json()["error"]
        # A brand-new MCP authorization for A yields a token that is refused too.
        fresh_bearer, _ = enrolled.browser.mcp_authorize(USER_A)
        if fresh_bearer is not None:
            assert rpc(enrolled.client, fresh_bearer, "tools/list").status_code == 403
        assert enrolled.canvas.seen == []

        # The still-valid sealed session cannot put the row back.
        enrolled.browser.fresh_session()
        enrolled.client.cookies.set("__Host-cmcp_session", a_session, domain="canvas.example.test", path="/")
        assert "Sign in with Microsoft" in enrolled.client.get("/account").text
        replay = enrolled.client.post("/account/token", data={
            "csrf": "x", "canvas_token": USER_A.canvas_token,
        }, headers=ORIGIN, follow_redirects=False)
        assert replay.status_code == 303
        assert enrolled.runtime.store.info(user_a_key) is None
        # Signing in again is refused with a clear message, so no new session starts.
        refused_sign_in = enrolled.browser.account_sign_in(USER_A)
        assert refused_sign_in.status_code == 403 and "disabled by an administrator" in refused_sign_in.text

        # B is untouched throughout.
        bearer_b = enrolled.browser.bearer_for(USER_B)
        assert call_tool(enrolled.client, bearer_b, "list_courses")["isError"] is False

        # An owner lifts it: A signs in again (the old session stays dead), enrolls, and the
        # bearer A held all along works again.
        assert enrolled.browser.account_sign_in(OWNER).status_code == 303
        csrf = enrolled.browser.csrf("/account/admin")
        enable = enrolled.client.post("/account/admin/enable", data={
            "csrf": csrf, "principal_key": user_a_key,
        }, headers=ORIGIN, follow_redirects=False)
        assert enable.status_code == 303
        enrolled.browser.fresh_session()
        enrolled.client.cookies.set("__Host-cmcp_session", a_session, domain="canvas.example.test", path="/")
        assert "Sign in with Microsoft" in enrolled.client.get("/account").text
        assert enrolled.browser.enroll(USER_A).status_code == 303
        assert call_tool(enrolled.client, bearer_a, "list_courses")["isError"] is False

    def test_a_user_deleting_their_own_token_may_enroll_again(self, enrolled):
        user_a_key = f"entra:{TENANT}:{USER_A.oid}"
        assert enrolled.browser.account_sign_in(USER_A).status_code == 303
        deleted = enrolled.client.post("/account/token/delete", data={
            "csrf": enrolled.browser.csrf(),
        }, headers=ORIGIN, follow_redirects=False)
        assert deleted.status_code == 303
        assert enrolled.runtime.store.info(user_a_key) is None
        assert not enrolled.runtime.store.get_principal_status(user_a_key).disabled
        assert enrolled.browser.enroll(USER_A).status_code == 303
        assert enrolled.runtime.store.get(TENANT, USER_A.oid) is not None

    def test_a_non_owner_cannot_open_the_admin_page(self, enrolled):
        enrolled.browser.account_sign_in(USER_A)
        assert enrolled.client.get("/account/admin").status_code == 403


class TestRefusedUsers:
    def test_a_user_without_the_role_is_refused_on_every_mcp_request(self, enrolled):
        bearer, response = enrolled.browser.mcp_authorize(USER_C)
        if bearer is None:  # refused while signing in is also a refusal
            assert response.status_code >= 400
        else:
            for method, params in (("tools/list", None), ("tools/call", {"name": "list_courses", "arguments": {}})):
                refused = rpc(enrolled.client, bearer, method, params)
                assert refused.status_code == 403, refused.text
                assert refused.json()["error"]
        assert enrolled.canvas.seen == []

    def test_a_user_from_another_tenant_is_refused(self, enrolled):
        bearer, response = enrolled.browser.mcp_authorize(USER_D)
        if bearer is None:
            assert response.status_code >= 400
        else:
            refused = rpc(enrolled.client, bearer, "tools/call", {"name": "list_courses", "arguments": {}})
            assert refused.status_code in (401, 403), refused.text
        assert enrolled.canvas.seen == []

    def test_a_token_that_entra_signed_for_the_right_issuer_but_another_tenant_is_refused(self, enrolled):
        """tid disagrees with the configured tenant even though signature, issuer and roles pass."""
        forged = EntraUser("Mallory", "ffffffff-0000-4000-8000-00000000000f")
        original = enrolled.entra._base_claims

        def mismatched_tid(user: EntraUser, audience: str) -> dict[str, Any]:
            claims = original(user, audience)
            if user.oid == forged.oid:
                claims["tid"] = OTHER_TENANT
            return claims

        enrolled.entra._base_claims = mismatched_tid  # type: ignore[method-assign]
        bearer, response = enrolled.browser.mcp_authorize(forged)
        assert bearer, response.text
        refused = rpc(enrolled.client, bearer, "tools/call", {"name": "list_courses", "arguments": {}})
        assert refused.status_code == 403
        assert enrolled.canvas.seen == []

    def test_a_bearer_issued_by_entra_itself_is_never_accepted(self, enrolled):
        entra_token = enrolled.entra.access_token(USER_A)
        assert rpc(enrolled.client, entra_token, "tools/list").status_code == 401
        assert rpc(enrolled.client, "garbage.token.value", "tools/list").status_code == 401
        assert enrolled.canvas.seen == []

    def test_no_bearer_gets_a_401_pointing_at_the_resource_metadata(self, world):
        response = rpc(world.client, None, "tools/list")
        assert response.status_code == 401
        assert f'resource_metadata="{BASE}/.well-known/oauth-protected-resource/mcp"' in response.headers["www-authenticate"]

    def test_a_spoofed_easy_auth_header_grants_nothing(self, world):
        response = rpc(world.client, None, "tools/list", **{
            "X-MS-CLIENT-PRINCIPAL-ID": USER_A.oid, "X-Canvas-Token": USER_A.canvas_token,
        })
        assert response.status_code == 401
        assert world.canvas.seen == []


class TestRefreshAndRevocation:
    @staticmethod
    def _refresh(world: SimpleNamespace, refresh_token: str) -> httpx.Response:
        return world.client.post("/token", data={
            "grant_type": "refresh_token", "refresh_token": refresh_token,
            "client_id": world.browser.register(),
        })

    def test_a_connector_keeps_working_across_an_expiry_by_refreshing_through_entra(self, enrolled, monkeypatch):
        bearer, response = enrolled.browser.mcp_authorize(USER_A)
        assert bearer, response.text
        refresh_token = response.json()["refresh_token"]
        assert call_tool(enrolled.client, bearer, "list_courses")["isError"] is False

        real_time = time.time
        monkeypatch.setattr(time, "time", lambda: real_time() + 3700)  # past the access-token lifetime
        assert rpc(enrolled.client, bearer, "tools/list").status_code == 401

        refreshed = self._refresh(enrolled, refresh_token)
        assert refreshed.status_code == 200, refreshed.text
        assert any(r.get("grant_type") == "refresh_token" for r in enrolled.entra.token_requests)
        new_bearer = refreshed.json()["access_token"]
        enrolled.canvas.seen.clear()
        assert "ICS 33" in text_of(call_tool(enrolled.client, new_bearer, "list_courses"))
        assert enrolled.canvas.calls_with("/api/v1/courses") == [USER_A.canvas_token]

    def test_once_entra_refuses_the_refresh_the_user_is_cut_off(self, enrolled, monkeypatch):
        bearer, response = enrolled.browser.mcp_authorize(USER_A)
        assert bearer, response.text
        refresh_token = response.json()["refresh_token"]

        enrolled.entra.refresh_tokens.clear()  # user removed from the group / sessions revoked
        real_time = time.time
        monkeypatch.setattr(time, "time", lambda: real_time() + 3700)
        refreshed = self._refresh(enrolled, refresh_token)
        assert refreshed.status_code >= 400
        assert rpc(enrolled.client, bearer, "tools/list").status_code == 401
        assert enrolled.canvas.seen == []


class TestHostProtection:
    def test_a_foreign_host_header_is_refused(self, world):
        response = world.client.post("/mcp", json={}, headers={"Host": "evil.example"})
        assert response.status_code == 421

    def test_healthz_is_open_and_says_nothing(self, world):
        response = world.client.get("/healthz")
        assert response.status_code == 200 and response.text == "ok"


# ---------------------------------------------------------------- unchanged modes


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
        assert legacy.canvas.calls_with("/api/v1/courses") == [USER_A.canvas_token, USER_B.canvas_token]

    def test_a_request_without_a_token_is_refused(self, legacy):
        response = legacy.client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={
            "Accept": "application/json, text/event-stream",
        })
        assert response.status_code == 401
        assert legacy.canvas.seen == []

    def test_header_tokens_no_longer_share_a_course_cache(self, legacy):
        call_tool_headers(legacy.client, USER_A.canvas_token, "list_courses")
        legacy.canvas.seen.clear()
        result = call_tool_headers(legacy.client, USER_B.canvas_token, "get_course_details", {"course_identifier": "ICS 33"})
        assert "Intermediate Python" not in text_of(result)
        assert USER_A.canvas_token not in legacy.canvas.tokens_used()


def call_tool_headers(client: TestClient, canvas_token: str, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    response = client.post("/mcp", json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments or {}},
    }, headers={
        "Accept": "application/json, text/event-stream", "Content-Type": "application/json",
        "X-Canvas-Token": canvas_token,
    })
    return result_of(response)


class TestStdioModeUnchanged:
    async def test_the_server_token_is_used_and_state_is_local(self, canvas_only, monkeypatch):
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
            assert "ICS 33" in "".join(getattr(block, "text", "") for block in result.content)
            assert canvas_only.calls_with("/api/v1/courses") == [USER_A.canvas_token]
            assert current_principal_key() == "local"
            assert is_http_request_active() is False
            assert current_cache_state().code_to_id == {"ICS 33": "101"}  # the single local state
        finally:
            reset_course_cache()
            await canvas_client.cleanup_http_client()
            reset_config()


class TestAccountHelperSanity:
    """Guards the test helpers themselves, so a silent no-op cannot make the suite pass."""

    def test_the_fake_entra_tokens_verify_only_with_its_own_key(self, world):
        other = RSAKey.generate_key(2048)
        forged = jwt.encode({"alg": "RS256"}, {"sub": "x"}, other)
        assert rpc(world.client, forged, "tools/list").status_code == 401

    def test_pending_callbacks_are_single_use(self, world):
        signed_in = world.browser.account_sign_in(USER_A)
        assert signed_in.status_code == 303
        assert world.entra.grants == {}  # the code was consumed by the token endpoint
