"""Tests for the /account browser pages (all identity and network I/O faked)."""

from __future__ import annotations

import base64
import hashlib
import pathlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from canvas_mcp.core.selfhost import account_web
from canvas_mcp.core.selfhost.account_web import (
    ACCOUNT_CALLBACK_PATH,
    ACCOUNT_PATH,
    LOGIN_COOKIE,
    SESSION_COOKIE,
    AccountConfig,
    CanvasCheckError,
    CanvasIdentity,
    build_account_routes,
    register_account_routes,
)
from canvas_mcp.core.selfhost.token_store import Keyring, TokenStore

BASE = "https://canvas.example.test"
TID = "11111111-2222-3333-4444-555555555555"
CLIENT_ID = "99999999-8888-7777-6666-555555555555"
CLIENT_SECRET = "client-secret-value-0123456789"
OID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID_2 = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
OID_OWNER = "cccccccc-dddd-eeee-ffff-000000000000"
CANVAS_TOKEN = "7~" + "T" * 62
SESSION_SECRET = bytes(range(32))
ORIGIN = {"Origin": BASE}


@dataclass(frozen=True)
class FakePrincipal:
    tenant_id: str
    object_id: str
    display_name: str
    upn: str
    is_owner: bool


def fake_authorize(claims: Mapping[str, Any]) -> tuple[FakePrincipal | None, str]:
    roles = claims.get("roles") or []
    if "Canvas.Owner" in roles or "Canvas.User" in roles:
        return (
            FakePrincipal(
                tenant_id=claims["tid"],
                object_id=claims["oid"],
                display_name=claims.get("name", ""),
                upn=claims.get("preferred_username", ""),
                is_owner="Canvas.Owner" in roles,
            ),
            "",
        )
    return None, "Your account is <b>not assigned</b> to this app."


@dataclass
class Harness:
    client: TestClient
    store: TokenStore
    now: float = 1_800_000_000.0
    claims: dict[str, Any] = field(default_factory=dict)
    verifier_result: str = "claims"  # "claims" | "none" | "raise"
    token_requests: list[httpx.Request] = field(default_factory=list)
    token_response: Callable[[httpx.Request], httpx.Response] = field(
        default=lambda request: httpx.Response(200, json={"id_token": "fake-id-token"})
    )
    whoami_calls: list[str] = field(default_factory=list)
    whoami_result: CanvasIdentity | CanvasCheckError = field(
        default_factory=lambda: CanvasIdentity("42", "Ada Canvas")
    )

    def clock(self) -> float:
        return self.now


def make_cfg(**kw: Any) -> AccountConfig:
    args: dict[str, Any] = {
        "public_base_url": BASE,
        "tenant_id": TID,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "session_secret": SESSION_SECRET,
        "canvas_api_url": "https://canvas.example.test/api/v1",
    }
    args.update(kw)
    return AccountConfig(**args)


@pytest.fixture
def h(tmp_path: pathlib.Path) -> Harness:
    keyring = Keyring.parse("k1:" + base64.b64encode(b"\x01" * 32).decode())
    store = TokenStore(tmp_path / "tokens.sqlite3", keyring, clock=lambda: 1_800_000_000)
    store.initialize()
    harness = Harness(client=None, store=store)  # type: ignore[arg-type]

    async def verify(_token: str) -> Mapping[str, Any] | None:
        if harness.verifier_result == "raise":
            raise RuntimeError("jwks exploded")
        if harness.verifier_result == "none":
            return None
        return dict(harness.claims)

    async def whoami(token: str) -> CanvasIdentity:
        harness.whoami_calls.append(token)
        if isinstance(harness.whoami_result, CanvasCheckError):
            raise harness.whoami_result
        return harness.whoami_result

    def handler(request: httpx.Request) -> httpx.Response:
        harness.token_requests.append(request)
        return harness.token_response(request)

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    routes = build_account_routes(
        make_cfg(),
        store,
        fake_authorize,
        id_token_verifier=verify,
        canvas_whoami=whoami,
        http_client_factory=factory,
        clock=harness.clock,
    )
    harness.client = TestClient(
        Starlette(routes=routes), base_url=BASE, follow_redirects=False
    )
    return harness


def login_params(h: Harness) -> dict[str, str]:
    response = h.client.get("/account/login")
    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    return {k: v[0] for k, v in query.items()}


def sign_in(
    h: Harness,
    *,
    oid: str = OID,
    name: str = "Ada Lovelace",
    upn: str = "ada@example.test",
    roles: tuple[str, ...] = ("Canvas.User",),
    **overrides: Any,
) -> httpx.Response:
    params = login_params(h)
    h.claims = {
        "tid": TID,
        "oid": oid,
        "name": name,
        "preferred_username": upn,
        "roles": list(roles),
        "nonce": params["nonce"],
        "iat": int(h.now),
        "exp": int(h.now) + 3600,
        "aud": CLIENT_ID,
    }
    h.claims.update(overrides)
    return h.client.get(
        ACCOUNT_CALLBACK_PATH, params={"code": "auth-code", "state": params["state"]}
    )


def csrf_of(h: Harness) -> str:
    page = h.client.get(ACCOUNT_PATH)
    assert page.status_code == 200
    match = re.search(r'name="csrf" value="([^"]+)"', page.text)
    assert match, "page has no csrf field (not signed in?)"
    return match.group(1)


def post_form(
    h: Harness,
    path: str,
    fields: dict[str, str],
    *,
    origin: str | None = BASE,
    content_type: str = "application/x-www-form-urlencoded",
) -> httpx.Response:
    headers = {"Content-Type": content_type}
    if origin is not None:
        headers["Origin"] = origin
    return h.client.post(path, data=fields, headers=headers)


def set_cookie_headers(response: httpx.Response) -> list[str]:
    return response.headers.get_list("set-cookie")


def cookie_line(response: httpx.Response, name: str) -> str:
    for line in set_cookie_headers(response):
        if line.startswith(name + "="):
            return line
    raise AssertionError(f"no Set-Cookie for {name}")


def assert_security_headers(response: httpx.Response) -> None:
    headers = response.headers
    assert headers["cache-control"] == "no-store"
    assert headers["pragma"] == "no-cache"
    assert headers["content-security-policy"] == (
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert headers["cross-origin-resource-policy"] == "same-origin"
    assert headers["content-type"] == "text/html; charset=utf-8"


# -- signed-out page and headers ---------------------------------------------


class TestSignedOut:
    def test_page_and_security_headers(self, h: Harness) -> None:
        response = h.client.get(ACCOUNT_PATH)
        assert response.status_code == 200
        assert_security_headers(response)
        assert 'href="/account/login"' in response.text
        assert f"{BASE}/mcp" in response.text
        assert "<script" not in response.text.lower()
        assert 'name="canvas_token"' not in response.text

    def test_every_kind_of_response_carries_the_headers(self, h: Harness) -> None:
        responses = [
            h.client.get(ACCOUNT_PATH),
            h.client.get("/account/login"),  # 302
            h.client.get(ACCOUNT_CALLBACK_PATH),  # 400
            h.client.post("/account/token", headers=ORIGIN),  # 303 (no session)
            h.client.get("/account/admin"),  # 403
            h.client.put(ACCOUNT_PATH),  # 405
            sign_in(h),  # 303 with cookies
        ]
        assert {r.status_code for r in responses} >= {200, 302, 303, 400, 403, 405}
        for response in responses:
            assert_security_headers(response)

    @pytest.mark.parametrize(
        "path",
        [
            "/account",
            "/account/login",
            "/account/callback",
            "/account/token",
            "/account/token/delete",
            "/account/logout",
            "/account/admin",
            "/account/admin/revoke",
        ],
    )
    def test_head_and_put_are_405(self, h: Harness, path: str) -> None:
        for method in ("HEAD", "PUT", "DELETE", "PATCH"):
            response = h.client.request(method, path)
            assert response.status_code == 405, (method, path)
            assert response.headers["cache-control"] == "no-store"
        # The wrong-but-supported method (GET on a POST-only path and the
        # reverse) is refused too.
        assert h.client.get("/account/token").status_code == 405
        assert h.client.post("/account", headers=ORIGIN).status_code == 405
        assert h.client.get("/account/token").headers["allow"] == "POST"


# -- login redirect ----------------------------------------------------------


class TestLogin:
    def test_redirect_parameters(self, h: Harness) -> None:
        response = h.client.get("/account/login")
        assert response.status_code == 302
        location = urlparse(response.headers["location"])
        assert location.scheme == "https"
        assert location.netloc == "login.microsoftonline.com"
        assert location.path == f"/{TID}/oauth2/v2.0/authorize"
        q = {k: v[0] for k, v in parse_qs(location.query).items()}
        assert q["client_id"] == CLIENT_ID
        assert q["response_type"] == "code"
        assert q["redirect_uri"] == f"{BASE}/account/callback"
        assert q["response_mode"] == "query"
        assert q["scope"] == "openid profile"
        assert q["code_challenge_method"] == "S256"
        assert q["prompt"] == "select_account"
        assert len(q["state"]) >= 43 and len(q["nonce"]) >= 43
        assert q["state"] != q["nonce"]
        assert len(q["code_challenge"]) == 43  # sha256, base64url, no padding
        assert "client_secret" not in location.query

    def test_login_cookie_flags_and_pkce_binding(self, h: Harness) -> None:
        response = h.client.get("/account/login")
        params = {
            k: v[0]
            for k, v in parse_qs(urlparse(response.headers["location"]).query).items()
        }
        line = cookie_line(response, LOGIN_COOKIE)
        lowered = line.lower()
        assert line.startswith("__Host-cmcp_login=v1.")
        assert "secure" in lowered and "httponly" in lowered
        assert "samesite=lax" in lowered and "path=/" in lowered
        assert "max-age=600" in lowered
        assert "domain" not in lowered
        # The sealed transaction matches the redirect, and its verifier hashes
        # to the challenge sent to Entra (S256).
        codec = account_web._CookieCodec(SESSION_SECRET)
        opened = codec.unseal(LOGIN_COOKIE, h.client.cookies.get(LOGIN_COOKIE))
        assert opened is not None
        assert opened["state"] == params["state"]
        assert opened["nonce"] == params["nonce"]
        assert 43 <= len(opened["verifier"]) <= 128
        digest = hashlib.sha256(opened["verifier"].encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        assert challenge == params["code_challenge"]

    def test_each_login_gets_fresh_secrets(self, h: Harness) -> None:
        first, second = login_params(h), login_params(h)
        assert first["state"] != second["state"]
        assert first["nonce"] != second["nonce"]
        assert first["code_challenge"] != second["code_challenge"]


# -- callback ----------------------------------------------------------------


class TestCallback:
    def test_without_login_cookie_is_400(self, h: Harness) -> None:
        response = h.client.get(ACCOUNT_CALLBACK_PATH, params={"code": "x", "state": "y"})
        assert response.status_code == 400
        assert h.token_requests == []
        assert SESSION_COOKIE not in "".join(set_cookie_headers(response))

    def test_wrong_state_is_400_and_login_cookie_cleared(self, h: Harness) -> None:
        login_params(h)
        response = h.client.get(
            ACCOUNT_CALLBACK_PATH, params={"code": "x", "state": "not-the-state"}
        )
        assert response.status_code == 400
        assert h.token_requests == []
        line = cookie_line(response, LOGIN_COOKIE).lower()
        assert "max-age=0" in line
        # The transaction is single use: a replay with the right state fails.
        assert h.client.cookies.get(LOGIN_COOKIE) is None

    def test_missing_state_param_is_400(self, h: Harness) -> None:
        login_params(h)
        assert h.client.get(ACCOUNT_CALLBACK_PATH, params={"code": "x"}).status_code == 400

    def test_expired_login_transaction_is_400(self, h: Harness) -> None:
        params = login_params(h)
        h.now += 601
        response = h.client.get(
            ACCOUNT_CALLBACK_PATH, params={"code": "x", "state": params["state"]}
        )
        assert response.status_code == 400

    def test_access_denied_never_reflects_error_description(self, h: Harness) -> None:
        params = login_params(h)
        evil = "<script>alert(1)</script> AADSTS50105 secret-detail"
        response = h.client.get(
            ACCOUNT_CALLBACK_PATH,
            params={
                "state": params["state"],
                "error": "access_denied",
                "error_description": evil,
            },
        )
        assert response.status_code == 403
        assert_security_headers(response)
        assert "access_denied" in response.text
        assert "<script>" not in response.text
        assert "alert(1)" not in response.text
        assert "secret-detail" not in response.text
        assert "max-age=0" in cookie_line(response, LOGIN_COOKIE).lower()
        assert h.token_requests == []

    def test_odd_error_code_is_not_shown(self, h: Harness) -> None:
        params = login_params(h)
        response = h.client.get(
            ACCOUNT_CALLBACK_PATH,
            params={"state": params["state"], "error": "<b>Evil</b>"},
        )
        assert response.status_code == 403
        assert "Evil" not in response.text and "<b>" not in response.text

    def test_missing_code_is_400(self, h: Harness) -> None:
        params = login_params(h)
        response = h.client.get(ACCOUNT_CALLBACK_PATH, params={"state": params["state"]})
        assert response.status_code == 400

    def test_token_endpoint_failure_is_502_with_fixed_text(self, h: Harness) -> None:
        h.token_response = lambda r: httpx.Response(
            400, json={"error_description": "AADSTS-LEAK-DETAIL"}
        )
        response = sign_in(h)
        assert response.status_code == 502
        assert "AADSTS-LEAK-DETAIL" not in response.text
        assert SESSION_COOKIE not in "".join(set_cookie_headers(response))

    def test_missing_id_token_is_502(self, h: Harness) -> None:
        h.token_response = lambda r: httpx.Response(200, json={"access_token": "a"})
        assert sign_in(h).status_code == 502

    def test_non_json_token_response_is_502(self, h: Harness) -> None:
        h.token_response = lambda r: httpx.Response(200, content=b"<html>")
        assert sign_in(h).status_code == 502

    def test_network_error_is_502(self, h: Harness) -> None:
        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down")

        h.token_response = boom
        assert sign_in(h).status_code == 502

    def test_token_request_is_correct(self, h: Harness) -> None:
        params = login_params(h)
        h.claims = {
            "tid": TID,
            "oid": OID,
            "roles": ["Canvas.User"],
            "nonce": params["nonce"],
            "iat": int(h.now),
            "exp": int(h.now) + 3600,
        }
        h.client.get(
            ACCOUNT_CALLBACK_PATH, params={"code": "the-code", "state": params["state"]}
        )
        (request,) = h.token_requests
        assert request.method == "POST"
        assert str(request.url) == (
            f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token"
        )
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        assert form["client_id"] == CLIENT_ID
        assert form["client_secret"] == CLIENT_SECRET
        assert form["grant_type"] == "authorization_code"
        assert form["code"] == "the-code"
        assert form["redirect_uri"] == f"{BASE}/account/callback"
        assert form["scope"] == "openid profile"
        digest = hashlib.sha256(form["code_verifier"].encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        assert challenge == params["code_challenge"]

    def test_unverifiable_id_token_is_400(self, h: Harness) -> None:
        h.verifier_result = "none"
        response = sign_in(h)
        assert response.status_code == 400
        assert SESSION_COOKIE not in "".join(set_cookie_headers(response))

    def test_verifier_exception_is_400(self, h: Harness) -> None:
        h.verifier_result = "raise"
        response = sign_in(h)
        assert response.status_code == 400
        assert "jwks exploded" not in response.text

    def test_nonce_mismatch_is_400(self, h: Harness) -> None:
        response = sign_in(h, nonce="some-other-nonce")
        assert response.status_code == 400
        assert SESSION_COOKIE not in "".join(set_cookie_headers(response))

    def test_missing_nonce_is_400(self, h: Harness) -> None:
        response = sign_in(h, nonce=None)
        assert response.status_code == 400

    def test_wrong_tenant_is_403(self, h: Harness) -> None:
        response = sign_in(h, tid="deadbeef-0000-0000-0000-000000000000")
        assert response.status_code == 403
        assert SESSION_COOKIE not in "".join(set_cookie_headers(response))

    @pytest.mark.parametrize("delta", [-601, 601])
    def test_iat_outside_window_is_400(self, h: Harness, delta: int) -> None:
        response = sign_in(h, iat=int(h.now) + delta)
        assert response.status_code == 400

    def test_iat_inside_window_is_accepted(self, h: Harness) -> None:
        assert sign_in(h, iat=int(h.now) - 590).status_code == 303

    def test_expired_or_missing_exp_is_400(self, h: Harness) -> None:
        assert sign_in(h, exp=int(h.now) - 1).status_code == 400
        assert sign_in(h, exp=None).status_code == 400

    def test_authorize_denial_is_403_without_session(self, h: Harness) -> None:
        response = sign_in(h, roles=())
        assert response.status_code == 403
        # the (escaped) denial message is shown
        assert "&lt;b&gt;not assigned&lt;/b&gt;" in response.text
        assert "<b>not assigned</b>" not in response.text
        assert SESSION_COOKIE not in "".join(set_cookie_headers(response))
        assert h.client.get(ACCOUNT_PATH).text.count("Sign in with Microsoft") >= 1

    def test_principal_for_another_tenant_is_refused(self, h: Harness) -> None:
        def sneaky(claims: Mapping[str, Any]) -> tuple[FakePrincipal | None, str]:
            return FakePrincipal("00000000-0000-0000-0000-000000000000", OID, "x", "x", False), ""

        # Rebuild the app with the sneaky authorizer, reusing the harness fakes.
        async def verify(_t: str) -> Mapping[str, Any] | None:
            return dict(h.claims)

        routes = build_account_routes(
            make_cfg(), h.store, sneaky, id_token_verifier=verify,
            http_client_factory=lambda: httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda r: httpx.Response(200, json={"id_token": "x"})
                )
            ),
            clock=h.clock,
        )
        client = TestClient(Starlette(routes=routes), base_url=BASE, follow_redirects=False)
        location = client.get("/account/login").headers["location"]
        q = parse_qs(urlparse(location).query)
        h.claims = {
            "tid": TID, "oid": OID, "nonce": q["nonce"][0],
            "iat": int(h.now), "exp": int(h.now) + 60,
        }
        response = client.get(
            ACCOUNT_CALLBACK_PATH, params={"code": "c", "state": q["state"][0]}
        )
        assert response.status_code == 403
        assert SESSION_COOKIE not in "".join(set_cookie_headers(response))

    def test_happy_path(self, h: Harness) -> None:
        response = sign_in(h, name="<script>alert(1)</script>")
        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        line = cookie_line(response, SESSION_COOKIE)
        lowered = line.lower()
        assert line.startswith("__Host-cmcp_session=v1.")
        assert "secure" in lowered and "httponly" in lowered
        assert "samesite=lax" in lowered and "path=/" in lowered
        assert "max-age=900" in lowered and "domain" not in lowered
        assert "max-age=0" in cookie_line(response, LOGIN_COOKIE).lower()

        page = h.client.get(ACCOUNT_PATH)
        assert page.status_code == 200
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
        assert "<script>alert(1)" not in page.text
        assert "ada@example.test" in page.text
        assert 'type="password"' in page.text
        assert 'autocomplete="off"' in page.text and 'spellcheck="false"' in page.text
        assert "+ New Access Token" in page.text or "New Access Token" in page.text
        assert "Claude MCP" in page.text
        assert "Never paste the token into Claude" in page.text
        assert f"{BASE}/mcp" in page.text
        assert "/account/admin" not in page.text  # not an owner

    def test_session_cookie_does_not_contain_identity_in_clear(self, h: Harness) -> None:
        sign_in(h, upn="visible-check@example.test")
        raw = h.client.cookies.get(SESSION_COOKIE) or ""
        assert "visible-check" not in raw and OID not in raw
        padded = raw[3:] + "=" * (-len(raw[3:]) % 4)
        assert b"visible-check" not in base64.urlsafe_b64decode(padded)


# -- session handling --------------------------------------------------------


class TestSession:
    def test_tampered_cookie_is_signed_out(self, h: Harness) -> None:
        sign_in(h)
        good = h.client.cookies.get(SESSION_COOKIE)
        assert good
        flipped = good[:-2] + ("AA" if good[-2:] != "AA" else "BB")
        h.client.cookies.set(SESSION_COOKIE, flipped, domain="canvas.example.test", path="/")
        assert "Sign in with Microsoft" in h.client.get(ACCOUNT_PATH).text

    def test_garbage_cookie_is_signed_out(self, h: Harness) -> None:
        for value in ("", "v1.", "v1.!!!", "v2.abcd", "plain", "v1." + "A" * 10):
            h.client.cookies.set(SESSION_COOKIE, value, domain="canvas.example.test", path="/")
            response = h.client.get(ACCOUNT_PATH)
            assert response.status_code == 200
            assert "Sign in with Microsoft" in response.text

    def test_cookie_sealed_with_another_secret_is_signed_out(self, h: Harness) -> None:
        other = account_web._CookieCodec(b"\xff" * 32)
        forged = other.seal(
            SESSION_COOKIE,
            {
                "v": 1, "tid": TID, "oid": OID, "name": "x", "upn": "x",
                "owner": True, "iat": int(h.now), "exp": int(h.now) + 600, "csrf": "c",
            },
        )
        h.client.cookies.set(SESSION_COOKIE, forged, domain="canvas.example.test", path="/")
        assert "Sign in with Microsoft" in h.client.get(ACCOUNT_PATH).text

    def test_cookie_for_another_cookie_name_is_rejected(self, h: Harness) -> None:
        # A sealed login cookie cannot be replayed as a session (AAD = name).
        sign_in(h)
        params = login_params(h)
        login_value = h.client.cookies.get(LOGIN_COOKIE)
        assert login_value and params
        h.client.cookies.set(SESSION_COOKIE, login_value, domain="canvas.example.test", path="/")
        assert "Sign in with Microsoft" in h.client.get(ACCOUNT_PATH).text

    def test_expiry_is_enforced_server_side(self, h: Harness) -> None:
        sign_in(h)
        assert "Sign out" in h.client.get(ACCOUNT_PATH).text
        h.now += 899
        assert "Sign out" in h.client.get(ACCOUNT_PATH).text
        h.now += 2  # past exp; the browser would still send the cookie
        response = h.client.get(ACCOUNT_PATH)
        assert "Sign in with Microsoft" in response.text
        assert "Sign out" not in response.text
        assert h.client.post("/account/token", data={"csrf": "x"}, headers=ORIGIN).status_code == 303

    def test_custom_ttl_sets_cookie_and_expiry(self, h: Harness) -> None:
        async def verify(_t: str) -> Mapping[str, Any] | None:
            return dict(h.claims)

        routes = build_account_routes(
            make_cfg(session_ttl_seconds=120), h.store, fake_authorize,
            id_token_verifier=verify,
            http_client_factory=lambda: httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda r: httpx.Response(200, json={"id_token": "x"})
                )
            ),
            clock=h.clock,
        )
        client = TestClient(Starlette(routes=routes), base_url=BASE, follow_redirects=False)
        q = parse_qs(urlparse(client.get("/account/login").headers["location"]).query)
        h.claims = {
            "tid": TID, "oid": OID, "roles": ["Canvas.User"], "nonce": q["nonce"][0],
            "iat": int(h.now), "exp": int(h.now) + 3600,
        }
        response = client.get(
            ACCOUNT_CALLBACK_PATH, params={"code": "c", "state": q["state"][0]}
        )
        assert "max-age=120" in cookie_line(response, SESSION_COOKIE).lower()
        h.now += 121
        assert "Sign in with Microsoft" in client.get(ACCOUNT_PATH).text


# -- POST /account/token -----------------------------------------------------


class TestSaveToken:
    @pytest.fixture
    def signed_in(self, h: Harness) -> Harness:
        assert sign_in(h).status_code == 303
        return h

    def test_missing_csrf_is_403(self, signed_in: Harness) -> None:
        response = post_form(signed_in, "/account/token", {"canvas_token": CANVAS_TOKEN})
        assert response.status_code == 403
        assert signed_in.store.count() == 0 and signed_in.whoami_calls == []

    def test_wrong_csrf_is_403(self, signed_in: Harness) -> None:
        csrf_of(signed_in)
        response = post_form(
            signed_in, "/account/token", {"csrf": "nope", "canvas_token": CANVAS_TOKEN}
        )
        assert response.status_code == 403 and signed_in.store.count() == 0

    def test_wrong_origin_is_403(self, signed_in: Harness) -> None:
        csrf = csrf_of(signed_in)
        for origin in ("https://evil.example", BASE + ".evil.example", "null", BASE + "/"):
            response = post_form(
                signed_in, "/account/token",
                {"csrf": csrf, "canvas_token": CANVAS_TOKEN}, origin=origin,
            )
            assert response.status_code == 403, origin
        assert signed_in.store.count() == 0

    def test_missing_origin_is_403(self, signed_in: Harness) -> None:
        csrf = csrf_of(signed_in)
        response = post_form(
            signed_in, "/account/token",
            {"csrf": csrf, "canvas_token": CANVAS_TOKEN}, origin=None,
        )
        assert response.status_code == 403 and signed_in.store.count() == 0

    def test_without_session_redirects_to_account(self, h: Harness) -> None:
        response = post_form(h, "/account/token", {"csrf": "x", "canvas_token": CANVAS_TOKEN})
        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        assert h.store.count() == 0

    def test_oversized_body_is_413(self, signed_in: Harness) -> None:
        csrf = csrf_of(signed_in)
        response = post_form(
            signed_in, "/account/token",
            {"csrf": csrf, "canvas_token": "a" * 9000},
        )
        assert response.status_code == 413
        assert signed_in.store.count() == 0 and signed_in.whoami_calls == []

    def test_oversized_streamed_body_without_length_is_413(
        self, signed_in: Harness
    ) -> None:
        csrf = csrf_of(signed_in)

        def chunks():  # no Content-Length: the stream itself must be capped
            yield f"csrf={csrf}&canvas_token=".encode()
            for _ in range(10):
                yield b"a" * 1000

        response = signed_in.client.post(
            "/account/token", content=chunks(),
            headers={"Content-Type": "application/x-www-form-urlencoded", **ORIGIN},
        )
        assert response.status_code == 413 and signed_in.store.count() == 0

    def test_body_at_the_limit_is_read(self, signed_in: Harness) -> None:
        csrf = csrf_of(signed_in)
        padding = "p=" + "a" * (8192 - len(f"csrf={csrf}&") - 2)
        body = f"csrf={csrf}&{padding}"
        assert len(body) == 8192
        response = signed_in.client.post(
            "/account/token", content=body,
            headers={"Content-Type": "application/x-www-form-urlencoded", **ORIGIN},
        )
        assert response.status_code == 400  # read fine, token missing

    def test_wrong_content_type_is_415(self, signed_in: Harness) -> None:
        csrf = csrf_of(signed_in)
        for ctype in ("application/json", "text/plain", "multipart/form-data; boundary=x"):
            response = signed_in.client.post(
                "/account/token",
                content=f"csrf={csrf}&canvas_token={CANVAS_TOKEN}",
                headers={"Content-Type": ctype, **ORIGIN},
            )
            assert response.status_code == 415, ctype
        assert signed_in.store.count() == 0

    def test_content_type_with_charset_is_accepted(self, signed_in: Harness) -> None:
        csrf = csrf_of(signed_in)
        response = post_form(
            signed_in, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN},
            content_type="application/x-www-form-urlencoded; charset=UTF-8",
        )
        assert response.status_code == 303

    def test_too_many_fields_is_400(self, signed_in: Harness) -> None:
        csrf = csrf_of(signed_in)
        fields = {f"f{i}": "1" for i in range(12)}
        fields["csrf"] = csrf
        assert post_form(signed_in, "/account/token", fields).status_code == 400

    @pytest.mark.parametrize(
        "bad",
        ["", "short", "a" * 19, "a" * 513, "tok en" + "a" * 30, "toké" + "a" * 30,
         "a" * 20 + "<script>", "a" * 20 + "%00"],
    )
    def test_bad_format_is_400_and_store_untouched(
        self, signed_in: Harness, bad: str
    ) -> None:
        csrf = csrf_of(signed_in)
        response = post_form(signed_in, "/account/token", {"csrf": csrf, "canvas_token": bad})
        assert response.status_code == 400
        assert signed_in.store.count() == 0 and signed_in.whoami_calls == []
        assert bad not in response.text or bad == ""

    def test_surrounding_whitespace_is_stripped(self, signed_in: Harness) -> None:
        csrf = csrf_of(signed_in)
        response = post_form(
            signed_in, "/account/token",
            {"csrf": csrf, "canvas_token": f"  {CANVAS_TOKEN}\n"},
        )
        assert response.status_code == 303
        assert signed_in.whoami_calls == [CANVAS_TOKEN]

    def test_canvas_rejects_token_is_400(self, signed_in: Harness) -> None:
        signed_in.whoami_result = CanvasCheckError("invalid")
        csrf = csrf_of(signed_in)
        response = post_form(
            signed_in, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN}
        )
        assert response.status_code == 400
        assert "Canvas rejected this token" in response.text
        assert CANVAS_TOKEN not in response.text
        assert signed_in.store.count() == 0

    def test_canvas_unavailable_is_503(self, signed_in: Harness) -> None:
        signed_in.whoami_result = CanvasCheckError("unavailable")
        csrf = csrf_of(signed_in)
        response = post_form(
            signed_in, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN}
        )
        assert response.status_code == 503
        assert CANVAS_TOKEN not in response.text
        assert signed_in.store.count() == 0

    def test_success_stores_token_and_never_echoes_it(self, signed_in: Harness) -> None:
        csrf = csrf_of(signed_in)
        response = post_form(
            signed_in, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN}
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        assert CANVAS_TOKEN not in response.text
        assert CANVAS_TOKEN not in str(response.headers)
        stored = signed_in.store.get(TID, OID)
        assert stored is not None
        assert stored.api_token == CANVAS_TOKEN
        assert stored.canvas_user_id == "42"
        assert stored.canvas_user_name == "Ada Canvas"
        assert stored.entra_display_name == "Ada Lovelace"
        assert stored.entra_upn == "ada@example.test"
        page = signed_in.client.get(ACCOUNT_PATH)
        assert "Ada Canvas" in page.text and "id 42" in page.text
        assert "2027-01-15T08:00:00Z" in page.text  # created, ISO 8601 UTC
        assert CANVAS_TOKEN not in page.text
        for call in signed_in.client.cookies.jar:
            assert CANVAS_TOKEN not in (call.value or "")

    def test_replacing_a_token_updates_the_row(self, signed_in: Harness) -> None:
        csrf = csrf_of(signed_in)
        post_form(signed_in, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN})
        signed_in.now += 60
        newer = "8~" + "N" * 62
        post_form(signed_in, "/account/token", {"csrf": csrf, "canvas_token": newer})
        stored = signed_in.store.get(TID, OID)
        assert stored is not None and stored.api_token == newer
        assert signed_in.store.count() == 1

    def test_eleventh_attempt_is_429(self, signed_in: Harness) -> None:
        csrf = csrf_of(signed_in)
        for _ in range(10):
            response = post_form(
                signed_in, "/account/token", {"csrf": csrf, "canvas_token": "bad"}
            )
            assert response.status_code == 400
        response = post_form(
            signed_in, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN}
        )
        assert response.status_code == 429
        assert signed_in.whoami_calls == [] and signed_in.store.count() == 0
        # The window slides: after 10 minutes (inside the 15 minute session)
        # the user may try again.
        signed_in.now += 601
        csrf = csrf_of(signed_in)
        response = post_form(
            signed_in, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN}
        )
        assert response.status_code == 303

    def test_rate_limit_is_per_user(self, h: Harness) -> None:
        sign_in(h)
        csrf = csrf_of(h)
        for _ in range(10):
            post_form(h, "/account/token", {"csrf": csrf, "canvas_token": "bad"})
        assert post_form(h, "/account/token", {"csrf": csrf, "canvas_token": "bad"}).status_code == 429
        # a different user signs in on the same client
        sign_in(h, oid=OID_2, upn="bob@example.test", name="Bob")
        csrf2 = csrf_of(h)
        response = post_form(h, "/account/token", {"csrf": csrf2, "canvas_token": "bad"})
        assert response.status_code == 400

    def test_csrf_of_one_session_is_not_valid_for_another(self, h: Harness) -> None:
        sign_in(h)
        csrf_a = csrf_of(h)
        sign_in(h, oid=OID_2)
        response = post_form(h, "/account/token", {"csrf": csrf_a, "canvas_token": CANVAS_TOKEN})
        assert response.status_code == 403

    def test_store_failure_is_503_without_leaking(
        self, signed_in: Harness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken(**kwargs: Any) -> None:
            raise RuntimeError(f"disk exploded {kwargs['api_token']}")

        monkeypatch.setattr(signed_in.store, "put", broken)
        csrf = csrf_of(signed_in)
        response = post_form(
            signed_in, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN}
        )
        assert response.status_code == 503
        assert CANVAS_TOKEN not in response.text and "disk exploded" not in response.text


# -- delete and logout -------------------------------------------------------


class TestDeleteAndLogout:
    def test_delete_removes_only_my_row(self, h: Harness) -> None:
        h.store.put(
            tenant_id=TID, object_id=OID_2, api_token="x" * 30, canvas_user_id="9",
            canvas_user_name="Bob", entra_display_name="Bob", entra_upn="bob@example.test",
        )
        sign_in(h)
        csrf = csrf_of(h)
        post_form(h, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN})
        assert h.store.count() == 2
        response = post_form(h, "/account/token/delete", {"csrf": csrf})
        assert response.status_code == 303 and response.headers["location"] == "/account"
        assert h.store.get(TID, OID) is None
        assert h.store.get(TID, OID_2) is not None
        assert "Delete my token" not in h.client.get(ACCOUNT_PATH).text

    def test_delete_checks_csrf_and_origin(self, h: Harness) -> None:
        sign_in(h)
        csrf = csrf_of(h)
        post_form(h, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN})
        assert post_form(h, "/account/token/delete", {"csrf": "bad"}).status_code == 403
        assert post_form(h, "/account/token/delete", {"csrf": csrf}, origin=None).status_code == 403
        assert post_form(h, "/account/token/delete", {"csrf": csrf}, origin="https://evil.example").status_code == 403
        assert h.store.count() == 1

    def test_logout_clears_the_session(self, h: Harness) -> None:
        sign_in(h)
        csrf = csrf_of(h)
        response = post_form(h, "/account/logout", {"csrf": csrf})
        assert response.status_code == 303 and response.headers["location"] == "/account"
        line = cookie_line(response, SESSION_COOKIE).lower()
        assert "max-age=0" in line and "secure" in line and "httponly" in line
        assert "Sign in with Microsoft" in h.client.get(ACCOUNT_PATH).text

    def test_logout_checks_csrf_and_origin(self, h: Harness) -> None:
        sign_in(h)
        csrf = csrf_of(h)
        assert post_form(h, "/account/logout", {"csrf": "bad"}).status_code == 403
        assert post_form(h, "/account/logout", {"csrf": csrf}, origin="https://evil.example").status_code == 403
        assert "Sign out" in h.client.get(ACCOUNT_PATH).text  # still signed in


# -- admin -------------------------------------------------------------------


class TestAdmin:
    def _enroll(self, h: Harness, oid: str, upn: str, name: str, token: str) -> None:
        h.store.put(
            tenant_id=TID, object_id=oid, api_token=token, canvas_user_id="77",
            canvas_user_name=name, entra_display_name=name, entra_upn=upn,
        )

    def test_non_owner_and_signed_out_are_403(self, h: Harness) -> None:
        assert h.client.get("/account/admin").status_code == 403
        sign_in(h)
        assert h.client.get("/account/admin").status_code == 403
        assert "/account/admin" not in h.client.get(ACCOUNT_PATH).text

    def test_owner_sees_enrollments_without_tokens(self, h: Harness) -> None:
        secret = "9~" + "S" * 60
        self._enroll(h, OID_2, "bob@example.test", "Bob <img src=x>", secret)
        sign_in(h, oid=OID_OWNER, name="Olive Owner", roles=("Canvas.Owner",))
        assert 'href="/account/admin"' in h.client.get(ACCOUNT_PATH).text
        response = h.client.get("/account/admin")
        assert response.status_code == 200
        assert_security_headers(response)
        text = response.text
        assert secret not in text and "S" * 40 not in text
        assert "bob@example.test" in text
        assert "Bob &lt;img src=x&gt;" in text and "<img src=x>" not in text
        assert "2027-01-15T08:00:00Z" in text
        assert f'name="object_id" value="{OID_2}"' in text
        assert f'name="tenant_id" value="{TID}"' in text
        assert 'action="/account/admin/revoke"' in text
        assert re.search(r'name="csrf" value="[^"]+"', text)

    def test_revoke_requires_owner_origin_and_csrf(self, h: Harness) -> None:
        self._enroll(h, OID_2, "bob@example.test", "Bob", "9~" + "S" * 60)
        target = {"tenant_id": TID, "object_id": OID_2}
        # signed out
        assert post_form(h, "/account/admin/revoke", {"csrf": "x", **target}).status_code == 403
        # regular user
        sign_in(h)
        csrf = csrf_of(h)
        assert post_form(h, "/account/admin/revoke", {"csrf": csrf, **target}).status_code == 403
        assert h.store.count() == 1
        # owner
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        csrf = csrf_of(h)
        assert post_form(h, "/account/admin/revoke", {"csrf": "bad", **target}).status_code == 403
        assert post_form(h, "/account/admin/revoke", {"csrf": csrf, **target}, origin=None).status_code == 403
        assert post_form(h, "/account/admin/revoke", {"csrf": csrf, **target}, origin="https://evil.example").status_code == 403
        assert h.store.count() == 1
        response = post_form(h, "/account/admin/revoke", {"csrf": csrf, **target})
        assert response.status_code == 303
        assert response.headers["location"] == "/account/admin"
        assert h.store.count() == 0

    @pytest.mark.parametrize(
        "fields",
        [
            {"tenant_id": "x", "object_id": OID_2},
            {"tenant_id": TID, "object_id": "../../etc"},
            {"tenant_id": TID},
            {},
        ],
    )
    def test_revoke_validates_guids(self, h: Harness, fields: dict[str, str]) -> None:
        self._enroll(h, OID_2, "bob@example.test", "Bob", "9~" + "S" * 60)
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        csrf = csrf_of(h)
        response = post_form(h, "/account/admin/revoke", {"csrf": csrf, **fields})
        assert response.status_code == 400
        assert h.store.count() == 1

    def test_owner_can_use_the_user_pages_too(self, h: Harness) -> None:
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        csrf = csrf_of(h)
        response = post_form(h, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN})
        assert response.status_code == 303
        assert h.store.get(TID, OID_OWNER) is not None


# -- defaults: Canvas check ---------------------------------------------------


class TestDefaultCanvasCheck:
    def _client(
        self, tmp_path: pathlib.Path, handler: Callable[[httpx.Request], httpx.Response],
        seen: list[httpx.Request],
    ) -> tuple[TestClient, TokenStore, Harness]:
        keyring = Keyring.parse("k1:" + base64.b64encode(b"\x01" * 32).decode())
        store = TokenStore(tmp_path / "t.sqlite3", keyring)
        store.initialize()
        harness = Harness(client=None, store=store)  # type: ignore[arg-type]

        async def verify(_t: str) -> Mapping[str, Any] | None:
            return dict(harness.claims)

        def recording(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            if "login.microsoftonline.com" in str(request.url):
                return httpx.Response(200, json={"id_token": "x"})
            return handler(request)

        routes = build_account_routes(
            make_cfg(), store, fake_authorize, id_token_verifier=verify,
            http_client_factory=lambda: httpx.AsyncClient(
                transport=httpx.MockTransport(recording)
            ),
            clock=harness.clock,
        )
        client = TestClient(Starlette(routes=routes), base_url=BASE, follow_redirects=False)
        harness.client = client
        return client, store, harness

    def _enroll(self, harness: Harness) -> httpx.Response:
        assert sign_in(harness).status_code == 303
        csrf = csrf_of(harness)
        return post_form(
            harness, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN}
        )

    def test_success_request_shape(self, tmp_path: pathlib.Path) -> None:
        seen: list[httpx.Request] = []
        _client, store, harness = self._client(
            tmp_path, lambda r: httpx.Response(200, json={"id": 4242, "name": "Real Name", "secret": "no"}), seen
        )
        assert self._enroll(harness).status_code == 303
        (request,) = [r for r in seen if "canvas.example.test" in str(r.url)]
        assert str(request.url) == "https://canvas.example.test/api/v1/users/self"
        assert request.headers["authorization"] == f"Bearer {CANVAS_TOKEN}"
        assert request.headers["accept"] == "application/json"
        stored = store.get(TID, OID)
        assert stored is not None
        assert (stored.canvas_user_id, stored.canvas_user_name) == ("4242", "Real Name")

    def test_short_name_fallback_and_truncation(self, tmp_path: pathlib.Path) -> None:
        seen: list[httpx.Request] = []
        _c, store, harness = self._client(
            tmp_path, lambda r: httpx.Response(200, json={"id": 1, "short_name": "S" * 300}), seen
        )
        self._enroll(harness)
        stored = store.get(TID, OID)
        assert stored is not None and stored.canvas_user_name == "S" * 200

    @pytest.mark.parametrize("status", [401, 403])
    def test_401_403_mean_invalid(self, tmp_path: pathlib.Path, status: int) -> None:
        _c, store, harness = self._client(
            tmp_path, lambda r: httpx.Response(status, text="invalid access token"), []
        )
        response = self._enroll(harness)
        assert response.status_code == 400
        assert "invalid access token" not in response.text
        assert store.count() == 0

    @pytest.mark.parametrize(
        "make",
        [
            lambda r: httpx.Response(500, text="boom"),
            lambda r: httpx.Response(302, headers={"Location": "https://evil.example/"}),
            lambda r: httpx.Response(404),
            lambda r: httpx.Response(200, content=b"not json"),
            lambda r: httpx.Response(200, json={"name": "no id"}),
            lambda r: httpx.Response(200, json=["list"]),
        ],
    )
    def test_everything_else_is_unavailable(
        self, tmp_path: pathlib.Path, make: Callable[[httpx.Request], httpx.Response]
    ) -> None:
        _c, store, harness = self._client(tmp_path, make, [])
        assert self._enroll(harness).status_code == 503
        assert store.count() == 0

    def test_network_error_is_unavailable(self, tmp_path: pathlib.Path) -> None:
        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("slow")

        _c, store, harness = self._client(tmp_path, boom, [])
        assert self._enroll(harness).status_code == 503
        assert store.count() == 0


# -- units -------------------------------------------------------------------


class TestCookieCodec:
    def test_roundtrip_and_name_binding(self) -> None:
        codec = account_web._CookieCodec(SESSION_SECRET)
        sealed = codec.seal("__Host-a", {"k": "v", "n": 1})
        assert sealed.startswith("v1.") and "=" not in sealed
        assert codec.unseal("__Host-a", sealed) == {"k": "v", "n": 1}
        assert codec.unseal("__Host-b", sealed) is None
        assert codec.unseal("__Host-a", None) is None
        assert codec.unseal("__Host-a", sealed[:-1]) is None

    def test_sealing_is_randomised(self) -> None:
        codec = account_web._CookieCodec(SESSION_SECRET)
        assert codec.seal("n", {"a": 1}) != codec.seal("n", {"a": 1})

    def test_different_secrets_do_not_open_each_other(self) -> None:
        a = account_web._CookieCodec(b"a" * 32)
        b = account_web._CookieCodec(b"b" * 32)
        assert b.unseal("n", a.seal("n", {"x": 1})) is None


class TestRateLimiter:
    def test_limit_window_and_bounded_keys(self) -> None:
        now = [1000.0]
        limiter = account_web._RateLimiter(3, 100, 4, lambda: now[0])
        key = ("t", "o")
        assert [limiter.allow(key) for _ in range(4)] == [True, True, True, False]
        now[0] += 101
        assert limiter.allow(key) is True
        for i in range(50):
            limiter.allow(("t", f"user-{i}"))
        assert len(limiter._hits) <= 4


class TestDataclasses:
    def test_config_repr_hides_secrets(self) -> None:
        text = repr(make_cfg())
        assert CLIENT_SECRET not in text and "session_secret" not in text

    def test_canvas_check_error_kind(self) -> None:
        assert CanvasCheckError("invalid").kind == "invalid"
        assert CanvasCheckError("unavailable").kind == "unavailable"


# -- FastMCP registration ----------------------------------------------------


class TestRegistration:
    def test_register_account_routes_serves_the_pages(self, h: Harness) -> None:
        from fastmcp import FastMCP

        mcp = FastMCP("account-test")
        register_account_routes(
            mcp, make_cfg(), h.store, fake_authorize, clock=h.clock
        )
        paths = {route.path for route in mcp._additional_http_routes}  # type: ignore[attr-defined]
        assert paths == {
            "/account",
            "/account/login",
            "/account/callback",
            "/account/token",
            "/account/token/delete",
            "/account/logout",
            "/account/admin",
            "/account/admin/revoke",
        }
        client = TestClient(mcp.http_app(), base_url=BASE, follow_redirects=False)
        response = client.get("/account")
        assert response.status_code == 200
        assert "Sign in with Microsoft" in response.text
        assert_security_headers(response)
