"""Tests for the /account browser pages (all identity and network I/O faked)."""

from __future__ import annotations

import ast
import asyncio
import base64
import hashlib
import pathlib
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo

import httpx
import pytest
from dbbackend import make_store
from starlette.applications import Starlette
from starlette.testclient import TestClient

from canvas_mcp.core.selfhost import account_web
from canvas_mcp.core.selfhost import accounts as acc
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
from canvas_mcp.core.selfhost.accounts import EntraClaimsPolicy, default_policy
from canvas_mcp.core.selfhost.identity import IdentityService
from canvas_mcp.core.selfhost.schools import SchoolPolicy
from canvas_mcp.core.selfhost.token_store import Keyring, TokenStore

from .conftest import acct_key, make_account

BASE = "https://canvas.example.test"
TID = "11111111-2222-3333-4444-555555555555"
CLIENT_ID = "99999999-8888-7777-6666-555555555555"
CLIENT_SECRET = "client-secret-value-0123456789"
OID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID_2 = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
OID_OWNER = "cccccccc-dddd-eeee-ffff-000000000000"
KEY = acct_key(OID)
KEY_2 = acct_key(OID_2)
KEY_OWNER = acct_key(OID_OWNER)
CANVAS_TOKEN = "7~" + "T" * 62
SESSION_SECRET = bytes(range(32))
ORIGIN = {"Origin": BASE}


POLICY = default_policy("Canvas.User", "Canvas.Owner")


def make_identity(store: TokenStore, policy: Any = POLICY, access: Any = None) -> IdentityService:
    """The real identity service over ``store`` (new accounts get the key the tests expect)."""
    store._new_account_id = lambda ext: acct_key(ext.subject).removeprefix("acct:")  # type: ignore[attr-defined]
    return IdentityService(store, EntraClaimsPolicy(TID, CLIENT_ID), policy, access=access)


def put_row(
    store: TokenStore,
    oid: str,
    *,
    token: str,
    name: str,
    upn: str = "",
    display: str | None = None,
    canvas_user_id: str = "77",
    **kw: Any,
) -> Any:
    """Create the account of ``oid`` (if need be) and save a Canvas token for it."""
    key = make_account(store, oid, name=display if display is not None else name, username=upn)
    return store.put(
        principal_key=key,
        api_token=token,
        canvas_user_id=canvas_user_id,
        canvas_user_name=name,
        **kw,
    )


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
    whoami_urls: list[str] = field(default_factory=list)
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
        "schools": SchoolPolicy.pinned("https://canvas.example.test/api/v1"),
    }
    args.update(kw)
    return AccountConfig(**args)


@pytest.fixture(autouse=True)
def _display_in_utc(monkeypatch: pytest.MonkeyPatch) -> None:
    """Timestamps render in TIMEZONE; pin it so the suite does not depend on the machine."""
    monkeypatch.setattr(account_web, "output_timezone", lambda: UTC)


def build_harness(
    tmp_path: pathlib.Path,
    *,
    cfg: AccountConfig | None = None,
    identity: Any = None,
    **route_kwargs: Any,
) -> Harness:
    """A signed-out harness; ``route_kwargs`` (directory, resolve_host, ...) go to the routes."""
    keyring = Keyring.parse("k1:" + base64.b64encode(b"\x01" * 32).decode())
    store = make_store(tmp_path / "tokens.sqlite3", keyring, clock=lambda: 1_800_000_000)
    store.initialize()
    harness = Harness(client=None, store=store)  # type: ignore[arg-type]
    identity = identity or make_identity(store)

    async def verify(_token: str) -> Mapping[str, Any] | None:
        if harness.verifier_result == "raise":
            raise RuntimeError("jwks exploded")
        if harness.verifier_result == "none":
            return None
        return dict(harness.claims)

    async def whoami(token: str, api_url: str) -> CanvasIdentity:
        harness.whoami_calls.append(token)
        harness.whoami_urls.append(api_url)
        if isinstance(harness.whoami_result, CanvasCheckError):
            raise harness.whoami_result
        return harness.whoami_result

    def handler(request: httpx.Request) -> httpx.Response:
        harness.token_requests.append(request)
        return harness.token_response(request)

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    routes = build_account_routes(
        cfg or make_cfg(),
        store,
        identity,
        id_token_verifier=verify,
        canvas_whoami=whoami,
        http_client_factory=factory,
        clock=harness.clock,
        **route_kwargs,
    )
    harness.client = TestClient(
        Starlette(routes=routes), base_url=BASE, follow_redirects=False
    )
    return harness


@pytest.fixture
def h(tmp_path: pathlib.Path) -> Harness:
    return build_harness(tmp_path)


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
            "/account/admin/remove",
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
        # the closed denial message is shown, and nothing is created for the visitor
        assert "is not allowed to use this server" in response.text
        assert h.store.list_principal_statuses() == []
        assert SESSION_COOKIE not in "".join(set_cookie_headers(response))
        assert h.client.get(ACCOUNT_PATH).text.count("Sign in with Microsoft") >= 1

    def test_a_refusal_from_the_identity_service_is_403_without_a_session(self, h: Harness) -> None:
        class Refusing:
            def sign_in(self, claims: Mapping[str, Any], **kw: Any) -> acc.Denied:
                return acc.denied(acc.DENY_WRONG_TENANT)

        async def verify(_t: str) -> Mapping[str, Any] | None:
            return dict(h.claims)

        routes = build_account_routes(
            make_cfg(), h.store, Refusing(), id_token_verifier=verify,  # type: ignore[arg-type]
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
        assert "different directory" in response.text
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
                "v": 3, "ep": 0, "acct": KEY, "pid": "entra", "name": "x", "upn": "x",
                "owner": True, "iat": int(h.now), "exp": int(h.now) + 600, "csrf": "c",
            },
        )
        h.client.cookies.set(SESSION_COOKIE, forged, domain="canvas.example.test", path="/")
        assert "Sign in with Microsoft" in h.client.get(ACCOUNT_PATH).text

    def test_a_cookie_of_the_previous_version_is_signed_out(self, h: Harness) -> None:
        # Version 2 named the Entra tenant and object id; it is refused, so everyone
        # signs in once after the account-model upgrade.
        codec = account_web._CookieCodec(SESSION_SECRET)
        old = codec.seal(
            SESSION_COOKIE,
            {
                "v": 2, "ep": 0, "tid": TID, "oid": OID, "name": "x", "upn": "x",
                "owner": False, "iat": int(h.now), "exp": int(h.now) + 600, "csrf": "c",
            },
        )
        h.client.cookies.set(SESSION_COOKIE, old, domain="canvas.example.test", path="/")
        assert "Sign in with Microsoft" in h.client.get(ACCOUNT_PATH).text

    def test_the_session_names_the_account_not_the_tenant_and_object(self, h: Harness) -> None:
        sign_in(h)
        codec = account_web._CookieCodec(SESSION_SECRET)
        opened = codec.unseal(SESSION_COOKIE, h.client.cookies.get(SESSION_COOKIE))
        assert opened is not None
        assert opened["v"] == 3 and opened["acct"] == KEY and opened["pid"] == "entra"
        assert "tid" not in opened and "oid" not in opened

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
            make_cfg(session_ttl_seconds=120), h.store, make_identity(h.store),
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
        stored = signed_in.store.get(KEY)
        assert stored is not None
        assert stored.api_token == CANVAS_TOKEN
        assert stored.canvas_user_id == "42"
        assert stored.canvas_user_name == "Ada Canvas"
        # The person's name and sign-in name belong to the account, not to the token row.
        assert signed_in.store.get_principal_status(KEY).display_name == "Ada Lovelace"
        (account,) = [a for a in signed_in.store.list_accounts() if a.principal_key == KEY]
        assert account.username == "ada@example.test"
        page = signed_in.client.get(ACCOUNT_PATH)
        assert "Ada Canvas" in page.text and "id 42" in page.text
        assert "2027-01-15 08:00 UTC" in page.text  # enrolled, no seconds, no T/Z
        assert CANVAS_TOKEN not in page.text
        for call in signed_in.client.cookies.jar:
            assert CANVAS_TOKEN not in (call.value or "")

    def test_replacing_a_token_updates_the_row(self, signed_in: Harness) -> None:
        csrf = csrf_of(signed_in)
        post_form(signed_in, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN})
        signed_in.now += 60
        newer = "8~" + "N" * 62
        post_form(signed_in, "/account/token", {"csrf": csrf, "canvas_token": newer})
        stored = signed_in.store.get(KEY)
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
        put_row(h.store, OID_2, token="x" * 30, name="Bob", upn="bob@example.test", canvas_user_id="9")
        sign_in(h)
        csrf = csrf_of(h)
        post_form(h, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN})
        assert h.store.count() == 2
        response = post_form(h, "/account/token/delete", {"csrf": csrf})
        assert response.status_code == 303 and response.headers["location"] == "/account"
        assert h.store.get(KEY) is None
        assert h.store.get(KEY_2) is not None
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
        put_row(h.store, oid, token=token, name=name, upn=upn)

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
        assert "2027-01-15 08:00 UTC" in text
        assert f'name="principal_key" value="{KEY_2}"' in text
        assert 'name="tenant_id"' not in text and 'name="object_id"' not in text
        assert 'action="/account/admin/remove"' in text
        assert re.search(r'name="csrf" value="[^"]+"', text)

    def test_revoke_requires_owner_origin_and_csrf(self, h: Harness) -> None:
        self._enroll(h, OID_2, "bob@example.test", "Bob", "9~" + "S" * 60)
        target = {"principal_key": KEY_2}
        # signed out
        assert post_form(h, "/account/admin/remove", {"csrf": "x", **target}).status_code == 403
        # regular user
        sign_in(h)
        csrf = csrf_of(h)
        assert post_form(h, "/account/admin/remove", {"csrf": csrf, **target}).status_code == 403
        assert h.store.count() == 1
        # owner
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        csrf = csrf_of(h)
        assert post_form(h, "/account/admin/remove", {"csrf": "bad", **target}).status_code == 403
        assert post_form(h, "/account/admin/remove", {"csrf": csrf, **target}, origin=None).status_code == 403
        assert post_form(h, "/account/admin/remove", {"csrf": csrf, **target}, origin="https://evil.example").status_code == 403
        assert h.store.count() == 1
        response = post_form(h, "/account/admin/remove", {"csrf": csrf, **target})
        assert response.status_code == 303
        assert response.headers["location"] == "/account/admin"
        assert h.store.count() == 0

    @pytest.mark.parametrize(
        "fields",
        [
            {"principal_key": "x"},
            {"principal_key": "acct:../../etc"},
            {"principal_key": f"entra:{TID}:{OID_2}"},
            {"principal_key": KEY_2.upper()},
            {"tenant_id": TID, "object_id": OID_2},
            {},
        ],
    )
    def test_revoke_validates_the_account_key(self, h: Harness, fields: dict[str, str]) -> None:
        self._enroll(h, OID_2, "bob@example.test", "Bob", "9~" + "S" * 60)
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        csrf = csrf_of(h)
        response = post_form(h, "/account/admin/remove", {"csrf": csrf, **fields})
        assert response.status_code == 400
        assert h.store.count() == 1

    def test_owner_can_use_the_user_pages_too(self, h: Harness) -> None:
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        csrf = csrf_of(h)
        response = post_form(h, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN})
        assert response.status_code == 303
        assert h.store.get(KEY_OWNER) is not None


# -- defaults: Canvas check ---------------------------------------------------


class TestDefaultCanvasCheck:
    def _client(
        self, tmp_path: pathlib.Path, handler: Callable[[httpx.Request], httpx.Response],
        seen: list[httpx.Request],
    ) -> tuple[TestClient, TokenStore, Harness]:
        keyring = Keyring.parse("k1:" + base64.b64encode(b"\x01" * 32).decode())
        store = make_store(tmp_path / "t.sqlite3", keyring)
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
            make_cfg(), store, make_identity(store), id_token_verifier=verify,
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
        stored = store.get(KEY)
        assert stored is not None
        assert (stored.canvas_user_id, stored.canvas_user_name) == ("4242", "Real Name")

    def test_short_name_fallback_and_truncation(self, tmp_path: pathlib.Path) -> None:
        seen: list[httpx.Request] = []
        _c, store, harness = self._client(
            tmp_path, lambda r: httpx.Response(200, json={"id": 1, "short_name": "S" * 300}), seen
        )
        self._enroll(harness)
        stored = store.get(KEY)
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


# -- language, layout and timestamps -------------------------------------------

# Pick a language for one GET request (the toggle link does the same).
ZH = {"lang": "zh"}
EN = {"lang": "en"}
ZH_BROWSER = {"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"}
CJK = re.compile("[\u4e00-\u9fff]")
LANG_COOKIE_NAME = "canvas_mcp_lang"
SOURCE = pathlib.Path(account_web.__file__)


def strip_chrome(text: str) -> str:
    """Page body without <style> and the header (the toggle names the other language)."""
    text = re.sub(r"<style>.*?</style>", "", text, flags=re.S)
    return re.sub(r"<header.*?</header>", "", text, flags=re.S)


def use_lang(h: Harness, lang: str) -> None:
    """Remember a language in the client's cookie jar the way a browser would."""
    response = h.client.get(ACCOUNT_PATH, params={"lang": lang})
    assert response.status_code == 200


def bi_calls() -> list[tuple[int, ast.expr, ast.expr]]:
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_bi":
            assert len(node.args) == 2 and not node.keywords, f"line {node.lineno}"
            found.append((node.lineno, node.args[0], node.args[1]))
    return found


def static_text(node: ast.expr) -> str | None:
    """The literal text of a str constant or the literal parts of an f-string."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)
        )
    return None


class TestLanguageChoice:
    def test_default_is_english(self, h: Harness) -> None:
        response = h.client.get(ACCOUNT_PATH)
        assert '<html lang="en">' in response.text
        assert "Sign in with Microsoft" in response.text
        assert not CJK.search(strip_chrome(response.text))
        assert LANG_COOKIE_NAME not in "".join(set_cookie_headers(response))

    def test_query_param_selects_chinese_and_html_lang(self, h: Harness) -> None:
        response = h.client.get(ACCOUNT_PATH, params={"lang": "zh"})
        assert '<html lang="zh-CN">' in response.text
        assert "使用 Microsoft 登录" in response.text
        assert "Sign in with Microsoft" not in response.text
        assert_security_headers(response)

    def test_query_param_beats_cookie(self, h: Harness) -> None:
        use_lang(h, "zh")
        response = h.client.get(ACCOUNT_PATH, params={"lang": "en"})
        assert '<html lang="en">' in response.text
        assert "Sign in with Microsoft" in response.text

    def test_cookie_is_remembered_on_later_pages(self, h: Harness) -> None:
        use_lang(h, "zh")
        assert h.client.cookies.get(LANG_COOKIE_NAME) == "zh"
        later = h.client.get(ACCOUNT_PATH)
        assert '<html lang="zh-CN">' in later.text
        assert "使用 Microsoft 登录" in later.text
        use_lang(h, "en")
        assert "Sign in with Microsoft" in h.client.get(ACCOUNT_PATH).text

    def test_cookie_selects_the_language(self, h: Harness) -> None:
        response = h.client.get(ACCOUNT_PATH, headers={"Cookie": f"{LANG_COOKIE_NAME}=zh"})
        assert '<html lang="zh-CN">' in response.text
        response = h.client.get(ACCOUNT_PATH, headers={"Cookie": f"{LANG_COOKIE_NAME}=en"})
        assert '<html lang="en">' in response.text

    @pytest.mark.parametrize(
        "header",
        ["zh-CN,zh;q=0.9,en;q=0.8", "zh", "zh-TW", "ZH-hans", "fr, zh;q=0.5", "*", ""],
    )
    def test_browser_language_is_ignored_english_is_the_default(
        self, h: Harness, header: str
    ) -> None:
        """English unless the user picks Chinese: Accept-Language never switches it."""
        response = h.client.get(ACCOUNT_PATH, headers={"Accept-Language": header})
        assert '<html lang="en">' in response.text
        assert "Sign in with Microsoft" in response.text
        assert LANG_COOKIE_NAME not in "".join(set_cookie_headers(response))

    def test_a_chinese_browser_still_gets_chinese_after_picking_it(self, h: Harness) -> None:
        h.client.headers.update(ZH_BROWSER)
        assert '<html lang="en">' in h.client.get(ACCOUNT_PATH).text
        use_lang(h, "zh")
        assert '<html lang="zh-CN">' in h.client.get(ACCOUNT_PATH).text

    @pytest.mark.parametrize(
        "value",
        ["fr", "ZH", "zh-CN", "", "zh,en", " zh", "zh ", "<script>x</script>", "zh%00", "1", "null"],
    )
    def test_invalid_query_values_are_ignored(self, h: Harness, value: str) -> None:
        response = h.client.get(ACCOUNT_PATH, params={"lang": value})
        assert '<html lang="en">' in response.text
        assert LANG_COOKIE_NAME not in "".join(set_cookie_headers(response))
        assert "<script>x" not in response.text
        # An invalid value does not cancel a valid cookie either.
        response = h.client.get(
            ACCOUNT_PATH,
            params={"lang": value},
            headers={"Cookie": f"{LANG_COOKIE_NAME}=zh"},
        )
        assert '<html lang="zh-CN">' in response.text

    @pytest.mark.parametrize("value", ["fr", "ZH", "", "zh,en", "<b>x</b>", "z" * 500])
    def test_invalid_cookie_values_are_ignored_and_not_echoed(
        self, h: Harness, value: str
    ) -> None:
        response = h.client.get(
            ACCOUNT_PATH, headers={"Cookie": f"{LANG_COOKIE_NAME}={value}"}
        )
        assert '<html lang="en">' in response.text
        assert "<b>x</b>" not in response.text and "zzzzzz" not in response.text

    def test_lang_query_is_ignored_on_post(self, h: Harness) -> None:
        sign_in(h)
        csrf = csrf_of(h)
        response = h.client.post(
            "/account/token?lang=zh",
            data={"csrf": csrf, "canvas_token": "short"},
            headers={"Origin": BASE, "Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status_code == 400
        assert '<html lang="en">' in response.text
        assert LANG_COOKIE_NAME not in "".join(set_cookie_headers(response))

    def test_lang_query_works_on_any_get_page(self, h: Harness) -> None:
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        response = h.client.get("/account/admin", params={"lang": "zh"})
        assert response.status_code == 200
        assert '<html lang="zh-CN">' in response.text
        assert LANG_COOKIE_NAME in "".join(set_cookie_headers(response))
        denied = h.client.get(ACCOUNT_CALLBACK_PATH, params={"lang": "zh"})
        assert denied.status_code == 400 and "登录请求已失效" in denied.text

    def test_language_survives_a_post_redirect(self, h: Harness) -> None:
        use_lang(h, "zh")
        sign_in(h)
        csrf = csrf_of(h)
        response = post_form(
            h, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN}
        )
        assert response.status_code == 303 and response.headers["location"] == "/account"
        page = h.client.get(response.headers["location"])
        assert '<html lang="zh-CN">' in page.text
        assert "Canvas 令牌已绑定" in page.text

    def test_cookie_attributes(self, h: Harness) -> None:
        response = h.client.get(ACCOUNT_PATH, params={"lang": "zh"})
        line = cookie_line(response, LANG_COOKIE_NAME)
        lowered = line.lower()
        assert line.startswith(f"{LANG_COOKIE_NAME}=zh;")
        assert "path=/account" in lowered and "path=/account/" not in lowered
        assert "samesite=lax" in lowered
        assert "secure" in lowered and "httponly" in lowered
        assert "max-age=31536000" in lowered
        assert "domain" not in lowered
        english = cookie_line(h.client.get(ACCOUNT_PATH, params={"lang": "en"}), LANG_COOKIE_NAME)
        assert english.startswith(f"{LANG_COOKIE_NAME}=en;")

    def test_cookie_is_not_an_auth_input_or_redirect_target(self, h: Harness) -> None:
        # A language cookie alone signs nobody in and never steers a redirect.
        response = h.client.get(
            "/account/admin", headers={"Cookie": f"{LANG_COOKIE_NAME}=zh"}
        )
        assert response.status_code == 403 and "location" not in response.headers
        sign_in(h)
        csrf = csrf_of(h)
        out = post_form(h, "/account/logout", {"csrf": csrf})
        assert out.headers["location"] == "/account"

    def test_other_status_pages_follow_the_language_too(self, h: Harness) -> None:
        response = h.client.put(ACCOUNT_PATH, headers={"Cookie": f"{LANG_COOKIE_NAME}=zh"})
        assert response.status_code == 405 and "不支持该请求方法" in response.text
        response = h.client.put(ACCOUNT_PATH, headers={"Cookie": f"{LANG_COOKIE_NAME}=en"})
        assert "Method not allowed" in response.text and not CJK.search(
            strip_chrome(response.text)
        )

    def test_languages_never_cross_between_concurrent_requests(self, h: Harness) -> None:
        sign_in(h)
        session_cookie = h.client.cookies.get(SESSION_COOKIE)
        assert session_cookie
        real_info = h.store.info

        def slow_info(key: str) -> Any:
            time.sleep(0.05)  # keep many requests in flight at once
            return real_info(key)

        h.store.info = slow_info  # type: ignore[method-assign]
        routes = build_account_routes(
            make_cfg(),
            h.store,
            make_identity(h.store),
            clock=h.clock,
        )
        app = Starlette(routes=routes)

        async def fetch(client: httpx.AsyncClient, lang: str) -> tuple[str, str]:
            response = await client.get(
                ACCOUNT_PATH,
                params={"lang": lang},
                headers={"Cookie": f"{SESSION_COOKIE}={session_cookie}"},
            )
            return lang, response.text

        async def run() -> list[tuple[str, str]]:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url=BASE) as client:
                jobs = [fetch(client, "zh" if i % 2 else "en") for i in range(24)]
                return await asyncio.gather(*jobs)

        results = asyncio.run(run())
        assert len(results) == 24
        for lang, text in results:
            if lang == "zh":
                assert '<html lang="zh-CN">' in text and "绑定你的 Canvas 令牌" in text
                assert "Add your Canvas token" not in text
            else:
                assert '<html lang="en">' in text and "Add your Canvas token" in text
                assert not CJK.search(strip_chrome(text))
        # Nothing is left behind on the calling context.
        assert account_web._current_lang() == "en"


class TestSingleLanguageRendering:
    def test_every_bi_call_has_both_languages(self) -> None:
        calls = bi_calls()
        assert len(calls) > 40
        for lineno, zh, en in calls:
            zh_text, en_text = static_text(zh), static_text(en)
            assert zh_text is not None and en_text is not None, f"line {lineno}: not literal"
            assert zh_text.strip() and en_text.strip(), f"line {lineno}: empty text"
            assert CJK.search(zh_text), f"line {lineno}: zh string has no Chinese"
            assert not CJK.search(en_text), f"line {lineno}: en string has Chinese"

    def test_no_bi_call_runs_at_import_time(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                continue
            for inner in ast.walk(node):
                assert not (
                    isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Name)
                    and inner.func.id == "_bi"
                ), f"line {inner.lineno}: _bi evaluated at import time freezes the language"

    def test_bi_returns_only_the_chosen_text(self) -> None:
        assert account_web._bi("中", "en") == "en"  # no request context: default English
        token = account_web._RENDER.set(account_web._RenderContext(lang="zh"))
        try:
            assert account_web._bi("中", "en") == "中"
        finally:
            account_web._RENDER.reset(token)

    @pytest.mark.parametrize("lang", ["zh", "en"])
    def test_pages_render_one_language_only(self, h: Harness, lang: str) -> None:
        pairs = [
            (static_text(zh), static_text(en))
            for _, zh, en in bi_calls()
        ]
        use_lang(h, lang)
        pages = [
            h.client.get(ACCOUNT_PATH),
            h.client.get(ACCOUNT_CALLBACK_PATH),
            h.client.put(ACCOUNT_PATH),
        ]
        put_row(h.store, OID_2, token="x" * 30, name="Bob", upn="bob@example.test", canvas_user_id="9")
        sign_in(h)
        csrf = csrf_of(h)
        pages.append(h.client.get(ACCOUNT_PATH))  # not enrolled
        pages.append(post_form(h, "/account/token", {"csrf": csrf, "canvas_token": "bad"}))
        post_form(h, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN})
        pages.append(h.client.get(ACCOUNT_PATH))  # enrolled
        pages.append(h.client.get("/account/admin"))  # forbidden for a non-owner
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        pages.append(h.client.get("/account/admin"))  # table with rows
        assert len(pages) == 8
        for page in pages:
            text = page.text
            assert 'class="en"' not in text and '<br><span class="en"' not in text
            assert_security_headers(page)
            body = strip_chrome(text)
            if lang == "en":
                assert not CJK.search(body)
            for zh_text, en_text in pairs:
                if zh_text is None or en_text is None or zh_text == en_text:
                    continue
                if lang == "zh" and len(en_text) >= 10:
                    assert en_text not in body, en_text
                if lang == "en":
                    assert zh_text not in body, zh_text
        if lang == "zh":
            assert "技术信息" in pages[-1].text and "Technical details" not in pages[-1].text

    def test_html_lang_matches_on_every_kind_of_page(self, h: Harness) -> None:
        for lang, attr in (("zh", "zh-CN"), ("en", "en")):
            use_lang(h, lang)
            for response in (
                h.client.get(ACCOUNT_PATH),
                h.client.get(ACCOUNT_CALLBACK_PATH),
                h.client.get("/account/admin"),
                h.client.put(ACCOUNT_PATH),
            ):
                assert f'<html lang="{attr}">' in response.text


class TestLanguageToggle:
    def toggles(self, text: str) -> list[str]:
        return re.findall(r'href="([^"]*\?lang=[^"]*)"', text)

    def test_toggle_is_a_same_path_link_to_the_other_language(self, h: Harness) -> None:
        text = h.client.get(ACCOUNT_PATH, params=EN).text
        assert self.toggles(text) == ["/account?lang=zh"]
        assert ">中文</a>" in text
        text = h.client.get(ACCOUNT_PATH, params=ZH).text
        assert self.toggles(text) == ["/account?lang=en"]
        assert ">English</a>" in text

    def test_toggle_on_the_admin_page_and_on_other_routes(self, h: Harness) -> None:
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        assert self.toggles(h.client.get("/account/admin").text) == ["/account/admin?lang=zh"]
        # Pages produced by POST or redirect routes link back to the GET page.
        bad = post_form(
            h, "/account/token", {"csrf": csrf_of(h), "canvas_token": "bad"}
        )
        assert bad.status_code == 400
        assert self.toggles(bad.text) == ["/account?lang=zh"]
        callback = h.client.get(ACCOUNT_CALLBACK_PATH)
        assert self.toggles(callback.text) == ["/account?lang=zh"]

    @pytest.mark.parametrize(
        "query",
        [
            {"lang": "zh", "next": "https://evil.example/", "x": "<script>alert(1)</script>"},
            {"lang": "<img src=x onerror=alert(1)>"},
            {"redirect": "//evil.example", "return": "javascript:alert(1)"},
        ],
    )
    def test_nothing_from_the_request_is_reflected(
        self, h: Harness, query: dict[str, str]
    ) -> None:
        sign_in(h)
        for path in (ACCOUNT_PATH, "/account/admin", ACCOUNT_CALLBACK_PATH):
            text = h.client.get(path, params=query).text
            assert "evil.example" not in text
            assert "alert(1)" not in text and "onerror" not in text
            assert "javascript:" not in text
            for href in re.findall(r'href="([^"]*)"', text):
                assert href in {
                    "/account",
                    "/account?lang=zh",
                    "/account?lang=en",
                    "/account/admin",
                    "/account/admin?lang=zh",
                    "/account/admin?lang=en",
                    "/account/login",
                }, href

    def test_header_for_signed_in_users(self, h: Harness) -> None:
        sign_in(h, name="Ada Lovelace")
        text = h.client.get(ACCOUNT_PATH, params=EN).text
        header = re.search(r"<header.*?</header>", text, flags=re.S)
        assert header is not None
        head = header.group(0)
        assert "Canvas MCP" in head and "Ada Lovelace" in head
        assert 'action="/account/logout"' in head and 'name="csrf"' in head
        assert "Sign out" in head and "Admin" not in head  # not an owner
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        owner_text = h.client.get(ACCOUNT_PATH, params=ZH).text
        found = re.search(r"<header.*?</header>", owner_text, flags=re.S)
        assert found is not None
        owner_head = found.group(0)
        assert 'href="/account/admin"' in owner_head and ">管理</a>" in owner_head
        assert "退出登录" in owner_head

    def test_signed_out_header_has_no_user_controls(self, h: Harness) -> None:
        head = re.search(r"<header.*?</header>", h.client.get(ACCOUNT_PATH).text, flags=re.S)
        assert head is not None
        assert "csrf" not in head.group(0) and "logout" not in head.group(0)


class TestLayout:
    @pytest.fixture
    def signed_in(self, h: Harness) -> Harness:
        assert sign_in(h).status_code == 303
        return h

    def test_not_enrolled_is_one_card_with_numbered_steps(self, signed_in: Harness) -> None:
        text = signed_in.client.get(ACCOUNT_PATH).text
        assert text.count("<ol>") == 1 and text.count("<li>") == 3
        assert "Account → Settings → + New Access Token" in text
        assert "Never paste the token into Claude" in text
        assert 'type="password"' in text
        assert "<details" not in text  # nothing collapsed before enrolling
        assert "Delete my token" not in text
        assert f"{BASE}/mcp" in text

    def test_enrolled_page_has_status_delete_and_collapsed_replace_form(
        self, signed_in: Harness
    ) -> None:
        post_form(
            signed_in,
            "/account/token",
            {"csrf": csrf_of(signed_in), "canvas_token": CANVAS_TOKEN},
        )
        text = signed_in.client.get(ACCOUNT_PATH).text
        assert "<ol>" not in text
        status = text[: text.index("<details")]
        for label in ("Canvas user", "Last used", "Enrolled", "Updated"):
            assert f"<dt>{label}</dt>" in status
        assert "<dt>Last used</dt><dd>-</dd>" in status  # never used yet
        assert 'action="/account/token/delete"' in status and "Delete my token" in status
        assert 'name="canvas_token"' not in status
        details = re.search(r"<details class=\"card\">(.*?)</details>", text, flags=re.S)
        assert details is not None, "replace form must be collapsed by default"
        assert "<summary>Replace token</summary>" in details.group(1)
        assert 'name="canvas_token"' in details.group(1)
        assert 'action="/account/token"' in details.group(1)

    def test_replace_form_opens_when_the_attempt_failed(self, signed_in: Harness) -> None:
        post_form(
            signed_in,
            "/account/token",
            {"csrf": csrf_of(signed_in), "canvas_token": CANVAS_TOKEN},
        )
        signed_in.whoami_result = CanvasCheckError("invalid")
        failed = post_form(
            signed_in,
            "/account/token",
            {"csrf": csrf_of(signed_in), "canvas_token": "9~" + "Z" * 62},
        )
        assert failed.status_code == 400
        assert '<details class="card" open>' in failed.text
        assert "Canvas rejected this token" in failed.text

    def test_chinese_enrolled_summary(self, signed_in: Harness) -> None:
        post_form(
            signed_in,
            "/account/token",
            {"csrf": csrf_of(signed_in), "canvas_token": CANVAS_TOKEN},
        )
        text = signed_in.client.get(ACCOUNT_PATH, params=ZH).text
        assert "<summary>替换令牌</summary>" in text
        assert "删除我的令牌" in text

    @staticmethod
    def _rules(css: str) -> list[tuple[str, str, str]]:
        """Flatten the stylesheet into (media, selector, body) in source order."""
        out: list[tuple[str, str, str]] = []
        pos, media = 0, ""
        while pos < len(css):
            if css[pos].isspace():
                pos += 1
                continue
            if css[pos] == "}":
                media, pos = "", pos + 1
                continue
            brace = css.index("{", pos)
            head = css[pos:brace].strip()
            if head.startswith("@media"):
                media, pos = head, brace + 1
                continue
            end = css.index("}", brace)
            out.append((media, head, css[brace + 1 : end]))
            pos = end + 1
        return out

    def _effective(self, selector: str, prop: str, media: str = "") -> str | None:
        """The last declaration of ``prop`` for exactly ``selector`` that applies."""
        value = None
        for m, sel, body in self._rules(account_web._CSS):
            if m not in ("", media) or selector not in [x.strip() for x in sel.split(",")]:
                continue
            for decl in body.split(";"):
                name, _, val = decl.partition(":")
                if name.strip() == prop:
                    value = val.strip()
        return value

    def test_buttons_are_single_line(self) -> None:
        for media in ("", "@media (max-width:40rem)"):
            assert self._effective(".btn", "white-space", media) == "nowrap"

    def test_mobile_layout_rules_exist(self) -> None:
        css = account_web._CSS
        mobile = "@media (max-width:40rem)"
        assert "max-width:40rem" in css and "padding:.9rem 16px" in css
        assert "@media (prefers-color-scheme:dark)" in css
        assert "attr(data-label)" in css
        # Admin rows stack as cards on a phone and nothing later undoes it.
        assert self._effective("tr", "display", mobile) == "block"
        assert self._effective("td", "display", mobile) == "block"
        # The name shrinks on a phone so the header stays on one or two short lines.
        assert self._effective(".who", "max-width", mobile) == "7rem"
        assert self._effective(".who", "overflow") == "hidden"

    def test_upn_is_visible_text_not_only_a_tooltip(self, signed_in: Harness) -> None:
        en = signed_in.client.get(ACCOUNT_PATH, params=EN).text
        assert '<p class="muted small acct">Microsoft account: ada@example.test</p>' in en
        zh = signed_in.client.get(ACCOUNT_PATH, params=ZH).text
        assert "Microsoft 账号: ada@example.test" in zh

    def test_upn_is_escaped(self, h: Harness) -> None:
        sign_in(h, upn="<i>x</i>@example.test")
        text = h.client.get(ACCOUNT_PATH).text
        assert "<i>x</i>" not in text and "&lt;i&gt;x&lt;/i&gt;@example.test" in text

    def test_denial_messages_have_chinese_translations(self) -> None:
        # Every refusal a sign-in can end in has a translation; the disabled-account and
        # waiting-for-approval pages have their own wording.
        own_pages = {acc.DENY_ACCESS_DISABLED, acc.DENY_PENDING_APPROVAL, acc.DENY_UNAVAILABLE}
        expected = {m for code, m in acc.DENIAL_MESSAGES.items() if code not in own_pages}
        assert set(account_web._DENIAL_ZH) == expected
        for message, zh in account_web._DENIAL_ZH.items():
            assert CJK.search(zh) and message not in zh

    def test_denial_zh_maps_known_and_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(account_web, "_current_lang", lambda: "zh")
        known = acc.DENIAL_MESSAGES[acc.DENY_ACCESS_DENIED]
        assert account_web._denial_html(known) == account_web._DENIAL_ZH[known]
        generic = account_web._denial_html("<b>something new</b>")
        assert CJK.search(generic) and "<b>" not in generic and "something new" not in generic
        monkeypatch.setattr(account_web, "_current_lang", lambda: "en")
        assert account_web._denial_html("<b>x</b>") == "&lt;b&gt;x&lt;/b&gt;"

    def test_no_script_and_no_external_resources(self, signed_in: Harness) -> None:
        text = signed_in.client.get(ACCOUNT_PATH).text.lower()
        assert "<script" not in text and "http://" not in text
        assert "src=" not in text and "<link" not in text and "@import" not in text


class TestAdminLayout:
    def _enroll(self, h: Harness) -> None:
        put_row(
            h.store, OID_2, token="9~" + "S" * 60, name="Bob C", display="Bob E",
            upn="bob@example.test",
        )

    def test_rows_keep_ids_and_timestamps_inside_technical_details(self, h: Harness) -> None:
        self._enroll(h)
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        text = h.client.get("/account/admin").text
        for header in ("Entra user", "Canvas user", "Last used"):
            assert f"<th>{header}</th>" in text
        assert "<th>IDs</th>" not in text and "<th>Created</th>" not in text
        row = re.search(r"<tr><td data-label.*?</tr>", text, flags=re.S)
        assert row is not None
        cells = row.group(0)
        outside, _, rest = cells.partition('<details class="tech">')
        inside, _, after = rest.partition("</details>")
        assert "<summary>Technical details</summary>" in inside
        assert TID in inside and OID_2 in inside
        assert "2027-01-15 08:00 UTC" in inside  # created and updated
        # Visible part: names and the last-used value only, no GUIDs.
        assert TID not in outside and OID_2 not in outside
        assert "Bob E" in outside and "bob@example.test" in outside
        assert "Bob C" in after and "id 77" in after
        # The Remove enrollment form (POST + CSRF + the two ids) is outside the details.
        assert 'method="post" action="/account/admin/remove"' in after
        assert 'name="csrf"' in after and f'name="principal_key" value="{KEY_2}"' in after
        assert "Remove enrollment" in after

    def test_stacked_card_labels_come_from_the_page_language(self, h: Harness) -> None:
        self._enroll(h)
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        text = h.client.get("/account/admin", params=ZH).text
        assert 'data-label="Entra 用户"' in text and 'data-label="Canvas 用户"' in text
        assert 'data-label="最近使用"' in text and "<summary>技术信息</summary>" in text

    def test_one_details_block_per_row(self, h: Harness) -> None:
        self._enroll(h)
        put_row(
            h.store, OID, token="8~" + "R" * 60, name="Ada", upn="ada@example.test",
            canvas_user_id="78",
        )
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        text = h.client.get("/account/admin").text
        assert text.count("<tr><td") == 2 and text.count('<details class="tech">') == 2

    def test_empty_list_has_no_table(self, h: Harness) -> None:
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        text = h.client.get("/account/admin").text
        assert "No enrollments yet." in text and "<table" not in text


class TestTimestamps:
    def test_utc_format_without_seconds_t_or_z(self) -> None:
        assert account_web._fmt_ts(1_800_000_000) == "2027-01-15 08:00 UTC"
        assert account_web._fmt_ts(None) == "-"
        assert account_web._fmt_ts(10**30) == "-"

    def test_configured_timezone_is_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        la = ZoneInfo("America/Los_Angeles")
        monkeypatch.setattr(account_web, "output_timezone", lambda: la)
        summer = int(datetime(2026, 9, 1, 21, 12, 40, tzinfo=UTC).timestamp())
        assert account_web._fmt_ts(summer) == "2026-09-01 14:12 PDT"
        assert account_web._fmt_ts(1_800_000_000) == "2027-01-15 00:00 PST"
        text = account_web._fmt_ts(summer)
        assert re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d [A-Z]{3,5}", text)

    def test_timezone_comes_from_the_timezone_setting(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from canvas_mcp.core import dates
        from canvas_mcp.core.config import reset_config

        monkeypatch.setattr(account_web, "output_timezone", dates.output_timezone)
        monkeypatch.setenv("TIMEZONE", "Asia/Tokyo")
        reset_config()
        try:
            assert account_web._fmt_ts(1_800_000_000) == "2027-01-15 17:00 JST"
            monkeypatch.setenv("TIMEZONE", "Not/AZone")
            reset_config()
            assert account_web._fmt_ts(1_800_000_000) == "2027-01-15 08:00 UTC"
        finally:
            monkeypatch.undo()
            reset_config()

    def test_unusable_timezone_falls_back_to_utc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom() -> Any:
            raise RuntimeError("config exploded")

        monkeypatch.setattr(account_web, "output_timezone", boom)
        assert account_web._fmt_ts(1_800_000_000) == "2027-01-15 08:00 UTC"

    def test_pages_show_the_configured_timezone(
        self, h: Harness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(account_web, "output_timezone", lambda: ZoneInfo("America/Los_Angeles"))
        sign_in(h)
        post_form(h, "/account/token", {"csrf": csrf_of(h), "canvas_token": CANVAS_TOKEN})
        text = h.client.get(ACCOUNT_PATH).text
        assert "2027-01-15 00:00 PST" in text and "T00:00:00" not in text
        assert "Z</dd>" not in text


# -- FastMCP registration ----------------------------------------------------


class TestRegistration:
    def test_register_account_routes_serves_the_pages(self, h: Harness) -> None:
        from fastmcp import FastMCP

        mcp = FastMCP("account-test")
        register_account_routes(
            mcp, make_cfg(), h.store, make_identity(h.store), clock=h.clock
        )
        paths = {route.path for route in mcp._additional_http_routes}  # type: ignore[attr-defined]
        assert paths == {
            "/account",
            "/account/login",
            "/account/callback",
            "/account/token",
            "/account/token/delete",
            "/account/token/recheck",
            "/account/logout",
            "/account/admin",
            "/account/admin/remove",
            "/account/admin/disable",
            "/account/admin/enable",
            "/account/admin/invalidate",
            "/account/admin/approve",
            "/account/admin/deny",
            "/account/admin/audit",
            "/account/schools",
            "/account/write-tools",
        }
        client = TestClient(mcp.http_app(), base_url=BASE, follow_redirects=False)
        response = client.get("/account")
        assert response.status_code == 200
        assert "Sign in with Microsoft" in response.text
        assert_security_headers(response)


# -- token health pages in Chinese --------------------------------------------


class TestTokenHealthChinese:
    """The invalid-token banner, the reminder and the admin columns, in both languages."""

    KEY = KEY

    def seed(self, h: Harness, **kw: Any) -> None:
        put_row(
            h.store, OID, token=CANVAS_TOKEN, canvas_user_id="42", name="Ada Canvas",
            display="Ada", upn="ada@example.test", canvas_host="canvas.example.test", **kw,
        )

    def test_the_banner_and_the_check_button(self, h: Harness) -> None:
        self.seed(h)
        h.store.mark_invalid(self.KEY, reason="canvas_token_rejected")
        sign_in(h)
        response = h.client.get(ACCOUNT_PATH, params=ZH)
        text = response.text
        assert "你的 Canvas 令牌已于 2027-01-15 失效。" in text
        assert "Canvas → 账户 → 设置 → 新建访问令牌" in text
        assert "重新检测" in text and "需要新的令牌" in text
        assert "打开学校的 Canvas 设置页" in text
        assert "stopped working" not in text and "Check again" not in text
        english = h.client.get(ACCOUNT_PATH, params=EN).text
        assert "Your Canvas token stopped working on 2027-01-15." in english
        assert not CJK.search(strip_chrome(english))

    def test_the_other_reasons(self, h: Harness) -> None:
        self.seed(h)
        sign_in(h)
        h.store.mark_invalid(self.KEY, reason="revoked_by_admin")
        text = h.client.get(ACCOUNT_PATH, params=ZH).text
        assert "管理员已于 2027-01-15 将你的 Canvas 令牌标记为失效。" in text
        assert "重新检测" not in text
        self.seed(h)  # a fresh token clears the mark
        h.store.mark_invalid(self.KEY, reason="decrypt_failed")
        assert "服务器自 2027-01-15 起无法读取你保存的 Canvas 令牌。" in h.client.get(
            ACCOUNT_PATH, params=ZH
        ).text

    def test_the_expiry_reminder_and_the_date_field(self, h: Harness) -> None:
        self.seed(h, expires_hint_at=int(datetime(2027, 1, 20, tzinfo=UTC).timestamp()))
        sign_in(h)
        text = h.client.get(ACCOUNT_PATH, params=ZH).text
        assert "你的 Canvas 令牌将于 2027-01-20 到期。" in text
        assert "令牌到期日（可选）" in text and "令牌到期日" in text

    def test_the_recheck_notices(self, h: Harness) -> None:
        self.seed(h)
        h.store.mark_invalid(self.KEY, reason="canvas_token_rejected")
        sign_in(h)
        use_lang(h, "zh")
        csrf = csrf_of(h)
        h.whoami_result = CanvasCheckError("invalid")
        assert "Canvas 仍然拒绝这个令牌" in post_form(h, "/account/token/recheck", {"csrf": csrf}).text
        h.now += 61
        h.whoami_result = CanvasIdentity("42", "Ada Canvas")
        restored = post_form(h, "/account/token/recheck", {"csrf": csrf})
        assert "Canvas 接受了这个令牌，已恢复使用。" in restored.text

    def test_the_identity_confirmation_and_the_bad_date(self, h: Harness) -> None:
        self.seed(h)
        sign_in(h)
        use_lang(h, "zh")
        csrf = csrf_of(h)
        h.whoami_result = CanvasIdentity("99", "Grace")
        changed = post_form(h, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN})
        assert changed.status_code == 409
        assert "这个令牌属于另一个 Canvas 用户" in changed.text
        assert "我确认要换成另一个 Canvas 用户的令牌" in changed.text
        bad = post_form(
            h, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN, "expires_on": "2020-01-01"}
        )
        assert "到期日无效" in bad.text

    def test_the_admin_columns_and_filter(self, h: Harness) -> None:
        self.seed(h)
        put_row(
            h.store, OID_2, token="9~" + "Q" * 62, name="Bob", upn="bob@example.test",
            canvas_host="canvas.example.test",
        )
        h.store.mark_invalid(KEY_2, reason="canvas_token_rejected")
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        text = h.client.get("/account/admin", params=ZH).text
        assert "<th>状态</th>" in text and "<th>最近验证</th>" in text
        assert "需重新绑定" in text and "Canvas 拒绝了令牌" in text and "失效时间" in text
        assert "1 个绑定需要重新录入令牌（共 2 个），0 个用户已停用。" in text
        assert "标记为失效" in text and "只看需要重新绑定的" in text
        assert "Needs re-enroll" not in text and "Mark as invalid" not in text
        filtered = h.client.get("/account/admin", params={"filter": "needs_reenroll", **ZH}).text
        assert "显示全部" in filtered


# -- write tools in Chinese -----------------------------------------------------


class TestWriteToolsChinese:
    """The Write tools section and its notices, in both languages."""

    OFFERED = ["list_courses", "send_message", "submit_assignment", "create_assignment"]

    def rig(self, tmp_path: pathlib.Path) -> Harness:
        from canvas_mcp.core.selfhost.tool_prefs import WriteToolCatalog

        async def listing() -> list[str]:
            return list(self.OFFERED)

        return build_harness(
            tmp_path,
            write_tools=WriteToolCatalog(
                ceiling={"send_message", "create_assignment"}, list_registered=listing
            ),
        )

    def test_the_section_the_layers_and_the_notes(self, tmp_path: pathlib.Path) -> None:
        h = self.rig(tmp_path)
        sign_in(h)
        text = h.client.get(ACCOUNT_PATH, params=ZH).text
        assert "<h2>写工具</h2>" in text
        assert "服务器允许" in text and "你已开启" in text and "课程允许" in text
        assert "写工具仍然会先预览并要求确认" in text
        assert "开启新的对话或重新连接连接器" in text
        assert "<legend>站内信</legend>" in text and "<legend>作业提交与评论</legend>" in text
        assert "<legend>其他写工具</legend>" in text
        assert "以你的名义向你指定的人发送 Canvas 站内信" in text  # send_message
        assert "以你的名义修改 Canvas 中的内容。" in text  # create_assignment, the generic note
        assert "本服务器未开放" in text  # submit_assignment is over the ceiling
        assert "保存" in text and "全部关闭" in text
        for english in ("The server allows it", "Turn all off", "not offered on this server", "Write tools"):
            assert english not in text
        english = h.client.get(ACCOUNT_PATH, params=EN).text
        assert "<h2>Write tools</h2>" in english
        assert not CJK.search(strip_chrome(english))

    def test_the_notices(self, tmp_path: pathlib.Path) -> None:
        h = self.rig(tmp_path)
        sign_in(h)
        use_lang(h, "zh")
        csrf = csrf_of(h)
        saved = post_form(h, "/account/write-tools", {"csrf": csrf, "tool.send_message": "1"})
        assert "写工具设置已保存。" in saved.text
        again = post_form(h, "/account/write-tools", {"csrf": csrf, "tool.send_message": "1"})
        assert "没有需要保存的更改。" in again.text
        h.now += 700
        refused = post_form(
            h, "/account/write-tools", {"csrf": csrf, "tool.send_message": "1", "tool.create_assignment": "1"}
        )
        assert refused.status_code == 403
        assert "开启写工具需要最近 10 分钟内的登录" in refused.text
        assert "needs a sign-in" not in refused.text

    def test_the_no_write_tools_notice(self, tmp_path: pathlib.Path) -> None:
        from canvas_mcp.core.selfhost.tool_prefs import WriteToolCatalog

        async def listing() -> list[str]:
            return ["list_courses"]

        h = build_harness(tmp_path, write_tools=WriteToolCatalog(ceiling=set(), list_registered=listing))
        sign_in(h)
        text = h.client.get(ACCOUNT_PATH, params=ZH).text
        assert "本服务器没有开放任何写工具" in text
