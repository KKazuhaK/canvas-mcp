"""The shared Entra ceremony exercises real signed ID tokens and PKCE offline."""

from urllib.parse import parse_qs, urlsplit

import pytest

from canvas_mcp.core.selfhost.login.ceremony import FLOW_COOKIE

from .stack import ALICE, Browser


def callback(stack, start):
    params = {
        k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()
    }
    stack.idp.set_user(ALICE, params["nonce"])
    return stack.idp.authorize(start.headers["location"])


def test_entra_signed_token_pkce_and_one_time_callback(stack):
    browser = Browser(stack)
    start = browser.get("/auth/login/entra")
    url = callback(stack, start)
    completed = browser.get(url)
    assert completed.status_code == 303
    assert completed.headers["location"] == "/account/"
    assert browser.api("GET", "/me").status_code == 200
    assert stack.idp.token_requests == 1
    replay = browser.get(url)
    assert "state_invalid" in replay.headers["location"]
    assert stack.idp.token_requests == 1
    assert "Max-Age=0" in replay.headers["set-cookie"]


def test_callback_cannot_move_to_another_browser(stack):
    browser = Browser(stack)
    url = callback(stack, browser.get("/auth/login/entra"))
    attacker = Browser(stack)
    refused = attacker.get(url)
    assert "state_invalid" in refused.headers["location"]
    assert stack.idp.token_requests == 0
    assert browser.get(url).headers["location"] == "/account/"


@pytest.mark.parametrize(
    "path", ["/auth/callback/missing", "/auth/callback/oidc/missing"]
)
@pytest.mark.parametrize("method", ["GET", "POST", "HEAD", "OPTIONS"])
def test_every_callback_response_clears_flow_cookie(stack, path, method):
    response = stack.client.request(method, path)
    assert response.status_code == (404 if method == "GET" else 405)
    assert FLOW_COOKIE in response.headers["set-cookie"]
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert response.headers["referrer-policy"] == "no-referrer"


def test_entra_scopes_never_request_api_or_refresh_credentials(stack):
    start = stack.client.get("/auth/login/entra")
    params = parse_qs(urlsplit(start.headers["location"]).query)
    assert params["scope"] == ["openid profile email"]
    assert params["response_mode"] == ["query"]
    assert params["prompt"] == ["select_account"]
    assert params["code_challenge_method"] == ["S256"]


@pytest.mark.parametrize(
    "claims",
    [
        {"tid": "99999999-2222-3333-4444-555555555555"},
        {"oid": "not-an-object-id"},
        {"iss": "https://other.example.test/"},
        {"aud": "another-client"},
        {"nonce": "another-nonce"},
    ],
)
def test_entra_rejects_untrusted_identity_claims(stack, claims):
    browser = Browser(stack)
    start = browser.get("/auth/login/entra")
    url = callback(stack, start)
    stack.idp.provider.id_token_override = claims
    response = browser.get(url)
    assert response.status_code == 303
    assert "/account/sign-in?error=" in response.headers["location"]
    assert browser.api("GET", "/me").status_code == 401
    assert "Max-Age=0" in response.headers["set-cookie"]


def test_callback_exception_also_clears_flow_cookie(stack, monkeypatch):
    from canvas_mcp.core.selfhost.account_core import AccountCore

    async def unavailable(self, request):
        raise RuntimeError("private backend details")

    monkeypatch.setattr(AccountCore, "_resolve_session", unavailable)
    response = stack.client.get("/auth/callback/entra?state=x&code=y")
    assert response.status_code == 303
    assert (
        response.headers["location"] == "/account/sign-in?error=token_store_unavailable"
    )
    assert "private backend" not in response.text
    assert "Max-Age=0" in response.headers["set-cookie"]


@pytest.mark.parametrize("claims,code", [
    ({"tid": "99999999-2222-3333-4444-555555555555"}, "wrong_tenant"),
    ({"oid": "not-an-object-id"}, "bad_subject"),
    ({"roles": "Canvas.Owner"}, "bad_roles"),
])
def test_entra_reducer_preserves_closed_refusal_codes(stack, claims, code):
    browser = Browser(stack)
    start = browser.get("/auth/login/entra")
    url = callback(stack, start)
    stack.idp.provider.id_token_override = claims
    response = browser.get(url)
    assert response.headers["location"] == "/account/sign-in?error=" + code
