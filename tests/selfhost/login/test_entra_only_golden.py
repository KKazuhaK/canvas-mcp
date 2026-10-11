"""Entra-only v1 uses native ceremonies and mandatory React/API composition."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from canvas_mcp.core.selfhost import account_core as web
from canvas_mcp.core.selfhost.login.ceremony import FLOW_COOKIE
from canvas_mcp.core.selfhost.login.routes import build_login_routes

from ..authz.stack import ALICE, Browser, Stack

SESSION_KEYS = {"v", "acct", "pid", "name", "upn", "owner", "iat", "exp", "csrf", "ep"}
LOGIN_PATHS = {
    "/auth/login",
    "/auth/login/{provider}",
    "/auth/login/oidc/{slug}",
    "/auth/callback/{provider}",
    "/auth/callback/oidc/{slug}",
}


def account_app(stack: Stack) -> web.AccountCore:
    """Find the registered core, preserving actual runtime configuration."""
    route = next(
        r for r in stack.mcp._additional_http_routes if r.path == "/auth/login"
    )
    handler = route.app.handler
    cells = dict(zip(handler.__code__.co_freevars, handler.__closure__, strict=True))
    app = cells["app"].cell_contents
    assert isinstance(app, web.AccountCore)
    return app


def test_native_login_route_contract(entra_local: Stack):
    app = account_app(entra_local)
    assert {r.path for r in build_login_routes(app)} == LOGIN_PATHS
    assert app.external.app is app and app.logins.providers.keys() == {"entra"}


@pytest.mark.parametrize(
    "path",
    [
        "/auth/login/google",
        "/auth/login/github",
        "/auth/login/oidc/unknown",
        "/auth/callback/google",
        "/auth/callback/oidc/unknown",
    ],
)
def test_unknown_provider_creates_no_ceremony(entra_local: Stack, path):
    response = entra_local.client.get(path)
    assert response.status_code == 404
    cookie = response.headers.get("set-cookie", "")
    assert FLOW_COOKIE not in cookie or "Max-Age=0" in cookie


def test_bare_login_selects_the_only_provider(entra_local: Stack):
    response = entra_local.client.get("/auth/login")
    assert (
        response.status_code == 303
        and response.headers["location"] == "/auth/login/entra"
    )


@pytest.mark.parametrize(
    "path", ["/auth/login", "/auth/login/entra", "/auth/callback/entra"]
)
def test_browser_ceremonies_are_get_only(entra_local: Stack, path):
    response = entra_local.client.post(path)
    assert response.status_code == 405 and response.headers["allow"] == "GET"
    assert response.headers["cache-control"] == "no-store"


def test_provider_payload(entra_react: Stack):
    body = entra_react.client.get("/api/v1/providers").json()
    assert body["mcp_url"] == "https://canvas.example.test/mcp"
    assert body["providers"] == [
        {
            "id": "entra",
            "kind": "oidc",
            "name": "Microsoft",
            "icon": "microsoft",
            "start_url": "/auth/login/entra",
        }
    ]


def test_identities_refuse_without_linking(entra_react: Stack):
    browser = Browser(entra_react)
    browser.sign_in(ALICE)
    assert browser.api("GET", "/me").json()["features"]["identities"] is False
    assert browser.api("GET", "/me/identities").status_code == 404


@pytest.mark.parametrize(
    "path", ["/account", "/account/", "/account/admin", "/account/sign-in-methods"]
)
def test_react_shell(entra_react: Stack, path):
    response = entra_react.client.get(path)
    assert response.status_code == 200 and '<div id="root"></div>' in response.text
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_authorize_request_shape(entra_local: Stack):
    response = entra_local.new_client().get("/auth/login/entra")
    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert location.netloc == "login.microsoftonline.com"
    assert location.path.endswith("/protocol/openid-connect/auth")
    query = {k: v[0] for k, v in parse_qs(location.query).items()}
    assert query["redirect_uri"] == "https://canvas.example.test/auth/callback/entra"
    assert query["scope"] == "openid profile email" and query["prompt"] == "select_account"
    assert (
        query["response_mode"] == "query" and query["code_challenge_method"] == "S256"
    )
    assert len(query["state"]) >= 40 and len(query["nonce"]) >= 40


def test_cookie_contains_binding_and_no_verifier(entra_local: Stack):
    client = entra_local.new_client()
    response = client.get("/auth/login/entra")
    value = client.cookies.get(FLOW_COOKIE)
    payload = web._CookieCodec(entra_local.settings.account_session_secret).unseal(
        FLOW_COOKIE, value
    )
    assert payload is not None and set(payload) == {"v", "s", "b", "p", "pp", "iat"}
    assert payload["p"] == "entra" and payload["pp"] == "sign_in"
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie


def test_session_names_native_account(entra_local: Stack):
    browser = Browser(entra_local)
    browser.sign_in(ALICE)
    value = browser.client.cookies.get(web.SESSION_COOKIE)
    payload = web._CookieCodec(entra_local.settings.account_session_secret).unseal(
        web.SESSION_COOKIE, value
    )
    assert payload is not None and set(payload) == SESSION_KEYS
    assert payload["pid"] == "entra" and payload["v"] == 3
    assert (
        payload["acct"] == entra_local.account_of(ALICE) and len(payload["acct"]) == 36
    )
    assert ALICE.oid not in value and ALICE.upn not in value


@pytest.mark.parametrize(
    ("state", "error", "expected"),
    [
        ("forged", "access_denied", "provider_error"),
        ("", "access_denied", "provider_error"),
        ("forged", None, "state_invalid"),
    ],
)
def test_callback_refuses_before_exchange(entra_local: Stack, state, error, expected):
    client = entra_local.new_client()
    client.get("/auth/login/entra")
    params = {"code": "unused", "state": state}
    if error is not None:
        params["error"] = error
    response = client.get("/auth/callback/entra", params=params)
    assert response.status_code == 303
    assert parse_qs(urlsplit(response.headers["location"]).query)["error"] == [expected]
    assert client.cookies.get(web.SESSION_COOKIE) is None
    assert entra_local.idp.provider.counts["token"] == 0
    assert any(
        h.startswith(FLOW_COOKIE + "=") and "Max-Age=0" in h
        for h in response.headers.get_list("set-cookie")
    )
