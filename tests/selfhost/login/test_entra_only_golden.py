"""An Entra-only deployment behaves exactly as it did before the other providers existed.

Frozen facts about routes, the provider list, the redirect to Entra, the cookies, the callback's
order of checks, the pages and the modules that are (not) loaded. They hold in ``entra_proxy`` mode
and in ``local`` mode, with the server-rendered pages and with the single-page app.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from canvas_mcp.core.selfhost import account_web as web

from ..authz.stack import ALICE, Browser, Stack

LEGACY_PATHS = frozenset(
    {
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
)
LOCAL_EXTRA = frozenset(
    {"/account/consent", "/account/grants/revoke", "/account/admin/grants/revoke"}
)
TODAYS_PROVIDERS = {
    "providers": [
        {"id": "entra", "kind": "oidc", "name": "Microsoft", "icon": "microsoft", "start_url": "/account/login"}
    ],
    "mcp_url": "https://canvas.example.test/mcp",
}
SESSION_KEYS = {"v", "acct", "pid", "name", "upn", "owner", "iat", "exp", "csrf", "ep"}


def account_app(stack: Stack) -> web._AccountApp:
    """The account application behind the routes of a running stack (found on a route's endpoint)."""
    for route in stack.mcp._additional_http_routes:
        if getattr(route, "path", "") == "/account/login":
            endpoint = route.endpoint  # type: ignore[attr-defined]
            names = endpoint.__code__.co_freevars
            return endpoint.__closure__[names.index("self")].cell_contents  # type: ignore[no-any-return]
    raise AssertionError("no /account/login route")


def server_paths(stack: Stack) -> set[str]:
    return {getattr(r, "path", "") for r in stack.mcp._additional_http_routes}


@pytest.fixture(params=["entra_proxy", "entra_local"])
def either(request: pytest.FixtureRequest) -> Stack:
    stack: Stack = request.getfixturevalue(request.param)
    return stack


class TestRoutes:
    def test_the_legacy_route_table_is_exactly_todays(self, either: Stack) -> None:
        app = account_app(either)
        paths = {path for path, _ in app.route_table()}
        expected = LEGACY_PATHS | (LOCAL_EXTRA if either.settings.authz_mode == "local" else frozenset())
        assert paths == expected
        for new in ("/account/login/entra", "/account/login/google", "/account/sign-in-methods"):
            assert new not in server_paths(either)

    def test_no_provider_route_exists(self, either: Stack) -> None:
        for path in (
            "/account/login/entra", "/account/login/google", "/account/login/github",
            "/account/login/oidc/x", "/account/callback/google", "/account/identities/link",
            "/account/sign-in-methods",
        ):
            assert path not in server_paths(either)
            assert either.client.get(path).status_code in (404, 405, 401), path

    def test_react_keeps_exactly_the_two_sign_in_halves(self, entra_react: Stack) -> None:
        app = account_app(entra_react)
        assert {r.path for r in app.routes()} == {"/account/login", "/account/callback"}  # type: ignore[attr-defined]


class TestProvidersAndFeatures:
    def test_the_provider_list_is_todays_payload(self, entra_react: Stack) -> None:
        assert entra_react.client.get("/account/api/providers").json() == TODAYS_PROVIDERS

    def test_identities_are_not_a_feature_and_the_api_has_no_identity_route(self, entra_react: Stack) -> None:
        browser = Browser(entra_react, react=True)
        browser.sign_in(ALICE)
        me = browser.api("GET", "/me").json()
        assert me["features"]["identities"] is False
        assert browser.api("GET", "/me/identities").status_code == 404


class TestTheEntraRedirectAndCookies:
    def test_the_authorize_redirect(self, either: Stack) -> None:
        response = either.new_client().get("/account/login")
        assert response.status_code == 302
        location = urlsplit(response.headers["location"])
        assert location.netloc == "login.microsoftonline.com"
        assert location.path.endswith("/oauth2/v2.0/authorize")
        query = {k: v[0] for k, v in parse_qs(location.query).items()}
        assert set(query) == {
            "client_id", "response_type", "redirect_uri", "response_mode", "scope", "state", "nonce",
            "code_challenge", "code_challenge_method", "prompt",
        }
        assert query["redirect_uri"] == "https://canvas.example.test/account/callback"
        assert query["scope"] == "openid profile" and query["prompt"] == "select_account"
        assert query["response_mode"] == "query" and query["code_challenge_method"] == "S256"
        assert list(parse_qs(location.query)) == [
            "client_id", "response_type", "redirect_uri", "response_mode", "scope", "state", "nonce",
            "code_challenge", "code_challenge_method", "prompt",
        ]

    def test_the_login_cookie_payload_keys(self, either: Stack) -> None:
        client = either.new_client()
        response = client.get("/account/login")
        cookie = next(
            h for h in response.headers.get_list("set-cookie") if h.startswith("__Host-cmcp_login=")
        )
        value = cookie.split(";", 1)[0].split("=", 1)[1]
        codec = web._CookieCodec(either.settings.account_session_secret)
        payload = codec.unseal("__Host-cmcp_login", value)
        assert payload is not None and set(payload) == {"state", "nonce", "verifier", "iat"}
        assert "__Host-cmcp_flow" not in str(response.headers)

    def test_the_session_payload_keys(self, either: Stack) -> None:
        browser = Browser(either)
        browser.sign_in(ALICE)
        value = browser.client.cookies.get("__Host-cmcp_session")
        codec = web._CookieCodec(either.settings.account_session_secret)
        payload = codec.unseal("__Host-cmcp_session", value)
        assert payload is not None and set(payload) == SESSION_KEYS
        assert payload["pid"] == "entra" and payload["v"] == 3


class TestCallbackOrder:
    def test_state_is_checked_before_the_providers_error(self, either: Stack) -> None:
        client = either.new_client()
        client.get("/account/login")
        wrong = client.get("/account/callback", params={"error": "access_denied", "state": "forged"})
        assert wrong.status_code == 400 and "invalid or expired" in wrong.text
        client = either.new_client()
        login = client.get("/account/login")
        state = parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
        right = client.get("/account/callback", params={"error": "access_denied", "state": state})
        assert right.status_code == 403 and "not completed" in right.text and "access_denied" in right.text

    def test_the_callback_still_clears_the_login_cookie(self, either: Stack) -> None:
        client = either.new_client()
        client.get("/account/login")
        response = client.get("/account/callback", params={"state": "x"})
        assert any(
            h.startswith("__Host-cmcp_login=") and "Max-Age=0" in h
            for h in response.headers.get_list("set-cookie")
        )


class TestPages:
    def test_the_signed_out_page_offers_microsoft_only(self, either: Stack) -> None:
        page = either.client.get("/account")
        assert "Sign in with Microsoft" in page.text and 'href="/account/login"' in page.text
        for other in ("Google", "GitHub", "providers", "pico"):
            assert other not in page.text

    def test_login_does_not_choose_anything(self, either: Stack) -> None:
        assert either.new_client().get("/account/login").status_code == 302

    def test_the_identity_line_still_says_microsoft(self, either: Stack) -> None:
        browser = Browser(either)
        browser.sign_in(ALICE)
        assert "Microsoft account: alice@example.test" in browser.get("/account").text


def test_no_login_runtime_is_built(either: Stack) -> None:
    assert account_app(either).logins is None
    assert account_app(either).external is None
    assert either.settings.login_providers.single and either.settings.entra_enabled
