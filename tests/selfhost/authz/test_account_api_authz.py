"""The consent and connected-apps endpoints of the JSON API (``ACCOUNT_UI=react``, local mode).

Driven over the whole stack with a scripted browser, on SQLite or PostgreSQL. The routes are
always in the API's route table, so the web app and the server list the same ones; every one
of them answers ``not_found`` before anything else unless ``SELFHOST_AUTH_MODE=local``.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from dbbackend import raw_sql

from canvas_mcp.core.selfhost import account_api
from canvas_mcp.core.selfhost.account_api import API_PREFIX

from ..test_account_api_parity import LEGACY_TO_API, LOCAL_LEGACY_TO_API
from .stack import (
    ALICE,
    AUDIENCE,
    BASE,
    BOB,
    CLAUDE_REDIRECT,
    ISSUER,
    LOOPBACK_REDIRECT,
    OWNER,
    Browser,
    Stack,
    cimd_document,
    local_stack,
    pkce,
    query_of,
)
from .test_account_grant_ops import make_app
from .test_authz_flows import start_request

CIMD_URL = "https://client.example/cimd.json"
TXN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
GRANT_VIEW_KEYS = {"id", "client", "redirect_host", "created_at", "last_used_at", "expires_at"}
CLIENT_KEYS = {"kind", "label", "name", "host", "verified"}


@pytest.fixture
def react(react_stack: Stack) -> Stack:
    return react_stack


def signed_in(stack: Stack, user: Any = ALICE) -> Browser:
    browser = Browser(stack, react=True)
    browser.sign_in(user)
    return browser


def open_request(stack: Stack, browser: Browser | None = None, user: Any = ALICE, **kw: Any) -> tuple[Browser, str]:
    """A request started by ``browser`` (a fresh one, signed in as ``user`` unless it is given)."""
    given = browser is not None
    browser = browser or Browser(stack, react=True)
    _, txn, url = start_request(stack, browser, **kw)
    if not given:
        login = browser.get(url)
        assert login.status_code == 302
        browser.entra_login(user, login)
    return browser, txn


def get_consent(browser: Browser, txn: str, **headers: str) -> Any:
    return browser.api("GET", f"/consent/{txn}", **headers)


def decide(browser: Browser, txn: str, decision: Any = "approve", **kw: Any) -> Any:
    return browser.api(
        "POST", f"/consent/{txn}", body={"decision": decision}, csrf=kw.pop("csrf", None) or browser.csrf_token(), **kw
    )


def error_of(response: Any, status: int, code: str) -> None:
    assert response.status_code == status, (response.status_code, response.text)
    body = response.json()
    assert body["error"]["code"] == code, body
    assert response.headers["cache-control"] == "no-store"


def location_query(url: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(url).query)


# ------------------------------------------------------------------------- the route table


class TestRouteTable:
    def test_the_legacy_pages_and_the_api_list_the_same_routes_with_the_local_server(self, react: Stack) -> None:
        app = make_app(react)
        legacy = {(method, path) for path, handlers in app.route_table() for method in handlers}
        assert legacy == set(LEGACY_TO_API) | set(LOCAL_LEGACY_TO_API)
        registered = account_api.ApiApp(app).route_keys()
        for targets in LOCAL_LEGACY_TO_API.values():
            for target in targets:
                assert target in registered, target

    def test_without_the_local_server_the_legacy_pages_have_none_of_them(self, react: Stack) -> None:
        app = make_app(react, with_authz=False)
        legacy = {(method, path) for path, handlers in app.route_table() for method in handlers}
        assert legacy == set(LEGACY_TO_API)

    def test_the_react_ui_registers_only_the_two_halves_of_the_sign_in(self, react: Stack) -> None:
        # the consent screen and the connected apps are the single-page app's now
        from canvas_mcp.core.selfhost.account_web import build_account_app

        legacy = make_app(react)
        assert {"/account/consent", "/account/grants/revoke"} <= {route.path for route in legacy.routes()}
        reactive = build_account_app(
            legacy.cfg, react.store, react.runtime.identity, access=react.runtime.access, clock=react.clock,
            authz=react.authz, ui="react",
        )
        assert {route.path for route in reactive.routes()} == {"/account/login", "/account/callback"}


class TestFeaturesAndThePrefix:
    def test_me_says_the_screens_exist(self, react: Stack) -> None:
        react.enroll(ALICE)
        browser = signed_in(react)
        features = browser.api("GET", "/me").json()["features"]
        assert features["consent"] is True and features["connected_apps"] is True
        assert features["identities"] is False

    def test_a_waiting_account_has_the_consent_screen_but_no_connected_apps(self, tmp_path, monkeypatch, react_env) -> None:
        with local_stack(tmp_path, monkeypatch, env={**react_env, "ACCESS_POLICY": "approval"}) as stack:
            browser = signed_in(stack)
            features = browser.api("GET", "/me").json()["features"]
            assert features["consent"] is True and features["connected_apps"] is False
            error_of(browser.api("GET", "/me/grants"), 403, "pending_approval")

    def test_in_the_default_mode_every_route_is_not_found_whatever_the_caller(self, tmp_path, monkeypatch, react_env) -> None:
        env = {**react_env, "SELFHOST_AUTH_MODE": "entra_proxy"}
        with local_stack(tmp_path, monkeypatch, env=env) as stack:
            anonymous = Browser(stack, react=True)
            signed = signed_in(stack)
            txn = "A" * 43
            gid = "00000000-0000-4000-8000-000000000001"
            calls = [
                ("GET", f"/consent/{txn}", None), ("POST", f"/consent/{txn}", {"decision": "deny"}),
                ("PUT", f"/consent/{txn}", None), ("GET", "/me/grants", None),
                ("DELETE", f"/me/grants/{gid}", None), ("GET", f"/admin/accounts/{gid}/grants", None),
                ("DELETE", f"/admin/grants/{gid}", None), ("OPTIONS", "/me/grants", None),
            ]
            for who in (anonymous, signed):
                for method, path, body in calls:
                    response = who.api(method, path, body=body, csrf="x")
                    error_of(response, 404, "not_found")
            features = signed.api("GET", "/me").json()["features"]
            assert features["consent"] is False and features["connected_apps"] is False


# ------------------------------------------------------------------------- GET /consent/{id}


class TestGetConsent:
    def test_a_self_registered_app_is_shown_as_unverified(self, react: Stack) -> None:
        browser, txn = open_request(react)
        response = get_consent(browser, txn)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        body = response.json()
        assert set(body) == {"client", "redirect", "scopes", "account", "can_approve", "expires_at"}
        assert body["client"] == {"kind": "dcr", "label": "Test app", "name": "Test app", "host": None, "verified": False}
        assert body["redirect"] == {"host": "claude.ai", "loopback": False}
        assert body["scopes"] == [{"name": "Canvas.Access"}]
        assert body["account"] == {"display_name": "Alice", "username": "alice@example.test"}
        assert body["can_approve"] is True
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", body["expires_at"])
        assert response.headers["x-content-type-options"] == "nosniff"
        # looking does not use the request up
        assert get_consent(browser, txn).status_code == 200
        assert raw_sql(react.store, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 0

    def test_an_app_that_identifies_itself_by_a_domain_is_verified(self, react: Stack) -> None:
        react.cimd.serve(CIMD_URL, cimd_document(CIMD_URL, client_name="Client Example"))
        browser, txn = open_request(react, client_id=CIMD_URL)
        client = get_consent(browser, txn).json()["client"]
        assert client == {
            "kind": "cimd", "label": "client.example", "name": "Client Example", "host": "client.example",
            "verified": True,
        }

    def test_a_second_person_connecting_within_the_documents_freshness_window_is_not_refused(self, react: Stack) -> None:
        # The metadata document is shared by everybody who uses the app. /authorize reuses the copy
        # an earlier request fetched, and the consent screen must accept that same copy.
        react.cimd.serve(CIMD_URL, cimd_document(CIMD_URL, client_name="Client Example"))
        react.enroll(ALICE)
        react.enroll(BOB)
        react.tokens_for(ALICE, client_id=CIMD_URL)
        calls = len(react.cimd.calls)
        react.clock.advance(120)  # still fresh (the fake host says max-age=300)
        browser, txn = open_request(react, user=BOB, client_id=CIMD_URL)
        assert len(react.cimd.calls) == calls  # authorize used the stored copy
        shown = get_consent(browser, txn)
        assert shown.status_code == 200 and shown.json()["client"]["host"] == "client.example"
        assert decide(browser, txn).status_code == 200

    def test_a_loopback_return_address_is_flagged(self, react: Stack) -> None:
        client_id = react.register(LOOPBACK_REDIRECT)
        browser, txn = open_request(react, client_id=client_id, redirect_uri=LOOPBACK_REDIRECT)
        redirect = get_consent(browser, txn).json()["redirect"]
        assert redirect == {"host": "127.0.0.1", "loopback": True}

    def test_markup_in_a_name_is_data_not_markup(self, react: Stack) -> None:
        client_id = react.register(CLAUDE_REDIRECT, client_name="<img src=x onerror=alert(1)>")
        browser, txn = open_request(react, client_id=client_id)
        response = get_consent(browser, txn)
        assert response.json()["client"]["name"] == "<img src=x onerror=alert(1)>"
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["x-content-type-options"] == "nosniff"

    def test_a_waiting_account_may_look_but_not_approve(self, tmp_path, monkeypatch, react_env) -> None:
        with local_stack(tmp_path, monkeypatch, env={**react_env, "ACCESS_POLICY": "approval"}) as stack:
            browser, txn = open_request(stack)
            assert get_consent(browser, txn).json()["can_approve"] is False

    def test_it_needs_a_session(self, react: Stack) -> None:
        _, txn, _ = start_request(react)
        error_of(get_consent(Browser(react, react=True), txn), 401, "not_authenticated")

    def test_it_needs_the_browser_that_started_the_request(self, react: Stack) -> None:
        _, txn = open_request(react)
        other = signed_in(react)  # signed in, but its binding cookie is not the request's
        error_of(get_consent(other, txn), 400, "authorization_invalid")
        elsewhere = signed_in(react, BOB)
        error_of(get_consent(elsewhere, txn), 400, "authorization_invalid")

    @pytest.mark.parametrize("txn", ["x", "A" * 42, "A" * 44, "A" * 43 + "=", "a b" * 15, "%2e" * 20])
    def test_a_malformed_or_unknown_id_is_authorization_invalid(self, react: Stack, txn: str) -> None:
        browser, _ = open_request(react)
        error_of(get_consent(browser, txn), 400, "authorization_invalid")
        error_of(get_consent(browser, "B" * 43), 400, "authorization_invalid")

    def test_a_request_older_than_ten_minutes_is_gone(self, react: Stack) -> None:
        browser, txn = open_request(react)
        react.clock.advance(601)
        error_of(get_consent(browser, txn), 400, "authorization_invalid")

    def test_a_cross_site_fetch_is_refused(self, react: Stack) -> None:
        browser, txn = open_request(react)
        error_of(get_consent(browser, txn, **{"Sec-Fetch-Site": "cross-site"}), 403, "origin_not_allowed")

    def test_a_registration_that_expired_meanwhile_is_client_unavailable(self, react: Stack) -> None:
        browser, txn = open_request(react)
        raw_sql(react.store, "UPDATE oauth_clients SET expires_at = 1")
        error_of(get_consent(browser, txn), 409, "client_unavailable")

    def test_a_database_error_is_a_closed_503(self, react: Stack, monkeypatch) -> None:
        browser, txn = open_request(react)

        def broken(*a: Any, **k: Any) -> Any:
            raise RuntimeError("secret detail")

        monkeypatch.setattr(react.authz.consent, "describe", broken)
        response = get_consent(browser, txn)
        error_of(response, 503, "token_store_unavailable")
        assert "secret" not in response.text


# ------------------------------------------------------------------------- POST /consent/{id}


class TestDecide:
    def test_approve_returns_the_apps_redirect_with_the_code_state_and_one_issuer(self, react: Stack) -> None:
        browser, txn = open_request(react)
        response = decide(browser, txn)
        assert response.status_code == 200 and set(response.json()) == {"redirect_to"}
        target = response.json()["redirect_to"]
        assert target.startswith(CLAUDE_REDIRECT + "?")
        q = location_query(target)
        assert q["state"] == ["state-1"] and q["iss"] == [ISSUER] and len(q["code"]) == 1
        assert raw_sql(react.store, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 1
        assert response.headers["cache-control"] == "no-store"

    def test_a_whole_connection_through_the_json_api(self, react: Stack) -> None:
        react.enroll(ALICE)
        client_id = react.register(CLAUDE_REDIRECT)
        verifier, challenge = pkce()
        landed = Browser(react, react=True).connect(
            react.authorize_params(client_id, challenge), ALICE
        )
        assert landed.query["iss"] == ISSUER and landed.url.startswith(CLAUDE_REDIRECT + "?")
        response = react.token(
            grant_type="authorization_code", code=landed.query["code"], client_id=client_id,
            redirect_uri=CLAUDE_REDIRECT, code_verifier=verifier, resource=AUDIENCE,
        )
        assert response.status_code == 200, response.text
        assert react.whoami(response.json()["access_token"]) == react.account_of(ALICE)

    def test_the_redirect_carries_exactly_the_code_state_and_issuer(self, react: Stack) -> None:
        browser, txn = open_request(react)
        target = decide(browser, txn).json()["redirect_to"]
        assert set(location_query(target)) == {"code", "state", "iss"}
        assert target.count("iss=") == 1

    def test_deny_returns_access_denied_with_state_and_issuer_and_no_code(self, react: Stack) -> None:
        browser, txn = open_request(react)
        target = decide(browser, txn, "deny").json()["redirect_to"]
        q = location_query(target)
        assert q["error"] == ["access_denied"] and q["state"] == ["state-1"] and q["iss"] == [ISSUER]
        assert "code" not in q
        assert raw_sql(react.store, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 0

    def test_a_decision_is_single_use(self, react: Stack) -> None:
        browser, txn = open_request(react)
        assert decide(browser, txn).status_code == 200
        error_of(decide(browser, txn), 400, "authorization_invalid")
        error_of(decide(browser, txn, "deny"), 400, "authorization_invalid")
        error_of(get_consent(browser, txn), 400, "authorization_invalid")
        assert raw_sql(react.store, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 1

    def test_the_pipeline_of_every_mutation_applies(self, react: Stack) -> None:
        browser, txn = open_request(react)
        path = f"/consent/{txn}"
        csrf = browser.csrf_token()
        body = {"decision": "approve"}
        error_of(browser.api("POST", path, body=body), 403, "csrf_invalid")
        error_of(browser.api("POST", path, body=body, csrf="wrong"), 403, "csrf_invalid")
        foreign = browser.api("POST", path, body=body, csrf=csrf, Origin="https://evil.example")
        assert foreign.status_code == 403  # the host/origin guard answers before the API does
        error_of(browser.api("POST", path, body=body, csrf=csrf, **{"Sec-Fetch-Site": "cross-site"}), 403, "origin_not_allowed")
        wrong_type = browser.client.post(
            "/account/api" + path, content=b"decision=approve",
            headers={"Origin": BASE, "X-CSRF-Token": csrf, "Content-Type": "application/x-www-form-urlencoded"},
        )
        error_of(wrong_type, 415, "unsupported_media_type")
        for bad in ({}, {"decision": "maybe"}, {"decision": None}, {"decision": ["approve"]}, {"decision": "approve", "x": 1}):
            error_of(browser.api("POST", path, body=bad, csrf=csrf), 422, "validation_failed")
        # none of that used the request up
        assert get_consent(browser, txn).status_code == 200
        assert decide(browser, txn).status_code == 200

    def test_it_needs_the_browser_that_started_the_request(self, react: Stack) -> None:
        _, txn = open_request(react)
        other = signed_in(react)
        error_of(decide(other, txn), 400, "authorization_invalid")
        assert raw_sql(react.store, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 0

    def test_a_waiting_account_cannot_approve_and_the_request_survives_for_cancel(
        self, tmp_path, monkeypatch, react_env
    ) -> None:
        with local_stack(tmp_path, monkeypatch, env={**react_env, "ACCESS_POLICY": "approval"}) as stack:
            browser, txn = open_request(stack)
            error_of(decide(browser, txn, "approve"), 403, "pending_approval")
            assert raw_sql(stack.store, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 0
            target = decide(browser, txn, "deny").json()["redirect_to"]
            assert location_query(target)["error"] == ["access_denied"]

    def test_a_registration_that_expired_before_the_decision_gets_no_redirect(self, react: Stack) -> None:
        browser, txn = open_request(react)
        raw_sql(react.store, "UPDATE oauth_clients SET expires_at = 1")
        response = decide(browser, txn)
        error_of(response, 409, "client_unavailable")
        assert "redirect_to" not in response.text
        assert raw_sql(react.store, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 0

    def test_an_allowlist_that_no_longer_has_the_uri_gets_no_redirect(self, react: Stack) -> None:
        browser, txn = open_request(react)
        react.authz.clients._allowlist = ("https://other.example/cb",)
        error_of(decide(browser, txn), 409, "client_unavailable")

    def test_a_disabled_account_has_no_session_to_decide_with(self, react: Stack) -> None:
        from canvas_mcp.core.selfhost.token_store import OPERATOR

        browser, txn = open_request(react)
        react.store.disable_principal(react.account_of(ALICE), actor=OPERATOR, reason="operator_disabled")
        response = browser.api("POST", f"/consent/{txn}", body={"decision": "approve"}, csrf="x")
        assert response.status_code in (401, 403)
        assert raw_sql(react.store, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 0


# ------------------------------------------------------------------------- connected apps


class TestMyGrants:
    def test_lists_only_my_connections_with_the_shape_the_page_needs(self, react: Stack) -> None:
        react.enroll(ALICE)
        react.enroll(BOB)
        react.tokens_for(ALICE)
        react.cimd.serve(CIMD_URL, cimd_document(CIMD_URL, client_name="Client Example"))
        react.tokens_for(ALICE, client_id=CIMD_URL)
        react.tokens_for(BOB)
        browser = signed_in(react)
        response = browser.api("GET", "/me/grants")
        assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
        grants = response.json()["grants"]
        assert len(grants) == 2
        for grant in grants:
            assert set(grant) == GRANT_VIEW_KEYS and set(grant["client"]) == CLIENT_KEYS
            assert UUID_RE.fullmatch(grant["id"]) and grant["redirect_host"] == "claude.ai"
            assert grant["created_at"] and grant["expires_at"]
        kinds = {grant["client"]["kind"]: grant["client"] for grant in grants}
        assert kinds["dcr"]["verified"] is False and kinds["dcr"]["host"] is None
        assert kinds["dcr"]["label"] == "Test app"
        assert kinds["cimd"] == {
            "kind": "cimd", "label": "client.example", "name": "Client Example", "host": "client.example",
            "verified": True,
        }
        assert "client_id" not in response.text and "cmcp_" not in response.text

    def test_last_used_follows_a_request_with_the_token(self, react: Stack) -> None:
        react.enroll(ALICE)
        _, tokens = react.tokens_for(ALICE)
        browser = signed_in(react)
        before = browser.api("GET", "/me/grants").json()["grants"][0]["last_used_at"]
        react.clock.advance(400)
        react.authz.cache.clear()
        assert react.mcp_status(tokens["access_token"]) == 200
        after = browser.api("GET", "/me/grants").json()["grants"][0]["last_used_at"]
        assert after > before  # ISO timestamps in one format order like the times

    def test_revoking_ends_the_connection_at_once(self, react: Stack) -> None:
        react.enroll(ALICE)
        client_id, tokens = react.tokens_for(ALICE)
        assert react.mcp_status(tokens["access_token"]) == 200
        browser = signed_in(react)
        gid = browser.api("GET", "/me/grants").json()["grants"][0]["id"]
        csrf = browser.csrf_token()
        gone = browser.api("DELETE", f"/me/grants/{gid}", csrf=csrf)
        assert gone.status_code == 204 and gone.content == b""
        assert react.mcp_status(tokens["access_token"]) == 401
        assert react.refresh(client_id, tokens["refresh_token"]).status_code == 401
        assert browser.api("GET", "/me/grants").json() == {"grants": []}
        reason = raw_sql(react.store, "SELECT revoked_reason, revoked_by FROM oauth_grants")[0]
        assert reason == ("user_revoked", react.account_of(ALICE))
        # the second try is the same as an unknown id
        error_of(browser.api("DELETE", f"/me/grants/{gid}", csrf=csrf), 404, "not_found")

    def test_someone_elses_connection_is_not_found_and_stays_alive(self, react: Stack) -> None:
        react.enroll(ALICE)
        react.enroll(BOB)
        _, tokens = react.tokens_for(BOB)
        bob_grant = raw_sql(react.store, "SELECT id FROM oauth_grants")[0][0]
        browser = signed_in(react)
        error_of(browser.api("DELETE", f"/me/grants/{bob_grant}", csrf=browser.csrf_token()), 404, "not_found")
        assert raw_sql(react.store, "SELECT revoked_at FROM oauth_grants")[0][0] is None
        assert react.mcp_status(tokens["access_token"]) == 200

    def test_an_unknown_or_malformed_id(self, react: Stack) -> None:
        react.enroll(ALICE)
        browser = signed_in(react)
        csrf = browser.csrf_token()
        error_of(browser.api("DELETE", "/me/grants/00000000-0000-4000-8000-000000000000", csrf=csrf), 404, "not_found")
        for bad in ("x", "ABCDEF00-0000-4000-8000-000000000000", "0" * 36):
            error_of(browser.api("DELETE", f"/me/grants/{bad}", csrf=csrf), 422, "validation_failed")

    def test_the_pipeline_of_a_mutation_applies(self, react: Stack) -> None:
        react.enroll(ALICE)
        react.tokens_for(ALICE)
        browser = signed_in(react)
        gid = browser.api("GET", "/me/grants").json()["grants"][0]["id"]
        error_of(browser.api("DELETE", f"/me/grants/{gid}"), 403, "csrf_invalid")
        csrf = browser.csrf_token()
        assert browser.api("DELETE", f"/me/grants/{gid}", csrf=csrf, Origin="https://evil.example").status_code == 403
        error_of(browser.api("DELETE", f"/me/grants/{gid}", csrf=csrf, **{"Sec-Fetch-Site": "cross-site"}), 403, "origin_not_allowed")
        error_of(browser.api("DELETE", f"/me/grants/{gid}", csrf=csrf, body={"x": 1}), 400, "malformed_request")
        assert raw_sql(react.store, "SELECT revoked_at FROM oauth_grants")[0][0] is None
        error_of(Browser(react, react=True).api("GET", "/me/grants"), 401, "not_authenticated")
        error_of(Browser(react, react=True).api("DELETE", f"/me/grants/{gid}", csrf="x"), 401, "not_authenticated")
        error_of(browser.api("POST", "/me/grants"), 405, "method_not_allowed")

    def test_a_database_error_is_a_closed_503(self, react: Stack, monkeypatch) -> None:
        from canvas_mcp.core.selfhost.db.errors import StoreUnavailable

        react.enroll(ALICE)
        browser = signed_in(react)

        def broken(*a: Any, **k: Any) -> Any:
            raise StoreUnavailable(kind="OperationalError")

        monkeypatch.setattr(react.authz.store, "list_grants", broken)
        monkeypatch.setattr(react.authz.store, "revoke_own_grant", broken)
        error_of(browser.api("GET", "/me/grants"), 503, "token_store_unavailable")
        gid = "00000000-0000-4000-8000-000000000001"
        error_of(browser.api("DELETE", f"/me/grants/{gid}", csrf=browser.csrf_token()), 503, "token_store_unavailable")


class TestAdminGrants:
    def test_an_owner_lists_and_ends_any_connection(self, react: Stack) -> None:
        react.enroll(ALICE)
        owner_key = react.enroll(OWNER)
        _, tokens = react.tokens_for(ALICE)
        browser = signed_in(react, OWNER)
        alice_id = react.account_of(ALICE).removeprefix("acct:")
        listed = browser.api("GET", f"/admin/accounts/{alice_id}/grants")
        assert listed.status_code == 200
        grants = listed.json()["grants"]
        assert len(grants) == 1 and set(grants[0]) == GRANT_VIEW_KEYS
        gid = grants[0]["id"]
        csrf = browser.csrf_token()
        done = browser.api("DELETE", f"/admin/grants/{gid}", csrf=csrf)
        assert done.status_code == 200 and done.json() == {"changed": True}
        assert react.mcp_status(tokens["access_token"]) == 401
        assert raw_sql(react.store, "SELECT revoked_reason, revoked_by FROM oauth_grants")[0] == ("owner_revoked", owner_key)
        audit = [e for e in react.store.list_audit() if e.action == "grant_revoked"]
        assert len(audit) == 1 and audit[0].actor == owner_key and audit[0].target == react.account_of(ALICE)
        assert audit[0].detail["via"] == "admin" and audit[0].detail["client_kind"] == "dcr"
        assert browser.api("GET", f"/admin/accounts/{alice_id}/grants").json() == {"grants": []}
        # asking again, or for something that never existed, changes nothing
        assert browser.api("DELETE", f"/admin/grants/{gid}", csrf=csrf).json() == {"changed": False}
        unknown = "00000000-0000-4000-8000-000000000000"
        assert browser.api("DELETE", f"/admin/grants/{unknown}", csrf=csrf).json() == {"changed": False}

    def test_a_user_is_forbidden_even_for_their_own_connections(self, react: Stack) -> None:
        react.enroll(ALICE)
        react.tokens_for(ALICE)
        browser = signed_in(react)
        mine = react.account_of(ALICE).removeprefix("acct:")
        gid = browser.api("GET", "/me/grants").json()["grants"][0]["id"]
        error_of(browser.api("GET", f"/admin/accounts/{mine}/grants"), 403, "forbidden")
        error_of(browser.api("DELETE", f"/admin/grants/{gid}", csrf=browser.csrf_token()), 403, "forbidden")
        assert raw_sql(react.store, "SELECT revoked_at FROM oauth_grants")[0][0] is None

    def test_an_owner_needs_a_recent_sign_in(self, react: Stack) -> None:
        react.enroll(ALICE)
        react.enroll(OWNER)
        react.tokens_for(ALICE)
        browser = signed_in(react, OWNER)
        alice_id = react.account_of(ALICE).removeprefix("acct:")
        react.clock.advance(700)
        error_of(browser.api("GET", f"/admin/accounts/{alice_id}/grants"), 403, "reauth_required")
        gid = raw_sql(react.store, "SELECT id FROM oauth_grants")[0][0]
        error_of(browser.api("DELETE", f"/admin/grants/{gid}", csrf=browser.csrf_token()), 403, "reauth_required")
        assert raw_sql(react.store, "SELECT revoked_at FROM oauth_grants")[0][0] is None

    def test_an_owner_demoted_meanwhile_is_refused_by_the_store(self, react: Stack) -> None:
        react.enroll(ALICE)
        owner_key = react.enroll(OWNER)
        react.tokens_for(ALICE)
        browser = signed_in(react, OWNER)
        csrf = browser.csrf_token()
        gid = raw_sql(react.store, "SELECT id FROM oauth_grants")[0][0]
        raw_sql(react.store, "UPDATE accounts SET role = 'user' WHERE id = :i", {"i": owner_key.removeprefix("acct:")})
        error_of(browser.api("DELETE", f"/admin/grants/{gid}", csrf=csrf), 403, "forbidden")
        assert raw_sql(react.store, "SELECT revoked_at FROM oauth_grants")[0][0] is None

    def test_malformed_ids_and_the_mutation_pipeline(self, react: Stack) -> None:
        react.enroll(OWNER)
        browser = signed_in(react, OWNER)
        csrf = browser.csrf_token()
        error_of(browser.api("GET", "/admin/accounts/x/grants"), 422, "validation_failed")
        error_of(browser.api("DELETE", "/admin/grants/x", csrf=csrf), 422, "validation_failed")
        gid = "00000000-0000-4000-8000-000000000000"
        error_of(browser.api("DELETE", f"/admin/grants/{gid}"), 403, "csrf_invalid")
        assert browser.api("DELETE", f"/admin/grants/{gid}", csrf=csrf, Origin="https://evil.example").status_code == 403
        error_of(browser.api("DELETE", f"/admin/grants/{gid}", csrf=csrf, **{"Sec-Fetch-Site": "cross-site"}), 403, "origin_not_allowed")


class TestPublicSurface:
    def test_the_api_prefix_is_what_the_web_app_calls(self) -> None:
        assert API_PREFIX == "/account/api"

    def test_query_of_is_used_for_the_redirects_only(self) -> None:
        assert query_of("https://x.test/cb?code=1&iss=2") == {"code": "1", "iss": "2"}
