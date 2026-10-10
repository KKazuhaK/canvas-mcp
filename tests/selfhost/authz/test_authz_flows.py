"""Every route of the local authorization server, driven in-process over the whole stack."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from dbbackend import raw_sql

from canvas_mcp.core.selfhost.authz import tokens as tk
from canvas_mcp.core.selfhost.db.errors import StoreUnavailable
from canvas_mcp.core.selfhost.token_store import OPERATOR

from .stack import (
    ALICE,
    AUDIENCE,
    BASE,
    BOB,
    CLAUDE_REDIRECT,
    ISSUER,
    LOOPBACK_REDIRECT,
    Browser,
    Stack,
    cimd_document,
    local_stack,
    pkce,
    query_of,
)

CIMD_URL = "https://client.example/cimd.json"


def query(response: Any) -> dict[str, list[str]]:
    return parse_qs(urlsplit(response.headers["location"]).query)


def set_cookie(response: Any, name: str) -> str:
    for line in response.headers.get_list("set-cookie"):
        if line.startswith(name + "="):
            return str(line)
    raise AssertionError(f"no Set-Cookie for {name}")


@pytest.fixture
def alice(stack: Stack) -> str:
    return stack.enroll(ALICE)


# ------------------------------------------------------------------------------------ /authorize


class TestAuthorize:
    def test_an_unknown_client_is_shown_not_redirected(self, stack: Stack) -> None:
        _, challenge = pkce()
        response = stack.client.get("/authorize", params=stack.authorize_params("nobody", challenge))
        assert response.status_code == 400 and "location" not in response.headers

    def test_an_unregistered_redirect_uri_is_shown_not_redirected(self, stack: Stack) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)
        _, challenge = pkce()
        for uri in ("https://evil.example/cb", CLAUDE_REDIRECT + "/x", "http://localhost/callback"):
            response = stack.client.get(
                "/authorize", params=stack.authorize_params(client_id, challenge, redirect_uri=uri)
            )
            assert response.status_code == 400 and "location" not in response.headers, uri

    @pytest.mark.parametrize(
        ("overrides", "error"),
        [
            ({"resource": "https://other.example/mcp"}, "invalid_target"),
            ({"resource": AUDIENCE + "/deeper"}, "invalid_target"),
            ({"resource": "not a url"}, "invalid_target"),
            ({"code_challenge": "short"}, "invalid_request"),
            ({"code_challenge": "A" * 44}, "invalid_request"),
            ({"scope": "admin"}, "invalid_scope"),
            ({"scope": "Canvas.Access admin"}, "invalid_scope"),
            ({"code_challenge_method": "plain"}, "invalid_request"),
            ({"response_type": "token"}, "unsupported_response_type"),
        ],
    )
    def test_a_bad_request_is_redirected_with_error_state_and_one_iss(self, stack, overrides, error) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)
        _, challenge = pkce()
        params = stack.authorize_params(client_id, challenge, **overrides)
        response = stack.client.get("/authorize", params=params)
        assert response.status_code == 302
        assert response.headers["location"].startswith(CLAUDE_REDIRECT + "?")
        q = query(response)
        assert q["error"] == [error] and q["state"] == ["state-1"] and q["iss"] == [ISSUER]
        assert response.headers["cache-control"] == "no-store"
        assert "set-cookie" not in response.headers  # no browser binding for a failed request

    def test_a_missing_code_challenge_is_an_invalid_request_redirect(self, stack: Stack) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)
        response = stack.client.get(
            "/authorize",
            params={"response_type": "code", "client_id": client_id, "redirect_uri": CLAUDE_REDIRECT, "state": "s"},
        )
        assert response.status_code == 302 and query(response)["error"] == ["invalid_request"]
        assert query(response)["iss"] == [ISSUER]

    def test_a_trailing_slash_resource_and_a_missing_resource_are_accepted(self, stack: Stack) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)
        _, challenge = pkce()
        for resource in (AUDIENCE + "/", "https://CANVAS.EXAMPLE.TEST:443/mcp", None):
            response = stack.client.get(
                "/authorize", params=stack.authorize_params(client_id, challenge, resource=resource)
            )
            assert response.status_code == 302, resource
            assert response.headers["location"].startswith(f"{BASE}/account/login?txn="), resource

    def test_a_missing_scope_defaults_to_the_clients(self, stack: Stack) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)
        _, challenge = pkce()
        response = stack.client.get("/authorize", params=stack.authorize_params(client_id, challenge, scope=None))
        assert response.status_code == 302 and "/account/login?txn=" in response.headers["location"]

    def test_success_goes_to_the_sign_in_with_a_browser_binding_cookie(self, stack: Stack) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)
        _, challenge = pkce()
        response = stack.client.get("/authorize", params=stack.authorize_params(client_id, challenge))
        assert response.status_code == 302
        location = response.headers["location"]
        assert re.fullmatch(rf"{re.escape(BASE)}/account/login\?txn=[A-Za-z0-9_-]{{43}}", location)
        cookie = set_cookie(response, "__Host-cmcp_bind")
        for needle in ("HttpOnly", "Secure", "SameSite=lax", "Path=/", "Max-Age=600"):
            assert needle.lower() in cookie.lower(), needle
        assert "domain" not in cookie.lower()
        assert response.headers["cache-control"] == "no-store"

    def test_an_existing_binding_cookie_is_reused(self, stack: Stack) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)
        _, challenge = pkce()
        first = stack.client.get("/authorize", params=stack.authorize_params(client_id, challenge))
        value = set_cookie(first, "__Host-cmcp_bind").split(";")[0].split("=", 1)[1]
        second = stack.client.get("/authorize", params=stack.authorize_params(client_id, challenge))
        assert set_cookie(second, "__Host-cmcp_bind").split(";")[0].split("=", 1)[1] == value
        assert first.headers["location"] != second.headers["location"]  # a new transaction each time

    def test_only_a_hash_of_the_binding_and_of_the_transaction_id_is_stored(self, stack: Stack) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)
        _, challenge = pkce()
        response = stack.client.get("/authorize", params=stack.authorize_params(client_id, challenge))
        txn = query_of(response.headers["location"])["txn"]
        binding = set_cookie(response, "__Host-cmcp_bind").split(";")[0].split("=", 1)[1]
        rows = raw_sql(stack.store, "SELECT id_hash, binding_hash, payload FROM login_states")
        assert len(rows) == 1 and txn not in rows[0][0] and binding not in rows[0][1]
        assert rows[0][1] == tk.hash_secret(binding)

    def test_a_storage_failure_is_a_redirected_temporarily_unavailable(self, stack: Stack, monkeypatch) -> None:
        async def failing(*a: Any, **k: Any) -> str:
            raise StoreUnavailable(kind="OperationalError")

        monkeypatch.setattr(stack.authz.txns, "put", failing)
        client_id = stack.register(CLAUDE_REDIRECT)
        _, challenge = pkce()
        response = stack.client.get("/authorize", params=stack.authorize_params(client_id, challenge))
        assert response.status_code == 302
        assert query(response)["error"] == ["temporarily_unavailable"] and query(response)["iss"] == [ISSUER]

    def test_an_outage_while_loading_the_client_is_a_503_not_an_unknown_client(self, stack: Stack, monkeypatch) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)

        def failing(*a: Any, **k: Any) -> Any:
            raise StoreUnavailable(kind="OperationalError")

        monkeypatch.setattr(stack.authz.store, "get_client_record", failing)
        _, challenge = pkce()
        response = stack.client.get("/authorize", params=stack.authorize_params(client_id, challenge))
        assert response.status_code == 503 and response.json()["error"] == "temporarily_unavailable"

    def test_post_authorize_works_like_get(self, stack: Stack) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)
        _, challenge = pkce()
        response = stack.client.post("/authorize", data=stack.authorize_params(client_id, challenge))
        assert response.status_code == 302 and "/account/login?txn=" in response.headers["location"]

    def test_head_authorize_with_a_form_body_creates_no_transaction(self, stack: Stack) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)
        _, challenge = pkce()
        params = stack.authorize_params(client_id, challenge)
        for _ in range(40):
            response = stack.client.request("HEAD", "/authorize", data=params)
            assert response.status_code in (405, 429)
        assert raw_sql(stack.store, "SELECT COUNT(*) FROM login_states")[0][0] == 0


# ------------------------------------------------------------------------- /account/login?txn


def start_request(stack: Stack, browser: Browser | None = None, **kw: Any) -> tuple[Browser, str, str]:
    """Start an /authorize in ``browser``; returns (browser, txn id, login url)."""
    browser = browser or Browser(stack)
    client_id = kw.pop("client_id", None) or stack.register(CLAUDE_REDIRECT)
    _, challenge = pkce()
    response = browser.start(stack.authorize_params(client_id, challenge, **kw))
    assert response.status_code == 302, response.text
    url = response.headers["location"]
    return browser, query_of(url)["txn"], url


class TestLoginContinuation:
    def test_another_browser_is_refused_without_reaching_microsoft(self, stack: Stack) -> None:
        _, _, url = start_request(stack)
        stranger = Browser(stack)
        response = stranger.get(url)
        assert response.status_code == 400
        assert "expired or was opened in another browser" in response.text
        assert "location" not in response.headers

    def test_a_browser_with_a_different_binding_is_refused(self, stack: Stack) -> None:
        _, _, url = start_request(stack)
        other, _, _ = start_request(stack)  # has its own binding cookie
        assert other.get(url).status_code == 400

    @pytest.mark.parametrize("txn", ["", "x", "A" * 43, "../../etc", "A" * 500])
    def test_a_bogus_transaction_is_refused(self, stack: Stack, txn: str) -> None:
        browser, _, _ = start_request(stack)
        assert browser.get("/account/login", params={"txn": txn}).status_code == 400

    def test_an_expired_transaction_is_refused(self, stack: Stack) -> None:
        browser, _, url = start_request(stack)
        stack.clock.advance(601)
        assert browser.get(url).status_code == 400

    def test_the_owner_of_the_request_is_sent_to_microsoft_and_comes_back_to_consent(self, stack: Stack) -> None:
        browser, txn, url = start_request(stack)
        response = browser.get(url)
        assert response.status_code == 302
        assert urlsplit(response.headers["location"]).netloc == "login.microsoftonline.com"
        callback = browser.entra_login(ALICE, response)
        assert callback.status_code == 303
        assert callback.headers["location"] == f"/account/consent?txn={txn}"

    def test_a_signed_in_browser_goes_straight_to_consent(self, stack: Stack) -> None:
        browser = Browser(stack)
        browser.sign_in(ALICE)
        _, txn, url = start_request(stack, browser)
        response = browser.get(url)
        assert response.status_code == 303 and response.headers["location"] == f"/account/consent?txn={txn}"

    def test_reauth_forces_microsoft_again(self, stack: Stack) -> None:
        browser = Browser(stack)
        browser.sign_in(ALICE)
        _, _, url = start_request(stack, browser)
        response = browser.get(url + "&reauth=1")
        assert response.status_code == 302 and "login.microsoftonline.com" in response.headers["location"]

    def test_a_failed_sign_in_does_not_reach_consent(self, stack: Stack) -> None:
        browser, _, url = start_request(stack)
        response = browser.entra_login(ALICE, browser.get(url), tid="99999999-8888-7777-6666-555555555555")
        assert response.status_code == 403 and "/account/consent" not in response.headers.get("location", "")

    def test_without_the_local_mode_the_txn_parameter_means_nothing(self, proxy_stack: Stack) -> None:
        response = proxy_stack.client.get("/account/login", params={"txn": "A" * 43})
        assert response.status_code == 302 and "login.microsoftonline.com" in response.headers["location"]

    def test_the_code_belongs_to_the_account_that_is_signed_in_when_the_user_decides(self, stack: Stack) -> None:
        alice_key = stack.enroll(ALICE)
        bob_key = stack.enroll(BOB)
        browser = Browser(stack)
        browser.sign_in(ALICE)
        client_id = stack.register(CLAUDE_REDIRECT)
        _, challenge = pkce()
        landed = browser.connect(stack.authorize_params(client_id, challenge), BOB)
        record = stack.authz.store.load_code(tk.hash_secret(landed.query["code"]))
        assert record is not None and f"acct:{record.account_id}" == alice_key  # Alice's session was valid
        # "Use a different account": the sign-in is run again, now as Bob
        browser2, txn, url = start_request(stack, Browser(stack))
        browser2.sign_in(ALICE)
        response = browser2.get(url + "&reauth=1")
        callback = browser2.entra_login(BOB, response)
        assert callback.headers["location"] == f"/account/consent?txn={txn}"
        page = browser2.get(callback.headers["location"])
        assert "Bob" in page.text
        landed2 = browser2.decide(page, "approve")
        record2 = stack.authz.store.load_code(tk.hash_secret(query(landed2)["code"][0]))
        assert record2 is not None and f"acct:{record2.account_id}" == bob_key


class TestAdmissionLost:
    def test_a_sign_in_that_is_no_longer_admitted_ends_the_apps_that_account_had_connected(self, stack: Stack) -> None:
        alice = stack.enroll(ALICE)
        _, tokens = stack.tokens_for(ALICE)
        assert stack.mcp_status(tokens["access_token"]) == 200
        browser = Browser(stack)
        # Alice signs in again, but Entra no longer shows the role that admitted her
        response = browser.entra_login(replace(ALICE, roles=()), browser.get("/account/login"))
        assert response.status_code == 403
        rows = raw_sql(stack.store, "SELECT revoked_reason, revoked_by FROM oauth_grants")
        assert rows == [("admission_lost", "system")]
        assert stack.mcp_status(tokens["access_token"]) == 401  # in this process: at once
        assert any(
            e.action == "grants_revoked_for_account" and e.target == alice for e in stack.store.list_audit()
        )

    def test_a_session_that_was_still_open_cannot_connect_again_without_the_identity_provider(
        self, stack: Stack
    ) -> None:
        stack.enroll(ALICE)
        browser_a = Browser(stack)
        browser_a.sign_in(ALICE)  # an /account session that is still valid
        elsewhere = Browser(stack)
        refused = elsewhere.entra_login(replace(ALICE, roles=()), elsewhere.get("/account/login"))
        assert refused.status_code == 403
        _, _, url = start_request(stack, browser_a)
        response = browser_a.get(url)
        # not "straight to consent": the session ended, so it is the Entra round trip again
        assert response.status_code == 302 and "login.microsoftonline.com" in response.headers["location"]

    def test_a_code_approved_before_the_refusal_cannot_be_redeemed_afterwards(self, stack: Stack) -> None:
        stack.enroll(ALICE)
        client_id, verifier, code, _ = stack.code_for(ALICE)
        elsewhere = Browser(stack)
        refused = elsewhere.entra_login(replace(ALICE, roles=()), elsewhere.get("/account/login"))
        assert refused.status_code == 403
        response = stack.token(
            grant_type="authorization_code", code=code, client_id=client_id, redirect_uri=CLAUDE_REDIRECT,
            code_verifier=verifier, resource=AUDIENCE,
        )
        assert response.status_code in (400, 401), response.text
        assert response.json()["error"] == "invalid_grant", response.text
        assert raw_sql(stack.store, "SELECT COUNT(*) FROM oauth_grants")[0][0] == 0

    def test_a_refused_sign_in_of_a_stranger_revokes_nothing(self, stack: Stack) -> None:
        stack.enroll(ALICE)
        stack.tokens_for(ALICE)
        browser = Browser(stack)
        response = browser.entra_login(replace(BOB, roles=()), browser.get("/account/login"))
        assert response.status_code == 403
        assert raw_sql(stack.store, "SELECT revoked_reason FROM oauth_grants") == [(None,)]


# ------------------------------------------------------------------------------- consent: GET


class TestConsentPage:
    def test_without_a_session_it_goes_to_the_sign_in(self, stack: Stack) -> None:
        browser, txn, _ = start_request(stack)
        response = browser.get(f"/account/consent?txn={txn}")
        assert response.status_code == 303
        assert response.headers["location"] == f"/account/login?txn={txn}"

    def test_without_the_binding_cookie_it_is_refused(self, stack: Stack) -> None:
        _, txn, _ = start_request(stack)
        other = Browser(stack)
        other.sign_in(ALICE)
        response = other.get(f"/account/consent?txn={txn}")
        assert response.status_code == 400 and "another browser" in response.text

    def test_a_dcr_app_is_shown_as_unverified_with_its_escaped_name(self, stack: Stack) -> None:
        client_id = stack.register(CLAUDE_REDIRECT, client_name='<script>alert("x")</script> Claude')
        browser = Browser(stack)
        browser.sign_in(ALICE)
        _, txn, _ = start_request(stack, browser, client_id=client_id)
        page = browser.get(f"/account/consent?txn={txn}")
        assert page.status_code == 200
        assert "<script>" not in page.text and "&lt;script&gt;" in page.text
        assert "Unverified" in page.text
        assert "claude.ai" in page.text  # where the answer goes
        assert "alice@example.test" in page.text and "Alice" in page.text
        assert "Use a different account" in page.text
        assert f"/account/login?txn={txn}&amp;reauth=1" in page.text

    def test_a_cimd_app_is_shown_by_its_verified_host(self, stack: Stack) -> None:
        stack.cimd.serve(CIMD_URL, cimd_document(CIMD_URL, client_name="Totally Claude"))
        browser = Browser(stack)
        browser.sign_in(ALICE)
        _, txn, _ = start_request(stack, browser, client_id=CIMD_URL)
        page = browser.get(f"/account/consent?txn={txn}")
        assert page.status_code == 200
        assert "client.example" in page.text and "verified domain" in page.text
        assert "Totally Claude" in page.text
        assert "Unverified" not in page.text

    def test_a_loopback_redirect_carries_a_warning(self, stack: Stack) -> None:
        stack.cimd.serve(CIMD_URL, cimd_document(CIMD_URL, redirect_uris=["http://127.0.0.1/callback"]))
        browser = Browser(stack)
        browser.sign_in(ALICE)
        _, txn, _ = start_request(stack, browser, client_id=CIMD_URL, redirect_uri=LOOPBACK_REDIRECT)
        page = browser.get(f"/account/consent?txn={txn}")
        assert page.status_code == 200 and "on this computer" in page.text and "127.0.0.1" in page.text

    def test_the_security_headers_have_no_form_action_and_forbid_framing(self, stack: Stack) -> None:
        browser = Browser(stack)
        browser.sign_in(ALICE)
        _, txn, _ = start_request(stack, browser)
        page = browser.get(f"/account/consent?txn={txn}")
        csp = page.headers["content-security-policy"]
        assert "form-action" not in csp
        assert "frame-ancestors 'none'" in csp and "default-src 'none'" in csp and "base-uri 'none'" in csp
        assert page.headers["x-frame-options"] == "DENY"
        assert page.headers["cache-control"] == "no-store"
        assert "<script" not in page.text.lower() and "http://" not in page.text.replace("http://127", "")

    def test_the_other_account_pages_keep_their_form_action(self, stack: Stack) -> None:
        browser = Browser(stack)
        browser.sign_in(ALICE)
        assert "form-action 'self'" in browser.get("/account").headers["content-security-policy"]

    def test_a_pending_account_sees_the_request_but_can_only_cancel(self, tmp_path, monkeypatch) -> None:
        with local_stack(tmp_path, monkeypatch, env={"ACCESS_POLICY": "approval"}) as stack:
            browser = Browser(stack)
            _, txn, url = start_request(stack, browser)
            assert browser.get(url).status_code == 302
            browser.entra_login(ALICE, browser.get(url))
            page = browser.get(f"/account/consent?txn={txn}")
            assert page.status_code == 200
            assert "waiting for the server owner to approve" in page.text
            assert 'value="approve"' not in page.text and 'value="deny"' in page.text and "Cancel" in page.text

    def test_a_language_switch_keeps_the_transaction(self, stack: Stack) -> None:
        browser = Browser(stack)
        browser.sign_in(ALICE)
        _, txn, _ = start_request(stack, browser)
        page = browser.get(f"/account/consent?txn={txn}&lang=zh")
        # the Chinese page (written as escapes: this file stays English-only)
        assert page.status_code == 200 and 'lang="zh-CN"' in page.text and "\u8fde\u63a5" in page.text
        assert f"/account/consent?txn={txn}&amp;lang=en" in page.text

    def test_a_malformed_transaction_id_is_refused(self, stack: Stack) -> None:
        browser = Browser(stack)
        browser.sign_in(ALICE)
        assert browser.get("/account/consent?txn=<b>").status_code == 400
        assert browser.get("/account/consent").status_code == 400


# ------------------------------------------------------------------------------ consent: POST


def consent_page(stack: Stack, **kw: Any) -> tuple[Browser, Any, str]:
    browser = kw.pop("browser", None) or Browser(stack)
    if not kw.pop("signed_in", False):
        browser.sign_in(kw.pop("user", ALICE))
    _, txn, _ = start_request(stack, browser, **kw)
    page = browser.get(f"/account/consent?txn={txn}")
    assert page.status_code == 200, page.text
    return browser, page, txn


class TestConsentDecision:
    def test_approve_redirects_with_code_state_and_a_single_iss(self, stack: Stack) -> None:
        browser, page, _ = consent_page(stack)
        response = browser.decide(page, "approve")
        assert response.status_code == 303
        assert response.headers["location"].startswith(CLAUDE_REDIRECT + "?")
        q = query(response)
        assert set(q) == {"code", "state", "iss"} and q["state"] == ["state-1"] and q["iss"] == [ISSUER]
        assert tk.CODE_RE.fullmatch(q["code"][0])
        assert "form-action" not in response.headers["content-security-policy"]

    def test_a_redirect_uri_with_a_query_can_not_exist_so_an_iss_in_it_can_not_either(self, stack: Stack) -> None:
        # The allowlist has no queries, and a registration must match it exactly; so the
        # "an iss already in the redirect URI" case of RFC 9207 never reaches a redirect.
        response = stack.client.post(
            "/register",
            json={"redirect_uris": [CLAUDE_REDIRECT + "?iss=attacker"], "client_name": "x"},
        )
        assert response.status_code == 400 and response.json()["error"] == "invalid_redirect_uri"

    def test_deny_redirects_with_access_denied_state_and_iss(self, stack: Stack) -> None:
        browser, page, _ = consent_page(stack)
        response = browser.decide(page, "deny")
        assert response.status_code == 303
        q = query(response)
        assert q["error"] == ["access_denied"] and q["state"] == ["state-1"] and q["iss"] == [ISSUER]
        assert "code" not in q
        assert ("oauth", "consent_denied", "denied") in raw_sql(stack.store, "SELECT surface, reason, outcome FROM auth_events")

    def test_the_transaction_is_single_use(self, stack: Stack) -> None:
        browser, page, _ = consent_page(stack)
        assert browser.decide(page, "approve").status_code == 303
        again = browser.decide(page, "approve")
        assert again.status_code == 400 and "location" not in again.headers
        assert raw_sql(stack.store, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 1

    def test_an_expired_transaction_cannot_be_decided(self, stack: Stack) -> None:
        browser, page, _ = consent_page(stack)
        stack.clock.advance(601)
        assert browser.decide(page, "approve").status_code == 400

    def test_a_missing_or_wrong_csrf_token_is_refused_and_the_request_survives(self, stack: Stack) -> None:
        browser, page, txn = consent_page(stack)
        for csrf in (None, "wrong", ""):
            data = {"txn": txn, "decision": "approve", **({} if csrf is None else {"csrf": csrf})}
            response = browser.client.post("/account/consent", data=data, headers={"Origin": BASE})
            assert response.status_code == 403
        assert browser.decide(page, "approve").status_code == 303

    def test_a_foreign_or_missing_origin_is_refused(self, stack: Stack) -> None:
        browser, page, _ = consent_page(stack)
        csrf, txn = browser.consent_form(page)
        for headers in ({"Origin": "https://evil.example"}, {}):
            response = browser.client.post(
                "/account/consent", data={"csrf": csrf, "txn": txn, "decision": "approve"}, headers=headers
            )
            assert response.status_code == 403

    def test_a_post_from_a_browser_without_the_binding_is_refused(self, stack: Stack) -> None:
        browser, page, _ = consent_page(stack)
        csrf, txn = browser.consent_form(page)
        thief = Browser(stack)
        thief.sign_in(ALICE)
        response = thief.client.post(
            "/account/consent", data={"csrf": thief_csrf(thief), "txn": txn, "decision": "approve"},
            headers={"Origin": BASE},
        )
        assert response.status_code == 400
        assert csrf  # the rightful browser can still decide
        assert browser.decide(page, "approve").status_code == 303

    @pytest.mark.parametrize("decision", ["", "maybe", "APPROVE", "approve deny"])
    def test_an_unknown_decision_is_refused(self, stack: Stack, decision: str) -> None:
        browser, page, _ = consent_page(stack)
        csrf, txn = browser.consent_form(page)
        response = browser.client.post(
            "/account/consent", data={"csrf": csrf, "txn": txn, "decision": decision}, headers={"Origin": BASE}
        )
        assert response.status_code == 400

    def test_a_pending_account_cannot_approve_but_can_cancel(self, tmp_path, monkeypatch) -> None:
        with local_stack(tmp_path, monkeypatch, env={"ACCESS_POLICY": "approval"}) as stack:
            browser = Browser(stack)
            _, txn, url = start_request(stack, browser)
            browser.entra_login(ALICE, browser.get(url))
            page = browser.get(f"/account/consent?txn={txn}")
            csrf, _ = browser.consent_form(page)
            refused = browser.client.post(
                "/account/consent", data={"csrf": csrf, "txn": txn, "decision": "approve"}, headers={"Origin": BASE}
            )
            assert refused.status_code == 403 and "location" not in refused.headers
            assert raw_sql(stack.store, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 0
            cancelled = browser.client.post(
                "/account/consent", data={"csrf": csrf, "txn": txn, "decision": "deny"}, headers={"Origin": BASE}
            )
            assert cancelled.status_code == 303 and query(cancelled)["error"] == ["access_denied"]

    def test_a_disabled_account_cannot_get_here(self, stack: Stack) -> None:
        browser, page, _ = consent_page(stack)
        key = stack.account_of(ALICE)
        stack.store.disable_principal(key, actor=OPERATOR, reason="operator_disabled")
        response = browser.decide(page, "approve")
        assert response.status_code in (303, 403) and "code=" not in response.headers.get("location", "")
        assert raw_sql(stack.store, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 0

    def test_a_registration_that_expired_before_the_decision_gets_no_redirect(self, stack: Stack) -> None:
        browser, page, _ = consent_page(stack)
        raw_sql(stack.store, "UPDATE oauth_clients SET expires_at = 1")
        response = browser.decide(page, "approve")
        assert response.status_code == 409 and "location" not in response.headers

    def test_an_allowlist_that_no_longer_has_the_uri_gets_no_redirect(self, stack: Stack) -> None:
        browser, page, _ = consent_page(stack)
        stack.authz.clients._allowlist = ("https://other.example/cb",)
        response = browser.decide(page, "approve")
        assert response.status_code == 409 and "location" not in response.headers
        assert raw_sql(stack.store, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 0

    def test_the_decision_is_noted_for_the_operator_but_not_in_the_sign_in_history(self, stack: Stack) -> None:
        browser, page, _ = consent_page(stack)
        browser.decide(page, "approve")
        assert ("oauth", "consent_granted", "success") in raw_sql(
            stack.store, "SELECT surface, reason, outcome FROM auth_events"
        )
        key = stack.account_of(ALICE)
        assert all(e.surface != "oauth" for e in stack.store.list_auth_events(key))


def thief_csrf(browser: Browser) -> str:
    page = browser.get("/account")
    match = re.search(r'name="csrf" value="([^"]+)"', page.text)
    assert match
    return match.group(1)
