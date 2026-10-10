"""The server-rendered "Connected apps" card, its revoke form, and the owner's block on the admin page."""

from __future__ import annotations

import re
from typing import Any

import pytest
from dbbackend import raw_sql

from .stack import ALICE, BASE, BOB, OWNER, Browser, Stack, cimd_document, local_stack

ORIGIN = {"Origin": BASE}
CIMD_URL = "https://client.example/cimd.json"


def csrf_in(html: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', html)
    assert match, html[:400]
    return match.group(1)


def grant_forms(html: str, action: str) -> list[str]:
    return re.findall(rf'action="{re.escape(action)}">.*?name="grant" value="([0-9a-f-]{{36}})"', html, re.S)


@pytest.fixture
def alice_browser(stack: Stack) -> Browser:
    stack.enroll(ALICE)
    browser = Browser(stack)
    browser.sign_in(ALICE)
    return browser


class TestAccountPage:
    def test_a_person_with_no_apps_sees_so(self, stack: Stack, alice_browser: Browser) -> None:
        page = alice_browser.get("/account")
        assert page.status_code == 200 and 'id="connected-apps"' in page.text
        assert "No apps are connected." in page.text
        assert "/account/grants/revoke" not in page.text

    def test_each_app_shows_who_it_is_where_it_returns_to_and_a_revoke_button(self, stack: Stack, alice_browser: Browser) -> None:
        stack.cimd.serve(CIMD_URL, cimd_document(CIMD_URL, client_name="Client Example"))
        stack.tokens_for(ALICE)
        stack.tokens_for(ALICE, client_id=CIMD_URL)
        page = alice_browser.get("/account")
        text = page.text
        assert "Connected apps" in text
        assert "<strong>client.example</strong>" in text and "verified domain" in text
        assert "Client Example" in text
        assert "<strong>Test app</strong>" in text and "Unverified: a self-registered app" in text
        assert text.count("<code>claude.ai</code>") == 2
        assert len(grant_forms(text, "/account/grants/revoke")) == 2
        assert page.headers["cache-control"] == "no-store"

    def test_a_name_with_markup_is_escaped(self, stack: Stack, alice_browser: Browser) -> None:
        client_id = stack.register(client_name="<script>alert(1)</script>")
        stack.tokens_for(ALICE, client_id=client_id)
        text = alice_browser.get("/account").text
        assert "<script>alert(1)</script>" not in text
        assert "&lt;script&gt;" in text

    def test_other_peoples_apps_are_not_listed(self, stack: Stack, alice_browser: Browser) -> None:
        stack.enroll(BOB)
        stack.tokens_for(BOB)
        text = alice_browser.get("/account").text
        assert "No apps are connected." in text

    def test_the_card_is_in_chinese_after_the_toggle(self, stack: Stack, alice_browser: Browser) -> None:
        stack.tokens_for(ALICE)
        text = alice_browser.get("/account?lang=zh").text
        assert "已连接的应用" in text  # the heading
        assert "Connected apps" not in text and "Revoke" not in text

    def test_a_waiting_account_has_no_card(self, tmp_path, monkeypatch) -> None:
        from .stack import local_stack

        with local_stack(tmp_path, monkeypatch, env={"ACCESS_POLICY": "approval"}) as stack:
            browser = Browser(stack)
            browser.sign_in(ALICE)
            assert 'id="connected-apps"' not in browser.get("/account").text

    def test_the_default_mode_has_no_card(self, tmp_path, monkeypatch) -> None:
        with local_stack(tmp_path, monkeypatch, env={"SELFHOST_AUTH_MODE": "entra_proxy"}) as stack:
            browser = Browser(stack)
            browser.sign_in(ALICE)
            text = browser.get("/account").text
            assert 'id="connected-apps"' not in text and "Connected apps" not in text


class TestRevokeForm:
    def revoke(self, browser: Browser, grant: str, **kw: Any) -> Any:
        page = browser.get("/account")
        data = {"csrf": csrf_in(page.text), "grant": grant, **kw.pop("data", {})}
        return browser.client.post("/account/grants/revoke", data=data, headers=kw.pop("headers", ORIGIN))

    def test_revoking_ends_the_connection_at_once(self, stack: Stack, alice_browser: Browser) -> None:
        client_id, tokens = stack.tokens_for(ALICE)
        assert stack.mcp_status(tokens["access_token"]) == 200
        gid = grant_forms(alice_browser.get("/account").text, "/account/grants/revoke")[0]
        response = self.revoke(alice_browser, gid)
        assert response.status_code == 303 and response.headers["location"] == "/account#connected-apps"
        assert stack.mcp_status(tokens["access_token"]) == 401
        assert stack.refresh(client_id, tokens["refresh_token"]).status_code == 401
        assert raw_sql(stack.store, "SELECT revoked_reason FROM oauth_grants")[0][0] == "user_revoked"
        assert "No apps are connected." in alice_browser.get("/account").text
        # a second click on a stale page is harmless
        assert self.revoke_stale(alice_browser, gid).status_code == 303

    def revoke_stale(self, browser: Browser, gid: str) -> Any:
        page = browser.get("/account")
        return browser.client.post(
            "/account/grants/revoke", data={"csrf": csrf_in(page.text), "grant": gid}, headers=ORIGIN
        )

    def test_someone_elses_connection_is_left_alone(self, stack: Stack, alice_browser: Browser) -> None:
        stack.enroll(BOB)
        _, bob_tokens = stack.tokens_for(BOB)
        bob_grant = raw_sql(stack.store, "SELECT id FROM oauth_grants")[0][0]
        assert self.revoke(alice_browser, bob_grant).status_code == 303
        assert stack.mcp_status(bob_tokens["access_token"]) == 200
        assert raw_sql(stack.store, "SELECT revoked_at FROM oauth_grants")[0][0] is None

    def test_the_post_pipeline_applies(self, stack: Stack, alice_browser: Browser) -> None:
        stack.tokens_for(ALICE)
        gid = grant_forms(alice_browser.get("/account").text, "/account/grants/revoke")[0]
        page = alice_browser.get("/account")
        token = csrf_in(page.text)
        post = alice_browser.client.post
        assert post("/account/grants/revoke", data={"csrf": token, "grant": gid}).status_code == 403  # no Origin
        assert post("/account/grants/revoke", data={"csrf": "x", "grant": gid}, headers=ORIGIN).status_code == 403
        assert post("/account/grants/revoke", data={"grant": gid}, headers=ORIGIN).status_code == 403
        for bad in ("", "x", "../", gid.upper() + "x"):
            assert post("/account/grants/revoke", data={"csrf": token, "grant": bad}, headers=ORIGIN).status_code == 400
        assert raw_sql(stack.store, "SELECT revoked_at FROM oauth_grants")[0][0] is None
        assert Browser(stack).client.post("/account/grants/revoke", data={"grant": gid}, headers=ORIGIN).status_code == 303

    def test_a_waiting_account_cannot_use_it(self, tmp_path, monkeypatch) -> None:
        with local_stack(tmp_path, monkeypatch, env={"ACCESS_POLICY": "approval"}) as stack:
            browser = Browser(stack)
            browser.sign_in(ALICE)
            page = browser.get("/account")
            response = browser.client.post(
                "/account/grants/revoke",
                data={"csrf": csrf_in(page.text), "grant": "00000000-0000-4000-8000-000000000000"},
                headers=ORIGIN,
            )
            assert response.status_code == 403

    def test_the_route_does_not_exist_in_the_default_mode(self, tmp_path, monkeypatch) -> None:
        with local_stack(tmp_path, monkeypatch, env={"SELFHOST_AUTH_MODE": "entra_proxy"}) as stack:
            browser = Browser(stack)
            browser.sign_in(ALICE)
            assert browser.client.post("/account/grants/revoke", data={}, headers=ORIGIN).status_code in (404, 405)
            assert browser.client.post("/account/admin/grants/revoke", data={}, headers=ORIGIN).status_code in (404, 405)


class TestAdminPage:
    @pytest.fixture
    def owner_browser(self, stack: Stack) -> Browser:
        stack.enroll(OWNER)
        browser = Browser(stack)
        browser.sign_in(OWNER)
        return browser

    def post(self, browser: Browser, **data: str) -> Any:
        page = browser.get("/account/admin")
        return browser.client.post(
            "/account/admin/grants/revoke", data={"csrf": csrf_in(page.text), **data}, headers=ORIGIN
        )

    def test_each_account_has_a_connected_apps_block(self, stack: Stack, owner_browser: Browser) -> None:
        stack.enroll(ALICE)
        stack.tokens_for(ALICE)
        stack.tokens_for(ALICE)
        text = owner_browser.get("/account/admin").text
        assert "Connected apps (2)" in text
        assert text.count("Connected apps (") == 1  # only the account that has some
        assert "Revoke all for this account" in text
        assert len(grant_forms(text, "/account/admin/grants/revoke")) == 2

    def test_an_owner_ends_one_connection(self, stack: Stack, owner_browser: Browser) -> None:
        alice = stack.enroll(ALICE)
        _, first = stack.tokens_for(ALICE)
        _, second = stack.tokens_for(ALICE)
        gid = grant_forms(owner_browser.get("/account/admin").text, "/account/admin/grants/revoke")[0]
        response = self.post(owner_browser, grant=gid)
        assert response.status_code == 303 and response.headers["location"] == "/account/admin"
        statuses = sorted([stack.mcp_status(first["access_token"]), stack.mcp_status(second["access_token"])])
        assert statuses == [200, 401]
        entry = [e for e in stack.store.list_audit() if e.action == "grant_revoked"][0]
        assert entry.target == alice and entry.reason == "owner_revoked"
        assert "Connected apps (1)" in owner_browser.get("/account/admin").text

    def test_an_owner_ends_all_of_an_accounts_connections(self, stack: Stack, owner_browser: Browser) -> None:
        alice = stack.enroll(ALICE)
        stack.enroll(BOB)
        _, a1 = stack.tokens_for(ALICE)
        _, a2 = stack.tokens_for(ALICE)
        _, b1 = stack.tokens_for(BOB)
        response = self.post(owner_browser, principal_key=alice)
        assert response.status_code == 303
        assert stack.mcp_status(a1["access_token"]) == 401 and stack.mcp_status(a2["access_token"]) == 401
        assert stack.mcp_status(b1["access_token"]) == 200
        assert len([e for e in stack.store.list_audit() if e.action == "grant_revoked"]) == 2

    def test_a_user_cannot(self, stack: Stack, alice_browser: Browser) -> None:
        _, tokens = stack.tokens_for(ALICE)
        page = alice_browser.get("/account")
        response = alice_browser.client.post(
            "/account/admin/grants/revoke",
            data={"csrf": csrf_in(page.text), "principal_key": stack.account_of(ALICE)},
            headers=ORIGIN,
        )
        assert response.status_code == 403
        assert stack.mcp_status(tokens["access_token"]) == 200

    def test_the_fresh_sign_in_rule_applies(self, stack: Stack, owner_browser: Browser) -> None:
        stack.enroll(ALICE)
        _, tokens = stack.tokens_for(ALICE)
        gid = grant_forms(owner_browser.get("/account/admin").text, "/account/admin/grants/revoke")[0]
        page = owner_browser.get("/account/admin")
        stack.clock.advance(700)
        response = owner_browser.client.post(
            "/account/admin/grants/revoke", data={"csrf": csrf_in(page.text), "grant": gid}, headers=ORIGIN
        )
        assert response.status_code == 403
        assert stack.mcp_status(tokens["access_token"]) == 200

    def test_malformed_input_is_refused(self, stack: Stack, owner_browser: Browser) -> None:
        assert self.post(owner_browser, grant="not-a-uuid").status_code == 400
        assert self.post(owner_browser, principal_key="nobody").status_code == 400
        assert self.post(owner_browser).status_code == 400

    def test_the_audit_page_names_the_new_actions(self, stack: Stack, owner_browser: Browser) -> None:
        alice = stack.enroll(ALICE)
        stack.tokens_for(ALICE)
        self.post(owner_browser, principal_key=alice)
        stack.authz.store.bump_jwt_epoch()
        text = owner_browser.get("/account/admin/audit").text
        assert "Connected app ended" in text
        assert "App access tokens invalidated" in text

    def test_the_default_mode_page_has_no_block(self, tmp_path, monkeypatch) -> None:
        with local_stack(tmp_path, monkeypatch, env={"SELFHOST_AUTH_MODE": "entra_proxy"}) as stack:
            stack.enroll(OWNER)
            browser = Browser(stack)
            browser.sign_in(OWNER)
            text = browser.get("/account/admin").text
            assert "Connected apps" not in text
