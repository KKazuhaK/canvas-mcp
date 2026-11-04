"""Entra's account picker is configurable, and a signed-in person is not sent back to Microsoft.

``always_select_account`` (Admin > Settings > Entra) defaults to on, which sends
``prompt=select_account``. Off sends no ``prompt`` on a normal sign-in; reauthentication and
linking send ``prompt=login``. A person with an active session issued within the last 10
minutes who arrives with a safe ``return_to`` goes straight there.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select

from canvas_mcp.core.selfhost import account_core as web
from canvas_mcp.core.selfhost.accounts import entra_issuer
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.login.entra import build_entra_provider
from canvas_mcp.core.selfhost.login.http import SafeHttp

from ..authz.stack import ALICE, ENTRA_CLIENT_ID, ENTRA_TENANT, Browser, Stack
from .fake_idp import FakeNetwork, FakeOidcIdp

BASE = "https://canvas.example.test"
SECRET_STATE = "s" * 43


def entra_provider(**options: bool):
    net = FakeNetwork()
    FakeOidcIdp(net, entra_issuer(ENTRA_TENANT), client_id=ENTRA_CLIENT_ID)
    return build_entra_provider(
        tenant_id=ENTRA_TENANT,
        client_id=ENTRA_CLIENT_ID,
        client_secret="entra-client-secret-0123456789",
        public_base_url=BASE,
        http=SafeHttp(transport=net.transport),
        parse_groups=False,
        **options,
    )


async def authorize_query(provider, *, reauth: bool = False) -> dict[str, list[str]]:
    await provider.prepare()
    url = provider.authorize_url(
        state=SECRET_STATE, nonce="n" * 43, code_challenge="c" * 43, reauth=reauth
    )
    return parse_qs(urlsplit(url).query)


class TestAuthorizeRequest:
    async def test_the_picker_is_requested_by_default(self) -> None:
        assert (await authorize_query(entra_provider()))["prompt"] == ["select_account"]

    async def test_no_prompt_is_sent_when_the_setting_is_off(self) -> None:
        query = await authorize_query(entra_provider(always_select_account=False))
        assert "prompt" not in query
        assert query["response_mode"] == ["query"] and query["scope"] == ["openid profile email"]

    async def test_reauthentication_asks_again_when_the_setting_is_off(self) -> None:
        provider = entra_provider(always_select_account=False)
        assert (await authorize_query(provider, reauth=True))["prompt"] == ["login"]

    async def test_reauthentication_with_the_picker_on_is_unchanged(self) -> None:
        provider = entra_provider(always_select_account=True)
        assert (await authorize_query(provider, reauth=True))["prompt"] == ["select_account"]


def provider_revision(stack: Stack) -> int:
    with stack.store.database.read() as conn:
        return int(conn.execute(select(s.server_state.c.settings_revision)).scalar_one())


def set_picker(stack: Stack, value: bool) -> None:
    stack.runtime.provider_store.save(
        "entra",
        config={
            "tenant_id": ENTRA_TENANT,
            "client_id": ENTRA_CLIENT_ID,
            "always_select_account": value,
        },
        client_secret=None,
        enabled=True,
        rank=0,
        revision=provider_revision(stack),
        actor=None,
        now=int(stack.clock()),
    )


def start_query(stack: Stack, path: str = "/auth/login/entra") -> dict[str, list[str]]:
    response = stack.new_client().get(path)
    assert response.status_code == 302, response.text
    return parse_qs(urlsplit(response.headers["location"]).query)


class TestThroughTheAdminConfiguration:
    def test_an_existing_registration_keeps_the_picker(self, entra_local: Stack) -> None:
        assert start_query(entra_local)["prompt"] == ["select_account"]

    def test_turning_it_off_removes_the_prompt_and_turning_it_on_restores_it(
        self, entra_local: Stack
    ) -> None:
        set_picker(entra_local, False)
        assert "prompt" not in start_query(entra_local)
        set_picker(entra_local, True)
        assert start_query(entra_local)["prompt"] == ["select_account"]

    def test_reauth_still_sends_login_with_the_picker_off(self, entra_local: Stack) -> None:
        set_picker(entra_local, False)
        assert start_query(entra_local, "/auth/login/entra?reauth=1")["prompt"] == ["login"]


class TestAlreadySignedIn:
    def signed_in(self, stack: Stack) -> Browser:
        browser = Browser(stack)
        assert browser.sign_in(ALICE).status_code == 303
        return browser

    @pytest.mark.parametrize("start", ["/auth/login/entra", "/auth/login"])
    def test_a_safe_return_to_is_followed_without_the_provider(
        self, entra_local: Stack, start: str
    ) -> None:
        browser = self.signed_in(entra_local)
        response = browser.get(start, params={"return_to": "/account/token"})
        assert response.status_code == 303
        assert response.headers["location"] == "/account/token"
        assert response.headers["cache-control"] == "no-store"
        assert "set-cookie" not in response.headers  # no flow ceremony was started

    @pytest.mark.parametrize(
        "target",
        [
            "//evil.example/x",
            "https://evil.example/account/x",
            "/account/../admin",
            "/auth/login/entra",
            "/api/v1/me",
            "/token",
            "/account/%2e%2e/x",
            "/account/x\\y",
        ],
    )
    def test_an_unsafe_return_to_is_not_followed(self, entra_local: Stack, target: str) -> None:
        browser = self.signed_in(entra_local)
        response = browser.get("/auth/login/entra", params={"return_to": target})
        assert response.status_code == 302
        assert urlsplit(response.headers["location"]).netloc == "login.microsoftonline.com"
        assert "return_to" not in response.headers["location"]

    def test_without_return_to_the_provider_is_still_used(self, entra_local: Stack) -> None:
        browser = self.signed_in(entra_local)
        assert browser.get("/auth/login/entra").status_code == 302

    def test_reauth_still_goes_to_the_provider(self, entra_local: Stack) -> None:
        browser = self.signed_in(entra_local)
        response = browser.get(
            "/auth/login/entra", params={"return_to": "/account/token", "reauth": "1"}
        )
        assert response.status_code == 302
        assert urlsplit(response.headers["location"]).netloc == "login.microsoftonline.com"

    def test_a_signed_out_browser_is_sent_to_the_provider_with_its_return_to(
        self, entra_local: Stack
    ) -> None:
        response = entra_local.new_client().get(
            "/auth/login/entra", params={"return_to": "/account/token"}
        )
        assert response.status_code == 302
        assert urlsplit(response.headers["location"]).netloc == "login.microsoftonline.com"

    def test_a_session_the_server_no_longer_accepts_goes_to_the_provider(
        self, entra_local: Stack
    ) -> None:
        browser = self.signed_in(entra_local)
        with entra_local.store.database.write() as conn:
            conn.execute(s.accounts.update().values(session_epoch=s.accounts.c.session_epoch + 1))
        response = browser.get("/auth/login/entra", params={"return_to": "/account/token"})
        assert response.status_code == 302
        assert urlsplit(response.headers["location"]).netloc == "login.microsoftonline.com"

    def test_a_session_older_than_the_step_up_window_goes_to_the_provider(
        self, entra_local: Stack
    ) -> None:
        browser = self.signed_in(entra_local)
        entra_local.clock.advance(web._FRESH_SIGN_IN_SECONDS + 1)
        response = browser.get("/auth/login/entra", params={"return_to": "/account/token"})
        assert response.status_code == 302
        assert urlsplit(response.headers["location"]).netloc == "login.microsoftonline.com"

    def test_a_session_inside_the_window_is_followed(self, entra_local: Stack) -> None:
        browser = self.signed_in(entra_local)
        entra_local.clock.advance(web._FRESH_SIGN_IN_SECONDS - 5)
        response = browser.get("/auth/login/entra", params={"return_to": "/account/token"})
        assert response.status_code == 303

    def test_a_pending_account_goes_to_the_provider(self, entra_local: Stack) -> None:
        browser = self.signed_in(entra_local)
        with entra_local.store.database.write() as conn:
            conn.execute(s.accounts.update().values(status="pending"))
        response = browser.get("/auth/login/entra", params={"return_to": "/account/token"})
        assert response.status_code == 302
        assert urlsplit(response.headers["location"]).netloc == "login.microsoftonline.com"

    def test_the_single_provider_step_up_flow_ends_at_the_provider(
        self, entra_local: Stack
    ) -> None:
        """The URL the "Sign in again" button builds (see ReauthNotice) must reach Microsoft."""
        browser = self.signed_in(entra_local)
        # Fresh session: only reauth=1 distinguishes a step-up from the shortcut.
        step_up = browser.get(
            "/auth/login", params={"return_to": "/account/sign-in-methods", "reauth": "1"}
        )
        assert step_up.status_code == 303
        assert step_up.headers["location"].startswith("/auth/login/entra")
        start = browser.get(step_up.headers["location"])
        assert start.status_code == 302
        assert urlsplit(start.headers["location"]).netloc == "login.microsoftonline.com"


class TestStartBudget:
    def bucket(self, stack: Stack):
        from .test_entra_only_golden import account_app

        return account_app(stack).logins.start_buckets["entra"]

    def counting(self, stack: Stack, monkeypatch: pytest.MonkeyPatch) -> list[int]:
        bucket = self.bucket(stack)
        calls: list[int] = []
        original = bucket.take

        def take() -> float:
            calls.append(1)
            return original()

        monkeypatch.setattr(bucket, "take", take)
        return calls

    def test_a_shortcut_redirect_spends_no_start_budget(
        self, entra_local: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        browser = Browser(entra_local)
        assert browser.sign_in(ALICE).status_code == 303
        calls = self.counting(entra_local, monkeypatch)
        response = browser.get("/auth/login/entra", params={"return_to": "/account/token"})
        assert response.status_code == 303 and calls == []

    def test_a_request_that_starts_a_ceremony_spends_one(
        self, entra_local: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = self.counting(entra_local, monkeypatch)
        assert entra_local.new_client().get("/auth/login/entra").status_code == 302
        assert calls == [1]
