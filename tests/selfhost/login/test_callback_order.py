"""The callback order of the design's checklist (A.11), for every non-Entra provider."""

from __future__ import annotations

import pathlib
import threading
from typing import Any

import httpx
import pytest
from dbbackend import IS_POSTGRES
from sqlalchemy import text

from ..authz.stack import Browser, query_of
from .stack_providers import ProviderStack, provider_stack

PROVIDERS = ["google", "github", "school"]
COOKIE = "__Host-cmcp_flow"
WAIT = 20


@pytest.fixture
def ps(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    with provider_stack(tmp_path, monkeypatch) as stack:
        yield stack


def token_requests(ps: ProviderStack, provider: str) -> int:
    if provider == "google":
        return ps.google.counts["token"]
    if provider == "school":
        return ps.school.counts["token"]
    return len(ps.github.token_requests)


def flow_rows(ps: ProviderStack) -> int:
    with ps.store.database.read() as conn:
        return int(
            conn.execute(
                text("SELECT count(*) FROM login_states WHERE kind = 'login_flow'")
            ).scalar_one()
        )


def flow_cookie_of(response: httpx.Response) -> str:
    for header in response.headers.get_list("set-cookie"):
        if header.startswith(COOKIE + "="):
            return header.split(";", 1)[0].split("=", 1)[1]
    raise AssertionError("no flow cookie")


def clears_flow_cookie(response: httpx.Response) -> bool:
    return any(
        h.startswith(COOKIE + "=") and ("Max-Age=0" in h or "expires=" in h.lower())
        for h in response.headers.get_list("set-cookie")
    )


def failure_text(response: httpx.Response) -> str:
    assert response.status_code == 303
    assert response.headers["cache-control"] == "no-store"
    code = query_of(response.headers["location"])["error"]
    assert response.headers["location"] == f"/account/sign-in?error={code}"
    return code


@pytest.mark.parametrize("provider", PROVIDERS)
class TestEveryResponseClearsTheCookie:
    def test_success(self, ps: ProviderStack, provider: str) -> None:
        response = ps.person().sign_in(provider)
        assert response.status_code == 303 and clears_flow_cookie(response)

    def test_a_provider_error(self, ps: ProviderStack, provider: str) -> None:
        person = ps.person()
        start = person.start(provider)
        response = person.get(
            person.callback_url(provider, start, error="access_denied")
        )
        assert failure_text(response) == "provider_error" and clears_flow_cookie(
            response
        )

    def test_a_missing_cookie(self, ps: ProviderStack, provider: str) -> None:
        person = ps.person()
        start = person.start(provider)
        callback = person.callback_url(provider, start)
        person.client.cookies.clear()
        response = person.get(callback)
        assert failure_text(response) == "state_invalid" and clears_flow_cookie(
            response
        )


@pytest.mark.parametrize("provider", PROVIDERS)
class TestProviderErrors:
    def test_error_ends_the_ceremony_before_anything_is_consumed_or_called(
        self, ps: ProviderStack, provider: str
    ) -> None:
        person = ps.person()
        start = person.start(provider)
        rows = flow_rows(ps)
        response = person.get(
            person.callback_url(provider, start, error="access_denied")
        )
        assert failure_text(response) == "provider_error"
        assert token_requests(ps, provider) == 0
        assert flow_rows(ps) == rows  # the record was not consumed
        assert "script" not in response.text and "secret idp text" not in response.text
        assert "must never be shown" not in response.text

    def test_error_comes_before_the_state_check(
        self, ps: ProviderStack, provider: str
    ) -> None:
        person = ps.person()
        response = person.get(
            f"/auth/callback/{'oidc/school' if provider == 'school' else provider}",
            params={"error": "access_denied", "state": "forged"},
        )
        assert (
            failure_text(response) == "provider_error"
        )  # the provider's refusal, not state_invalid

    def test_odd_error_values_are_not_echoed(
        self, ps: ProviderStack, provider: str
    ) -> None:
        person = ps.person()
        path = f"/auth/callback/{'oidc/school' if provider == 'school' else provider}"
        response = person.get(path, params={"error": "<script>alert(1)</script>"})
        assert (
            failure_text(response) == "provider_error"
            and "<script>" not in response.text
        )


@pytest.mark.parametrize("provider", PROVIDERS)
class TestStateAndCookie:
    def test_a_tampered_cookie_is_refused(
        self, ps: ProviderStack, provider: str
    ) -> None:
        person = ps.person()
        start = person.start(provider)
        callback = person.callback_url(provider, start)
        value = flow_cookie_of(start)
        person.client.cookies.set(
            COOKIE,
            value[:-3] + ("AAA" if not value.endswith("AAA") else "BBB"),
            domain="canvas.example.test",
        )
        response = person.get(callback)
        assert (
            failure_text(response) == "state_invalid"
            and token_requests(ps, provider) == 0
        )

    def test_a_state_that_differs_from_the_cookies_is_refused(
        self, ps: ProviderStack, provider: str
    ) -> None:
        person = ps.person()
        start = person.start(provider)
        callback = person.callback_url(provider, start)
        forged = callback.replace("state=", "state=x")
        response = person.get(forged)
        assert (
            failure_text(response) == "state_invalid"
            and token_requests(ps, provider) == 0
        )

    def test_a_cookie_for_another_provider_is_refused(
        self, ps: ProviderStack, provider: str
    ) -> None:
        other = "github" if provider != "github" else "google"
        person = ps.person()
        start_other = person.start(other)
        cookie = flow_cookie_of(start_other)
        start = person.start(provider)
        callback = person.callback_url(provider, start)
        person.client.cookies.set(COOKIE, cookie, domain="canvas.example.test")
        response = person.get(callback)
        assert (
            failure_text(response) == "state_invalid"
            and token_requests(ps, provider) == 0
        )

    def test_an_expired_cookie_is_refused(
        self, ps: ProviderStack, provider: str
    ) -> None:
        person = ps.person()
        start = person.start(provider)
        callback = person.callback_url(provider, start)
        ps.clock.advance(601)
        response = person.get(callback)
        assert (
            failure_text(response) == "state_invalid"
            and token_requests(ps, provider) == 0
        )

    def test_a_replayed_callback_exchanges_the_code_once(
        self, ps: ProviderStack, provider: str
    ) -> None:
        person = ps.person()
        start = person.start(provider)
        callback = person.callback_url(provider, start)
        cookie = flow_cookie_of(start)
        assert person.get(callback).status_code == 303
        person.client.cookies.set(COOKIE, cookie, domain="canvas.example.test")
        replay = person.get(callback)
        assert failure_text(replay) == "state_invalid"
        assert token_requests(ps, provider) == 1

    def test_one_browsers_cookie_with_anothers_state_is_refused_and_leaves_the_record(
        self, ps: ProviderStack, provider: str
    ) -> None:
        a, b = ps.person(), ps.person()
        start_a, start_b = a.start(provider), b.start(provider)
        callback_b = b.callback_url(provider, start_b)
        callback_for_a_with_b_state = a.callback_url(provider, start_a).replace(
            query_of(a.callback_url(provider, start_a))["state"],
            query_of(callback_b)["state"],
        )
        # (a's code, b's state) arrives at a's browser, which holds a's cookie.
        assert failure_text(a.get(callback_for_a_with_b_state)) == "state_invalid"
        assert token_requests(ps, provider) == 0
        assert b.get(callback_b).status_code == 303  # b's own ceremony is intact

    def test_a_cookie_taken_to_another_browser_does_not_pop_the_record(
        self, ps: ProviderStack, provider: str
    ) -> None:
        victim, thief = ps.person(), ps.person()
        start = victim.start(provider)
        callback = victim.callback_url(provider, start)
        # The thief has the state (from the URL) but forges a cookie of their own.
        thief_start = thief.start(provider)
        thief.get(
            thief.callback_url(provider, thief_start)
        )  # a fully valid ceremony of their own
        response = thief.get(callback)
        assert failure_text(response) == "state_invalid"
        assert victim.get(callback).status_code == 303

    def test_a_storage_error_fails_closed(
        self, ps: ProviderStack, provider: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        person = ps.person()
        start = person.start(provider)
        callback = person.callback_url(provider, start)

        def boom(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("database is gone")

        monkeypatch.setattr(ps.stack.runtime.authz.txns, "pop_sync", boom)
        response = person.get(callback)
        assert (
            failure_text(response) == "token_store_unavailable"
            and "database is gone" not in response.text
        )
        assert token_requests(ps, provider) == 0
        assert not person.signed_in()


@pytest.mark.parametrize("provider", PROVIDERS)
class TestCode:
    @pytest.mark.parametrize("code", ["", "x" * 4097])
    def test_a_missing_or_huge_code_is_incomplete(
        self, ps: ProviderStack, provider: str, code: str
    ) -> None:
        person = ps.person()
        start = person.start(provider)
        callback = person.callback_url(provider, start)
        state = query_of(callback)["state"]
        path = callback.split("?", 1)[0]
        params = {"state": state, **({"code": code} if code else {})}
        if provider == "google":
            params["iss"] = "https://accounts.google.com"
        response = person.get(path, params=params)
        assert (
            failure_text(response) == "sign_in_incomplete"
            and token_requests(ps, provider) == 0
        )
        assert not person.signed_in()

    def test_the_code_is_used_only_after_every_check(
        self, ps: ProviderStack, provider: str
    ) -> None:
        person = ps.person()
        start = person.start(provider)
        callback = person.callback_url(provider, start)
        person.client.cookies.clear()
        person.get(callback)
        assert token_requests(ps, provider) == 0


class TestRfc9207:
    def test_google_must_send_its_issuer(self, ps: ProviderStack) -> None:
        person = ps.person()
        start = person.start("google")
        response = person.get(person.callback_url("google", start, iss=None))
        assert (
            failure_text(response) == "state_invalid" and ps.google.counts["token"] == 0
        )

    def test_a_wrong_issuer_is_refused_before_the_exchange(
        self, ps: ProviderStack
    ) -> None:
        person = ps.person()
        start = person.start("google")
        response = person.get(
            person.callback_url("google", start, iss="https://evil.example")
        )
        assert (
            failure_text(response) == "state_invalid" and ps.google.counts["token"] == 0
        )
        assert not person.signed_in()

    def test_the_correct_issuer_is_accepted(self, ps: ProviderStack) -> None:
        assert ps.person().sign_in("google").status_code == 303

    def test_a_provider_that_announces_the_parameter_must_send_it(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with provider_stack(tmp_path, monkeypatch) as ps:
            ps.school.iss_param = True
            person = ps.person()
            start = person.start("school")
            assert (
                failure_text(person.get(person.callback_url("school", start, iss=None)))
                == "state_invalid"
            )
            start = person.start("school")
            assert (
                person.get(person.callback_url("school", start)).status_code == 303
            )  # auto: sends iss

    def test_a_provider_that_does_not_announce_it_may_omit_it_but_not_lie(
        self, ps: ProviderStack
    ) -> None:
        person = ps.person()
        start = person.start("school")
        assert (
            person.get(person.callback_url("school", start, iss=None)).status_code
            == 303
        )
        person2 = ps.person()
        start = person2.start("school")
        wrong = person2.get(
            person2.callback_url("school", start, iss="https://evil.example")
        )
        assert failure_text(wrong) == "state_invalid"

    def test_github_has_no_issuer_to_compare(self, ps: ProviderStack) -> None:
        person = ps.person()
        start = person.start("github")
        callback = person.callback_url("github", start) + "&iss=https%3A%2F%2Fanything"
        assert person.get(callback).status_code == 303


class TestStartRoute:
    def test_the_authorize_url_is_built_from_the_configured_public_url(
        self, ps: ProviderStack
    ) -> None:
        person = ps.person()
        person.sign_in("google")
        assert (
            ps.google.last_authorize["redirect_uri"]
            == "https://canvas.example.test/auth/callback/google"
        )
        person.sign_in("github")
        assert (
            ps.github.last_authorize["redirect_uri"]
            == "https://canvas.example.test/auth/callback/github"
        )

    def test_head_is_refused_and_writes_nothing(self, ps: ProviderStack) -> None:
        rows = flow_rows(ps)
        response = ps.stack.client.head("/auth/login/google")
        assert response.status_code == 405 and flow_rows(ps) == rows

    def test_the_rate_bucket_limits_starts_per_provider(
        self, ps: ProviderStack
    ) -> None:
        from .test_entra_only_golden import account_app

        client = ps.stack.new_client()
        bucket = account_app(ps.stack).logins.start_buckets["github"]
        while bucket.take() == 0:
            pass
        assert failure_text(client.get("/auth/login/github")) == "rate_limited"
        assert (
            client.get("/auth/login/google").status_code == 302
        )  # another provider's bucket
        ps.clock.advance(3)
        assert client.get("/auth/login/github").status_code == 302

    def test_discovery_down_is_a_provider_error_and_writes_no_row(
        self, ps: ProviderStack
    ) -> None:
        ps.net.blocked.add("idp.example.edu")
        rows = flow_rows(ps)
        response = ps.stack.client.get("/auth/login/oidc/school")
        assert (
            failure_text(response) == "provider_error"
            and "idp.example.edu" not in response.text
        )
        assert flow_rows(ps) == rows

    def test_the_flow_cookie_is_host_prefixed_sealed_and_short_lived(
        self, ps: ProviderStack
    ) -> None:
        response = ps.stack.new_client().get("/auth/login/google")
        header = next(
            h for h in response.headers.get_list("set-cookie") if h.startswith(COOKIE)
        )
        for needle in ("Secure", "HttpOnly", "SameSite=lax", "Path=/", "Max-Age=600"):
            assert needle.lower() in header.lower(), header
        assert "Domain" not in header
        value = header.split(";", 1)[0].split("=", 1)[1]
        assert value.startswith("v1.") and "state" not in value

    def test_a_request_for_another_browser_is_refused(self, ps: ProviderStack) -> None:
        owner = Browser(ps.stack)
        client_id = ps.stack.register()
        from ..authz.stack import pkce

        _, challenge = pkce()
        response = owner.start(ps.stack.authorize_params(client_id, challenge))
        txn = query_of(response.headers["location"])["txn"]
        stranger = ps.person()
        refused = stranger.get(f"/auth/login/google?txn={txn}")
        assert failure_text(refused) == "authorization_invalid"
        assert ps.google.counts["token"] == 0

    def test_a_malformed_return_to_or_reauth_is_not_carried(
        self, ps: ProviderStack
    ) -> None:
        response = ps.stack.client.get(
            "/auth/login", params={"return_to": "//evil.example", "reauth": "yes"}
        )
        assert (
            response.status_code == 303
        )  # the React chooser never receives untrusted targets
        assert response.headers["location"] == "/account/sign-in"
        assert "evil.example" not in response.text


class TestDoubleCallback:
    @pytest.mark.parametrize("provider", ["google", "github"])
    def test_two_simultaneous_callbacks_one_exchange(
        self, ps: ProviderStack, provider: str
    ) -> None:
        person = ps.person()
        start = person.start(provider)
        callback = person.callback_url(provider, start)
        cookie = flow_cookie_of(start)

        class Gate:
            def __init__(self) -> None:
                self.reached = threading.Event()
                self.release = threading.Event()

            def __call__(self, point: str) -> None:
                if point == "before_txn_pop":
                    self.reached.set()
                    assert self.release.wait(WAIT)

        gate = Gate()
        txns = ps.stack.runtime.authz.txns
        txns.pause_hook = gate
        results: dict[str, httpx.Response] = {}

        def run(name: str) -> None:
            client = ps.stack.new_client()
            client.cookies.set(COOKIE, cookie, domain="canvas.example.test")
            results[name] = client.get(callback)

        first = threading.Thread(target=run, args=("one",))
        first.start()
        assert gate.reached.wait(WAIT)
        second = threading.Thread(target=run, args=("two",))
        second.start()
        if not IS_POSTGRES:
            second.join(0.5)
            assert second.is_alive()  # SQLite: the writer lock is held by the first
        txns.pause_hook = None
        gate.release.set()
        first.join(WAIT)
        second.join(WAIT)
        assert len(results) == 2
        assert sorted(r.headers["location"] for r in results.values()) == [
            "/account/",
            "/account/sign-in?error=state_invalid",
        ]
        assert token_requests(ps, provider) == 1
