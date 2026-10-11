"""The server-side halves of the sign-in with ``ACCOUNT_UI=react`` and several providers."""

from __future__ import annotations

import pathlib
from urllib.parse import parse_qs, urlsplit

import pytest

from ..authz.stack import ALICE, Browser
from ..spa_fixture import make_dist
from .fake_idp import GitHubUser
from .stack_providers import ProviderStack, provider_stack

CALLBACK_PATHS = {"/auth/callback/google", "/auth/callback/github", "/auth/callback/oidc/school"}


@pytest.fixture
def ps(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    env = { "ACCOUNT_WEB_DIST": str(make_dist(tmp_path / "dist"))}
    with provider_stack(tmp_path / "app", monkeypatch, env=env) as stack:
        yield stack


def test_react_registers_the_start_and_callback_of_every_provider_and_no_legacy_page(ps: ProviderStack) -> None:
    client = ps.stack.client
    for path in ("/auth/login/google", "/auth/login/github", "/auth/login/oidc/school", "/auth/login/entra"):
        assert client.get(path).status_code == 302
    page = client.get("/account/")
    assert page.status_code == 200 and 'id="root"' in page.text
    # The pages of the server-rendered UI do not exist here: the single-page app owns them.
    assert client.post("/account/identities/link", data={}, headers={"Origin": "https://canvas.example.test"}).status_code in (404, 405)


def test_login_sends_the_single_page_app_to_its_chooser_carrying_only_validated_values(ps: ProviderStack) -> None:
    client = ps.stack.client
    plain = client.get("/auth/login")
    assert plain.status_code == 303 and plain.headers["location"] == "/account/sign-in"
    carried = client.get("/auth/login", params={"reauth": "1", "return_to": "/account/schools"})
    query = parse_qs(urlsplit(carried.headers["location"]).query)
    assert query == {"reauth": ["1"], "return_to": ["/account/schools"]}
    evil = client.get("/auth/login", params={"return_to": "//evil.example/x", "reauth": "no"})
    assert evil.headers["location"] == "/account/sign-in"


def test_the_providers_endpoint_lists_every_provider_with_a_built_in_icon(ps: ProviderStack) -> None:
    body = ps.stack.client.get("/api/v1/providers").json()
    assert body["providers"] == [
        {"id": "entra", "kind": "oidc", "name": "Microsoft", "icon": "microsoft", "start_url": "/auth/login/entra"},
        {"id": "google", "kind": "oidc", "name": "Google", "icon": "google", "start_url": "/auth/login/google"},
        {"id": "github", "kind": "oauth2", "name": "GitHub", "icon": "github", "start_url": "/auth/login/github"},
        {"id": "oidc:school", "kind": "oidc", "name": "school", "icon": "key", "start_url": "/auth/login/oidc/school"},
    ]


def test_me_names_the_provider_of_the_session(ps: ProviderStack) -> None:
    person = ps.person()
    person.sign_in("google")
    me = Browser(ps.stack, client=person.client, react=True).api("GET", "/me").json()
    assert me["account"]["provider_id"] == "google"
    assert me["account"]["username"] == "ada@example.edu"


@pytest.mark.parametrize("provider", ["google", "github", "school"])
def test_a_sign_in_returns_to_the_app(ps: ProviderStack, provider: str) -> None:
    person = ps.person()
    response = person.sign_in(provider)
    assert response.status_code == 303 and response.headers["location"] == "/account/"


def test_return_to_is_kept_and_sanitised(ps: ProviderStack) -> None:
    person = ps.person()
    start = person.start("github", return_to="/account/write-tools")
    done = person.get(person.callback_url("github", start))
    assert done.headers["location"] == "/account/write-tools"
    for bad in ("//evil.example", "/auth/login/google", "/auth/callback/github", "https://evil.example/", "/%2e%2e/x"):
        other = ps.person()
        started = other.start("github", return_to=bad)
        landed = other.get(other.callback_url("github", started))
        assert landed.headers["location"] == "/account/", bad


@pytest.mark.parametrize(
    ("provider", "options", "code"),
    [
        ("google", {"error": "access_denied"}, "provider_error"),
        ("github", {"error": "access_denied"}, "provider_error"),
    ],
)
def test_failures_are_closed_codes_on_the_sign_in_page(ps: ProviderStack, provider: str, options: dict, code: str) -> None:
    person = ps.person()
    start = person.start(provider)
    response = person.get(person.callback_url(provider, start, **options))
    assert response.status_code == 303 and response.headers["location"] == f"/account/sign-in?error={code}"


def test_every_failure_kind_has_a_code_the_page_knows(ps: ProviderStack) -> None:
    from canvas_mcp.core.selfhost.account_core import SIGN_IN_ERROR_CODES

    person = ps.person()
    # state_invalid: no cookie
    start = person.start("google")
    callback = person.callback_url("google", start)
    person.client.cookies.clear()
    seen = {urlsplit(person.get(callback).headers["location"]).query}
    # sign_in_incomplete: no code
    start = person.start("github")
    seen.add(urlsplit(person.get("/auth/callback/github", params={"state": parse_qs(urlsplit(start.headers["location"]).query)["state"][0]}).headers["location"]).query)
    # rate_limited: the start bucket
    client = ps.stack.new_client()
    from .test_entra_only_golden import account_app

    bucket = account_app(ps.stack).logins.start_buckets["github"]
    while bucket.take() == 0:
        pass
    last = client.get("/auth/login/github")
    seen.add(urlsplit(last.headers["location"]).query)
    assert seen == {"error=state_invalid", "error=sign_in_incomplete", "error=rate_limited"}
    assert {"state_invalid", "sign_in_incomplete", "rate_limited"} <= SIGN_IN_ERROR_CODES


def test_a_refused_account_gets_access_denied_on_the_page(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = {
         "ACCOUNT_WEB_DIST": str(make_dist(tmp_path / "dist")),
        "ACCESS_POLICY": "rules", "ACCESS_RULES": "github:user:1",
    }
    with provider_stack(tmp_path / "app", monkeypatch, env=env, providers="github", policy={}) as ps:
        ps.github.user = GitHubUser(id=2)
        response = ps.person().sign_in("github")
        assert response.status_code == 303 and response.headers["location"] == "/account/sign-in?error=access_denied"


def test_an_app_waiting_for_the_sign_in_is_carried_to_the_consent_screen(ps: ProviderStack) -> None:
    person = ps.person()
    client_id, verifier, login = person.begin_connect()
    txn = parse_qs(urlsplit(login).query)["txn"][0]
    chooser = person.get(login)
    assert chooser.status_code == 303 and chooser.headers["location"] == f"/account/sign-in?txn={txn}"
    start = person.get("/auth/login/google", params={"txn": txn})
    callback = person.get(person.callback_url("google", start))
    assert callback.status_code == 303 and callback.headers["location"] == f"/account/consent?txn={txn}"
    assert client_id and verifier


def test_entra_still_works_through_its_own_start(ps: ProviderStack) -> None:
    person = ps.person()
    assert person.sign_in_entra(ALICE).status_code == 303


@pytest.mark.parametrize("provider", ["google", "github", "school"])
def test_a_cancelled_re_sign_in_of_a_signed_in_person_goes_to_the_sign_in_page_not_the_methods_screen(
    ps: ProviderStack, provider: str
) -> None:
    person = ps.person()
    assert person.sign_in("google").status_code == 303
    start = person.start(provider, reauth="1")
    response = person.get(person.callback_url(provider, start, error="access_denied"))
    assert response.status_code == 303
    assert response.headers["location"] == "/account/sign-in?error=provider_error"
