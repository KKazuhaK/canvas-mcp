"""Native sign-in sessions, provider inventory and admission rules end to end."""

from __future__ import annotations

import pathlib

import pytest

from canvas_mcp.core.selfhost import accounts as acc

from ..authz.stack import ALICE
from .fake_idp import GitHubUser, IdpUser
from .stack_providers import ProviderStack, provider_stack
from .test_linking_web import api

GOOGLE_SUB = "110169484474386276334"


@pytest.fixture
def ps(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    with provider_stack(tmp_path, monkeypatch) as stack:
        yield stack


def test_login_redirects_to_the_react_chooser_with_the_native_provider_manifest(
    ps: ProviderStack,
) -> None:
    page = ps.stack.client.get("/auth/login")
    assert page.status_code == 303 and page.headers["location"] == "/account/sign-in"
    assert page.headers["cache-control"] == "no-store"
    providers = ps.stack.client.get("/api/v1/providers").json()["providers"]
    assert [(p["id"], p["start_url"]) for p in providers] == [
        ("entra", "/auth/login/entra"),
        ("google", "/auth/login/google"),
        ("github", "/auth/login/github"),
        ("oidc:school", "/auth/login/oidc/school"),
    ]
    assert all(not p["icon"].startswith(("http:", "https:")) for p in providers)


def test_the_signed_out_account_shell_and_public_manifest_are_available(
    ps: ProviderStack,
) -> None:
    page = ps.stack.client.get("/account")
    assert page.status_code == 200 and 'id="root"' in page.text
    assert ps.stack.client.get("/api/v1/providers").status_code == 200
    assert ps.stack.client.get("/api/v1/me").status_code == 401


@pytest.mark.parametrize("provider", ["google", "github", "school"])
def test_a_sign_in_creates_an_account_and_a_session(
    ps: ProviderStack, provider: str
) -> None:
    person = ps.person()
    response = person.sign_in(provider)
    assert response.status_code == 303 and response.headers["location"] == "/account/"
    assert person.signed_in()
    set_cookie = response.headers.get_list("set-cookie")
    assert any(
        c.startswith("__Host-cmcp_session=") and "Secure" in c and "HttpOnly" in c
        for c in set_cookie
    )
    assert any(
        c.startswith("__Host-cmcp_flow=") and "Max-Age=0" in c for c in set_cookie
    )
    me = api(person, "GET", "/me").json()
    assert me["canvas"]["state"] == "none"
    assert me["account"]["provider_id"] == (
        "oidc:school" if provider == "school" else provider
    )


def test_the_identity_key_is_provider_issuer_and_subject(ps: ProviderStack) -> None:
    ps.person().sign_in("google")
    ps.person().sign_in("github")
    ps.person().sign_in("school")
    assert ps.account_of("google", acc.GOOGLE_ISSUER, GOOGLE_SUB)
    assert ps.account_of("github", acc.GITHUB_ISSUER, "583231")
    assert ps.account_of(
        "oidc:school", "https://idp.example.edu/realms/school", "user-1"
    )
    assert ps.store.account_counts()["total"] == 3


def test_a_second_sign_in_reuses_the_account(ps: ProviderStack) -> None:
    ps.person().sign_in("google")
    ps.person().sign_in("google")
    assert ps.store.account_counts()["total"] == 1
    events = ps.store.auth_events_page(
        ps.account_of("google", acc.GOOGLE_ISSUER, GOOGLE_SUB) or ""
    ).items
    assert [e.provider_id for e in events] == ["google", "google"]


def test_the_session_api_names_the_verified_provider_and_username(
    ps: ProviderStack,
) -> None:
    person = ps.person()
    person.sign_in("google")
    me = api(person, "GET", "/me").json()
    assert me["account"]["provider_id"] == "google"
    assert me["account"]["username"] == "ada@example.edu"


def test_login_history_names_the_provider(ps: ProviderStack) -> None:
    person = ps.person()
    person.sign_in("github")
    response = api(person, "GET", "/me/login-history")
    assert response.status_code == 200
    assert [e["provider_id"] for e in response.json()["events"]] == ["github"]


def test_no_secret_code_or_token_is_in_the_pages_or_the_cookies(
    ps: ProviderStack,
) -> None:
    person = ps.person()
    start = person.start("github")
    callback = person.callback_url("github", start)
    done = person.get(callback)
    blob = done.text + str(dict(done.headers)) + str(person.client.cookies)
    blob += (
        api(person, "GET", "/me").text + api(person, "GET", "/me/login-history").text
    )
    for secret in (
        ps.github.client_secret,
        *ps.github.issued_tokens,
        ps.google.client_secret,
    ):
        assert secret not in blob
    assert "ghr_refresh_value" not in blob


def test_a_google_domain_rule_admits_the_workspace_account_only(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = {"ACCESS_POLICY": "rules", "ACCESS_RULES": "google:domain:example.edu"}
    with provider_stack(tmp_path, monkeypatch, policy=policy, providers="google") as ps:
        ok = ps.person().sign_in("google")
        assert ok.status_code == 303
        other = ps.person().sign_in(
            "google", user=IdpUser(sub="2", email="x@gmail.com", extra={})
        )
        assert (
            other.status_code == 303
            and other.headers["location"] == "/account/sign-in?error=access_denied"
        )
        assert "Microsoft" not in other.text
        assert ps.store.account_counts()["total"] == 1


def test_a_github_org_rule_needs_the_membership_and_requests_read_org(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = {"ACCESS_POLICY": "rules", "ACCESS_RULES": "github:org:Acme"}
    with provider_stack(tmp_path, monkeypatch, policy=policy, providers="github") as ps:
        ps.github.user = GitHubUser(orgs={"acme": "active"})
        member = ps.person()
        assert member.sign_in("github").status_code == 303
        assert ps.github.last_authorize["scope"] == "user:email read:org"
        ps.github.user = GitHubUser(id=999, login="outsider")
        assert (
            ps.person().sign_in("github").headers["location"]
            == "/account/sign-in?error=access_denied"
        )
        ps.github.user = GitHubUser(id=1000, login="locked", orgs={"acme": 403})
        assert (
            ps.person().sign_in("github").headers["location"]
            == "/account/sign-in?error=access_denied"
        )
        assert ps.store.account_counts()["total"] == 1


def test_a_oidc_claim_rule(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = {
        "ACCESS_POLICY": "rules",
        "ACCESS_RULES": "oidc:school:claim:groups=canvas-users",
    }
    with provider_stack(
        tmp_path, monkeypatch, policy=policy, providers="oidc:school"
    ) as ps:
        yes = IdpUser(sub="a", extra={"groups": ["x", "canvas-users"]})
        no = IdpUser(sub="b", extra={"groups": ["canvas-users-2"]})
        assert ps.person().sign_in("school", user=yes).status_code == 303
        assert (
            ps.person().sign_in("school", user=no).headers["location"]
            == "/account/sign-in?error=access_denied"
        )


def test_a_single_non_entra_provider_redirects_login_straight_to_it(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with provider_stack(tmp_path, monkeypatch, providers="google") as ps:
        response = ps.stack.client.get("/auth/login")
        assert (
            response.status_code == 303
            and response.headers["location"] == "/auth/login/google"
        )
        sub = ps.stack.client.get("/auth/login", params={"reauth": "1"})
        assert sub.headers["location"] == "/auth/login/google?reauth=1"


def test_entra_still_signs_in_next_to_the_others(ps: ProviderStack) -> None:
    person = ps.person()
    response = person.sign_in_entra(ALICE)
    assert response.status_code == 303 and person.signed_in()
    assert ps.stack.account_of(ALICE)


def test_without_entra_there_is_no_entra_callback_or_start(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with provider_stack(tmp_path, monkeypatch, providers="google,github") as ps:
        for path in ("/auth/callback/entra", "/auth/login/entra"):
            assert ps.stack.client.get(path, params={"state": "x"}).status_code in (
                404,
                405,
            )
        page = ps.stack.client.get("/auth/login")
        assert (
            page.status_code == 303 and page.headers["location"] == "/account/sign-in"
        )
        providers = ps.stack.client.get("/api/v1/providers").json()["providers"]
        assert [p["id"] for p in providers] == ["google", "github"]
        assert ps.stack.settings.tenant_id == "" and not ps.stack.settings.entra_enabled
