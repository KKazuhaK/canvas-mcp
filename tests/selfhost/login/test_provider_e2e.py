"""Every provider through sign-in, consent, the token endpoint and an MCP tool call (local mode)."""

from __future__ import annotations

import pathlib

import pytest
from dbbackend import raw_sql

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.token_store import OPERATOR

from ..authz.stack import ALICE
from .fake_idp import GitHubUser, IdpUser
from .stack_providers import ProviderStack, provider_stack

GOOGLE_SUB = "110169484474386276334"
IDENTITIES = {
    "google": ("google", acc.GOOGLE_ISSUER, GOOGLE_SUB),
    "github": ("github", acc.GITHUB_ISSUER, "583231"),
    "school": ("oidc:school", "https://idp.example.edu/realms/school", "user-1"),
}


@pytest.fixture
def ps(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    with provider_stack(tmp_path, monkeypatch) as stack:
        yield stack


@pytest.mark.parametrize("provider", ["google", "github", "school"])
def test_an_app_connects_through_the_provider_and_the_tool_call_carries_the_account(
    ps: ProviderStack, provider: str
) -> None:
    person = ps.person()
    landed, client_id, verifier = person.connect(provider)
    assert "code" in landed.query, landed
    tokens = person.tokens(landed, client_id, verifier)
    account = ps.account_of(*IDENTITIES[provider])
    assert account is not None
    ps.enroll_canvas(account)
    assert ps.stack.whoami(tokens["access_token"]) == account
    assert ps.stack.mcp_status(tokens["access_token"]) == 200
    # The apps list of the account names this client.
    assert [g.account_id for g in ps.stack.authz.store.list_all_grants(include_inactive=False, limit=10)] == [
        account.removeprefix("acct:")
    ]


def test_entra_still_connects_in_a_multi_provider_setup(ps: ProviderStack) -> None:
    person = ps.person()
    landed, client_id, verifier = person.connect("entra", user=ALICE)
    tokens = person.tokens(landed, client_id, verifier)
    account = ps.enroll_canvas(ps.stack.account_of(ALICE))
    assert ps.stack.whoami(tokens["access_token"]) == account


def test_consent_shortcut_when_already_signed_in_and_a_forced_provider_prompt_for_a_different_account(
    ps: ProviderStack,
) -> None:
    person = ps.person()
    person.connect("school")
    assert "prompt" not in ps.school.last_authorize
    client_id, verifier, login = person.begin_connect()
    shortcut = person.get(login)  # already signed in: straight to the consent page, no provider
    assert shortcut.status_code == 303 and shortcut.headers["location"].startswith("/account/consent?txn=")
    person.get(login + "&reauth=1")  # "use a different account": the chooser, which carries reauth
    start = person.get("/account/login/oidc/school", params={"txn": login.split("txn=")[1].split("&")[0], "reauth": "1"})
    assert start.status_code == 302
    ps.school.authorize(start.headers["location"])
    assert ps.school.last_authorize["prompt"] == "login"


def test_the_account_is_the_one_whose_provider_signed_in_even_with_two_providers_present(ps: ProviderStack) -> None:
    one, two = ps.person(), ps.person()
    landed1, c1, v1 = one.connect("google")
    landed2, c2, v2 = two.connect("github")
    t1, t2 = one.tokens(landed1, c1, v1), two.tokens(landed2, c2, v2)
    for identity in ("google", "github"):
        ps.enroll_canvas(ps.account_of(*IDENTITIES[identity]) or "")
    assert ps.stack.whoami(t1["access_token"]) != ps.stack.whoami(t2["access_token"])


def test_refresh_is_refused_after_the_upstream_age(ps: ProviderStack) -> None:
    person = ps.person()
    landed, client_id, verifier = person.connect("github")
    tokens = person.tokens(landed, client_id, verifier)
    ps.clock.advance(14 * 86400 + 1)
    refused = ps.stack.refresh(client_id, tokens["refresh_token"])
    assert refused.status_code == 401 and refused.json()["error"] == "invalid_grant"


def test_a_disabled_account_is_refused_at_the_provider_sign_in(ps: ProviderStack) -> None:
    ps.person().sign_in("google")
    key = ps.account_of(*IDENTITIES["google"])
    assert key is not None and ps.store.disable_principal(key, actor=OPERATOR, reason="operator_disabled")
    response = ps.person().sign_in("google")
    assert response.status_code == 403 and "disabled" in response.text.lower()


class TestApproval:
    def test_a_pending_account_signs_in_but_consent_can_only_cancel(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with provider_stack(
            tmp_path, monkeypatch, policy={"ACCESS_POLICY": "approval", "ACCESS_OPEN_ACKNOWLEDGE_PUBLIC": "true"}
        ) as ps:
            person = ps.person()
            client_id, verifier, login = person.begin_connect()
            txn = login.split("txn=")[1]
            start = person.get("/account/login/google", params={"txn": txn})
            callback = person.get(person.callback_url("google", start))
            assert callback.status_code == 303
            page = person.get(callback.headers["location"])
            assert page.status_code == 200 and 'value="approve"' not in page.text
            assert 'value="deny"' in page.text
            key = ps.account_of(*IDENTITIES["google"])
            assert key is not None and ps.store.get_principal_status(key).pending


class TestAdmissionLost:
    def test_a_github_member_who_left_the_org_loses_the_connected_apps(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy = {"ACCESS_POLICY": "rules", "ACCESS_RULES": "github:org:acme"}
        with provider_stack(tmp_path, monkeypatch, policy=policy, providers="github") as ps:
            ps.github.user = GitHubUser(orgs={"acme": "active"})
            person = ps.person()
            landed, client_id, verifier = person.connect("github")
            tokens = person.tokens(landed, client_id, verifier)
            assert ps.stack.mcp_status(tokens["access_token"]) == 200
            ps.github.user = GitHubUser(orgs={})
            refused = ps.person().sign_in("github")
            assert refused.status_code == 403
            rows = raw_sql(ps.store, "SELECT revoked_reason, revoked_by FROM oauth_grants")
            assert rows == [("admission_lost", "system")]
            assert ps.stack.mcp_status(tokens["access_token"]) == 401
            assert ps.stack.refresh(client_id, tokens["refresh_token"]).status_code == 401

    def test_a_google_user_whose_domain_changed(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy = {"ACCESS_POLICY": "rules", "ACCESS_RULES": "google:domain:example.edu"}
        with provider_stack(tmp_path, monkeypatch, policy=policy, providers="google") as ps:
            person = ps.person()
            landed, client_id, verifier = person.connect("google")
            tokens = person.tokens(landed, client_id, verifier)
            moved = IdpUser(sub=GOOGLE_SUB, email="ada@other.test", extra={"hd": "other.test"})
            assert ps.person().sign_in("google", user=moved).status_code == 403
            assert ps.stack.mcp_status(tokens["access_token"]) == 401

    def test_an_oidc_claim_that_was_removed(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy = {"ACCESS_POLICY": "rules", "ACCESS_RULES": "oidc:school:claim:groups=staff"}
        with provider_stack(tmp_path, monkeypatch, policy=policy, providers="oidc:school") as ps:
            person = ps.person()
            landed, client_id, verifier = person.connect(
                "school", user=IdpUser(extra={"groups": ["staff"]})
            )
            tokens = person.tokens(landed, client_id, verifier)
            assert ps.person().sign_in("school", user=IdpUser(extra={"groups": []})).status_code == 403
            assert ps.stack.mcp_status(tokens["access_token"]) == 401


class TestOwners:
    def test_a_bootstrap_google_identity_becomes_the_first_owner_and_reaches_the_admin_page(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env = {"SELFHOST_BOOTSTRAP_OWNER": f"google:{GOOGLE_SUB}"}
        with provider_stack(tmp_path, monkeypatch, env=env, providers="google") as ps:
            owner = ps.person()
            assert owner.sign_in("google").status_code == 303
            assert owner.get("/account/admin").status_code == 200
            key = ps.account_of(*IDENTITIES["google"])
            assert key is not None and ps.store.get_principal_status(key).is_owner
            other = ps.person()
            other.sign_in("google", user=IdpUser(sub="222", email="b@example.edu", extra={"hd": "example.edu"}))
            assert other.get("/account/admin").status_code == 403  # an ordinary user

    def test_a_deployment_without_entra_starts_with_token_admin_and_promote_owner_works(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with provider_stack(tmp_path, monkeypatch, providers="google") as ps:
            person = ps.person()
            person.sign_in("google")
            assert person.get("/account/admin").status_code == 403
            key = ps.account_of(*IDENTITIES["google"])
            assert key is not None and ps.store.promote_owner(key, actor=OPERATOR)
            fresh = ps.person()
            fresh.sign_in("google")
            assert fresh.get("/account/admin").status_code == 200

    def test_a_google_user_is_never_an_owner_through_the_rules(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with provider_stack(tmp_path, monkeypatch, providers="entra,google") as ps:
            person = ps.person()
            person.sign_in("google")
            assert person.get("/account/admin").status_code == 403
            key = ps.account_of(*IDENTITIES["google"])
            assert key is not None and not ps.store.get_principal_status(key).is_owner
