"""GitHub as a sign-in provider, against the offline fake."""

from __future__ import annotations

import logging
import secrets
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from canvas_mcp.core.selfhost.login.config import GitHubConfig
from canvas_mcp.core.selfhost.login.github import GitHubLoginProvider
from canvas_mcp.core.selfhost.login.http import SafeHttp
from canvas_mcp.core.selfhost.login.protocol import SignInRejected

from .fake_idp import FakeGitHub, FakeNetwork, GitHubUser, s256

BASE = "https://canvas.example.test"


def make(*, orgs: tuple[str, ...] = (), teams: tuple[str, ...] = ()) -> tuple[GitHubLoginProvider, FakeGitHub]:
    net = FakeNetwork()
    gh = FakeGitHub(net)
    provider = GitHubLoginProvider(
        GitHubConfig(gh.client_id, gh.client_secret), public_base_url=BASE,
        http=SafeHttp(transport=net.transport), orgs=orgs, teams=teams,
    )
    return provider, gh


async def sign_in(provider: GitHubLoginProvider, gh: FakeGitHub, *, reauth: bool = False, **authorize: Any) -> Any:
    verifier = secrets.token_urlsafe(48)
    state = secrets.token_urlsafe(32)
    url = provider.authorize_url(state=state, nonce="", code_challenge=s256(verifier), reauth=reauth)
    callback = gh.authorize(url, **authorize)
    code = parse_qs(urlsplit(callback).query)["code"][0]
    return await provider.finish(code=code, code_verifier=verifier, nonce="")


class TestAuthorizeUrl:
    def test_the_parameters_without_membership_rules(self) -> None:
        provider, _ = make()
        url = provider.authorize_url(state="S" * 43, nonce="ignored", code_challenge="C" * 43, reauth=False)
        parts = urlsplit(url)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == "https://github.com/login/oauth/authorize"
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        assert query == {
            "client_id": "Iv1.0123456789abcdef", "redirect_uri": f"{BASE}/auth/callback/github",
            "scope": "user:email", "state": "S" * 43, "code_challenge": "C" * 43, "code_challenge_method": "S256",
        }

    def test_read_org_is_requested_only_with_org_or_team_rules(self) -> None:
        for kwargs in ({"orgs": ("acme",)}, {"teams": ("acme/core",)}):
            provider, _ = make(**kwargs)
            url = provider.authorize_url(state="s", nonce="", code_challenge="c", reauth=False)
            assert parse_qs(urlsplit(url).query)["scope"] == ["user:email read:org"]

    def test_the_account_picker_is_asked_for_only_on_reauth(self) -> None:
        provider, _ = make()
        plain = provider.authorize_url(state="s", nonce="", code_challenge="c", reauth=False)
        forced = provider.authorize_url(state="s", nonce="", code_challenge="c", reauth=True)
        assert "prompt" not in parse_qs(urlsplit(plain).query)
        assert parse_qs(urlsplit(forced).query)["prompt"] == ["select_account"]

    def test_identity_of_the_provider(self) -> None:
        provider, _ = make()
        assert provider.id == "github" and provider.kind == "oauth2" and provider.response_issuer is None
        assert not provider.requires_iss()
        assert provider.redirect_uri == f"{BASE}/auth/callback/github"
        assert provider.display.icon == "github"


class TestIdentity:
    async def test_a_sign_in(self) -> None:
        provider, gh = make()
        ext = await sign_in(provider, gh)
        assert (ext.provider_id, ext.issuer, ext.subject) == ("github", "https://github.com", "583231")
        assert ext.username == "octocat" and ext.display_name == "The Octocat"
        assert (ext.email, ext.email_verified) == ("octocat@example.test", True)
        assert ext.orgs == frozenset() and ext.membership_unavailable is False

    async def test_the_token_request_and_the_api_headers(self) -> None:
        provider, gh = make()
        await sign_in(provider, gh)
        form = gh.token_requests[0]
        assert form["redirect_uri"] == f"{BASE}/auth/callback/github" and len(form["code_verifier"]) >= 43
        assert form["client_secret"] == gh.client_secret
        methods = {(m, p) for m, p, _ in gh.api_requests}
        assert methods == {("GET", "/user"), ("GET", "/user/emails")}
        for _, _, headers in gh.api_requests:
            assert headers["x-github-api-version"] == "2026-03-10"
            assert headers["user-agent"] == "canvas-mcp-selfhost"
            assert headers["authorization"].startswith("Bearer gho_")

    @pytest.mark.parametrize("error", ["bad_verification_code", "redirect_uri_mismatch", "incorrect_client_credentials"])
    async def test_an_error_in_a_200_body_is_a_provider_error(self, error: str) -> None:
        provider, gh = make()
        gh.token_error = {"error": error, "error_description": "text that is never shown"}
        with pytest.raises(SignInRejected) as info:
            await sign_in(provider, gh)
        assert info.value.code == "provider_error"
        assert gh.api_requests == []

    async def test_a_missing_access_token_is_a_provider_error(self) -> None:
        provider, gh = make()
        gh.token_error = {"token_type": "bearer"}
        with pytest.raises(SignInRejected):
            await sign_in(provider, gh)

    @pytest.mark.parametrize("bad", [True, "583231", 0, -5, None, 1.5, [1]])
    async def test_an_id_that_is_not_a_positive_integer_is_refused(self, bad: Any) -> None:
        provider, gh = make()
        gh.user = GitHubUser(id=bad)
        with pytest.raises(SignInRejected) as info:
            await sign_in(provider, gh)
        assert info.value.code == "sign_in_unverified"

    async def test_the_primary_verified_address_beats_the_public_one(self) -> None:
        provider, gh = make()
        gh.user = GitHubUser(
            email="public@example.test",
            emails=[
                {"email": "other@example.test", "primary": False, "verified": True},
                {"email": "primary-unverified@example.test", "primary": True, "verified": False},
            ],
        )
        ext = await sign_in(provider, gh)
        assert (ext.email, ext.email_verified) == ("public@example.test", False)
        gh.user.emails = [{"email": "main@example.test", "primary": True, "verified": True}]
        provider2, gh2 = make()
        gh2.user = GitHubUser(email="public@example.test", emails=gh.user.emails)
        ext = await sign_in(provider2, gh2)
        assert (ext.email, ext.email_verified) == ("main@example.test", True)

    @pytest.mark.parametrize("status", [403, 404])
    async def test_a_refused_email_listing_leaves_no_address(self, status: int) -> None:
        provider, gh = make()
        gh.emails_status = status
        ext = await sign_in(provider, gh)
        assert ext.email is None and ext.email_verified is False

    async def test_without_the_email_scope_the_emails_are_not_asked_for(self) -> None:
        provider, gh = make()
        gh.granted_scope = ""
        ext = await sign_in(provider, gh)
        assert ext.email is None
        assert ("GET", "/user/emails") not in {(m, p) for m, p, _ in gh.api_requests}

    async def test_the_name_falls_back_to_the_login(self) -> None:
        provider, gh = make()
        gh.user = GitHubUser(name=None)
        assert (await sign_in(provider, gh)).display_name == "octocat"

    async def test_an_odd_login_is_not_used_as_a_name_or_in_a_url(self) -> None:
        provider, gh = make(teams=("acme/core",))
        gh.user = GitHubUser(login="../x", teams={"acme/core": "active"})
        ext = await sign_in(provider, gh)
        assert ext.username == "" and ext.membership_unavailable and ext.teams == frozenset()


class TestMembershipRateLimit:
    @pytest.mark.parametrize(
        "headers",
        [{"x-ratelimit-remaining": "0"}, {"retry-after": "60"}],
        ids=["primary", "secondary"],
    )
    async def test_a_rate_limited_403_is_a_provider_error_not_a_lost_membership(
        self, headers: dict[str, str]
    ) -> None:
        provider, gh = make(orgs=("acme",))
        gh.user = GitHubUser(orgs={"acme": "active"})
        gh.membership_override = (403, headers)
        with pytest.raises(SignInRejected) as raised:
            await sign_in(provider, gh)
        assert raised.value.code == "provider_error"

    async def test_a_403_with_calls_remaining_is_still_unavailable(self) -> None:
        provider, gh = make(orgs=("acme",))
        gh.membership_override = (403, {"x-ratelimit-remaining": "4999"})
        ext = await sign_in(provider, gh)
        assert ext.membership_unavailable is True and ext.orgs == frozenset()

    async def test_a_429_is_a_provider_error(self) -> None:
        provider, gh = make(orgs=("acme",))
        gh.membership_override = (429, {})
        with pytest.raises(SignInRejected):
            await sign_in(provider, gh)


class TestMemberships:
    async def test_no_lookup_without_org_or_team_rules(self) -> None:
        provider, gh = make()
        gh.user = GitHubUser(orgs={"acme": "active"})
        await sign_in(provider, gh)
        assert not any("memberships" in p for _, p, _ in gh.api_requests)

    async def test_active_pending_missing_and_restricted_organisations(self) -> None:
        provider, gh = make(orgs=("acme", "pend", "gone", "locked"))
        gh.user = GitHubUser(orgs={"acme": "active", "pend": "pending", "locked": 403})
        ext = await sign_in(provider, gh)
        assert ext.orgs == frozenset({"acme"})
        assert ext.membership_unavailable is True

    async def test_child_team_membership_counts_and_a_missing_team_does_not(self) -> None:
        provider, gh = make(teams=("acme/core", "acme/other"))
        gh.user = GitHubUser(teams={"acme/core": "active"})
        ext = await sign_in(provider, gh)
        assert ext.teams == frozenset({"acme/core"}) and ext.membership_unavailable is False
        paths = [p for _, p, _ in gh.api_requests if "teams" in p]
        assert "/orgs/acme/teams/core/memberships/octocat" in paths

    async def test_a_pending_team_membership_does_not_match(self) -> None:
        provider, gh = make(teams=("acme/core",))
        gh.user = GitHubUser(teams={"acme/core": "pending"})
        assert (await sign_in(provider, gh)).teams == frozenset()

    async def test_a_403_on_a_team_is_unavailable(self) -> None:
        provider, gh = make(teams=("acme/core",))
        gh.user = GitHubUser(teams={"acme/core": 403})
        assert (await sign_in(provider, gh)).membership_unavailable is True

    async def test_scopes_the_person_reduced_mean_no_lookup_and_unavailable(self) -> None:
        provider, gh = make(orgs=("acme",))
        gh.user = GitHubUser(orgs={"acme": "active"})
        gh.granted_scope = "user:email"
        ext = await sign_in(provider, gh)
        assert ext.orgs == frozenset() and ext.membership_unavailable is True
        assert not any("memberships" in p for _, p, _ in gh.api_requests)

    async def test_a_broader_org_scope_is_enough(self) -> None:
        provider, gh = make(orgs=("acme",))
        gh.user = GitHubUser(orgs={"acme": "active"})
        gh.granted_scope = "user:email admin:org"
        assert (await sign_in(provider, gh)).orgs == frozenset({"acme"})

    async def test_a_server_error_while_looking_up_is_a_provider_error(self) -> None:
        provider, gh = make(orgs=("acme",))
        original = gh._api

        def broken(request: Any) -> Any:
            if "memberships" in request.url.path:
                import httpx

                return httpx.Response(500, json={"message": "x"})
            return original(request)

        gh.net.add("api.github.com", broken)
        with pytest.raises(SignInRejected) as info:
            await sign_in(provider, gh)
        assert info.value.code == "provider_error"


class TestTheTokenIsNeverKept:
    async def test_it_is_not_in_the_claims_the_logs_or_the_exception(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        provider, gh = make(orgs=("acme",))
        with caplog.at_level(logging.DEBUG):
            ext = await sign_in(provider, gh)
        token = gh.issued_tokens[0]
        assert token not in repr(ext) and token not in caplog.text and token not in repr(provider)
        gh.user = GitHubUser(id=0)
        with caplog.at_level(logging.DEBUG), pytest.raises(SignInRejected) as info:
            await sign_in(provider, gh)
        assert gh.issued_tokens[-1] not in caplog.text + repr(info.value) + str(info.value)
        assert "ghr_refresh_value" not in caplog.text  # nor the refresh token
