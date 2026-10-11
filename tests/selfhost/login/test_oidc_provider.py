"""The generic OpenID Connect provider and Google's profile, against the offline fake provider."""

from __future__ import annotations

import base64
import logging
import secrets
from typing import Any
from urllib.parse import parse_qs, unquote_plus, urlsplit

import pytest

from canvas_mcp.core.selfhost.accounts import GOOGLE_ISSUER
from canvas_mcp.core.selfhost.login.config import GoogleConfig, OidcConfig
from canvas_mcp.core.selfhost.login.google import build_google_provider
from canvas_mcp.core.selfhost.login.http import SafeHttp
from canvas_mcp.core.selfhost.login.metadata import ProviderUnavailable
from canvas_mcp.core.selfhost.login.oidc import OidcLoginProvider, build_oidc_provider
from canvas_mcp.core.selfhost.login.protocol import SignInRejected

from .fake_idp import DELETE, FakeNetwork, FakeOidcIdp, IdpUser, google_idp, s256

BASE = "https://canvas.example.test"
ISSUER = "https://idp.example.edu/realms/school"


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    return verifier, s256(verifier)


def make(
    net: FakeNetwork | None = None, *, claim_names: frozenset[str] = frozenset(), **cfg: Any
) -> tuple[OidcLoginProvider, FakeOidcIdp]:
    net = net or FakeNetwork()
    idp = FakeOidcIdp(net, ISSUER, **{k: cfg.pop(k) for k in list(cfg) if k in ("algs", "iss_param", "pkce_methods", "token_auth", "cache_control")})
    config = OidcConfig(
        slug="school", issuer=ISSUER, client_id=idp.client_id, client_secret=idp.client_secret, **cfg
    )
    provider = build_oidc_provider(
        config, public_base_url=BASE, http=SafeHttp(transport=net.transport), claim_names=claim_names
    )
    return provider, idp


async def sign_in(provider: Any, idp: FakeOidcIdp, *, reauth: bool = False, **authorize: Any) -> Any:
    """Run start + 'browser' + finish; returns the ExternalClaims."""
    await provider.prepare()
    verifier, challenge = pkce()
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    url = provider.authorize_url(state=state, nonce=nonce, code_challenge=challenge, reauth=reauth)
    callback = idp.authorize(url, **authorize)
    query = {k: v[0] for k, v in parse_qs(urlsplit(callback).query).items()}
    assert query["state"] == state
    return await provider.finish(code=query["code"], code_verifier=verifier, nonce=nonce)


class TestAuthorizeUrl:
    async def test_the_exact_parameters(self) -> None:
        provider, idp = make(scopes=("openid", "profile"))
        await provider.prepare()
        url = provider.authorize_url(state="S" * 43, nonce="N" * 43, code_challenge="C" * 43, reauth=False)
        parts = urlsplit(url)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == idp.endpoints["authorization"]
        query = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        assert query == {
            "response_type": "code", "client_id": "canvas-mcp", "redirect_uri": f"{BASE}/account/callback/oidc/school",
            "scope": "openid profile", "state": "S" * 43, "nonce": "N" * 43, "code_challenge": "C" * 43,
            "code_challenge_method": "S256",
        }
        assert "response_mode" not in query and "prompt" not in query

    async def test_a_forced_reauthentication_asks_the_provider_to_login_again(self) -> None:
        provider, _ = make()
        await provider.prepare()
        url = provider.authorize_url(state="s", nonce="n", code_challenge="c", reauth=True)
        assert parse_qs(urlsplit(url).query)["prompt"] == ["login"]

    async def test_the_url_cannot_be_built_before_discovery_has_succeeded(self) -> None:
        provider, _ = make()
        with pytest.raises(ProviderUnavailable):
            provider.authorize_url(state="s", nonce="n", code_challenge="c", reauth=False)

    async def test_a_provider_that_is_down_is_unavailable_at_the_start(self) -> None:
        provider, idp = make()
        idp.net.blocked.add("idp.example.edu")
        with pytest.raises(ProviderUnavailable):
            await provider.prepare()

    def test_the_redirect_uri_comes_from_the_public_url_and_the_slug(self) -> None:
        provider, _ = make()
        assert provider.redirect_uri == f"{BASE}/account/callback/oidc/school"
        assert provider.start_path == "/account/login/oidc/school" and provider.id == "oidc:school"
        assert provider.display.name == "school" and provider.display.icon == "key"


class TestFinish:
    async def test_a_full_sign_in_yields_neutral_claims(self) -> None:
        provider, idp = make()
        ext = await sign_in(provider, idp)
        assert (ext.provider_id, ext.issuer, ext.subject) == ("oidc:school", ISSUER, "user-1")
        assert (ext.email, ext.email_verified) == ("ada@example.edu", True)
        assert ext.display_name == "Ada Lovelace" and ext.username == "ada"
        assert ext.roles == frozenset() and ext.hd == "" and ext.claims == ()

    async def test_the_code_is_exchanged_with_pkce_and_the_registered_redirect_uri(self) -> None:
        provider, idp = make()
        await sign_in(provider, idp)
        form = idp.token_requests[0]["form"]
        assert form["grant_type"] == "authorization_code"
        assert form["redirect_uri"] == f"{BASE}/account/callback/oidc/school"
        assert len(form["code_verifier"]) >= 43 and "code" in form

    async def test_client_secret_basic_uses_the_rfc_6749_encoding(self) -> None:
        net = FakeNetwork()
        idp = FakeOidcIdp(net, ISSUER, client_id="id with space", client_secret="se:cret/+%value012345")
        provider = build_oidc_provider(
            OidcConfig("school", ISSUER, idp.client_id, idp.client_secret, token_auth_method="client_secret_basic"),
            public_base_url=BASE, http=SafeHttp(transport=net.transport),
        )
        await sign_in(provider, idp)
        record = idp.token_requests[0]
        assert record["auth"] == "client_secret_basic" and "client_secret" not in record["form"]
        raw = base64.b64decode(record["headers"]["authorization"][6:]).decode()
        user, _, password = raw.partition(":")
        assert user == "id+with+space" and unquote_plus(password) == "se:cret/+%value012345"
        assert "se:cret" not in password  # the colon was percent-encoded

    async def test_client_secret_post_puts_the_credentials_in_the_form(self) -> None:
        provider, idp = make(token_auth_method="client_secret_post")
        await sign_in(provider, idp)
        record = idp.token_requests[0]
        assert record["auth"] == "client_secret_post" and "authorization" not in record["headers"]
        assert record["form"]["client_id"] == "canvas-mcp"

    async def test_without_a_configured_method_basic_is_used_when_listed_or_nothing_is_listed(self) -> None:
        provider, idp = make()
        await sign_in(provider, idp)
        assert idp.token_requests[0]["auth"] == "client_secret_basic"
        provider, idp = make(token_auth=None)
        await sign_in(provider, idp)
        assert idp.token_requests[0]["auth"] == "client_secret_basic"

    async def test_without_a_configured_method_post_is_used_when_basic_is_not_listed(self) -> None:
        provider, idp = make(token_auth=("client_secret_post",))
        await sign_in(provider, idp)
        assert idp.token_requests[0]["auth"] == "client_secret_post"

    async def test_a_token_error_is_a_provider_error_and_only_a_code_is_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        provider, idp = make()
        await provider.prepare()
        idp.token_error = (400, {"error": "invalid_grant", "error_description": "secret idp text"})
        with caplog.at_level(logging.INFO), pytest.raises(SignInRejected) as info:
            await sign_in(provider, idp)
        assert info.value.code == "provider_error"
        assert "secret idp text" not in caplog.text and "invalid_grant" in caplog.text

    async def test_a_missing_id_token_is_a_provider_error(self) -> None:
        provider, idp = make()
        idp.drop_id_token = True
        with pytest.raises(SignInRejected) as info:
            await sign_in(provider, idp)
        assert info.value.code == "provider_error"

    @pytest.mark.parametrize("claims", [{"nonce": "other"}, {"aud": "other"}, {"iss": "https://evil.example"},
                                        {"nonce": DELETE}, {"sub": DELETE}])
    async def test_a_bad_id_token_is_unverified(self, claims: dict[str, Any]) -> None:
        provider, idp = make()
        idp.id_token_override = claims
        with pytest.raises(SignInRejected) as info:
            await sign_in(provider, idp)
        assert info.value.code == "sign_in_unverified"

    async def test_an_unreachable_token_endpoint_is_a_provider_error(self) -> None:
        provider, idp = make()
        await provider.prepare()
        verifier, challenge = pkce()
        url = provider.authorize_url(state="s", nonce="n" * 43, code_challenge=challenge, reauth=False)
        callback = idp.authorize(url)
        idp.net.blocked.add("idp.example.edu")
        with pytest.raises(SignInRejected) as info:
            await provider.finish(code=parse_qs(urlsplit(callback).query)["code"][0], code_verifier=verifier, nonce="n" * 43)
        assert info.value.code == "provider_error"

    async def test_the_wrong_pkce_verifier_is_refused_by_the_provider(self) -> None:
        provider, idp = make()
        await provider.prepare()
        _, challenge = pkce()
        url = provider.authorize_url(state="s", nonce="n" * 43, code_challenge=challenge, reauth=False)
        code = parse_qs(urlsplit(idp.authorize(url)).query)["code"][0]
        with pytest.raises(SignInRejected):
            await provider.finish(code=code, code_verifier="x" * 50, nonce="n" * 43)

    async def test_an_email_that_is_not_json_true_is_not_verified(self) -> None:
        for value in ("true", 1, "yes", None, False):
            provider, idp = make()
            idp.user = IdpUser(email_verified=value)
            ext = await sign_in(provider, idp)
            assert ext.email == "ada@example.edu" and ext.email_verified is False

    async def test_text_from_the_provider_is_cleaned(self) -> None:
        provider, idp = make()
        idp.user = IdpUser(name="Ada\x00\n  Lovelace\x7f", preferred_username="a\u0085b")
        ext = await sign_in(provider, idp)
        assert ext.display_name == "Ada Lovelace" and ext.username == "a b"

    async def test_only_the_claims_the_rules_reference_are_kept_and_bounded(self) -> None:
        provider, idp = make(claim_names=frozenset({"groups", "dept", "level", "missing"}))
        idp.user = IdpUser(
            extra={
                "groups": ["a", "b", "x" * 300], "dept": "cs", "level": 3, "secret": "never", "other": ["z"],
            }
        )
        ext = await sign_in(provider, idp)
        assert dict(ext.claims) == {"groups": ("a", "b"), "dept": ("cs",)}
        assert "secret" not in repr(ext)

    async def test_a_claim_list_with_a_non_string_is_ignored(self) -> None:
        provider, idp = make(claim_names=frozenset({"groups"}))
        idp.user = IdpUser(extra={"groups": ["a", 5]})
        assert (await sign_in(provider, idp)).claims == ()

    async def test_the_number_of_values_is_capped(self) -> None:
        provider, idp = make(claim_names=frozenset({"groups"}))
        idp.user = IdpUser(extra={"groups": [f"g{i}" for i in range(200)]})
        ext = await sign_in(provider, idp)
        assert len(dict(ext.claims)["groups"]) == 64


class TestUserinfo:
    async def test_userinfo_can_add_claims_but_never_override_the_id_token(self) -> None:
        provider, idp = make(userinfo=True, claim_names=frozenset({"groups", "dept"}))
        idp.user = IdpUser(extra={"dept": "from-id-token"})
        idp.userinfo_extra = {"groups": ["staff"], "dept": "from-userinfo", "email": "other@example.edu"}
        ext = await sign_in(provider, idp)
        assert dict(ext.claims) == {"groups": ("staff",), "dept": ("from-id-token",)}
        assert ext.email == "ada@example.edu"
        assert idp.counts["userinfo"] == 1

    async def test_userinfo_supplies_a_missing_email_with_its_own_verified_flag(self) -> None:
        provider, idp = make(userinfo=True)
        idp.user = IdpUser(email=None)
        idp.userinfo_extra = {"email": "late@example.edu", "email_verified": True}
        ext = await sign_in(provider, idp)
        assert (ext.email, ext.email_verified) == ("late@example.edu", True)

    async def test_a_userinfo_subject_that_differs_is_unverified(self) -> None:
        provider, idp = make(userinfo=True)
        idp.userinfo_sub = "someone-else"
        with pytest.raises(SignInRejected) as info:
            await sign_in(provider, idp)
        assert info.value.code == "sign_in_unverified"

    async def test_userinfo_is_not_called_unless_configured(self) -> None:
        provider, idp = make()
        await sign_in(provider, idp)
        assert idp.counts["userinfo"] == 0


class TestRfc9207:
    async def test_the_issuer_is_expected_when_the_metadata_announces_it(self) -> None:
        provider, idp = make(iss_param=True)
        await provider.prepare()
        assert provider.requires_iss() and provider.response_issuer == ISSUER

    async def test_it_is_not_required_when_the_metadata_is_silent(self) -> None:
        provider, _ = make()
        await provider.prepare()
        assert not provider.requires_iss() and provider.response_issuer == ISSUER


class TestGoogle:
    def build(self) -> tuple[OidcLoginProvider, FakeOidcIdp]:
        net = FakeNetwork()
        idp = google_idp(net)
        provider = build_google_provider(
            GoogleConfig(idp.client_id, idp.client_secret), public_base_url=BASE,
            http=SafeHttp(transport=net.transport), domain_hint="example.edu",
        )
        return provider, idp

    async def test_the_authorization_request(self) -> None:
        provider, idp = self.build()
        await provider.prepare()
        url = provider.authorize_url(state="s" * 43, nonce="n" * 43, code_challenge="c" * 43, reauth=False)
        parts = urlsplit(url)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == "https://accounts.google.com/o/oauth2/v2/auth"
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        assert query["scope"] == "openid email profile" and query["prompt"] == "select_account"
        assert query["hd"] == "example.edu" and query["redirect_uri"] == f"{BASE}/account/callback/google"
        assert query["code_challenge_method"] == "S256" and "response_mode" not in query

    async def test_no_hd_hint_without_a_single_domain_rule(self) -> None:
        net = FakeNetwork()
        idp = google_idp(net)
        provider = build_google_provider(
            GoogleConfig(idp.client_id, idp.client_secret), public_base_url=BASE, http=SafeHttp(transport=net.transport)
        )
        await provider.prepare()
        url = provider.authorize_url(state="s", nonce="n", code_challenge="c", reauth=True)
        assert "hd" not in parse_qs(urlsplit(url).query)

    async def test_the_response_issuer_is_always_required(self) -> None:
        provider, _ = self.build()
        assert provider.requires_iss() and provider.response_issuer == GOOGLE_ISSUER

    async def test_a_sign_in_carries_hd_and_uses_the_address_as_the_name(self) -> None:
        provider, idp = self.build()
        ext = await sign_in(provider, idp)
        assert (ext.provider_id, ext.issuer, ext.subject) == ("google", GOOGLE_ISSUER, "110169484474386276334")
        assert ext.hd == "example.edu" and ext.username == "ada@example.edu"
        assert ext.email_verified is True

    async def test_both_issuer_spellings_in_the_id_token_are_accepted(self) -> None:
        for spelling in (GOOGLE_ISSUER, "accounts.google.com"):
            provider, idp = self.build()
            idp.id_token_issuer = spelling
            ext = await sign_in(provider, idp)
            assert ext.issuer == GOOGLE_ISSUER  # always stored under the https spelling

    async def test_any_other_issuer_is_refused(self) -> None:
        for spelling in ("http://accounts.google.com", "https://accounts.google.com/", "https://evil.example"):
            provider, idp = self.build()
            idp.id_token_issuer = spelling
            with pytest.raises(SignInRejected) as info:
                await sign_in(provider, idp)
            assert info.value.code == "sign_in_unverified"

    async def test_a_consumer_account_has_no_hd_and_a_string_email_verified_is_false(self) -> None:
        provider, idp = self.build()
        idp.user = IdpUser(sub="1", email="me@gmail.com", email_verified="true")
        ext = await sign_in(provider, idp)
        assert ext.hd == "" and ext.email_verified is False

    async def test_hd_is_lower_cased(self) -> None:
        provider, idp = self.build()
        idp.user = IdpUser(sub="1", extra={"hd": "Example.EDU"})
        assert (await sign_in(provider, idp)).hd == "example.edu"

    async def test_the_hd_request_hint_is_never_read_from_the_response(self) -> None:
        provider, idp = self.build()
        idp.user = IdpUser(sub="1", email="x@evil.test", extra={})
        ext = await sign_in(provider, idp)  # the request said hd=example.edu, the token has none
        assert ext.hd == ""
