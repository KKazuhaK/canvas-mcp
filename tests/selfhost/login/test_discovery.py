"""OpenID Connect discovery: validation of the document and the cache around it."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from canvas_mcp.core.selfhost.login.http import SafeHttp
from canvas_mcp.core.selfhost.login.metadata import (
    DiscoveryCache,
    ProviderUnavailable,
    cache_ttl,
    discovery_url,
    parse_discovery,
)

from .fake_idp import FakeNetwork, FakeOidcIdp, google_idp

ISSUER = "https://idp.example.edu/realms/school"


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


def doc(**overrides: Any) -> dict[str, Any]:
    base = FakeOidcIdp(FakeNetwork(), ISSUER).discovery_document()
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not None}


class TestParseDiscovery:
    def test_a_good_document(self) -> None:
        meta = parse_discovery(doc(), ISSUER)
        assert meta.issuer == ISSUER and meta.token_endpoint.endswith("/token")
        assert meta.algs == ("RS256", "ES256") and meta.pkce_s256 and not meta.iss_param_supported
        assert meta.userinfo_endpoint is not None
        assert meta.token_auth_methods == ("client_secret_basic", "client_secret_post")

    def test_the_issuer_must_be_identical_even_to_a_trailing_slash(self) -> None:
        for other in (ISSUER + "/", ISSUER.replace("https", "http"), ISSUER.upper(), "https://evil.example"):
            with pytest.raises(ProviderUnavailable):
                parse_discovery(doc(issuer=other), ISSUER)
        assert parse_discovery(doc(issuer=ISSUER + "/"), ISSUER + "/").issuer == ISSUER + "/"
        with pytest.raises(ProviderUnavailable):
            parse_discovery(doc(issuer=ISSUER), ISSUER + "/")

    @pytest.mark.parametrize(
        "field", ["authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"]
    )
    @pytest.mark.parametrize(
        "bad",
        ["http://idp.example.edu/x", "https://user:pw@idp.example.edu/x", "https://localhost/x",
         "https://169.254.169.254/x", "ftp://x", "", 5],
    )
    def test_every_endpoint_must_be_a_plain_https_url(self, field: str, bad: Any) -> None:
        with pytest.raises(ProviderUnavailable):
            parse_discovery(doc(**{field: bad}), ISSUER)

    def test_the_userinfo_endpoint_is_optional(self) -> None:
        document = doc()
        del document["userinfo_endpoint"]
        assert parse_discovery(document, ISSUER).userinfo_endpoint is None

    @pytest.mark.parametrize("missing", ["authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"])
    def test_required_members_must_exist(self, missing: str) -> None:
        document = doc()
        del document[missing]
        with pytest.raises(ProviderUnavailable):
            parse_discovery(document, ISSUER)

    @pytest.mark.parametrize("types", [["id_token"], [], "code", None])
    def test_the_code_response_type_is_required(self, types: Any) -> None:
        with pytest.raises(ProviderUnavailable):
            parse_discovery(doc(response_types_supported=types), ISSUER)

    @pytest.mark.parametrize("algs", [["HS256"], ["none"], ["HS256", "none", "HS512"], [], "RS256", None])
    def test_a_provider_that_offers_only_unusable_algorithms_is_refused(self, algs: Any) -> None:
        with pytest.raises(ProviderUnavailable):
            parse_discovery(doc(id_token_signing_alg_values_supported=algs), ISSUER)

    def test_none_and_hmac_are_dropped_from_a_mixed_list(self) -> None:
        meta = parse_discovery(
            doc(id_token_signing_alg_values_supported=["none", "HS256", "PS256", "RS256", "ES512", "EdDSA", "HS384"]),
            ISSUER,
        )
        assert meta.algs == ("PS256", "RS256", "ES512", "EdDSA")

    @pytest.mark.parametrize("methods", [["plain"], [], "S256"])
    def test_a_document_that_lists_pkce_methods_must_list_s256(self, methods: Any) -> None:
        with pytest.raises(ProviderUnavailable):
            parse_discovery(doc(code_challenge_methods_supported=methods), ISSUER)

    def test_pkce_methods_may_be_missing(self) -> None:
        document = doc()
        del document["code_challenge_methods_supported"]
        assert parse_discovery(document, ISSUER).pkce_s256 is False

    def test_the_rfc_9207_flag_is_read_only_when_it_is_exactly_true(self) -> None:
        assert parse_discovery(doc(authorization_response_iss_parameter_supported=True), ISSUER).iss_param_supported
        for value in ("true", 1, False, None):
            assert not parse_discovery(
                doc(authorization_response_iss_parameter_supported=value), ISSUER
            ).iss_param_supported

    def test_googles_real_document_shape_is_accepted(self) -> None:
        google = google_idp(FakeNetwork())
        meta = parse_discovery(google.discovery_document(), "https://accounts.google.com")
        assert meta.algs == ("RS256",) and meta.iss_param_supported and meta.pkce_s256
        assert meta.authorization_endpoint == "https://accounts.google.com/o/oauth2/v2/auth"
        assert meta.token_endpoint == "https://oauth2.googleapis.com/token"
        assert meta.jwks_uri == "https://www.googleapis.com/oauth2/v3/certs"


def test_the_discovery_url_drops_a_terminating_slash() -> None:
    assert discovery_url("https://a.test/x/") == "https://a.test/x/.well-known/openid-configuration"
    assert discovery_url("https://a.test") == "https://a.test/.well-known/openid-configuration"


@pytest.mark.parametrize(
    ("header", "ttl"),
    [
        ("", 3600), ("public, max-age=10", 300), ("max-age=600", 600), ("max-age=999999999", 86400),
        ("private,max-age=86400", 86400), ("no-store", 300), ("no-cache", 300), ("s-maxage=5", 3600),
    ],
)
def test_the_cache_lifetime_is_the_clamped_max_age(header: str, ttl: int) -> None:
    assert cache_ttl({"cache-control": header} if header else {}) == ttl


def build(clock: Clock | None = None, **idp_kw: Any) -> tuple[DiscoveryCache, FakeOidcIdp, FakeNetwork]:
    net = FakeNetwork()
    idp = FakeOidcIdp(net, ISSUER, **idp_kw)
    cache = DiscoveryCache(ISSUER, SafeHttp(transport=net.transport), clock=clock or Clock())
    return cache, idp, net


class TestDiscoveryCache:
    async def test_nothing_is_fetched_until_asked_and_then_once(self) -> None:
        cache, idp, net = build()
        assert net.log == []
        first = await cache.get()
        second = await cache.get()
        assert first is second and idp.counts["discovery"] == 1

    async def test_the_snapshot_is_refreshed_after_its_lifetime(self) -> None:
        clock = Clock()
        cache, idp, _ = build(clock, cache_control="max-age=600")
        await cache.get()
        clock.now += 599
        await cache.get()
        assert idp.counts["discovery"] == 1
        clock.now += 2
        await cache.get()
        assert idp.counts["discovery"] == 2

    async def test_concurrent_callers_share_one_fetch(self) -> None:
        cache, idp, _ = build()
        results = await asyncio.gather(*(cache.get() for _ in range(8)))
        assert idp.counts["discovery"] == 1 and all(r is results[0] for r in results)

    async def test_the_first_failure_is_unavailable_and_backs_off_for_thirty_seconds(self) -> None:
        clock = Clock()
        cache, idp, net = build(clock)
        net.blocked.add("idp.example.edu")
        with pytest.raises(ProviderUnavailable):
            await cache.get()
        calls = len(net.log)
        with pytest.raises(ProviderUnavailable):
            await cache.get()
        assert len(net.log) == calls  # inside the backoff: no new request
        net.blocked.clear()
        clock.now += 31
        assert (await cache.get()).issuer == ISSUER
        assert idp.counts["discovery"] == 1

    async def test_the_last_good_snapshot_is_served_when_a_refresh_fails(self) -> None:
        clock = Clock()
        cache, _, net = build(clock)
        good = await cache.get()
        clock.now += 4000
        net.blocked.add("idp.example.edu")
        assert await cache.get() is good
        clock.now += 40
        assert await cache.get() is good

    async def test_a_snapshot_older_than_a_day_is_not_served_when_the_provider_is_down(self) -> None:
        clock = Clock()
        cache, _, net = build(clock)
        await cache.get()
        clock.now += 86400 + 100
        net.blocked.add("idp.example.edu")
        with pytest.raises(ProviderUnavailable):
            await cache.get()

    async def test_a_document_with_another_issuer_is_never_cached(self) -> None:
        cache, idp, _ = build()
        idp.discovery_overrides["issuer"] = "https://evil.example"
        with pytest.raises(ProviderUnavailable):
            await cache.get()
        assert cache.current() is None

    async def test_a_bad_refresh_keeps_the_old_good_snapshot(self) -> None:
        clock = Clock()
        cache, idp, _ = build(clock)
        good = await cache.get()
        idp.discovery_overrides["issuer"] = "https://evil.example"
        clock.now += 4000
        assert await cache.get() is good
