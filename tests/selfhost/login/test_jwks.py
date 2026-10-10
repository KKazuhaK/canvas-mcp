"""The key cache: rotation, bounded refetching, key filtering."""

from __future__ import annotations

import pytest
from joserfc.jwk import ECKey, RSAKey

from canvas_mcp.core.selfhost.login.http import SafeHttp
from canvas_mcp.core.selfhost.login.jwks import (
    MAX_KEYS,
    JwksCache,
    alg_fits_key,
    key_is_acceptable,
)

from .fake_idp import FakeNetwork, FakeOidcIdp, rsa_key

ISSUER = "https://idp.example.edu/realms/school"


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


def build() -> tuple[JwksCache, FakeOidcIdp, Clock]:
    net = FakeNetwork()
    idp = FakeOidcIdp(net, ISSUER)
    clock = Clock()
    return JwksCache(SafeHttp(transport=net.transport), clock=clock), idp, clock


URI = f"{ISSUER}/protocol/openid-connect/certs"


class TestLookup:
    async def test_a_known_kid_is_found_after_one_fetch(self) -> None:
        cache, idp, _ = build()
        await cache.ensure(URI, "rsa-1")
        await cache.ensure(URI, "ec-1")
        assert cache.lookup("rsa-1", "RS256") is not None
        assert cache.lookup("ec-1", "ES256") is not None
        assert idp.counts["jwks"] == 1

    async def test_the_token_algorithm_must_fit_the_key(self) -> None:
        cache, _, _ = build()
        await cache.ensure(URI, "rsa-1")
        assert cache.lookup("rsa-1", "ES256") is None
        assert cache.lookup("rsa-1", "HS256") is None
        assert cache.lookup("ec-1", "RS256") is None

    async def test_an_unknown_kid_refetches_once_and_a_rotated_key_then_works(self) -> None:
        cache, idp, clock = build()
        await cache.ensure(URI, "rsa-1")
        idp.rotate(drop_old=True)
        clock.now += 61
        await cache.ensure(URI, "rsa-2")
        assert idp.counts["jwks"] == 2
        assert cache.lookup("rsa-2", "RS256") is not None
        assert cache.lookup("rsa-1", "RS256") is None

    async def test_unknown_kids_cannot_make_the_server_refetch_more_than_once_a_minute(self) -> None:
        cache, idp, clock = build()
        await cache.ensure(URI, "rsa-1")
        for i in range(20):
            clock.now += 2
            await cache.ensure(URI, f"invented-{i}")
        assert idp.counts["jwks"] == 1  # forty seconds of invented ids: still only the first load
        clock.now += 30
        await cache.ensure(URI, "invented-x")
        await cache.ensure(URI, "invented-y")
        assert idp.counts["jwks"] == 2  # one refetch after the minute, not one per token
        assert cache.lookup("invented-3", "RS256") is None

    async def test_the_refetch_is_allowed_again_after_a_minute(self) -> None:
        cache, idp, clock = build()
        await cache.ensure(URI, "rsa-1")
        await cache.ensure(URI, "nope")
        before = idp.counts["jwks"]
        await cache.ensure(URI, "nope-2")
        assert idp.counts["jwks"] == before
        clock.now += 61
        await cache.ensure(URI, "nope-3")
        assert idp.counts["jwks"] == before + 1

    async def test_the_key_set_expires_after_an_hour(self) -> None:
        cache, idp, clock = build()
        await cache.ensure(URI, "rsa-1")
        clock.now += 3599
        await cache.ensure(URI, "rsa-1")
        assert idp.counts["jwks"] == 1
        clock.now += 2
        await cache.ensure(URI, "rsa-1")
        assert idp.counts["jwks"] == 2

    async def test_keys_survive_a_failed_refresh(self) -> None:
        cache, idp, clock = build()
        await cache.ensure(URI, "rsa-1")
        clock.now += 4000
        idp.net.blocked.add("idp.example.edu")
        await cache.ensure(URI, "rsa-1")
        assert cache.lookup("rsa-1", "RS256") is not None

    async def test_without_a_kid_exactly_one_suitable_key_is_needed(self) -> None:
        cache, idp, _ = build()
        idp.published = [idp.rsa]
        await cache.ensure(URI, None)
        assert cache.lookup(None, "RS256") is not None
        idp.rotate(drop_old=False)
        cache2, idp2, _ = build()
        idp2.rotate(drop_old=False)
        await cache2.ensure(URI, None)
        assert cache2.lookup(None, "RS256") is None  # two RSA keys: ambiguous
        assert cache2.lookup(None, "ES256") is not None  # one EC key

    async def test_keys_without_a_kid_are_usable_only_for_tokens_without_one(self) -> None:
        cache, idp, _ = build()
        anonymous = rsa_key("rsa-1").as_dict(private=False)
        del anonymous["kid"]
        idp.published = []
        idp.extra_jwks = [anonymous]
        await cache.ensure(URI, None)
        assert cache.lookup(None, "RS256") is not None
        assert cache.lookup("rsa-1", "RS256") is None

    async def test_a_new_jwks_uri_discards_the_old_keys(self) -> None:
        cache, idp, _ = build()
        await cache.ensure(URI, "rsa-1")
        await cache.ensure(URI + "2", "rsa-1")
        assert idp.counts["jwks"] == 1  # the second address 404s at the fake; nothing loaded
        assert cache.lookup("rsa-1", "RS256") is None


class TestFiltering:
    @pytest.mark.filterwarnings("ignore:Key size")
    async def test_encryption_keys_weak_keys_and_other_curves_are_ignored(self) -> None:
        cache, idp, _ = build()
        enc = rsa_key("rsa-1").as_dict(private=False) | {"kid": "enc", "use": "enc"}
        weak = RSAKey.generate_key(1024, parameters={"kid": "weak"}).as_dict(private=False)
        p384 = ECKey.generate_key("P-384", parameters={"kid": "p384"}).as_dict(private=False)
        secp = ECKey.generate_key("secp256k1", parameters={"kid": "k1"}).as_dict(private=False)
        oct_key = {"kty": "oct", "kid": "sym", "k": "c2VjcmV0"}
        idp.extra_jwks = [enc, weak, p384, secp, oct_key]
        await cache.ensure(URI, "rsa-1")
        assert cache.lookup("enc", "RS256") is None
        assert cache.lookup("weak", "RS256") is None
        assert cache.lookup("k1", "ES256") is None
        assert cache.lookup("sym", "HS256") is None
        assert cache.lookup("p384", "ES384") is not None

    async def test_a_key_that_declares_another_algorithm_is_not_a_candidate(self) -> None:
        cache, idp, _ = build()
        idp.extra_jwks = [rsa_key("rsa-1").as_dict(private=False) | {"kid": "pinned", "alg": "RS512"}]
        await cache.ensure(URI, "pinned")
        assert cache.lookup("pinned", "RS256") is None
        assert cache.lookup("pinned", "RS512") is not None

    async def test_a_document_with_too_many_keys_is_refused_as_a_whole(self) -> None:
        cache, idp, _ = build()
        base = rsa_key("rsa-1").as_dict(private=False)
        idp.extra_jwks = [base | {"kid": f"k{i}"} for i in range(MAX_KEYS)]  # plus the two published
        await cache.ensure(URI, "rsa-1")
        assert cache.lookup("rsa-1", "RS256") is None

    async def test_exactly_the_maximum_is_fine(self) -> None:
        cache, idp, _ = build()
        base = rsa_key("rsa-1").as_dict(private=False)
        idp.published = []
        idp.extra_jwks = [base | {"kid": f"k{i}"} for i in range(MAX_KEYS)]
        await cache.ensure(URI, "k3")
        assert cache.lookup("k3", "RS256") is not None

    async def test_a_garbage_key_does_not_poison_the_others(self) -> None:
        cache, idp, _ = build()
        idp.extra_jwks = [{"kty": "RSA", "kid": "broken", "n": "!!", "e": "AQAB"}, "nonsense", 5]  # type: ignore[list-item]
        await cache.ensure(URI, "rsa-1")
        assert cache.lookup("rsa-1", "RS256") is not None


def test_acceptable_key_rules() -> None:
    rsa = rsa_key("rsa-1").as_dict(private=False)
    assert key_is_acceptable(rsa) and key_is_acceptable(rsa | {"use": "sig"})
    assert not key_is_acceptable(rsa | {"use": "enc"})
    assert not key_is_acceptable(rsa | {"key_ops": ["encrypt"]})
    assert not key_is_acceptable({"kty": "RSA", "n": "AQAB", "e": "AQAB"})
    assert not key_is_acceptable({"kty": "oct", "k": "x"})
    assert key_is_acceptable({"kty": "OKP", "crv": "Ed25519", "x": "x"})
    assert not key_is_acceptable({"kty": "OKP", "crv": "X25519", "x": "x"})
    assert alg_fits_key({"kty": "OKP", "crv": "Ed25519"}, "EdDSA")
    assert not alg_fits_key({"kty": "EC", "crv": "P-256"}, "ES384")
    assert not alg_fits_key({"kty": "weird"}, "RS256")


@pytest.mark.parametrize("alg", ["none", "HS256", "RS1"])
def test_unknown_algorithms_fit_no_key(alg: str) -> None:
    assert not alg_fits_key(rsa_key("rsa-1").as_dict(private=False), alg)
