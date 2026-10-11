"""The bad-token matrix of the generic OpenID Connect relying party (OIDC Core 3.1.3.7)."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from canvas_mcp.core.selfhost.login.http import SafeHttp
from canvas_mcp.core.selfhost.login.idtoken import (
    IdTokenRejected,
    peek_header,
    verify_id_token,
)
from canvas_mcp.core.selfhost.login.jwks import JwksCache

from .fake_idp import DELETE, FakeNetwork, FakeOidcIdp, b64url, rsa_key

ISSUER = "https://idp.example.edu/realms/school"
URI = f"{ISSUER}/protocol/openid-connect/certs"
NONCE = "n" * 43
NOW = 1_800_000_000.0
ALGS = ("RS256", "ES256")


class Env:
    def __init__(self) -> None:
        net = FakeNetwork()
        self.idp = FakeOidcIdp(net, ISSUER)
        self.idp.now = lambda: NOW
        self.cache = JwksCache(SafeHttp(transport=net.transport), clock=lambda: NOW)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.idp, name)

    async def verify(self, token: str, **kw: Any) -> dict[str, Any]:
        kid = None
        try:
            kid = peek_header(token).get("kid")
        except IdTokenRejected:
            pass
        await self.cache.ensure(URI, kid if isinstance(kid, str) else None)
        options: dict[str, Any] = {
            "key_lookup": self.cache.lookup, "client_id": "canvas-mcp", "accepted_issuers": {ISSUER},
            "nonce": NONCE, "allowed_algs": ALGS, "now": NOW,
        }
        options.update(kw)
        return verify_id_token(token, **options)


@pytest.fixture
def env() -> Env:
    return Env()


async def reason(env: Env, token: str, **kw: Any) -> str:
    with pytest.raises(IdTokenRejected) as info:
        await env.verify(token, **kw)
    return info.value.reason


async def test_a_good_rs256_and_a_good_es256_token(env: Env) -> None:
    claims = await env.verify(env.mint_id_token(nonce=NONCE))
    assert claims["sub"] == "user-1" and claims["iss"] == ISSUER
    assert (await env.verify(env.mint_id_token(nonce=NONCE, key=env.idp.ec)))["sub"] == "user-1"


@pytest.mark.parametrize(
    ("claims", "expected"),
    [
        ({"iss": "https://idp.example.edu/realms/other"}, "iss"),
        ({"iss": ISSUER + "/"}, "iss"),
        ({"iss": DELETE}, "iss"),
        ({"iss": 5}, "iss"),
        ({"aud": "someone-else"}, "aud"),
        ({"aud": ["a", "b"]}, "aud"),
        ({"aud": []}, "aud"),
        ({"aud": DELETE}, "aud"),
        ({"aud": 7}, "aud"),
        ({"aud": ["canvas-mcp", "other"]}, "azp"),
        ({"aud": ["canvas-mcp", "other"], "azp": "other"}, "azp"),
        ({"azp": "other"}, "azp"),
        ({"exp": NOW - 601}, "exp"),
        ({"exp": DELETE}, "exp"),
        ({"exp": "soon"}, "exp"),
        ({"exp": True}, "exp"),
        ({"iat": NOW + 601}, "iat"),
        ({"iat": NOW - 601}, "iat"),
        ({"iat": DELETE}, "iat"),
        ({"iat": "now"}, "iat"),
        ({"nbf": NOW + 601}, "nbf"),
        ({"nbf": "later"}, "nbf"),
        ({"nonce": DELETE}, "nonce"),
        ({"nonce": "not-the-nonce"}, "nonce"),
        ({"nonce": 12345}, "nonce"),
        ({"nonce": ["x" * 43]}, "nonce"),
        ({"sub": DELETE}, "sub"),
        ({"sub": ""}, "sub"),
        ({"sub": "x" * 256}, "sub"),
        ({"sub": "café"}, "sub"),
        ({"sub": "has space"}, "sub"),
        ({"sub": 12345}, "sub"),
    ],
)
async def test_claim_failures(env: Env, claims: dict[str, Any], expected: str) -> None:
    token = env.mint_id_token(nonce=NONCE, claims=claims)
    assert await reason(env, token) == expected


@pytest.mark.parametrize(
    "claims",
    [
        {"exp": NOW - 599},  # inside the 600 s skew
        {"iat": NOW + 599},
        {"iat": NOW - 599},
        {"nbf": NOW + 599},
        {"aud": ["other", "canvas-mcp"], "azp": "canvas-mcp"},
        {"azp": "canvas-mcp"},
        {"sub": "x" * 255},
        {"exp": NOW + 10, "iat": float(NOW)},
    ],
)
async def test_boundaries_that_are_accepted(env: Env, claims: dict[str, Any]) -> None:
    assert await env.verify(env.mint_id_token(nonce=NONCE, claims=claims))


async def test_alg_none_is_refused_even_when_listed_by_a_careless_caller(env: Env) -> None:
    token = env.unsigned_token(nonce=NONCE)
    assert await reason(env, token) == "alg"
    assert await reason(env, token, allowed_algs=("none", "RS256")) == "alg"


async def test_the_hs256_key_confusion_attack_is_refused(env: Env) -> None:
    token = env.hs256_token(env.idp.client_secret, nonce=NONCE)
    assert await reason(env, token) == "alg"
    assert await reason(env, token, allowed_algs=("HS256", "RS256")) == "alg"
    # ...and signing with the provider's PUBLIC key as the HMAC secret is just as dead.
    public = json.dumps(env.idp.rsa.as_dict(private=False))
    assert await reason(env, env.hs256_token(public, nonce=NONCE), allowed_algs=("HS256",)) == "alg"


async def test_an_algorithm_the_provider_did_not_advertise_is_refused(env: Env) -> None:
    token = env.mint_id_token(nonce=NONCE)
    assert await reason(env, token, allowed_algs=("ES256",)) == "alg"
    ps = env.mint_id_token(nonce=NONCE, alg="PS256")
    assert await reason(env, ps) == "alg"


async def test_a_kid_that_is_unknown_even_after_a_refetch_is_refused(env: Env) -> None:
    other = rsa_key("not-published")
    token = env.mint_id_token(nonce=NONCE, key=other)
    assert await reason(env, token) == "kid"


async def test_a_token_signed_by_a_foreign_key_that_claims_a_known_kid_has_a_bad_signature(env: Env) -> None:
    foreign = rsa_key("foreign")
    token = env.mint_id_token(nonce=NONCE, key=foreign, header={"kid": "rsa-1"})
    assert await reason(env, token) == "signature"


async def test_a_payload_tampered_after_signing_is_refused(env: Env) -> None:
    head, body, sig = env.mint_id_token(nonce=NONCE).split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["sub"] = "admin"
    tampered = ".".join([head, b64url(json.dumps(claims).encode()), sig])
    assert await reason(env, tampered) == "signature"
    assert await reason(env, ".".join([head, body, sig[:-4] + "AAAA"])) == "signature"


async def test_a_header_edited_to_a_weaker_algorithm_is_refused(env: Env) -> None:
    head, body, sig = env.mint_id_token(nonce=NONCE).split(".")
    edited = b64url(json.dumps({"alg": "HS256", "kid": "rsa-1"}).encode())
    assert await reason(env, ".".join([edited, body, sig])) == "alg"
    ec_head = b64url(json.dumps({"alg": "ES256", "kid": "rsa-1"}).encode())
    assert await reason(env, ".".join([ec_head, body, sig])) == "kid"  # an EC alg never fits an RSA key


async def test_a_token_without_a_kid_needs_exactly_one_suitable_key(env: Env) -> None:
    token = env.mint_id_token(nonce=NONCE, header={"kid": DELETE})
    assert (await env.verify(token))["sub"] == "user-1"  # one RSA key published
    two = Env()  # a provider that publishes two RSA keys
    two.idp.rotate(drop_old=False)
    assert await reason(two, two.mint_id_token(nonce=NONCE, header={"kid": DELETE})) == "kid"


@pytest.mark.parametrize(
    "raw",
    [
        "", "onlyone", "a.b", "a.b.c.d", "a.b.c.d.e", "a..c", ".b.c", "a b.c.d", "é.é.é",
        "x" * (16 * 1024 + 1),
    ],
)
async def test_malformed_tokens(env: Env, raw: str) -> None:
    assert await reason(env, raw) == "malformed"


async def test_a_five_segment_jwe_is_refused(env: Env) -> None:
    jwe = ".".join(b64url(b"x") for _ in range(5))
    assert await reason(env, jwe) == "malformed"


async def test_a_token_at_the_size_limit_is_not_rejected_for_its_size(env: Env) -> None:
    token = env.mint_id_token(nonce=NONCE, claims={"filler": "x" * 2000})
    assert len(token) < 16 * 1024
    assert await env.verify(token)


@pytest.mark.parametrize(
    "header",
    [
        b"not json", b"[1]", b'{"alg":"RS256","alg":"RS256"}', b'{"alg":5}', b'{"kid":"rsa-1"}',
        b'{"alg":"RS256","kid":5}', b'{"alg":"RS256","crit":["x"],"x":1}', b'{"alg":NaN}',
    ],
)
async def test_bad_headers(env: Env, header: bytes) -> None:
    token = f"{b64url(header)}.{b64url(b'{}')}.{b64url(b'sig')}"
    assert await reason(env, token) in {"malformed", "alg", "kid"}


async def test_a_jku_or_embedded_jwk_in_the_header_is_never_used(env: Env) -> None:
    attacker = rsa_key("attacker")
    token = env.mint_id_token(
        nonce=NONCE, key=attacker,
        header={"kid": "rsa-1", "jku": "https://evil.example/jwks", "jwk": attacker.as_dict(private=False)},
    )
    assert await reason(env, token) == "signature"
    assert env.idp.counts["jwks"] == 1 and not env.idp.net.requests_to("evil.example")


async def test_nothing_but_a_closed_reason_leaves_the_verifier(env: Env) -> None:
    token = env.mint_id_token(nonce=NONCE, claims={"sub": DELETE})
    with pytest.raises(IdTokenRejected) as info:
        await env.verify(token)
    assert str(info.value) == info.value.reason == "sub"
    assert "user-1" not in repr(info.value)


async def test_multi_audience_with_a_matching_azp_passes_for_a_second_client(env: Env) -> None:
    token = env.mint_id_token(nonce=NONCE, claims={"aud": ["x", "canvas-mcp"], "azp": "canvas-mcp"})
    assert await env.verify(token)
    assert await reason(env, token, client_id="x") == "azp"


async def test_the_issuer_may_be_any_of_the_accepted_spellings(env: Env) -> None:
    token = env.mint_id_token(nonce=NONCE, claims={"iss": "accounts.example"})
    assert await reason(env, token) == "iss"
    assert await env.verify(token, accepted_issuers={ISSUER, "accounts.example"})
