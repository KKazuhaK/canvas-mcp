"""Every check of the verifier, one token at a time, through the real /mcp endpoint."""

from __future__ import annotations

import time

import pytest

from .issuer import FakeIssuer


@pytest.fixture
def trusted(open_hub):
    """A hub whose issuer is trusted with the defaults, and the open admission policy."""
    open_hub.trust()
    return open_hub


def test_a_valid_token_calls_a_tool(trusted):
    token = trusted.issuer.mint()
    response = trusted.call(token)
    assert response.status_code == 200, response.text
    # The account was made under the open policy, with one federated grant.
    assert len(trusted.accounts()) == 1
    assert len(trusted.grants()) == 1
    assert trusted.accounts()[0] in response.text or "enrolled" in response.text


def test_no_token_and_a_junk_token_are_401(trusted):
    assert trusted.status(None) == 401
    assert trusted.status("not-a-jwt") == 401


def _foreign_key(alg: str):
    from joserfc.jwk import ECKey, RSAKey

    if alg == "ES384":
        return ECKey.generate_key("P-384", parameters={"kid": "k3", "use": "sig"})
    return RSAKey.generate_key(2048, parameters={"kid": "k3", "use": "sig"})


@pytest.mark.parametrize("alg", ["ES384", "RS256", "PS256"])
def test_an_algorithm_the_issuer_did_not_allow_is_refused(open_hub, alg):
    # The issuer publishes a good key for this algorithm, but the operator allowed ES256 only.
    open_hub.trust(algorithms="ES256")
    key = _foreign_key(alg)
    open_hub.issuer.keys["k3"] = key
    assert open_hub.status(open_hub.issuer.mint(kid="k3", alg=alg, key=key)) == 401
    assert open_hub.accounts() == []


@pytest.mark.parametrize("alg", ["ES384", "RS256", "PS256"])
def test_an_algorithm_the_operator_allowed_is_accepted(open_hub, alg):
    open_hub.trust(algorithms=f"ES256 {alg}")
    key = _foreign_key(alg)
    open_hub.issuer.keys["k3"] = key
    assert open_hub.status(open_hub.issuer.mint(kid="k3", alg=alg, key=key)) == 200


def test_hs256_signed_with_the_public_key_is_refused(trusted):
    assert trusted.status(trusted.issuer.hs256_with_public_key()) == 401
    assert trusted.accounts() == []


def test_alg_none_is_refused(trusted):
    assert trusted.status(trusted.issuer.unsigned()) == 401
    assert trusted.accounts() == []


def test_hs_and_none_cannot_even_be_configured(open_hub):
    from canvas_mcp.core.selfhost.federation.config import (
        IssuerConfigError,
        build_issuer,
    )

    for bad in ("HS256", "ES256,HS512", "none", "NONE"):
        with pytest.raises(IssuerConfigError):
            build_issuer("https://hub.example.test", algorithms=bad)


def test_an_id_token_is_not_an_access_token(trusted):
    # typ JWT (an ID token), while the issuer requires at+jwt.
    assert trusted.status(trusted.issuer.mint(typ="JWT")) == 401
    assert trusted.status(trusted.issuer.mint(typ=None)) == 401
    assert trusted.accounts() == []


def test_typ_may_be_relaxed_for_issuers_that_do_not_set_it(open_hub):
    open_hub.trust(require_typ_at_jwt=False)
    assert open_hub.status(open_hub.issuer.mint(typ="JWT")) == 200
    assert open_hub.status(open_hub.issuer.mint(typ=None)) == 200


@pytest.mark.parametrize("header", ["jku", "jwk", "x5u"])
def test_key_pointing_headers_are_refused(trusted, header):
    # Signed with the attacker's own key, which the header offers to the verifier.
    from joserfc.jwk import ECKey

    attacker = ECKey.generate_key("P-256", parameters={"kid": "k1"})
    value = (
        attacker.as_dict(private=False)
        if header == "jwk"
        else "https://evil.example/keys"
    )
    token = trusted.issuer.mint(key=attacker, header={header: value})
    assert trusted.status(token) == 401
    assert "evil.example" not in " ".join(trusted.issuer.log)
    assert trusted.accounts() == []


def test_wrong_issuer_or_audience_is_refused(trusted):
    assert trusted.status(trusted.issuer.mint(iss="https://other.example")) == 401
    # A trailing slash is a different issuer string.
    assert trusted.status(trusted.issuer.mint(iss=trusted.issuer.issuer + "/")) == 401
    assert (
        trusted.status(trusted.issuer.mint(aud="https://elsewhere.example/mcp")) == 401
    )
    assert trusted.status(trusted.issuer.mint(aud=["a", "b"])) == 401
    assert trusted.accounts() == []


def test_audience_may_be_one_of_several(trusted):
    token = trusted.issuer.mint(aud=["https://other.example", trusted.issuer.audience])
    assert trusted.status(token) == 200


def test_a_custom_audience_replaces_the_default(open_hub):
    open_hub.trust(audience="canvas-api")
    assert open_hub.status(open_hub.issuer.mint()) == 401
    assert open_hub.status(open_hub.issuer.mint(aud="canvas-api")) == 200


def test_expired_and_missing_exp_are_refused(trusted):
    now = int(trusted.stack.clock())
    assert trusted.status(trusted.issuer.mint(exp=now - 1)) == 401
    assert trusted.status(trusted.issuer.mint(exp=None)) == 401
    assert trusted.status(trusted.issuer.mint(exp="soon")) == 401


def test_not_before_and_issued_at_use_a_sixty_second_skew(trusted):
    now = int(trusted.stack.clock())
    assert trusted.status(trusted.issuer.mint(nbf=now + 30)) == 200
    assert trusted.status(trusted.issuer.mint(nbf=now + 120)) == 401
    assert trusted.status(trusted.issuer.mint(iat=now + 120)) == 401
    assert trusted.status(trusted.issuer.mint(iat=now + 30)) == 200


def test_an_oversized_token_is_refused(trusted):
    token = trusted.issuer.mint(pad="x" * 9000)
    assert len(token) > 8192
    assert trusted.status(token) == 401


def test_the_subject_claim_is_required_and_never_replaced(open_hub):
    open_hub.trust(subject_claim="mcphub_uid")
    # No mcphub_uid: refused, although `sub` is there and valid.
    assert open_hub.status(open_hub.issuer.mint(sub="someone")) == 401
    assert open_hub.accounts() == []
    for bad in ("", 7, ["a"], None):
        assert open_hub.status(open_hub.issuer.mint(mcphub_uid=bad)) == 401
    assert open_hub.status(open_hub.issuer.mint(mcphub_uid="u-42", sub=None)) == 200
    from sqlalchemy import text

    with open_hub.stack.store.database.read() as conn:
        rows = [
            tuple(r)
            for r in conn.execute(
                text("SELECT claim, subject FROM federated_identities")
            )
        ]
    assert rows == [("mcphub_uid", "u-42")]


def test_the_default_subject_claim_is_sub(trusted):
    assert trusted.status(trusted.issuer.mint(sub=None)) == 401
    assert trusted.status(trusted.issuer.mint(sub="")) == 401


def test_a_signature_by_an_unknown_key_is_refused(trusted):
    other = FakeIssuer(trusted.stack.clock)
    token = other.mint()  # kid k1, but another key pair
    assert trusted.status(token) == 401


class TestScopes:
    def test_a_missing_read_scope_refuses_the_token(self, open_hub):
        open_hub.trust(read_scope="canvas:read")
        assert open_hub.status(open_hub.issuer.mint(scope="other")) == 401
        assert open_hub.status(open_hub.issuer.mint(scope="canvas:read")) == 200
        # Entra style: a list in `scp`.
        assert (
            open_hub.status(open_hub.issuer.mint(scope=None, scp=["canvas:read"]))
            == 200
        )


def _tool_names(hub, token: str) -> set[str]:
    import json

    response = hub.stack.rpc(token, "tools/list")
    assert response.status_code == 200, response.text
    text = response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        text = [ln[5:].strip() for ln in text.splitlines() if ln.startswith("data:")][
            -1
        ]
    return {tool["name"] for tool in json.loads(text)["result"]["tools"]}


class TestKeys:
    def test_unknown_kid_refetches_at_most_once_a_minute(self, trusted):
        issuer, clock = trusted.issuer, trusted.stack.clock
        assert trusted.status(issuer.mint()) == 200
        assert issuer.fetches() == 1
        # Tokens naming keys the issuer does not publish never make the server ask again ...
        for n in range(5):
            assert trusted.status(issuer.mint(kid="k1", header={"kid": f"x{n}"})) == 401
        # ... and neither does a key the issuer has published since, inside the minute.
        issuer.add_key("k2")
        assert trusted.status(issuer.mint(kid="k2")) == 401
        assert issuer.fetches() == 1
        # After the minute, a burst of unknown keys costs one refetch, and the new key works.
        clock.advance(61)
        for n in range(5):
            assert trusted.status(issuer.mint(kid="k1", header={"kid": f"y{n}"})) == 401
        assert issuer.fetches() == 2
        # That refetch also loaded the key published meanwhile: no further request is needed.
        assert trusted.status(issuer.mint(kid="k2")) == 200
        assert issuer.fetches() == 2

    def test_key_rotation(self, trusted):
        issuer, clock = trusted.issuer, trusted.stack.clock
        old = issuer.keys["k1"]
        assert trusted.status(issuer.mint()) == 200
        issuer.add_key("k2")
        issuer.retire("k1")
        clock.advance(61)
        assert trusted.status(issuer.mint(kid="k2")) == 200
        # The retired key's tokens are refused once the key set was refreshed.
        assert trusted.status(issuer.mint(kid="k1", key=old)) == 401

    def test_the_jwks_is_found_through_rfc8414_metadata(self, trusted):
        assert trusted.status(trusted.issuer.mint()) == 200
        assert "/.well-known/oauth-authorization-server" in trusted.issuer.log

    def test_metadata_whose_issuer_differs_is_refused(self, trusted):
        trusted.issuer.metadata_issuer = "https://hub.example.test/"
        assert trusted.status(trusted.issuer.mint()) == 401
        assert trusted.issuer.fetches() == 0

    def test_a_configured_jwks_url_skips_the_metadata(self, open_hub):
        open_hub.trust(jwks_url="https://hub.example.test/jwks.json")
        assert open_hub.status(open_hub.issuer.mint()) == 200
        assert "/.well-known/oauth-authorization-server" not in open_hub.issuer.log


def test_the_clock_of_the_test_is_the_servers(trusted):
    # A guard for the other tests: tokens are minted from the server's clock.
    assert abs(trusted.stack.clock() - time.time()) < 5
