"""The joserfc calls the relying party makes, pinned so a library upgrade fails loudly.

CI installs the versions in ``uv.lock`` and a developer's environment may carry a newer
release; both are checked by running this file on both interpreters.
"""

from __future__ import annotations

import pytest
from joserfc import jws, jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet, RSAKey, import_key

from .fake_idp import rsa_key


def test_import_key_reads_a_public_jwk_dict_and_keeps_the_kid() -> None:
    jwk = rsa_key("compat").as_dict(private=False)
    key = import_key(dict(jwk))
    assert key.kid == "compat" and key.key_type == "RSA"
    assert not key.is_private


def test_key_sets_are_indexed_by_kid() -> None:
    jwk = rsa_key("compat").as_dict(private=False)
    key_set = KeySet.import_key_set({"keys": [jwk]})
    assert key_set.get_by_kid("compat").kid == "compat"


def test_a_compact_jws_can_be_split_and_its_protected_header_read() -> None:
    token = jwt.encode({"alg": "RS256", "kid": "compat"}, {"sub": "x"}, rsa_key("compat"))
    segments = jws.extract_compact(token.encode("ascii"))
    assert segments.protected["alg"] == "RS256" and segments.protected["kid"] == "compat"


def test_decode_checks_the_signature_against_exactly_the_given_algorithms() -> None:
    private = rsa_key("compat")
    token = jwt.encode({"alg": "RS256", "kid": "compat"}, {"sub": "x"}, private)
    public = import_key(dict(private.as_dict(private=False)))
    assert jwt.decode(token, public, algorithms=["RS256"]).claims == {"sub": "x"}
    with pytest.raises(JoseError):
        jwt.decode(token, public, algorithms=["ES256"])
    with pytest.raises(JoseError):
        jwt.decode(token, public, algorithms=["PS256"])


def test_a_signature_made_with_another_key_is_a_jose_error() -> None:
    token = jwt.encode({"alg": "RS256"}, {"sub": "x"}, rsa_key("compat"))
    other = RSAKey.generate_key(2048, parameters={"kid": "other"})
    with pytest.raises(JoseError):
        jwt.decode(token, other, algorithms=["RS256"])


def test_decode_does_not_check_claims_so_the_relying_party_must() -> None:
    private = rsa_key("compat")
    token = jwt.encode({"alg": "RS256"}, {"sub": "x", "exp": 1}, private)
    assert jwt.decode(token, private, algorithms=["RS256"]).claims["exp"] == 1


def test_an_unsecured_token_is_refused_by_decode() -> None:
    private = rsa_key("compat")
    with pytest.raises(JoseError):
        jwt.decode("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", private, algorithms=["RS256"])
