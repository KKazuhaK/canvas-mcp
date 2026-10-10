"""Access tokens (JWTs) and the opaque secrets."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

import pytest
from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey

from canvas_mcp.core.selfhost.authz import tokens as tk
from canvas_mcp.core.selfhost.token_store import Keyring

ISSUER = "https://canvas.example.test/"
AUDIENCE = "https://canvas.example.test/mcp"
ACCT = "acct:aaaaaaaa-0000-4000-8000-00000000000a"
GRANT = "11111111-1111-4111-8111-111111111111"
SCOPE = "Canvas.Access"
NOW = 1_800_000_000


class Epoch:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> int:
        return self.value


def codec_for(keyring: Keyring, epoch: Epoch, now: float = NOW) -> tk.AccessTokenCodec:
    return tk.AccessTokenCodec(
        keyring, epoch, issuer=ISSUER, audience=AUDIENCE, scopes=[SCOPE], clock=lambda: now
    )


@pytest.fixture
def epoch() -> Epoch:
    return Epoch()


@pytest.fixture
def codec(keyring: Keyring, epoch: Epoch) -> tk.AccessTokenCodec:
    return codec_for(keyring, epoch)


def issue(codec: tk.AccessTokenCodec, **kw: Any) -> str:
    args: dict[str, Any] = {
        "account_key": ACCT,
        "client_id": "client-1",
        "grant_id": GRANT,
        "scopes": [SCOPE],
        "expires_at": NOW + 3600,
    }
    args.update(kw)
    return codec.encode(**args).token


def good_claims(**overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": ACCT, "acct": ACCT, "client_id": "client-1",
        "scope": SCOPE, "iat": NOW, "exp": NOW + 3600, "jti": "abc", "grant": GRANT,
        "token_use": "access",
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not ...}


def forge(
    keyring: Keyring, *, kid: str = "k1", epoch: int = 0, header: dict[str, Any] | None = None,
    claims: dict[str, Any] | None = None, key: OctKey | None = None, alg: str = "HS256",
) -> str:
    """A token signed with the real derived key, so only the content is wrong."""
    key = key or OctKey.import_key(keyring.derive(kid, f"mcp-access-jwt|v1|{kid}|{epoch}"))
    head = {"alg": alg, "typ": "at+jwt", "kid": f"{kid}.{epoch}", **(header or {})}
    return jwt.encode(head, claims if claims is not None else good_claims(), key, algorithms=[alg])


class TestRoundTrip:
    def test_a_token_verifies_and_carries_the_claims(self, codec: tk.AccessTokenCodec) -> None:
        claims = codec.decode(issue(codec))
        assert claims["iss"] == ISSUER and claims["aud"] == AUDIENCE
        assert claims["sub"] == claims["acct"] == ACCT
        assert claims["client_id"] == "client-1" and claims["grant"] == GRANT
        assert claims["scope"] == SCOPE and claims["token_use"] == "access"
        assert claims["exp"] - claims["iat"] == 3600
        assert len(claims["jti"]) >= 16

    def test_the_header_names_the_ring_key_and_the_epoch(self, codec: tk.AccessTokenCodec) -> None:
        header = json.loads(base64.urlsafe_b64decode(issue(codec).split(".")[0] + "=="))
        assert header == {"typ": "at+jwt", "alg": "HS256", "kid": "k1.0"} or header == {
            "alg": "HS256", "typ": "at+jwt", "kid": "k1.0"
        }

    def test_every_token_has_its_own_jti(self, codec: tk.AccessTokenCodec) -> None:
        assert codec.decode(issue(codec))["jti"] != codec.decode(issue(codec))["jti"]


def hand_signed(keyring: Keyring, header: dict[str, Any], claims: dict[str, Any] | None = None) -> str:
    """A compact JWS built by hand, signed correctly, for headers joserfc refuses to build."""
    import hashlib
    import hmac

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    signing_input = (
        b64(json.dumps(header).encode()) + "." + b64(json.dumps(claims or good_claims()).encode())
    )
    key = keyring.derive("k1", "mcp-access-jwt|v1|k1|0")
    return signing_input + "." + b64(hmac.new(key, signing_input.encode(), hashlib.sha256).digest())


class TestRejections:
    @pytest.mark.parametrize(
        "aud",
        [
            "https://canvas.example.test/",
            "https://canvas.example.test",
            "https://canvas.example.test/mcp/",
            "https://canvas.example.test/other",
            "https://other.example.test/mcp",
            [AUDIENCE],
            [AUDIENCE, "https://other.example.test/mcp"],
            None,
            "",
        ],
    )
    def test_the_audience_must_be_exactly_the_mcp_url(self, codec, keyring, aud) -> None:
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(forge(keyring, claims=good_claims(aud=aud)))

    @pytest.mark.parametrize("iss", ["https://canvas.example.test", "https://evil.example/", None, 5])
    def test_the_issuer_must_be_exact(self, codec, keyring, iss) -> None:
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(forge(keyring, claims=good_claims(iss=iss)))

    @pytest.mark.parametrize("missing", ["iss", "aud", "sub", "acct", "client_id", "scope", "iat", "exp", "jti", "grant", "token_use"])
    def test_every_claim_is_required(self, codec, keyring, missing) -> None:
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(forge(keyring, claims=good_claims(**{missing: ...})))

    @pytest.mark.parametrize(
        "overrides",
        [
            {"token_use": "refresh"},
            {"token_use": None},
            {"sub": "acct:bbbbbbbb-0000-4000-8000-00000000000b"},
            {"sub": "entra:x", "acct": "entra:x"},
            {"acct": "acct:NOT-A-UUID", "sub": "acct:NOT-A-UUID"},
            {"grant": "not-a-uuid"},
            {"grant": 5},
            {"scope": "Canvas.Access admin"},
            {"scope": ""},
            {"scope": ["Canvas.Access"]},
            {"client_id": ""},
            {"client_id": 7},
            {"exp": NOW - 1},
            {"exp": NOW},
            {"exp": str(NOW + 100)},
            {"exp": True},
            {"iat": NOW + 61},
            {"exp": NOW + 200_000},
            {"iat": None},
        ],
    )
    def test_bad_claim_values(self, codec, keyring, overrides) -> None:
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(forge(keyring, claims=good_claims(**overrides)))

    def test_a_small_clock_skew_in_iat_is_tolerated(self, codec, keyring) -> None:
        assert codec.decode(forge(keyring, claims=good_claims(iat=NOW + 60)))["iat"] == NOW + 60

    def test_an_expired_token_is_refused(self, keyring, epoch) -> None:
        late = codec_for(keyring, epoch, now=NOW + 3601)
        with pytest.raises(tk.AccessTokenInvalid):
            late.decode(issue(codec_for(keyring, epoch)))

    @pytest.mark.parametrize("alg", ["HS384", "HS512"])
    def test_only_hs256_is_accepted(self, codec, keyring, alg) -> None:
        key = OctKey.import_key(keyring.derive("k1", "mcp-access-jwt|v1|k1|0"))
        token = jwt.encode(
            {"alg": alg, "typ": "at+jwt", "kid": "k1.0"}, good_claims(), key, algorithms=[alg]
        )
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(token)

    def test_alg_none_is_refused(self, codec) -> None:
        def b64(data: dict[str, Any]) -> str:
            return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

        header = {"alg": "none", "typ": "at+jwt", "kid": "k1.0"}
        for tail in ("", "AAAA"):
            with pytest.raises(tk.AccessTokenInvalid):
                codec.decode(f"{b64(header)}.{b64(good_claims())}.{tail}")

    def test_an_rsa_signed_token_is_refused(self, codec) -> None:
        rsa = RSAKey.generate_key(2048)
        token = jwt.encode(
            {"alg": "RS256", "typ": "at+jwt", "kid": "k1.0"}, good_claims(), rsa, algorithms=["RS256"]
        )
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(token)

    @pytest.mark.parametrize(
        "header",
        [
            {"alg": "HS256", "typ": "JWT", "kid": "k1.0"},
            {"alg": "HS256", "kid": "k1.0"},
            {"alg": "HS256", "typ": "at+jwt", "kid": "k1.0", "jwk": {"kty": "oct", "k": "AA"}},
            {"alg": "HS256", "typ": "at+jwt", "kid": "k1.0", "crit": ["x"], "x": 1},
            {"alg": "HS256", "typ": "at+jwt", "kid": "k1.0", "jku": "https://e/"},
            {"alg": "HS256", "typ": "at+jwt", "kid": "k1.0", "x5u": "https://e/"},
        ],
    )
    def test_the_header_is_strict(self, codec, keyring, header) -> None:
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(hand_signed(keyring, header))

    def test_the_hand_signed_helper_makes_a_valid_token_for_a_good_header(self, codec, keyring) -> None:
        good = {"alg": "HS256", "typ": "at+jwt", "kid": "k1.0"}
        assert codec.decode(hand_signed(keyring, good))["grant"] == GRANT

    @pytest.mark.parametrize("kid", ["k1", "k1.", ".0", "nope.0", "k1.x", "k1.-1", "k1.0.0", 5, None])
    def test_the_kid_must_name_a_ring_key_and_an_epoch(self, codec, keyring, kid) -> None:
        header: dict[str, Any] = {"alg": "HS256", "typ": "at+jwt"}
        if kid is not None:
            header["kid"] = kid
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(hand_signed(keyring, header))

    def test_a_signature_from_another_keyring_is_refused(self, codec, epoch) -> None:
        other = Keyring.parse("k1:" + base64.b64encode(bytes([7]) * 32).decode())
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(issue(codec_for(other, epoch)))

    def test_a_tampered_payload_or_signature_is_refused(self, codec) -> None:
        head, body, sig = issue(codec).split(".")
        bad_body = base64.urlsafe_b64encode(
            json.dumps(good_claims(client_id="someone-else")).encode()
        ).rstrip(b"=").decode()
        for token in (f"{head}.{bad_body}.{sig}", f"{head}.{body}.{sig[:-2]}AA", f"{head}.{body}."):
            with pytest.raises(tk.AccessTokenInvalid):
                codec.decode(token)

    @pytest.mark.parametrize(
        "junk",
        ["", "x", "a.b", "a.b.c", "a.b.c.d", "....", "é.é.é", "Bearer abc", " " * 10, "\x00.\x00.\x00",
         "x" * 5000, "eyJhbGciOiJIUzI1NiJ9.e30.", None, 12, b"abc"],
    )
    def test_junk_is_refused_with_one_error_type(self, codec, junk) -> None:
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(junk)  # type: ignore[arg-type]

    def test_a_token_over_the_size_limit_is_refused(self, codec, keyring) -> None:
        token = forge(keyring, claims=good_claims(jti="x" * 5000))
        assert len(token) > tk.MAX_TOKEN_CHARS
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(token)

    def test_non_utf8_payload_is_refused(self, codec, keyring) -> None:
        key = OctKey.import_key(keyring.derive("k1", "mcp-access-jwt|v1|k1|0"))
        from joserfc import jws

        token = jws.serialize_compact(
            {"alg": "HS256", "typ": "at+jwt", "kid": "k1.0"}, b"\xff\xfe\x00", key, algorithms=["HS256"]
        )
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(token)


class TestEpochAndRotation:
    def test_bumping_the_epoch_invalidates_every_token(self, keyring, epoch) -> None:
        codec = codec_for(keyring, epoch)
        token = issue(codec)
        epoch.value = 1
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(token)
        assert codec.decode(issue(codec))["grant"] == GRANT

    def test_a_token_of_a_future_epoch_is_refused(self, codec, keyring) -> None:
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(forge(keyring, epoch=3))

    def test_rotating_the_ring_keeps_old_tokens_until_the_old_key_is_removed(self) -> None:
        raw1 = base64.b64encode(bytes([1]) * 32).decode()
        raw2 = base64.b64encode(bytes([2]) * 32).decode()
        epoch = Epoch()
        old = codec_for(Keyring.parse(f"k1:{raw1}"), epoch)
        token = issue(old)
        rotated = codec_for(Keyring.parse(f"k2:{raw2},k1:{raw1}"), epoch)
        assert rotated.decode(token)["grant"] == GRANT  # k1 is still in the ring
        fresh = issue(rotated)
        assert json.loads(base64.urlsafe_b64decode(fresh.split(".")[0] + "=="))["kid"] == "k2.0"
        assert rotated.decode(fresh)["grant"] == GRANT
        dropped = codec_for(Keyring.parse(f"k2:{raw2}"), epoch)
        with pytest.raises(tk.AccessTokenInvalid):
            dropped.decode(token)
        assert dropped.decode(fresh)["grant"] == GRANT

    def test_a_failing_epoch_read_fails_closed(self, keyring) -> None:
        def broken() -> int:
            raise RuntimeError("database down")

        codec = tk.AccessTokenCodec(
            keyring, broken, issuer=ISSUER, audience=AUDIENCE, scopes=[SCOPE], clock=lambda: NOW
        )
        epoch = Epoch()
        token = issue(codec_for(keyring, epoch))
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(token)


class TestEpochSource:
    def test_the_value_is_cached_and_invalidated(self) -> None:
        reads: list[int] = []
        clock = [0.0]

        def read() -> int:
            reads.append(len(reads))
            return len(reads) - 1

        source = tk.EpochSource(read, ttl=30, clock=lambda: clock[0])
        assert [source.get(), source.get()] == [0, 0]
        clock[0] = 31
        assert source.get() == 1
        source.invalidate()
        assert source.get() == 2

    def test_an_error_is_not_cached(self) -> None:
        calls = {"n": 0}

        def read() -> int:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("down")
            return 4

        source = tk.EpochSource(read, ttl=30, clock=lambda: 0.0)
        with pytest.raises(RuntimeError):
            source.get()
        assert source.get() == 4 and source.get() == 4 and calls["n"] == 2


class TestOtherIssuersTokens:
    def test_a_fastmcp_proxy_token_never_verifies(self, codec) -> None:
        from fastmcp.server.auth.jwt_issuer import JWTIssuer, derive_jwt_key

        key = derive_jwt_key(low_entropy_material="s" * 48, salt="fastmcp-jwt-signing-key")
        issuer = JWTIssuer(issuer=ISSUER, audience=AUDIENCE, signing_key=key)
        token = issuer.issue_access_token(
            client_id="client-1", scopes=[SCOPE], jti="j", expires_in=3600, subject=ACCT,
            extra_claims={"grant": GRANT, "acct": ACCT, "token_use": "access"},
        )
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(token)

    def test_a_token_signed_with_the_raw_ring_key_never_verifies(self, codec) -> None:
        raw = OctKey.import_key(bytes(range(32)))
        token = jwt.encode({"alg": "HS256", "typ": "at+jwt", "kid": "k1.0"}, good_claims(), raw, algorithms=["HS256"])
        with pytest.raises(tk.AccessTokenInvalid):
            codec.decode(token)

    def test_the_signing_key_is_not_the_encryption_key_or_another_purpose(self, keyring) -> None:
        a = keyring.derive("k1", "mcp-access-jwt|v1|k1|0")
        assert a != bytes(range(32))
        assert a != keyring.derive("k1", "mcp-access-jwt|v1|k1|1")
        assert a != keyring.derive("k1", "something-else")


class TestOpaqueSecrets:
    def test_refresh_tokens_and_codes_have_256_bits_and_a_prefix(self) -> None:
        for make, prefix, pattern in (
            (tk.new_refresh_token, "cmcp_rt_", tk.REFRESH_RE),
            (tk.new_auth_code, "cmcp_ac_", tk.CODE_RE),
        ):
            value = make()
            assert value.startswith(prefix) and pattern.fullmatch(value)
            assert len(base64.urlsafe_b64decode(value[len(prefix):] + "=")) == 32
            assert len({make() for _ in range(200)}) == 200

    def test_the_formats_do_not_cross(self) -> None:
        assert not tk.REFRESH_RE.fullmatch(tk.new_auth_code())
        assert not tk.CODE_RE.fullmatch(tk.new_refresh_token())
        assert not tk.REFRESH_RE.fullmatch(tk.new_refresh_token() + "x")
        assert not tk.REFRESH_RE.fullmatch("cmcp_rt_short")

    def test_the_hash_is_lowercase_sha256_hex(self) -> None:
        digest = tk.hash_secret("abc")
        assert digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assert tk.HASH_RE.fullmatch(digest)
        assert re.fullmatch(r"[0-9a-f]{64}", tk.hash_secret(tk.new_refresh_token()))
