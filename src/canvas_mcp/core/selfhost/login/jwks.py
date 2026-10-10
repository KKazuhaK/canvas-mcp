"""The signing keys of one provider: fetched, filtered, cached, rotated.

* Keys are kept by ``kid`` for an hour. A token with a ``kid`` the cache does not know
  triggers one refetch, but at most one a minute per provider, so a stream of tokens with
  invented key ids cannot make the server hammer the provider.
* A document with more than 50 keys is refused as a whole.
* Only signature keys are kept: ``use`` other than ``sig`` is ignored, RSA keys need at least
  2048 bits, EC keys must be on P-256, P-384 or P-521 and OKP keys must be Ed25519. A key whose
  own ``alg`` names an algorithm other than the token's is not a candidate for that token.
* A token without a ``kid`` is accepted only when exactly one suitable key exists.

joserfc is imported when a key is first built, never at import time of this module.
"""

from __future__ import annotations

import asyncio
import base64
import time
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from .http import CAP_JWKS, SafeHttp, UpstreamError

if TYPE_CHECKING:
    from joserfc.jwk import Key

TTL_S = 3600
REFETCH_MIN_INTERVAL_S = 60
STALE_IF_ERROR_S = 86400
MAX_KEYS = 50
MIN_RSA_BITS = 2048

_EC_CURVES = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
_RSA_ALGS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"})


class JwksError(Exception):
    """The key set is unusable (carries no detail)."""


def _rsa_bits(n: Any) -> int:
    if not isinstance(n, str) or not n:
        return 0
    try:
        raw = base64.urlsafe_b64decode(n + "=" * (-len(n) % 4))
    except (ValueError, TypeError):
        return 0
    return int.from_bytes(raw, "big").bit_length()


def key_is_acceptable(jwk: Mapping[str, Any]) -> bool:
    """Whether a JWK is a signature key this server is willing to verify with."""
    use = jwk.get("use")
    if use is not None and use != "sig":
        return False
    ops = jwk.get("key_ops")
    if ops is not None and (not isinstance(ops, list) or "verify" not in ops):
        return False
    kty = jwk.get("kty")
    if kty == "RSA":
        return _rsa_bits(jwk.get("n")) >= MIN_RSA_BITS and isinstance(jwk.get("e"), str)
    if kty == "EC":
        return jwk.get("crv") in _EC_CURVES
    if kty == "OKP":
        return jwk.get("crv") == "Ed25519"
    return False


def alg_fits_key(jwk: Mapping[str, Any], alg: str) -> bool:
    """Whether a token signed with ``alg`` may be checked against this key."""
    declared = jwk.get("alg")
    if declared is not None and declared != alg:
        return False
    kty = jwk.get("kty")
    if kty == "RSA":
        return alg in _RSA_ALGS
    if kty == "EC":
        return _EC_CURVES.get(str(jwk.get("crv"))) == alg
    if kty == "OKP":
        return alg == "EdDSA"
    return False


class JwksCache:
    """The verification keys behind one ``jwks_uri``."""

    def __init__(
        self,
        http: SafeHttp,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._http = http
        self._clock = clock
        self._jwks_uri = ""
        # kid -> (jwk dict, imported key). Keys without a kid are kept under "".
        self._keys: dict[str, tuple[dict[str, Any], Any]] = {}
        self._anonymous: list[tuple[dict[str, Any], Any]] = []
        self._loaded_at = 0.0
        self._last_fetch: float | None = None
        self._lock = asyncio.Lock()
        self.fetches = 0

    def _loaded(self) -> bool:
        return self._loaded_at > 0

    def _reset(self) -> None:
        self._keys, self._anonymous, self._loaded_at = {}, [], 0.0

    def _needs_fetch(self, kid: str | None, now: float) -> bool:
        """Whether a fetch is due: the key set is missing or expired, or ``kid`` is unknown.

        Every fetch, whatever the reason, waits at least a minute after the previous one, so
        neither tokens with invented key ids nor a failing provider can make the server
        hammer the key endpoint.
        """
        if self._last_fetch is not None and now - self._last_fetch < REFETCH_MIN_INTERVAL_S:
            return False
        if not self._loaded() or now - self._loaded_at >= TTL_S:
            return True
        return kid is not None and kid not in self._keys

    async def ensure(self, jwks_uri: str, kid: str | None) -> None:
        """Make sure the keys needed to check a token with this ``kid`` are loaded, if they can be."""
        if self._jwks_uri != jwks_uri:
            # The provider moved its key set: nothing cached is valid for the new address.
            self._jwks_uri = jwks_uri
            self._reset()
            self._last_fetch = None
        if not self._needs_fetch(kid, self._clock()):
            return
        async with self._lock:
            now = self._clock()
            if not self._needs_fetch(kid, now):
                return  # whoever held the lock just fetched
            self._last_fetch = now
            try:
                await self._load(jwks_uri)
            except (UpstreamError, JwksError):
                if not (self._loaded() and now - self._loaded_at < STALE_IF_ERROR_S):
                    self._reset()  # nothing trustworthy left to serve

    async def _load(self, jwks_uri: str) -> None:
        result = await self._http.get_json(jwks_uri, max_bytes=CAP_JWKS)
        self.fetches += 1
        keys = result.body.get("keys")
        if not isinstance(keys, list) or len(keys) > MAX_KEYS:
            raise JwksError
        from joserfc.jwk import import_key

        by_kid: dict[str, tuple[dict[str, Any], Any]] = {}
        anonymous: list[tuple[dict[str, Any], Any]] = []
        for jwk in keys:
            if not isinstance(jwk, dict) or not key_is_acceptable(jwk):
                continue
            try:
                imported = import_key(dict(jwk))
            except Exception:  # noqa: BLE001 - a key joserfc cannot read is simply not a candidate
                continue
            kid = jwk.get("kid")
            if isinstance(kid, str) and kid:
                by_kid.setdefault(kid, (dict(jwk), imported))
            elif kid is None:
                anonymous.append((dict(jwk), imported))
        self._keys, self._anonymous = by_kid, anonymous
        self._loaded_at = self._clock()

    def lookup(self, kid: str | None, alg: str) -> Key | None:
        """The key to verify a token with this ``kid`` and ``alg`` against, from what is loaded."""
        if kid is not None:
            entry = self._keys.get(kid)
            if entry is None or not alg_fits_key(entry[0], alg):
                return None
            key: Key = entry[1]
            return key
        candidates = [
            imported
            for jwk, imported in (*self._keys.values(), *self._anonymous)
            if alg_fits_key(jwk, alg)
        ]
        return candidates[0] if len(candidates) == 1 else None
