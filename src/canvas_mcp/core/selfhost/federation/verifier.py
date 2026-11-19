"""Verify an access token from a trusted external issuer (RFC 9068 style), in a fixed order.

1. size limit; 2. header: ``alg`` on the issuer's list (never ``none``, never ``HS*``), ``typ``
``at+jwt`` when required, no ``jku``/``jwk``/``x5u`` (or ``crit``); 3. the signature against the
issuer's cached key set (an unknown ``kid`` causes at most one refetch a minute per issuer);
4. the exact ``iss``; 5. ``aud`` contains the audience; 6. ``exp`` required, ``nbf`` and
``iat`` honoured with 60 seconds of skew; 7. the configured subject claim is a non-empty
string (there is no fallback to another claim); 8. the scopes, which can only narrow.

A refusal is :class:`TokenRejected` with a reason from a closed set; it carries no token text.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from ..login.http import CAP_DISCOVERY, SafeHttp, UpstreamError, check_url
from ..login.idtoken import IdTokenRejected, peek_header
from ..login.jwks import JwksCache
from ..login.metadata import cache_ttl
from .config import TrustedIssuer, metadata_url

#: Larger than the 4096 of this server's own tokens: an Entra or Keycloak token can be bigger.
MAX_TOKEN_CHARS = 8192
SKEW_SECONDS = 60
METADATA_FAILURE_BACKOFF_S = 30
_SUBJECT = re.compile(r"^[\x21-\x7e]{1,255}$")
_FORBIDDEN_HEADERS = ("jku", "jwk", "x5u", "crit")
_AT_JWT = frozenset({"at+jwt", "application/at+jwt"})

REASONS = frozenset(
    {
        "size",
        "malformed",
        "alg",
        "typ",
        "header",
        "key",
        "signature",
        "iss",
        "aud",
        "exp",
        "nbf",
        "iat",
        "subject",
        "scope",
        "metadata",
    }
)


class TokenRejected(Exception):
    """The token is not acceptable. ``reason`` is one of :data:`REASONS`."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason if reason in REASONS else "malformed"


@dataclass(frozen=True)
class VerifiedToken:
    issuer: str
    subject: str
    expires_at: int
    #: False when the issuer has a write scope and the token does not carry it.
    write_allowed: bool


def peek_issuer(token: str) -> str | None:
    """The unverified ``iss`` of a compact JWT, only to choose the decoder. None when there is none.

    Nothing is trusted from this: a token that names this server as issuer goes to the decoder of
    this server's own tokens, any other goes to the trusted issuers, and each checks everything.
    """
    if not isinstance(token, str) or token.count(".") != 2 or len(token) > 65536:
        return None
    try:
        segment = token.split(".")[1]
        payload = json.loads(
            base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)).decode(
                "utf-8"
            )
        )
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    issuer = payload.get("iss") if isinstance(payload, dict) else None
    return issuer if isinstance(issuer, str) else None


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _scopes(claims: Mapping[str, Any]) -> frozenset[str]:
    out: set[str] = set()
    for name in ("scope", "scp"):
        value = claims.get(name)
        if isinstance(value, str):
            out.update(value.split())
        elif isinstance(value, list):
            out.update(item for item in value if isinstance(item, str))
    return frozenset(out)


class _IssuerKeys:
    """The key set of one issuer, and where it is found."""

    def __init__(self, http: SafeHttp, clock: Callable[[], float]) -> None:
        self.http = http
        self.clock = clock
        self.jwks = JwksCache(http, clock=clock)
        self._discovered: str | None = None
        self._fetched_at = 0.0
        self._ttl = 3600
        self._backoff_until = 0.0
        self._lock = asyncio.Lock()

    async def uri(self, issuer: TrustedIssuer) -> str:
        if issuer.jwks_url is not None:
            return issuer.jwks_url
        now = self.clock()
        if self._discovered is not None and now - self._fetched_at < self._ttl:
            return self._discovered
        async with self._lock:
            now = self.clock()
            if self._discovered is not None and now - self._fetched_at < self._ttl:
                return self._discovered
            if now < self._backoff_until:
                return self._stale_or_fail(now)
            try:
                result = await self.http.get_json(
                    metadata_url(issuer.issuer), max_bytes=CAP_DISCOVERY
                )
                body = result.body
                jwks_uri = body.get("jwks_uri")
                if body.get("issuer") != issuer.issuer or not isinstance(jwks_uri, str):
                    raise TokenRejected("metadata")
                check_url(jwks_uri, allow_loopback=True)
            except (UpstreamError, TokenRejected):
                self._backoff_until = now + METADATA_FAILURE_BACKOFF_S
                return self._stale_or_fail(now)
            self._discovered, self._fetched_at = jwks_uri, now
            self._ttl = cache_ttl(result.headers)
            self._backoff_until = 0.0
            return jwks_uri

    def _stale_or_fail(self, now: float) -> str:
        if self._discovered is not None and now - self._fetched_at < 86400:
            return self._discovered
        raise TokenRejected("metadata")


class TokenVerifier:
    """Checks tokens for the issuers it is handed, keeping one key cache per issuer."""

    def __init__(
        self,
        http: SafeHttp,
        *,
        default_audience: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.http = http
        self.default_audience = default_audience
        self._clock = clock
        self._keys: dict[str, _IssuerKeys] = {}

    def _keys_of(self, issuer: str) -> _IssuerKeys:
        keys = self._keys.get(issuer)
        if keys is None:
            keys = self._keys[issuer] = _IssuerKeys(self.http, self._clock)
        return keys

    def forget_except(self, issuers: set[str]) -> None:
        """Drop the key caches of issuers that are no longer configured."""
        for name in set(self._keys) - issuers:
            del self._keys[name]

    async def verify(self, token: str, issuer: TrustedIssuer) -> VerifiedToken:
        if not isinstance(token, str) or not 0 < len(token) <= MAX_TOKEN_CHARS:
            raise TokenRejected("size")
        try:
            header = peek_header(token)
        except IdTokenRejected:
            raise TokenRejected("malformed") from None
        alg = header.get("alg")
        if (
            not isinstance(alg, str)
            or alg not in issuer.algorithms
            or alg.lower() == "none"
            or alg.upper().startswith("HS")
        ):
            raise TokenRejected("alg")
        if issuer.require_typ_at_jwt:
            typ = header.get("typ")
            if not isinstance(typ, str) or typ.lower() not in _AT_JWT:
                raise TokenRejected("typ")
        if any(name in header for name in _FORBIDDEN_HEADERS):
            raise TokenRejected("header")
        kid = header.get("kid")
        if kid is not None and not isinstance(kid, str):
            raise TokenRejected("key")
        keys = self._keys_of(issuer.issuer)
        uri = await keys.uri(issuer)
        await keys.jwks.ensure(uri, kid)
        key = keys.jwks.lookup(kid, alg)
        if key is None:
            raise TokenRejected("key")

        from joserfc import (
            jwt,  # imported here: only a token that got this far needs it
        )

        try:
            claims: dict[str, Any] = dict(
                jwt.decode(token, key, algorithms=[alg]).claims
            )
        except (
            Exception
        ):  # noqa: BLE001 - any failure of the signature check is one answer
            raise TokenRejected("signature") from None
        return self._check_claims(claims, issuer)

    def _check_claims(
        self, claims: Mapping[str, Any], issuer: TrustedIssuer
    ) -> VerifiedToken:
        now = self._clock()
        if claims.get("iss") != issuer.issuer:
            raise TokenRejected("iss")
        aud = claims.get("aud")
        audiences = (
            [aud]
            if isinstance(aud, str)
            else (
                aud
                if isinstance(aud, list) and all(isinstance(a, str) for a in aud)
                else []
            )
        )
        if (issuer.audience or self.default_audience) not in audiences:
            raise TokenRejected("aud")
        exp = _number(claims.get("exp"))
        if exp is None or exp <= now:
            raise TokenRejected("exp")
        if "nbf" in claims:
            nbf = _number(claims["nbf"])
            if nbf is None or nbf > now + SKEW_SECONDS:
                raise TokenRejected("nbf")
        if "iat" in claims:
            iat = _number(claims["iat"])
            if iat is None or iat > now + SKEW_SECONDS:
                raise TokenRejected("iat")
        subject = claims.get(issuer.subject_claim)
        if not isinstance(subject, str) or _SUBJECT.fullmatch(subject) is None:
            raise TokenRejected("subject")
        scopes = _scopes(claims)
        if issuer.read_scope is not None and issuer.read_scope not in scopes:
            raise TokenRejected("scope")
        return VerifiedToken(
            issuer=issuer.issuer,
            subject=subject,
            expires_at=int(exp),
            write_allowed=issuer.write_scope is None or issuer.write_scope in scopes,
        )
