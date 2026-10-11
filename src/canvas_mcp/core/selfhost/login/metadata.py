"""OpenID Connect discovery: parse a provider's metadata and cache it.

The metadata of a provider is an immutable snapshot that is replaced as a whole (never
patched field by field), so a request can never see half of an old and half of a new
document. Nothing is fetched at startup; the first sign-in does it. A failed refresh keeps
serving the last good snapshot for up to 24 hours.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .config import blocked_host
from .http import CAP_DISCOVERY, SafeHttp, UpstreamError

#: Signature algorithms the server will verify. ``none`` and the HMAC family are never allowed.
ALLOWED_ALGS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)

TTL_DEFAULT_S = 3600
TTL_MIN_S = 300
TTL_MAX_S = 86400
STALE_IF_ERROR_S = 86400
#: RFC 9207 metadata member (written in two pieces to keep the long name readable).
ISS_PARAM_KEY = "authorization_response_iss_" "parameter_supported"
FAILURE_BACKOFF_S = 30

_MAX_AGE_RE = re.compile(r"(?:^|[,\s])max-age\s*=\s*(\d{1,9})(?:[,\s]|$)", re.IGNORECASE)


class ProviderUnavailable(Exception):
    """The provider's metadata could not be obtained or is not acceptable (no details carried)."""


@dataclass(frozen=True)
class ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None
    algs: tuple[str, ...]
    #: The document lists ``S256`` in ``code_challenge_methods_supported``.
    pkce_s256: bool
    #: ``authorization_response_iss_parameter_supported`` (RFC 9207) is true.
    iss_param_supported: bool
    token_auth_methods: tuple[str, ...]


def discovery_url(issuer: str) -> str:
    """The issuer with a terminating ``/`` removed, plus ``/.well-known/openid-configuration``."""
    return issuer.rstrip("/") + "/.well-known/openid-configuration"


def _https_url(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 2048:
        return None
    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError:
        return None
    if (
        parts.scheme != "https"
        or not host
        or "@" in parts.netloc
        or parts.fragment
        or blocked_host(host)
    ):
        return None
    return value


def parse_discovery(doc: Mapping[str, Any], expected_issuer: str) -> ProviderMetadata:
    """Check a discovery document and reduce it to a snapshot, or raise :class:`ProviderUnavailable`.

    The ``issuer`` must equal the configured one character for character (OIDC Discovery
    section 4.3), every endpoint must be https, ``code`` must be a supported response type, at
    least one allowed signature algorithm must be offered (``none`` and ``HS*`` are dropped),
    and a document that lists its PKCE methods must list ``S256``.
    """
    if doc.get("issuer") != expected_issuer:
        raise ProviderUnavailable
    authorization = _https_url(doc.get("authorization_endpoint"))
    token = _https_url(doc.get("token_endpoint"))
    jwks = _https_url(doc.get("jwks_uri"))
    if authorization is None or token is None or jwks is None:
        raise ProviderUnavailable
    userinfo_raw = doc.get("userinfo_endpoint")
    userinfo = None
    if userinfo_raw is not None:
        userinfo = _https_url(userinfo_raw)
        if userinfo is None:
            raise ProviderUnavailable
    response_types = doc.get("response_types_supported")
    if not isinstance(response_types, list) or "code" not in response_types:
        raise ProviderUnavailable
    offered = doc.get("id_token_signing_alg_values_supported")
    if not isinstance(offered, list):
        raise ProviderUnavailable
    algs = tuple(a for a in offered if isinstance(a, str) and a in ALLOWED_ALGS)
    if not algs:
        raise ProviderUnavailable
    methods = doc.get("code_challenge_methods_supported")
    pkce = False
    if methods is not None:
        if not isinstance(methods, list) or "S256" not in methods:
            raise ProviderUnavailable
        pkce = True
    auth_methods_raw = doc.get("token_endpoint_auth_methods_supported")
    auth_methods = (
        tuple(m for m in auth_methods_raw if isinstance(m, str))
        if isinstance(auth_methods_raw, list)
        else ()
    )
    return ProviderMetadata(
        issuer=expected_issuer,
        authorization_endpoint=authorization,
        token_endpoint=token,
        jwks_uri=jwks,
        userinfo_endpoint=userinfo,
        algs=algs,
        pkce_s256=pkce,
        iss_param_supported=doc.get(ISS_PARAM_KEY) is True,
        token_auth_methods=auth_methods,
    )


def cache_ttl(headers: Mapping[str, str]) -> int:
    """The snapshot's lifetime: ``Cache-Control: max-age`` clamped to 5 minutes..24 hours, else 1 hour."""
    value = headers.get("cache-control", "")
    if "no-store" in value.lower() or "no-cache" in value.lower():
        return TTL_MIN_S
    match = _MAX_AGE_RE.search(value)
    if match is None:
        return TTL_DEFAULT_S
    return max(TTL_MIN_S, min(TTL_MAX_S, int(match.group(1))))


class DiscoveryCache:
    """The metadata of one issuer, fetched on demand and shared by every sign-in."""

    def __init__(
        self,
        issuer: str,
        http: SafeHttp,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._issuer = issuer
        self._http = http
        self._clock = clock
        self._snapshot: ProviderMetadata | None = None
        self._fetched_at = 0.0
        self._ttl = TTL_DEFAULT_S
        self._backoff_until = 0.0
        self._lock = asyncio.Lock()
        self.fetches = 0

    @property
    def issuer(self) -> str:
        return self._issuer

    def current(self) -> ProviderMetadata | None:
        """The snapshot held now, however old (None before the first successful fetch)."""
        return self._snapshot

    def _fresh(self, now: float) -> bool:
        return self._snapshot is not None and now - self._fetched_at < self._ttl

    async def get(self) -> ProviderMetadata:
        now = self._clock()
        if self._fresh(now):
            assert self._snapshot is not None
            return self._snapshot
        async with self._lock:
            # Single flight: whoever waited behind a fetch finds its result here.
            now = self._clock()
            if self._fresh(now):
                assert self._snapshot is not None
                return self._snapshot
            if now < self._backoff_until:
                return self._stale_or_fail(now)
            try:
                result = await self._http.get_json(
                    discovery_url(self._issuer), max_bytes=CAP_DISCOVERY
                )
                self.fetches += 1
                snapshot = parse_discovery(result.body, self._issuer)
            except (UpstreamError, ProviderUnavailable):
                self._backoff_until = now + FAILURE_BACKOFF_S
                return self._stale_or_fail(now)
            self._snapshot = snapshot
            self._fetched_at = now
            self._ttl = cache_ttl(result.headers)
            self._backoff_until = 0.0
            return snapshot

    def _stale_or_fail(self, now: float) -> ProviderMetadata:
        if self._snapshot is not None and now - self._fetched_at < STALE_IF_ERROR_S:
            return self._snapshot
        raise ProviderUnavailable
