"""Access tokens (signed JWTs) and the opaque secrets of the authorization server.

**Access tokens.** HS256 JWTs signed with joserfc. The key is not any stored key and not
FastMCP's ``OAUTH_JWT_SIGNING_KEY`` derivation: it is derived with HKDF from one key of
the ``CANVAS_TOKEN_KEYS`` ring (:meth:`Keyring.derive`), for the purpose
``mcp-access-jwt|v1|<kid>|<epoch>``. A token proxied by FastMCP can therefore never verify
here, and the other way round. The header carries ``kid`` as ``<ring key id>.<epoch>``:

* the ring key id selects which ring key the signing key derives from, so rotating
  ``CANVAS_TOKEN_KEYS`` (new key first, old key kept while its tokens live) rotates the
  signing key without invalidating tokens signed under a key that is still in the ring;
* the epoch (``meta.mcp_jwt_epoch``) is raised by the operator to invalidate every access
  token at once (clients simply refresh).

:meth:`AccessTokenCodec.decode` checks everything before it trusts a claim: size, compact
form, ``alg`` (HS256 only), ``typ``, a known ``kid`` at the current epoch, the signature,
the exact ``iss`` and ``aud`` strings, ``token_use``, the shape of every identifier and the
time window. Anything wrong raises :class:`AccessTokenInvalid`, a single error type with no
detail, so callers cannot distinguish (or leak) why.

**Opaque secrets.** Authorization codes and refresh tokens are random 256-bit values with a
prefix; only their SHA-256 hashes are ever stored.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from joserfc import jws as _jws
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import OctKey

from ..accounts import valid_account_key
from ..token_store import Keyring, KeyringError

MAX_TOKEN_CHARS = 4096
CLOCK_SKEW_SECONDS = 60
MAX_LIFETIME_SECONDS = 86400 + CLOCK_SKEW_SECONDS
ACCESS_TOKEN_TYPE = "at+jwt"
ALGORITHM = "HS256"
EPOCH_CACHE_SECONDS = 30.0
_KEY_PURPOSE = "mcp-access-jwt|v1"

REFRESH_PREFIX = "cmcp_rt_"
CODE_PREFIX = "cmcp_ac_"
REFRESH_RE = re.compile(r"^cmcp_rt_[A-Za-z0-9_-]{43}$")
CODE_RE = re.compile(r"^cmcp_ac_[A-Za-z0-9_-]{43}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_FORBIDDEN_HEADERS = ("jku", "jwk", "x5u", "x5c", "x5t", "x5t#S256", "crit", "zip")


class AccessTokenInvalid(Exception):
    """The token is not an access token this server issued (or it expired). No detail."""


def new_refresh_token() -> str:
    """A refresh token: 256 random bits, ``cmcp_rt_`` plus 43 URL-safe characters."""
    return REFRESH_PREFIX + secrets.token_urlsafe(32)


def new_auth_code() -> str:
    """An authorization code: 256 random bits, ``cmcp_ac_`` plus 43 URL-safe characters."""
    return CODE_PREFIX + secrets.token_urlsafe(32)


def hash_secret(value: str) -> str:
    """SHA-256 hex digest of a secret (the only form in which a code or token is stored)."""
    return sha256(value.encode("utf-8")).hexdigest()


class EpochSource:
    """The current ``mcp_jwt_epoch``, read through ``read`` at most every ``ttl`` seconds.

    A failing read is never cached: the cached value is not served past its lifetime, so
    verification fails closed when the database is down for longer than the cache.
    """

    def __init__(
        self,
        read: Callable[[], int],
        *,
        ttl: float = EPOCH_CACHE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._read = read
        self._ttl = ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._value = 0
        self._expires = float("-inf")
        self._generation = 0

    def get(self) -> int:
        with self._lock:
            if self._clock() < self._expires:
                return self._value
            generation = self._generation
        value = int(self._read())
        with self._lock:
            if generation == self._generation:
                self._value = value
                self._expires = self._clock() + self._ttl
        return value

    def invalidate(self) -> None:
        """Forget the cached epoch (this process just changed it)."""
        with self._lock:
            self._generation += 1
            self._expires = float("-inf")


@dataclass(frozen=True)
class IssuedAccessToken:
    token: str
    claims: dict[str, Any]


class AccessTokenCodec:
    """Issue and verify access tokens. Synchronous; the epoch read may touch the database."""

    def __init__(
        self,
        keyring: Keyring,
        epoch: Callable[[], int],
        *,
        issuer: str,
        audience: str,
        scopes: Collection[str],
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._keyring = keyring
        self._epoch = epoch
        self.issuer = issuer
        self.audience = audience
        self._scopes = frozenset(scopes)
        self._clock = clock
        self._keys: dict[tuple[str, int], OctKey] = {}
        self._lock = threading.Lock()

    # -- keys -----------------------------------------------------------------------

    def _key(self, kid: str, epoch: int) -> OctKey:
        with self._lock:
            key = self._keys.get((kid, epoch))
        if key is None:
            raw = self._keyring.derive(kid, f"{_KEY_PURPOSE}|{kid}|{epoch}")
            key = OctKey.import_key(raw)
            with self._lock:
                if len(self._keys) > 64:  # old epochs and retired ring keys do not pile up
                    self._keys.clear()
                self._keys[(kid, epoch)] = key
        return key

    # -- issue ----------------------------------------------------------------------

    def encode(
        self,
        *,
        account_key: str,
        client_id: str,
        grant_id: str,
        scopes: Collection[str],
        expires_at: int,
    ) -> IssuedAccessToken:
        """A signed access token for ``account_key`` that expires at ``expires_at``."""
        now = int(self._clock())
        kid = self._keyring.active_key_id
        epoch = self._epoch()
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": account_key,
            "acct": account_key,
            "client_id": client_id,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": int(expires_at),
            "jti": secrets.token_urlsafe(16),
            "grant": grant_id,
            "token_use": "access",
        }
        header = {"alg": ALGORITHM, "typ": ACCESS_TOKEN_TYPE, "kid": f"{kid}.{epoch}"}
        token = jwt.encode(header, claims, self._key(kid, epoch), algorithms=[ALGORITHM])
        return IssuedAccessToken(token, claims)

    # -- verify ---------------------------------------------------------------------

    def decode(self, token: str) -> dict[str, Any]:
        """The verified claims of an access token, or :class:`AccessTokenInvalid`."""
        try:
            return self._decode(token)
        except AccessTokenInvalid:
            raise
        except (JoseError, KeyringError, ValueError, TypeError, KeyError, AttributeError):
            raise AccessTokenInvalid from None
        except Exception:  # noqa: BLE001 - verification fails closed on anything unexpected
            raise AccessTokenInvalid from None

    def _decode(self, token: str) -> dict[str, Any]:
        if not isinstance(token, str) or not 0 < len(token) <= MAX_TOKEN_CHARS or not token.isascii():
            raise AccessTokenInvalid
        if token.count(".") != 2:
            raise AccessTokenInvalid
        header = _jws.extract_compact(token.encode("ascii")).headers()
        if (
            header.get("alg") != ALGORITHM
            or header.get("typ") != ACCESS_TOKEN_TYPE
            or any(name in header for name in _FORBIDDEN_HEADERS)
        ):
            raise AccessTokenInvalid
        raw_kid = header.get("kid")
        if not isinstance(raw_kid, str):
            raise AccessTokenInvalid
        kid, _, epoch_text = raw_kid.rpartition(".")
        if not kid or not epoch_text.isdigit() or kid not in self._keyring.key_ids:
            raise AccessTokenInvalid
        epoch = int(epoch_text)
        if epoch != self._epoch():
            raise AccessTokenInvalid
        decoded = jwt.decode(token, self._key(kid, epoch), algorithms=[ALGORITHM])
        claims = dict(decoded.claims)
        self._check_claims(claims)
        return claims

    def _check_claims(self, claims: dict[str, Any]) -> None:
        def text(name: str, limit: int = 512) -> str:
            value = claims.get(name)
            if not isinstance(value, str) or not value or len(value) > limit:
                raise AccessTokenInvalid
            return value

        def number(name: str) -> int:
            value = claims.get(name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise AccessTokenInvalid
            return value

        if text("iss") != self.issuer:
            raise AccessTokenInvalid
        if text("aud") != self.audience:  # an exact string: a list or another path is refused
            raise AccessTokenInvalid
        if text("token_use", 16) != "access":
            raise AccessTokenInvalid
        subject, acct = text("sub", 80), text("acct", 80)
        if subject != acct or not valid_account_key(acct):
            raise AccessTokenInvalid
        if not _UUID_RE.fullmatch(text("grant", 36)):
            raise AccessTokenInvalid
        text("client_id")
        text("jti", 64)
        scopes = text("scope", 1024).split(" ")
        if not scopes or not self._scopes.issuperset(scopes):
            raise AccessTokenInvalid
        now = self._clock()
        iat, exp = number("iat"), number("exp")
        if exp <= now or iat > now + CLOCK_SKEW_SECONDS or exp - iat > MAX_LIFETIME_SECONDS:
            raise AccessTokenInvalid
