"""ID token verification for a generic OpenID Connect provider (OIDC Core 3.1.3.7).

:func:`verify_id_token` is pure apart from the key lookup it is handed: it does no I/O. The
caller reads the header with :func:`peek_header` first (to know the ``kid``), makes sure the
key is loaded, and then verifies.

Before any cryptography the token must be at most 16 KiB, have exactly three segments (a JWE
has five, so it is refused here) and name an algorithm from the list the caller allows. ``none``
and the HMAC family are never allowed, whatever the caller passes: a token signed with the client
secret as an HMAC key is the classic key-confusion attack, and the provider's public key is the
only thing a signature is checked against.

A refusal is :class:`IdTokenRejected` with a reason from a closed set; the exception carries no
token text and no claim value.
"""

from __future__ import annotations

import base64
import hmac
import json
import re
from collections.abc import Callable, Collection, Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from joserfc.jwk import Key

MAX_TOKEN_CHARS = 16 * 1024
SKEW_SECONDS = 600

REASONS = frozenset(
    {
        "malformed", "alg", "kid", "signature", "iss", "aud", "azp", "exp", "iat", "nbf", "nonce",
        "sub",
    }
)
_SUB_RE = re.compile(r"^[\x21-\x7e]{1,255}$")
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]+$")

KeyLookup = Callable[[str | None, str], "Key | None"]


class IdTokenRejected(Exception):
    """The token is not acceptable. ``reason`` is one of :data:`REASONS`."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason if reason in REASONS else "malformed"


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in items:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _refuse(_name: str) -> Any:
    raise ValueError("not JSON")


def peek_header(raw: str) -> dict[str, Any]:
    """The protected header of a compact JWS, without checking anything about the token.

    Only used to learn ``kid`` and ``alg``; nothing in it is trusted before the signature
    is verified.
    """
    if not isinstance(raw, str) or len(raw) > MAX_TOKEN_CHARS:
        raise IdTokenRejected("malformed")
    parts = raw.split(".")
    # The signature segment of an unsecured token is empty: it is refused for its ``alg`` below.
    if (
        len(parts) != 3
        or not _SEGMENT_RE.fullmatch(parts[0])
        or not _SEGMENT_RE.fullmatch(parts[1])
        or (parts[2] != "" and not _SEGMENT_RE.fullmatch(parts[2]))
    ):
        raise IdTokenRejected("malformed")
    try:
        header = json.loads(
            base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)).decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_refuse,
        )
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise IdTokenRejected("malformed") from None
    if not isinstance(header, dict):
        raise IdTokenRejected("malformed")
    return header


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _same(value: Any, expected: str) -> bool:
    return isinstance(value, str) and hmac.compare_digest(
        value.encode("utf-8"), expected.encode("utf-8")
    )


def verify_id_token(
    raw: str,
    *,
    key_lookup: KeyLookup,
    client_id: str,
    accepted_issuers: Collection[str],
    nonce: str,
    allowed_algs: Collection[str],
    now: float,
    skew: int = SKEW_SECONDS,
) -> dict[str, Any]:
    """The verified claims of an ID token, or :class:`IdTokenRejected`."""
    header = peek_header(raw)
    alg = header.get("alg")
    if (
        not isinstance(alg, str)
        or alg not in allowed_algs
        or alg.lower() == "none"
        or alg.upper().startswith("HS")
    ):
        raise IdTokenRejected("alg")
    if "crit" in header:
        raise IdTokenRejected("malformed")
    kid = header.get("kid")
    if kid is not None and not isinstance(kid, str):
        raise IdTokenRejected("kid")
    key = key_lookup(kid, alg)
    if key is None:
        raise IdTokenRejected("kid")

    # Imported here: this is the only place that needs the library.
    from joserfc import jwt

    try:
        token = jwt.decode(raw, key, algorithms=[alg])
    except Exception:  # noqa: BLE001 - any failure of the signature check is one answer
        raise IdTokenRejected("signature") from None
    claims: dict[str, Any] = dict(token.claims)

    if not (isinstance(claims.get("iss"), str) and claims["iss"] in set(accepted_issuers)):
        raise IdTokenRejected("iss")
    _check_audience(claims, client_id)
    exp = _number(claims.get("exp"))
    if exp is None or exp <= now - skew:
        raise IdTokenRejected("exp")
    iat = _number(claims.get("iat"))
    if iat is None or abs(now - iat) > skew:
        raise IdTokenRejected("iat")
    if "nbf" in claims:
        nbf = _number(claims["nbf"])
        if nbf is None or nbf > now + skew:
            raise IdTokenRejected("nbf")
    if not _same(claims.get("nonce"), nonce):
        raise IdTokenRejected("nonce")
    sub = claims.get("sub")
    if not isinstance(sub, str) or _SUB_RE.fullmatch(sub) is None:
        raise IdTokenRejected("sub")
    return claims


def _check_audience(claims: Mapping[str, Any], client_id: str) -> None:
    aud = claims.get("aud")
    if isinstance(aud, str):
        audiences = [aud]
    elif isinstance(aud, list) and aud and all(isinstance(a, str) for a in aud):
        audiences = list(aud)
    else:
        raise IdTokenRejected("aud")
    if client_id not in audiences:
        raise IdTokenRejected("aud")
    azp = claims.get("azp")
    if len(audiences) > 1 and azp is None:
        raise IdTokenRejected("azp")
    if azp is not None and azp != client_id:
        raise IdTokenRejected("azp")
