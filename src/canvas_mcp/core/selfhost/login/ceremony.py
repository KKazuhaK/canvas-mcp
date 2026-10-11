"""The state of one sign-in (or link) ceremony, stored server side for ten minutes.

A ceremony starts at ``/account/login/<provider>``: the server stores a :class:`FlowRecord`
(PKCE verifier, nonce, what the sign-in is for) in the one-time ``login_states`` table under an
unguessable id, which becomes the OAuth ``state``, and gives the browser a sealed
``__Host-cmcp_flow`` cookie holding the state, a random binding secret and the provider. The
record is bound to the SHA-256 of that secret: only the browser that started the ceremony can
pop it, and it can be popped once.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

#: ``login_states.kind`` of a provider ceremony, and of an Entra link ceremony.
FLOW_KIND = "login_flow"
LINK_KIND = "account_link"
FLOW_TTL_S = 600
FLOW_COOKIE = "__Host-cmcp_flow"
FLOW_COOKIE_VERSION = 1
MAX_RECORD_BYTES = 4096

Purpose = Literal["sign_in", "link"]
_PURPOSES = ("sign_in", "link")


def binding_digest(binding: str) -> str:
    """SHA-256 hex of the binding secret (the only form the database holds)."""
    return hashlib.sha256(binding.encode("utf-8")).hexdigest()


def _text(value: Any, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError("shape")
    return value


def _opt_text(value: Any, limit: int) -> str | None:
    return None if value is None else _text(value, limit)


def _int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("shape")
    return value


@dataclass(frozen=True)
class FlowRecord:
    """What the callback needs to finish the ceremony this record was made for."""

    #: Provider id (``google``, ``github``, ``oidc:<slug>``, or ``entra`` for a link).
    p: str
    #: PKCE code verifier.
    cv: str
    #: OpenID Connect nonce (empty for GitHub).
    n: str
    #: ``sign_in`` or ``link``.
    pp: Purpose
    #: The authorization transaction waiting for this sign-in (local mode), if any.
    txn: str | None
    #: Where the single-page UI goes afterwards (``return_to``), if any.
    rt: str | None
    #: The sign-in forced the provider to ask again (``reauth=1``).
    rz: bool
    #: The redirect URI sent to the provider; the callback must be the one registered.
    ru: str
    #: For a link: the account key, the session epoch and the session's issue time it is bound to.
    la: str | None
    le: int | None
    li: int | None
    iat: int
    v: int = 1

    def to_json(self) -> bytes:
        raw = json.dumps(
            {
                "v": self.v,
                "p": self.p,
                "cv": self.cv,
                "n": self.n,
                "pp": self.pp,
                "txn": self.txn,
                "rt": self.rt,
                "rz": self.rz,
                "ru": self.ru,
                "la": self.la,
                "le": self.le,
                "li": self.li,
                "iat": self.iat,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        if len(raw) > MAX_RECORD_BYTES:
            raise ValueError("flow record too large")
        return raw

    @classmethod
    def from_json(cls, raw: bytes | str) -> FlowRecord:
        """Parse a stored record; raises ``ValueError`` for anything unexpected."""
        try:
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get("v") != 1:
                raise ValueError("version")
            purpose = data["pp"]
            if purpose not in _PURPOSES:
                raise ValueError("purpose")
            if not isinstance(data["rz"], bool):
                raise ValueError("shape")
            epoch = data["le"]
            issued = data["li"]
            record = cls(
                p=_text(data["p"], 64),
                cv=_text(data["cv"], 128),
                n=_text(data["n"], 128),
                pp=purpose,
                txn=_opt_text(data["txn"], 64),
                rt=_opt_text(data["rt"], 512),
                rz=data["rz"],
                ru=_text(data["ru"], 2048),
                la=_opt_text(data["la"], 64),
                le=None if epoch is None else _int(epoch),
                li=None if issued is None else _int(issued),
                iat=_int(data["iat"]),
            )
        except (KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("invalid flow record") from None
        if record.pp == "link" and (
            record.la is None or record.le is None or record.li is None
        ):
            raise ValueError("link without a session")
        return record


def new_cookie_payload(
    state: str, binding: str, provider_id: str, now: int, purpose: Purpose = "sign_in"
) -> dict[str, Any]:
    """The payload sealed into ``__Host-cmcp_flow``.

    ``purpose`` lets a callback that fails before it can pop the stored record (a cancelled
    consent, an expired state) still send a link ceremony back to the Sign-in methods screen.
    """
    return {
        "v": FLOW_COOKIE_VERSION,
        "s": state,
        "b": binding,
        "p": provider_id,
        "pp": purpose,
        "iat": now,
    }


@dataclass(frozen=True)
class FlowCookie:
    state: str
    binding: str
    provider_id: str
    iat: int
    #: What the ceremony is for; a cookie without the field (an older one) is a sign-in.
    purpose: Purpose = "sign_in"

    @classmethod
    def from_payload(cls, payload: dict[str, Any] | None) -> FlowCookie | None:
        """The cookie's content, or None unless every field is present and well-formed."""
        if payload is None or payload.get("v") != FLOW_COOKIE_VERSION:
            return None
        state, binding, provider, iat = (
            payload.get("s"),
            payload.get("b"),
            payload.get("p"),
            payload.get("iat"),
        )
        if (
            not isinstance(state, str)
            or not isinstance(binding, str)
            or not isinstance(provider, str)
            or isinstance(iat, bool)
            or not isinstance(iat, int)
            or not state
            or not binding
        ):
            return None
        purpose = payload.get("pp", "sign_in")
        if purpose not in _PURPOSES:
            return None
        return cls(state, binding, provider, iat, purpose)
