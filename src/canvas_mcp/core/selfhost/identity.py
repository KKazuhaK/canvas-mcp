"""Who may use the server: claim rules shared by the MCP path and /account.

The rules are pure functions of an already verified claims mapping. The MCP
endpoint applies them to the verified Entra access token (``token_kind='access'``,
which also checks the issuing client in ``azp``); the /account sign-in applies
them to the verified id_token (``token_kind='id'``, whose client is its ``aud``,
checked where the token is verified).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from ..credentials import RequestPrincipal

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

DenyReason = Literal["wrong_tenant", "wrong_client", "bad_subject", "missing_role", "bad_roles"]

_MESSAGES: dict[str, str] = {
    "wrong_tenant": "Your Microsoft account belongs to a different directory than this server accepts.",
    "wrong_client": "This sign-in was issued to a different application than this server accepts.",
    "bad_subject": "Your sign-in does not carry a valid account identifier.",
    "missing_role": (
        "Your Microsoft account is not allowed to use this server. "
        "Ask the server owner to add you to the access group."
    ),
    "bad_roles": "Your sign-in carries malformed role information. Sign in again.",
}


@dataclass(frozen=True)
class ClaimsPolicy:
    """What the operator configured: the tenant, the app and the two roles."""

    tenant_id: str
    client_id: str
    required_role: str
    owner_role: str


@dataclass(frozen=True)
class ClaimsDenied:
    """A refusal with a stable ``reason`` code and a safe user-facing ``message``."""

    reason: DenyReason
    message: str


def principal_key(tenant_id: str, object_id: str) -> str:
    """The stable, lower-case identity key ``entra:<tid>:<oid>``."""
    return f"entra:{tenant_id}:{object_id}".lower()


def _denied(reason: DenyReason) -> ClaimsDenied:
    return ClaimsDenied(reason=reason, message=_MESSAGES[reason])


def _same_guid(value: Any, expected: str) -> bool:
    return isinstance(value, str) and value.lower() == expected.lower()


def evaluate_entra_claims(
    claims: Mapping[str, Any],
    policy: ClaimsPolicy,
    *,
    token_kind: Literal["access", "id"],
) -> RequestPrincipal | ClaimsDenied:
    """Decide from VERIFIED claims whether the caller may use the server."""
    if not _same_guid(claims.get("tid"), policy.tenant_id):
        return _denied("wrong_tenant")
    if token_kind == "access" and not _same_guid(claims.get("azp"), policy.client_id):
        return _denied("wrong_client")
    oid = claims.get("oid")
    if not isinstance(oid, str) or not _GUID_RE.match(oid):
        return _denied("bad_subject")

    if "roles" not in claims:
        return _denied("missing_role")
    raw_roles = claims["roles"]
    if not isinstance(raw_roles, list) or not all(isinstance(r, str) for r in raw_roles):
        return _denied("bad_roles")
    roles = frozenset(raw_roles)
    if policy.required_role not in roles and policy.owner_role not in roles:
        return _denied("missing_role")

    tid = policy.tenant_id.lower()
    oid = oid.lower()
    return RequestPrincipal(
        key=principal_key(tid, oid),
        tenant_id=tid,
        object_id=oid,
        display_name=str(claims.get("name") or "")[:200],
        upn=str(claims.get("preferred_username") or claims.get("upn") or "")[:254],
        roles=roles,
        is_owner=policy.owner_role in roles,
    )


def authorize_id_token_claims(
    policy: ClaimsPolicy,
) -> Callable[[Mapping[str, Any]], tuple[RequestPrincipal | None, str]]:
    """Adapter for /account: ``(principal, '')`` or ``(None, safe message)``."""

    def authorize(claims: Mapping[str, Any]) -> tuple[RequestPrincipal | None, str]:
        result = evaluate_entra_claims(claims, policy, token_kind="id")
        if isinstance(result, ClaimsDenied):
            return None, result.message
        return result, ""

    return authorize
