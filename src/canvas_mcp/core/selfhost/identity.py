"""Who may use the server: the one place the MCP path and /account turn claims into an account.

Both entrances use :class:`IdentityService`:

* the MCP endpoint hands it the claims of the verified Entra *access* token
  (:meth:`IdentityService.resolve_request`), which also checks the issuing client in
  ``azp``;
* the ``/account`` sign-in hands it the claims of the verified *id* token
  (:meth:`IdentityService.sign_in`), whose client is its ``aud``, checked where the
  token is verified.

Each reduces the claims to an external identity ``(provider, issuer, subject)`` (for
Entra: the tenant's issuer URL and the ``oid``), matches it against the configured
rules, looks the identity up and lets the store decide and apply the result in one
transaction (:meth:`TokenStore.resolve_identity`). The pure rules live in
:mod:`.accounts`. For an account that already exists the MCP path only reads: it
writes when it creates an account the first time the identity is seen, or activates a
pending one.

``evaluate_entra_claims`` is the first release's rule, rebuilt on the pure functions;
it is kept as the oracle that the default policy admits exactly the same people.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from ..credentials import RequestPrincipal
from . import accounts as acc
from .accounts import (
    AccessPolicy,
    Denied,
    EntraClaimsPolicy,
    ExternalClaims,
    Verdict,
)
from .token_store import PrincipalStatus, Resolution

DenyReason = Literal["wrong_tenant", "wrong_client", "bad_subject", "missing_role", "bad_roles"]

#: How long a known identity -> account mapping is reused. A mapping never changes
#: (identities are not unlinked or moved in this release) and the account's own status
#: is read separately, so a stale entry cannot widen access.
IDENTITY_CACHE_SECONDS = 300.0
_MAX_CACHED_IDENTITIES = 4096


class IdentityStore(Protocol):
    """The slice of the token store the service uses."""

    def lookup_identity(self, provider_id: str, issuer: str, subject: str) -> str | None: ...

    def get_principal_status(self, principal_key: str) -> PrincipalStatus: ...

    def resolve_identity(
        self,
        ext: ExternalClaims,
        verdict: Verdict,
        policy: AccessPolicy,
        *,
        purpose: acc.Purpose,
        ip: str = "unknown",
        ua_hash: str | None = None,
    ) -> Resolution: ...

    def record_auth_event(
        self,
        *,
        account_key: str | None,
        provider_id: str,
        surface: str,
        outcome: str,
        reason: str,
        ip: str = "unknown",
        ua_hash: str | None = None,
    ) -> None: ...


class StatusSource(Protocol):
    """Where the service reads an existing account's status (the access cache, or the store)."""

    def status(self, principal_key: str) -> PrincipalStatus: ...


class IdentityCache:
    """``(provider, issuer, subject)`` -> account key, with a TTL and a size bound.

    Misses are never cached, so an identity that signs in for the first time is
    found at once. Thread-safe.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = IDENTITY_CACHE_SECONDS,
        max_entries: int = _MAX_CACHED_IDENTITIES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[tuple[str, str, str], tuple[float, str]] = OrderedDict()

    def get(self, identity: tuple[str, str, str]) -> str | None:
        now = self._clock()
        with self._lock:
            entry = self._entries.get(identity)
            if entry is None:
                return None
            if entry[0] <= now:
                del self._entries[identity]
                return None
            return entry[1]

    def put(self, identity: tuple[str, str, str], account_key: str) -> None:
        with self._lock:
            self._entries[identity] = (self._clock() + self._ttl, account_key)
            self._entries.move_to_end(identity)
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


@dataclass(frozen=True)
class SignInDenied(Denied):
    """A refused sign-in; ``account_key`` is the account it concerned, if there is one."""

    account_key: str | None = None


@dataclass(frozen=True)
class SignIn:
    """A successful ``/account`` sign-in (possibly of a pending account)."""

    status: PrincipalStatus
    ext: ExternalClaims
    #: The owner role as this sign-in shows it: the stored role, and for a role the
    #: rules granted, a match in this very sign-in. Admin pages need this.
    owner: bool
    #: Waiting for approval: the account page only, no token, no MCP.
    pending: bool

    @property
    def principal_key(self) -> str:
        return self.status.principal_key


def request_principal(
    ext: ExternalClaims, verdict: Verdict, account_key: str
) -> RequestPrincipal:
    """The request context for an admitted account (Entra: tenant and object id stay for the gate)."""
    return RequestPrincipal(
        key=account_key,
        tenant_id=ext.tenant_id,
        object_id=ext.subject,
        display_name=ext.display_name,
        upn=ext.username,
        roles=ext.roles,
        is_owner=verdict.owner_by_rule,
        provider_id=ext.provider_id,
        issuer=ext.issuer,
        subject=ext.subject,
        account_id=acc.account_id_of(account_key),
    )


class IdentityService:
    """Resolve verified claims to an account (or a refusal). Synchronous; run in a thread."""

    def __init__(
        self,
        store: IdentityStore,
        claims_policy: EntraClaimsPolicy,
        access_policy: AccessPolicy,
        *,
        access: StatusSource | None = None,
        cache: IdentityCache | None = None,
    ) -> None:
        self._store = store
        self.claims_policy = claims_policy
        self.access_policy = access_policy
        self._access = access
        self.cache = cache or IdentityCache()

    # -- the MCP path ----------------------------------------------------------------

    def resolve_request(self, claims: Mapping[str, Any]) -> RequestPrincipal | Denied:
        """The account behind a verified Entra access token, or why not.

        Existing accounts take a read-only path (identity cache or one indexed lookup,
        then the access cache). A first sight of the identity, or a pending account a
        rule now admits, goes through the store's single write transaction. A database
        error propagates: the caller must fail closed.
        """
        ext = acc.entra_external_claims(claims, self.claims_policy, token_kind="access")
        if isinstance(ext, Denied):
            return ext
        verdict = acc.evaluate_admission(ext, self.access_policy)
        key = self.cache.get(ext.identity)
        if key is None:
            key = self._store.lookup_identity(*ext.identity)
            if key is not None:
                self.cache.put(ext.identity, key)
        bootstrap = acc.is_bootstrap_identity(ext, self.access_policy)
        if key is None and not bootstrap:
            # An identity nobody has seen that no rule admits: refuse without taking the
            # writer lock. (The counts are irrelevant for a refusal; a creation is decided
            # again with the real counts inside the transaction.)
            first = acc.decide(None, verdict, self.access_policy, acc.DecisionFacts(), "request")
            if not first.create and first.denied is not None:
                return first.denied
        if key is not None and not bootstrap:
            status = self._status(key)
            if not status.missing:
                decision = acc.decide(
                    status.facts,
                    verdict,
                    self.access_policy,
                    acc.DecisionFacts(active_owner_count=1),
                    "request",
                )
                if not decision.writes:
                    if decision.outcome == "allow":
                        return request_principal(ext, verdict, key)
                    assert decision.denied is not None
                    return decision.denied
        return self._resolve_with_write(ext, verdict, purpose="request")

    def _status(self, key: str) -> PrincipalStatus:
        if self._access is not None:
            return self._access.status(key)
        return self._store.get_principal_status(key)

    def _resolve_with_write(
        self, ext: ExternalClaims, verdict: Verdict, *, purpose: acc.Purpose
    ) -> RequestPrincipal | Denied:
        resolution = self._store.resolve_identity(
            ext, verdict, self.access_policy, purpose=purpose
        )
        key = resolution.principal_key
        if key is not None:
            self.cache.put(ext.identity, key)
        if resolution.allowed and key is not None:
            return request_principal(ext, verdict, key)
        assert resolution.denied is not None
        return resolution.denied

    # -- the /account sign-in ----------------------------------------------------------

    def sign_in(
        self,
        claims: Mapping[str, Any],
        *,
        ip: str = "unknown",
        ua_hash: str | None = None,
    ) -> SignIn | Denied:
        """Decide a ``/account`` sign-in from the verified id token's claims.

        Every outcome is written to the sign-in history in the same transaction as the
        decision. A pending account signs in (the page shows that it waits for approval);
        a disabled one, or one the rules do not admit, is refused.
        """
        ext = acc.entra_external_claims(claims, self.claims_policy, token_kind="id")
        if isinstance(ext, Denied):
            self._store.record_auth_event(
                account_key=None,
                provider_id=acc.PROVIDER_ENTRA,
                surface=acc.SURFACE_ACCOUNT,
                outcome=acc.OUTCOME_DENIED,
                reason=ext.code,
                ip=ip,
                ua_hash=ua_hash,
            )
            return ext
        verdict = acc.evaluate_admission(ext, self.access_policy)
        resolution = self._store.resolve_identity(
            ext, verdict, self.access_policy, purpose="sign_in", ip=ip, ua_hash=ua_hash
        )
        key = resolution.principal_key
        if key is not None:
            self.cache.put(ext.identity, key)
        if resolution.outcome == "deny" or resolution.status is None:
            assert resolution.denied is not None
            return SignInDenied(
                resolution.denied.code, resolution.denied.message, account_key=key
            )
        return SignIn(
            status=resolution.status,
            ext=ext,
            owner=resolution.session_owner,
            pending=resolution.outcome == "pending",
        )


# -- the first release's rule, kept as the oracle -------------------------------------

_LEGACY_MESSAGES: dict[str, str] = {
    "wrong_tenant": acc.DENIAL_MESSAGES[acc.DENY_WRONG_TENANT],
    "wrong_client": acc.DENIAL_MESSAGES[acc.DENY_WRONG_CLIENT],
    "bad_subject": acc.DENIAL_MESSAGES[acc.DENY_BAD_SUBJECT],
    "missing_role": acc.DENIAL_MESSAGES[acc.DENY_ACCESS_DENIED],
    "bad_roles": acc.DENIAL_MESSAGES[acc.DENY_BAD_ROLES],
}


_LEGACY_CODES: dict[str, DenyReason] = {
    acc.DENY_WRONG_TENANT: "wrong_tenant",
    acc.DENY_WRONG_CLIENT: "wrong_client",
    acc.DENY_BAD_SUBJECT: "bad_subject",
    acc.DENY_BAD_ROLES: "bad_roles",
}


@dataclass(frozen=True)
class ClaimsPolicy:
    """What the first release configured: the tenant, the app and the two roles."""

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
    """The legacy identity key ``entra:<tid>:<oid>`` (audit lines before the account model)."""
    return f"entra:{tenant_id}:{object_id}".lower()


def _legacy_denied(reason: DenyReason) -> ClaimsDenied:
    return ClaimsDenied(reason=reason, message=_LEGACY_MESSAGES[reason])


def evaluate_entra_claims(
    claims: Mapping[str, Any],
    policy: ClaimsPolicy,
    *,
    token_kind: Literal["access", "id"],
) -> RequestPrincipal | ClaimsDenied:
    """The first release's decision, built on the pure functions of :mod:`.accounts`.

    Admits the holders of ``required_role`` or ``owner_role``; the group claims, which the
    first release did not read, are ignored. Its principal carries the legacy
    ``entra:<tid>:<oid>`` key: the production paths use :class:`IdentityService` instead.
    """
    trimmed = {
        k: v for k, v in claims.items() if k not in ("groups", "_claim_names", "hasgroups")
    }
    ext = acc.entra_external_claims(
        trimmed, EntraClaimsPolicy(policy.tenant_id, policy.client_id), token_kind=token_kind
    )
    if isinstance(ext, Denied):
        return _legacy_denied(_LEGACY_CODES.get(ext.code, "bad_roles"))
    if "roles" not in trimmed:
        return _legacy_denied("missing_role")
    verdict = acc.evaluate_admission(ext, acc.default_policy(policy.required_role, policy.owner_role))
    if not verdict.admitted_by_rule and not verdict.owner_by_rule:
        return _legacy_denied("missing_role")
    return RequestPrincipal(
        key=principal_key(ext.tenant_id, ext.subject),
        tenant_id=ext.tenant_id,
        object_id=ext.subject,
        display_name=ext.display_name,
        upn=ext.username,
        roles=ext.roles,
        is_owner=verdict.owner_by_rule,
    )


def authorize_id_token_claims(
    policy: ClaimsPolicy,
) -> Callable[[Mapping[str, Any]], tuple[RequestPrincipal | None, str]]:
    """Adapter of the first release's ``/account`` check: ``(principal, '')`` or ``(None, message)``.

    No longer used by the server (``/account`` calls :meth:`IdentityService.sign_in`);
    kept with :func:`evaluate_entra_claims` as the reference the default policy is
    tested against.
    """

    def authorize(claims: Mapping[str, Any]) -> tuple[RequestPrincipal | None, str]:
        result = evaluate_entra_claims(claims, policy, token_kind="id")
        if isinstance(result, ClaimsDenied):
            return None, result.message
        return result, ""

    return authorize
