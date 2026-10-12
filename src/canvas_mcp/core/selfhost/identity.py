"""Resolve verified sign-in claims and explicit identity links under the admission policy."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from . import accounts as acc
from .accounts import (
    AccessPolicy,
    Denied,
    EntraClaimsPolicy,
    ExternalClaims,
    Verdict,
)
from .token_store import (
    Actor,
    LinkResult,
    PrincipalStatus,
    Resolution,
    UnlinkResult,
)


class IdentityStore(Protocol):
    """The slice of the token store the service uses."""

    def lookup_identity(
        self, provider_id: str, issuer: str, subject: str
    ) -> str | None: ...

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
        listed_providers: Collection[str] | None = None,
        expected_revision: int | None = None,
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

    def link_identity(
        self,
        principal_key: str,
        ext: ExternalClaims,
        verdict: Verdict,
        policy: AccessPolicy,
        *,
        expected_epoch: int,
        ua_hash: str | None = None,
        expected_revision: int | None = None,
    ) -> LinkResult: ...

    def unlink_identity(
        self,
        principal_key: str,
        identity_id: str,
        *,
        actor: Actor,
        expected_epoch: int | None = None,
        listed_providers: Collection[str] | None = None,
    ) -> UnlinkResult: ...


@dataclass(frozen=True)
class SignInDenied(Denied):
    """A refused sign-in; ``account_key`` is the account it concerned, if there is one."""

    account_key: str | None = None
    #: Why the rules said no (a ``REASON_*`` of ``accounts``), when the decision recorded one.
    reason: str | None = None


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


class IdentityService:
    """Resolve verified claims to an account (or a refusal). Synchronous; run in a thread."""

    def __init__(
        self,
        store: IdentityStore,
        claims_policy: EntraClaimsPolicy,
        access_policy: AccessPolicy,
        *,
        login_providers: Collection[str] | None = None,
        expected_revision: int | None = None,
    ) -> None:
        # The providers of SELFHOST_LOGIN_PROVIDERS decide which owners are usable (None: every
        # provider is listed, which is only right for tests and the Entra-only default).
        self.login_providers: frozenset[str] | None = (
            None if login_providers is None else frozenset(login_providers)
        )
        self._store = store
        self.claims_policy = claims_policy
        self.access_policy = access_policy
        self.expected_revision = expected_revision

    # -- the MCP path ----------------------------------------------------------------

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
        ext = acc.entra_external_claims(
            claims,
            self.claims_policy,
            parse_groups=self.access_policy.has_group_rule(),
        )
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
        return self.sign_in_external(ext, ip=ip, ua_hash=ua_hash)

    def sign_in_external(
        self,
        ext: ExternalClaims,
        *,
        ip: str = "unknown",
        ua_hash: str | None = None,
    ) -> SignIn | Denied:
        """Decide a ``/account`` sign-in from claims a provider ceremony already verified.

        Entra's id token goes through :meth:`sign_in`, which reduces it first; every other
        provider reduces its own tokens in its ceremony and calls this directly. The
        admission rules are evaluated for the identity used, the store decides and applies
        the result, and the outcome is written to the sign-in history in the same
        transaction. A refusal for a provider other than Entra carries a message that does
        not name Microsoft.
        """
        verdict = acc.evaluate_admission(ext, self.access_policy)
        resolution = self._store.resolve_identity(
            ext,
            verdict,
            self.access_policy,
            purpose="sign_in",
            ip=ip,
            ua_hash=ua_hash,
            listed_providers=self.login_providers,
            expected_revision=self.expected_revision,
        )
        key = resolution.principal_key
        if resolution.outcome == "deny" or resolution.status is None:
            assert resolution.denied is not None
            message = resolution.denied.message
            if (
                ext.provider_id != acc.PROVIDER_ENTRA
                and resolution.denied.code == acc.DENY_ACCESS_DENIED
            ):
                message = acc.NEUTRAL_ACCESS_DENIED
            return SignInDenied(
                resolution.denied.code,
                message,
                account_key=key,
                reason=resolution.reason,
            )
        return SignIn(
            status=resolution.status,
            ext=ext,
            owner=resolution.session_owner,
            pending=resolution.outcome == "pending",
        )

    # -- linking (from /account, by a signed-in person) ------------------------------------------

    def link(
        self,
        account_key: str,
        ext: ExternalClaims,
        *,
        expected_epoch: int,
        ua_hash: str | None = None,
    ) -> LinkResult:
        """Attach the verified identity ``ext`` to ``account_key`` (see ``TokenStore.link_identity``)."""
        verdict = acc.evaluate_admission(ext, self.access_policy)
        result = self._store.link_identity(
            account_key,
            ext,
            verdict,
            self.access_policy,
            expected_epoch=expected_epoch,
            ua_hash=ua_hash,
            expected_revision=self.expected_revision,
        )
        return result

    def unlink(
        self,
        account_key: str,
        identity_id: str,
        *,
        actor: Actor,
        expected_epoch: int | None = None,
    ) -> UnlinkResult:
        """Remove an identity from an account."""
        result = self._store.unlink_identity(
            account_key,
            identity_id,
            actor=actor,
            expected_epoch=expected_epoch,
            listed_providers=self.login_providers,
        )
        return result
