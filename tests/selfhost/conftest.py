"""Shared helpers for the self-hosted mode tests."""

import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from canvas_mcp.core.credentials import (
    RequestPrincipal,
    clear_http_request_context,
    set_request_principal,
)
from canvas_mcp.core.selfhost.accounts import (
    EntraClaimsPolicy,
    ExternalClaims,
    Verdict,
    default_policy,
    entra_issuer,
)
from canvas_mcp.core.selfhost.identity import IdentityService
from canvas_mcp.core.selfhost.token_store import PrincipalStatus

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID_A = "aaaaaaaa-0000-4000-8000-00000000000a"
OID_B = "bbbbbbbb-0000-4000-8000-00000000000b"

_NAMESPACE = uuid.UUID("5f0c1c1e-1b1e-4c1e-9c1e-0123456789ab")


def acct_key(oid: str, *, tenant: str = TENANT) -> str:
    """The stable account key the tests use for an Entra identity.

    Derived from the tenant and object id, so a principal built without a database
    and an account created in a store agree on the key.
    """
    return f"acct:{uuid.uuid5(_NAMESPACE, f'{tenant}:{oid}'.lower())}"


def make_principal(oid: str, *, tenant: str = TENANT, owner: bool = False) -> RequestPrincipal:
    key = acct_key(oid, tenant=tenant)
    return RequestPrincipal(
        key=key,
        tenant_id=tenant,
        object_id=oid.lower(),
        display_name="",
        upn="",
        roles=frozenset({"Canvas.Owner" if owner else "Canvas.User"}),
        is_owner=owner,
        provider_id="entra",
        issuer=entra_issuer(tenant),
        subject=oid.lower(),
        account_id=key.removeprefix("acct:"),
    )


def make_account(
    store: Any,
    oid: str,
    *,
    tenant: str = TENANT,
    status: str = "active",
    role: str = "user",
    name: str = "",
    username: str = "",
    reason: str | None = None,
) -> str:
    """Create (or find) the account of an Entra identity and return its key.

    A disabled account needs a reason; the operator's is used unless one is given.
    """
    if status == "disabled" and reason is None:
        reason = "operator_disabled"
    return str(
        store.create_operator_account(
            provider_id="entra",
            issuer=entra_issuer(tenant),
            subject=oid.lower(),
            display_name=name,
            username=username,
            status=status,
            role=role,
            reason=reason,
            account_id=acct_key(oid, tenant=tenant).removeprefix("acct:"),
        )
    )


def ensure_account(
    store: Any, key: str, *, status: str = "active", role: str = "user", reason: str | None = None
) -> str:
    """Create the account behind a given account key (its identity is made up) and return the key."""
    account_id = key.removeprefix("acct:")
    if status == "disabled" and reason is None:
        reason = "operator_disabled"
    return str(
        store.create_operator_account(
            provider_id="entra",
            issuer=entra_issuer(TENANT),
            subject=account_id,
            status=status,
            role=role,
            reason=reason,
            account_id=account_id,
        )
    )


def store_put(
    store: Any,
    *,
    tenant_id: str = TENANT,
    object_id: str,
    entra_display_name: str = "",
    entra_upn: str = "",
    **put_kwargs: Any,
) -> Any:
    """Save a token the way the pre-account store did: name the person by tenant and object id.

    Creates the person's account first (the store only enrolls an active account), with
    the display and sign-in names the old call carried, then saves the token under it.
    """
    key = make_account(
        store, object_id, tenant=tenant_id, name=entra_display_name, username=entra_upn
    )
    return store.put(principal_key=key, **put_kwargs)


#: The admission policy of the first release: the Entra app roles, nothing else.
POLICY = default_policy("Canvas.User", "Canvas.Owner")


def external(
    oid: str,
    *,
    tenant: str = TENANT,
    name: str = "",
    username: str = "",
    roles: tuple[str, ...] = ("Canvas.User",),
) -> ExternalClaims:
    """The external identity a verified Entra token for ``oid`` reduces to."""
    return ExternalClaims(
        provider_id="entra",
        issuer=entra_issuer(tenant),
        subject=oid.lower(),
        display_name=name,
        username=username,
        roles=frozenset(roles),
        tenant_id=tenant,
    )


def sign_in(
    store: Any,
    oid: str,
    *,
    owner: bool = False,
    member: bool = True,
    policy: Any = POLICY,
    purpose: str = "sign_in",
    tenant: str = TENANT,
    name: str = "",
    ip: str = "unknown",
    ua_hash: str | None = None,
) -> Any:
    """Run the store's identity resolution as a verified sign-in of ``oid`` would.

    ``member`` says a rule admits the identity, ``owner`` that an owner rule matches it.
    """
    roles = tuple(r for r, on in (("Canvas.User", member), ("Canvas.Owner", owner)) if on)
    ext = external(oid, tenant=tenant, name=name, roles=roles)
    verdict = Verdict(admitted_by_rule=member or owner, owner_by_rule=owner)
    # A new account gets the same key as make_account / make_principal would give it.
    store._new_account_id = lambda e: acct_key(e.subject, tenant=tenant).removeprefix("acct:")
    return store.resolve_identity(ext, verdict, policy, purpose=purpose, ip=ip, ua_hash=ua_hash)


def identity_service(store: Any, *, access: Any = None, policy: Any = POLICY) -> IdentityService:
    """The identity service the server builds, over ``store`` (real or a fake with the same methods)."""
    return IdentityService(store, EntraClaimsPolicy(TENANT, CLIENT), policy, access=access)


class FakeAccounts:
    """Stands in for the account side of the store: every Entra identity of the test tenant
    has an active account whose key is :func:`acct_key` of its object id."""

    def __init__(self) -> None:
        self.lookups: list[tuple[str, str, str]] = []

    def lookup_identity(self, provider_id: str, issuer: str, subject: str) -> str | None:
        self.lookups.append((provider_id, issuer, subject))
        if provider_id != "entra" or issuer != entra_issuer(TENANT):
            return None
        return acct_key(subject)

    def get_principal_status(self, principal_key: str) -> PrincipalStatus:
        return PrincipalStatus(principal_key, stored=True)

    def resolve_identity(self, *_a: Any, **_k: Any) -> Any:  # pragma: no cover - not reached
        raise AssertionError("the fake has an account for everyone")

    def record_auth_event(self, **_k: Any) -> None:  # pragma: no cover - not reached
        raise AssertionError("not used on the request path")


@pytest.fixture(autouse=True)
def clean_request_context() -> Iterator[None]:
    """No test may leave request identity behind for the next one."""
    clear_http_request_context()
    yield
    clear_http_request_context()


@pytest.fixture
def as_principal() -> Iterator[object]:
    """Call ``as_principal(oid)`` to act as that principal for the rest of the test."""

    def activate(oid: str) -> RequestPrincipal:
        principal = make_principal(oid)
        set_request_principal(principal)
        return principal

    yield activate
