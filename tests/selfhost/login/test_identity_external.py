"""IdentityService with identities from providers other than Entra."""

from __future__ import annotations

import base64
import pathlib

import pytest
from dbbackend import make_store

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.accounts import (
    AccessPolicy,
    AccessRule,
    Denied,
    EntraClaimsPolicy,
    ExternalClaims,
)
from canvas_mcp.core.selfhost.identity import IdentityCache, IdentityService, SignIn
from canvas_mcp.core.selfhost.token_store import OPERATOR, Keyring, TokenStore

from ..conftest import CLIENT, OID_A, TENANT, make_account

GOOGLE_POLICY = AccessPolicy(
    mode="rules",
    rules=(AccessRule("google", "domain", "example.edu"), AccessRule("github", "org", "acme")),
    owner_rules=(AccessRule("entra", "role", "Canvas.Owner"),),
)


def google(subject: str = "g-1", **kw: object) -> ExternalClaims:
    base: dict[str, object] = {
        "provider_id": "google", "issuer": acc.GOOGLE_ISSUER, "subject": subject,
        "display_name": "Gia", "username": "gia@example.edu", "email": "gia@example.edu",
        "email_verified": True, "hd": "example.edu",
    }
    base.update(kw)
    return ExternalClaims(**base)  # type: ignore[arg-type]


def github(**kw: object) -> ExternalClaims:
    base: dict[str, object] = {
        "provider_id": "github", "issuer": acc.GITHUB_ISSUER, "subject": "583231",
        "display_name": "Octo", "username": "octocat",
    }
    base.update(kw)
    return ExternalClaims(**base)  # type: ignore[arg-type]


@pytest.fixture
def store(tmp_path: pathlib.Path) -> TokenStore:
    made = make_store(
        tmp_path / "tokens.sqlite3", Keyring.parse("k1:" + base64.b64encode(bytes([3]) * 32).decode())
    )
    made.initialize()
    return made


@pytest.fixture
def service(store: TokenStore) -> IdentityService:
    return IdentityService(store, EntraClaimsPolicy(TENANT, CLIENT), GOOGLE_POLICY)


def test_a_google_sign_in_creates_an_account_and_keeps_the_email(
    service: IdentityService, store: TokenStore
) -> None:
    outcome = service.sign_in_external(google())
    assert isinstance(outcome, SignIn) and not outcome.pending and not outcome.owner
    identity = store.list_identities(outcome.principal_key)[0]
    assert (identity.provider_id, identity.subject, identity.email) == ("google", "g-1", "gia@example.edu")
    event = store.list_auth_events(outcome.principal_key)[0]
    assert (event.provider_id, event.outcome, event.reason) == ("google", "success", "account_created")
    assert service.cache.get(("google", acc.GOOGLE_ISSUER, "g-1")) == outcome.principal_key


def test_a_second_sign_in_reaches_the_same_account(service: IdentityService, store: TokenStore) -> None:
    first = service.sign_in_external(google())
    second = service.sign_in_external(google())
    assert isinstance(first, SignIn) and isinstance(second, SignIn)
    assert first.principal_key == second.principal_key and len(store.list_principal_statuses()) == 1


def test_a_refusal_of_a_non_entra_provider_does_not_name_microsoft(service: IdentityService) -> None:
    outcome = service.sign_in_external(google("g-2", hd="other.edu"))
    assert isinstance(outcome, Denied) and outcome.code == acc.DENY_ACCESS_DENIED
    assert outcome.message == acc.NEUTRAL_ACCESS_DENIED and "Microsoft" not in outcome.message


def test_an_entra_refusal_keeps_its_message(store: TokenStore) -> None:
    service = IdentityService(store, EntraClaimsPolicy(TENANT, CLIENT), acc.default_policy("Canvas.User", "Canvas.Owner"))
    outcome = service.sign_in(
        {"tid": TENANT, "oid": OID_A, "roles": [], "name": "n", "preferred_username": "u@x.test"}
    )
    assert isinstance(outcome, Denied)
    assert outcome.message == acc.DENIAL_MESSAGES[acc.DENY_ACCESS_DENIED]


def test_unavailable_membership_is_a_denial_with_its_own_reason(
    service: IdentityService, store: TokenStore
) -> None:
    outcome = service.sign_in_external(github(membership_unavailable=True))
    assert isinstance(outcome, Denied) and outcome.code == acc.DENY_ACCESS_DENIED
    assert store.list_principal_statuses() == []


def test_a_github_org_member_is_admitted_and_a_non_member_is_not(service: IdentityService) -> None:
    assert isinstance(service.sign_in_external(github(orgs=frozenset({"acme"}))), SignIn)
    assert isinstance(service.sign_in_external(github(subject="2", orgs=frozenset())), Denied)


def test_link_attaches_the_identity_and_sign_in_then_finds_the_account(
    service: IdentityService, store: TokenStore
) -> None:
    key = make_account(store, OID_A)
    epoch = store.get_principal_status(key).session_epoch
    result = service.link(key, google("g-9"), expected_epoch=epoch)
    assert result.code == "linked"
    outcome = service.sign_in_external(google("g-9"))
    assert isinstance(outcome, SignIn) and outcome.principal_key == key


def test_link_refusals_do_not_populate_the_cache(service: IdentityService, store: TokenStore) -> None:
    key = make_account(store, OID_A)
    result = service.link(key, google("g-9", hd="other.edu"), expected_epoch=store.get_principal_status(key).session_epoch)
    # make_account is a personal (operator) admission, so the rules do not apply to it.
    assert result.code == "linked"
    other = make_account(store, "bbbbbbbb-0000-4000-8000-00000000000b")
    taken = service.link(other, google("g-9", hd="other.edu"), expected_epoch=store.get_principal_status(other).session_epoch)
    assert taken.code == "identity_in_use"
    assert service.cache.get(("google", acc.GOOGLE_ISSUER, "g-9")) == key


def test_unlink_forgets_the_cached_mapping(service: IdentityService, store: TokenStore) -> None:
    key = make_account(store, OID_A)
    assert service.link(key, google("g-9"), expected_epoch=store.get_principal_status(key).session_epoch).ok
    assert service.cache.get(("google", acc.GOOGLE_ISSUER, "g-9")) == key
    identity_id = store.list_identities(key)[1].id
    assert service.unlink(key, identity_id, actor=OPERATOR).ok
    assert service.cache.get(("google", acc.GOOGLE_ISSUER, "g-9")) is None


def test_the_cache_discard_is_safe_for_an_unknown_key() -> None:
    cache = IdentityCache()
    cache.put(("a", "b", "c"), "acct:x")
    cache.discard(("a", "b", "c"))
    cache.discard(("a", "b", "c"))
    assert len(cache) == 0
