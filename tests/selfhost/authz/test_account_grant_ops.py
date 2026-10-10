"""The operations behind a connected-apps page, on the account application (no UI yet)."""

from __future__ import annotations

import pytest
from dbbackend import raw_sql

from canvas_mcp.core.selfhost.account_ops import Refusal
from canvas_mcp.core.selfhost.account_web import (
    AccountConfig,
    _Session,
    build_account_app,
)
from canvas_mcp.core.selfhost.db.errors import StoreUnavailable
from canvas_mcp.core.selfhost.schools import SchoolPolicy
from canvas_mcp.core.selfhost.token_store import OPERATOR

from .stack import ALICE, BOB, OWNER, Stack, local_stack


def make_app(stack: Stack, *, with_authz: bool = True):  # type: ignore[no-untyped-def]
    cfg = AccountConfig(
        public_base_url="https://canvas.example.test", tenant_id=stack.settings.tenant_id,
        client_id=stack.settings.client_id, client_secret="x" * 20, session_secret=bytes(range(32)),
        schools=SchoolPolicy.pinned("https://canvas.example.edu/api/v1"),
    )
    return build_account_app(
        cfg, stack.store, stack.runtime.identity, access=stack.runtime.access, clock=stack.clock,
        authz=stack.authz if with_authz else None,
    )


def session(key: str, *, owner: bool = False, iat: float | None = None, clock=None) -> _Session:  # type: ignore[no-untyped-def]
    issued = int((clock or (lambda: 0))() if iat is None else iat)
    return _Session(key, "Name", "n@example.test", owner, "csrf-token", issued + 900, issued, 0, "entra", False)


@pytest.fixture
def stack(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    with local_stack(tmp_path, monkeypatch) as running:
        yield running


async def test_a_user_lists_and_ends_their_own_connections(stack: Stack) -> None:
    alice = stack.enroll(ALICE)
    bob = stack.enroll(BOB)
    stack.tokens_for(ALICE)
    stack.tokens_for(BOB)
    app = make_app(stack)
    mine = await app.list_own_grants(session(alice, clock=stack.clock))
    assert not isinstance(mine, Refusal) and len(mine) == 1 and mine[0].account_key == alice
    grant_id = mine[0].id
    foreign = await app.list_own_grants(session(bob, clock=stack.clock))
    assert not isinstance(foreign, Refusal)
    assert await app.revoke_own_grant(session(bob, clock=stack.clock), grant_id) is False  # not Bob's
    assert await app.revoke_own_grant(session(alice, clock=stack.clock), grant_id) is True
    assert await app.revoke_own_grant(session(alice, clock=stack.clock), grant_id) is False
    assert await app.list_own_grants(session(alice, clock=stack.clock)) == []


async def test_without_the_local_server_the_operations_answer_not_found(stack: Stack) -> None:
    app = make_app(stack, with_authz=False)
    s = session(stack.enroll(ALICE), clock=stack.clock)
    for outcome in (
        await app.list_own_grants(s),
        await app.revoke_own_grant(s, "g"),
        await app.list_account_grants(s, "acct:x"),
        await app.owner_revoke_grant(s, "g"),
    ):
        assert outcome == Refusal("not_found")


async def test_a_database_error_is_a_closed_refusal(stack: Stack, monkeypatch) -> None:
    alice = stack.enroll(ALICE)
    app = make_app(stack)

    def failing(*a, **k):  # type: ignore[no-untyped-def]
        raise StoreUnavailable(kind="OperationalError")

    monkeypatch.setattr(stack.authz.store, "list_grants", failing)
    monkeypatch.setattr(stack.authz.store, "revoke_own_grant", failing)
    s = session(alice, clock=stack.clock)
    assert await app.list_own_grants(s) == Refusal("token_store_unavailable")
    assert await app.revoke_own_grant(s, "g") == Refusal("token_store_unavailable")


async def test_owner_operations_need_an_owner_who_signed_in_recently(stack: Stack) -> None:
    alice = stack.enroll(ALICE)
    owner = stack.enroll(OWNER)
    stack.tokens_for(ALICE)
    grant_id = (await make_app(stack).list_own_grants(session(alice, clock=stack.clock)))[0].id  # type: ignore[index]
    app = make_app(stack)
    plain = session(alice, clock=stack.clock)
    assert await app.owner_revoke_grant(plain, grant_id) == Refusal("forbidden")
    assert await app.list_account_grants(plain, alice) == Refusal("forbidden")
    stale = session(owner, owner=True, iat=stack.clock() - 3600)
    assert await app.owner_revoke_grant(stale, grant_id) == Refusal("reauth_required")
    assert await app.list_account_grants(stale, alice) == Refusal("reauth_required")
    fresh = session(owner, owner=True, clock=stack.clock)
    listed = await app.list_account_grants(fresh, alice)
    assert not isinstance(listed, Refusal) and [g.id for g in listed] == [grant_id]
    assert await app.owner_revoke_grant(fresh, grant_id) is True
    assert raw_sql(stack.store, "SELECT revoked_reason FROM oauth_grants")[0][0] == "owner_revoked"


async def test_an_owner_who_lost_the_role_meanwhile_is_refused_by_the_store(stack: Stack) -> None:
    alice = stack.enroll(ALICE)
    owner = stack.enroll(OWNER)
    stack.tokens_for(ALICE)
    app = make_app(stack)
    grant_id = (await app.list_own_grants(session(alice, clock=stack.clock)))[0].id  # type: ignore[index]
    raw_sql(stack.store, "UPDATE accounts SET role = 'user' WHERE id = :i", {"i": owner.removeprefix("acct:")})
    outcome = await app.owner_revoke_grant(session(owner, owner=True, clock=stack.clock), grant_id)
    assert outcome == Refusal("forbidden")
    assert raw_sql(stack.store, "SELECT revoked_at FROM oauth_grants")[0][0] is None


async def test_an_access_change_made_on_the_account_pages_clears_the_grant_cache(stack: Stack) -> None:
    alice = stack.enroll(ALICE)
    _, tokens = stack.tokens_for(ALICE)
    assert stack.mcp_status(tokens["access_token"]) == 200  # now cached
    stack.store.disable_principal(alice, actor=OPERATOR, reason="operator_disabled")
    make_app(stack)._access_changed(alice)
    assert stack.mcp_status(tokens["access_token"]) == 401
