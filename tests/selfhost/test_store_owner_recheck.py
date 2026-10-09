"""Removing or invalidating someone's token re-checks the acting owner inside the transaction.

Disabling, enabling, approving and denying always did. Removing an enrollment and
marking it invalid now do too, for every account actor; the operator CLI needs no
identity. Runs on whichever backend the run selects.
"""

from __future__ import annotations

import base64
import pathlib

import pytest
from dbbackend import make_store

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.token_store import (
    OPERATOR,
    AccessActionRefused,
    Keyring,
    TokenStore,
)

from .conftest import acct_key, make_account

OID_OWNER = "aaaaaaaa-0000-4000-8000-0000000000a1"
OID_OTHER_OWNER = "aaaaaaaa-0000-4000-8000-0000000000a2"
OID_USER = "bbbbbbbb-0000-4000-8000-0000000000b1"
OID_TARGET = "cccccccc-0000-4000-8000-0000000000c1"
TOKEN = "7~" + "T" * 62


@pytest.fixture
def store(tmp_path: pathlib.Path) -> TokenStore:
    keyring = Keyring.parse("k1:" + base64.b64encode(b"\x01" * 32).decode())
    store = make_store(tmp_path / "tokens.sqlite3", keyring, clock=lambda: 1_800_000_000)
    store.initialize()
    return store


def target(store: TokenStore) -> str:
    key = make_account(store, OID_TARGET, name="Target")
    store.put(principal_key=key, api_token=TOKEN, canvas_user_id="9", canvas_user_name="Target")
    return key


def audit_actions(store: TokenStore) -> list[str]:
    return [e.action for e in store.list_audit(100)]


class TestDelete:
    def test_an_active_owner_may(self, store: TokenStore) -> None:
        owner = make_account(store, OID_OWNER, role="owner")
        key = target(store)
        assert store.delete(key, actor=owner) is True
        assert store.info(key) is None
        e = next(e for e in store.list_audit(10) if e.action == "token_deleted")
        assert e.actor == owner and e.target == key

    def test_the_operator_and_the_account_itself_need_no_owner(self, store: TokenStore) -> None:
        key = target(store)
        assert store.delete(key, actor=OPERATOR) is True
        key = target(store)
        assert store.delete(key) is True  # a self-disconnect: no actor

    @pytest.mark.parametrize("who", ["user", "disabled_owner", "pending_owner", "unknown", "self"])
    def test_anyone_else_is_refused_and_nothing_changes(self, store: TokenStore, who: str) -> None:
        key = target(store)
        actor = {
            "user": lambda: make_account(store, OID_USER),
            "disabled_owner": lambda: make_account(
                store, OID_OWNER, role="owner", status="disabled"
            ),
            "pending_owner": lambda: make_account(
                store, OID_OWNER, role="owner", status="pending"
            ),
            "unknown": lambda: acct_key("dddddddd-0000-4000-8000-0000000000d1"),
            "self": lambda: key,
        }[who]()
        before = store.list_audit(100)
        generation = store.credential_generation(key)
        with pytest.raises(AccessActionRefused) as info:
            store.delete(key, actor=actor)
        assert info.value.code == AccessActionRefused.NOT_OWNER
        assert store.info(key) is not None
        assert store.list_audit(100) == before
        assert store.credential_generation(key) == generation

    def test_an_owner_demoted_earlier_is_refused(self, store: TokenStore) -> None:
        owner = make_account(store, OID_OWNER, role="owner")
        make_account(store, OID_OTHER_OWNER, role="owner")
        key = target(store)
        with store._db.write() as conn:
            store._repos.accounts.set_role(
                conn, acc.account_id_of(owner), role="user", source=None, seen_at=None, now=1
            )
        with pytest.raises(AccessActionRefused):
            store.delete(key, actor=owner)
        assert store.info(key) is not None

    def test_a_missing_row_is_still_checked_first(self, store: TokenStore) -> None:
        user = make_account(store, OID_USER)
        with pytest.raises(AccessActionRefused):
            store.delete(acct_key(OID_TARGET), actor=user)


class TestMarkInvalid:
    def test_an_active_owner_may(self, store: TokenStore) -> None:
        owner = make_account(store, OID_OWNER, role="owner")
        key = target(store)
        assert store.mark_invalid(key, reason="revoked_by_admin", actor=owner) is True
        info = store.info(key)
        assert info is not None and info.status == "invalid"
        assert "token_marked_invalid" in audit_actions(store)

    def test_the_operator_and_the_automatic_probe_need_no_owner(self, store: TokenStore) -> None:
        key = target(store)
        assert store.mark_invalid(key, reason="revoked_by_admin", actor=OPERATOR) is True
        key2 = make_account(store, OID_USER)
        store.put(principal_key=key2, api_token=TOKEN, canvas_user_id="8", canvas_user_name="U")
        assert store.mark_invalid(key2, reason="canvas_token_rejected") is True

    @pytest.mark.parametrize("who", ["user", "disabled_owner", "unknown"])
    def test_anyone_else_is_refused_and_nothing_changes(self, store: TokenStore, who: str) -> None:
        key = target(store)
        actor = {
            "user": lambda: make_account(store, OID_USER),
            "disabled_owner": lambda: make_account(
                store, OID_OWNER, role="owner", status="disabled"
            ),
            "unknown": lambda: acct_key("dddddddd-0000-4000-8000-0000000000d1"),
        }[who]()
        generation = store.credential_generation(key)
        with pytest.raises(AccessActionRefused) as info:
            store.mark_invalid(key, reason="revoked_by_admin", actor=actor)
        assert info.value.code == AccessActionRefused.NOT_OWNER
        refreshed = store.info(key)
        assert refreshed is not None and refreshed.status == "active"
        assert store.credential_generation(key) == generation
        assert "token_marked_invalid" not in audit_actions(store)
