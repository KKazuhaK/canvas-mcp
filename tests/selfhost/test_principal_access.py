"""Native account standing comes from each authenticated database snapshot."""

import pytest
from sqlalchemy import select

from canvas_mcp.core.selfhost.authz.store import AuthzStore
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.mcp_state import McpRead
from canvas_mcp.core.selfhost.principal_access import (
    access_disabled_message,
    access_not_provisioned_message,
    access_pending_message,
    access_refusal_message,
    access_unavailable_message,
    snapshot_status,
)
from canvas_mcp.core.selfhost.token_store import (
    DISABLE_REASON_OPERATOR,
    OPERATOR,
    PrincipalStatus,
)

from .authz.stack import ALICE, BOB, local_stack
from .test_request_context import GRANT, native_snapshot

KEY = "019a1234-5678-7000-8000-000000000001"


@pytest.mark.parametrize(
    "state,message",
    [
        ("active", None),
        ("disabled", access_disabled_message()),
        ("pending", access_pending_message()),
        ("missing", access_not_provisioned_message()),
        ("future_state", access_not_provisioned_message()),
    ],
)
def test_account_refusal_is_closed_by_default(state, message):
    assert access_refusal_message(PrincipalStatus(KEY, status=state)) == message


def test_snapshot_status_preserves_native_account_fields():
    result = snapshot_status(
        McpRead(
            KEY,
            GRANT,
            native_snapshot(
                role="owner",
                display_name="Alice",
                session_epoch=7,
                credential_generation=9,
            ),
        )
    )
    assert result.principal_key == KEY and result.stored and result.active
    assert result.is_owner and result.display_name == "Alice"
    assert result.session_epoch == 7 and result.credential_generation == 9


def test_account_refusal_messages_do_not_ask_to_reenroll_credentials():
    for message in (
        access_disabled_message(),
        access_pending_message(),
        access_not_provisioned_message(),
        access_unavailable_message(),
    ):
        assert "token" not in message.lower() and message.isascii()


@pytest.fixture
def connection(tmp_path, monkeypatch):
    with local_stack(tmp_path, monkeypatch) as stack:
        alice = stack.enroll(ALICE)
        stack.enroll(BOB)
        client_a, tokens_a = stack.tokens_for(ALICE)
        _, tokens_b = stack.tokens_for(BOB)
        yield stack, alice, client_a, tokens_a, tokens_b


def test_operator_disable_revokes_access_and_refresh_without_touching_other_user(
    connection, monkeypatch
):
    stack, alice, client, tokens_a, tokens_b = connection
    before = stack.store.info(alice)
    assert stack.store.disable_principal(
        alice, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR
    )
    with monkeypatch.context() as check:
        check.setattr(
            stack.store,
            "decrypt_snapshot",
            lambda *args: pytest.fail("disabled credential decrypted"),
        )
        assert stack.mcp_status(tokens_a["access_token"]) == 401
        refusal = stack.refresh(client, tokens_a["refresh_token"])
        assert (
            refusal.status_code in (400, 401)
            and refusal.json()["error"] == "invalid_grant"
        )
    assert stack.mcp_status(tokens_b["access_token"]) == 200
    after = stack.store.info(alice)
    assert after.credential_id == before.credential_id
    assert (
        after.status == before.status and after.canvas_user_id == before.canvas_user_id
    )
    assert stack.store.get_principal_status(alice).disabled


def test_reenable_keeps_enrollment_but_does_not_revive_old_grants(connection):
    stack, alice, client, tokens_a, _ = connection
    before = stack.store.info(alice)
    stack.store.disable_principal(alice, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
    assert stack.store.enable_principal(alice, actor=OPERATOR)
    assert stack.store.info(alice).credential_id == before.credential_id
    assert stack.mcp_status(tokens_a["access_token"]) == 401
    refusal = stack.refresh(client, tokens_a["refresh_token"])
    assert (
        refusal.status_code in (400, 401) and refusal.json()["error"] == "invalid_grant"
    )
    _, replacement = stack.tokens_for(ALICE)
    assert stack.whoami(replacement["access_token"]) == alice


def test_disable_survives_a_new_authz_store_instance(connection):
    stack, alice, _, tokens_a, _ = connection
    claim = stack.authz.codec.decode(tokens_a["access_token"]).claims
    stack.store.disable_principal(alice, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
    restarted = AuthzStore(stack.store.database, clock=stack.clock)
    snapshot = restarted.read_mcp_snapshot(alice, claim["grant"])
    assert snapshot.status == "disabled" and snapshot.revoked_at is not None
    with stack.store.database.read() as conn:
        actions = (
            conn.execute(
                select(s.audit_log.c.action).where(s.audit_log.c.target_id == alice)
            )
            .scalars()
            .all()
        )
    assert "account_disabled" in actions
