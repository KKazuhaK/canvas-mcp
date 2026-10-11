"""Real MCP requests consume one authoritative read and fail closed before decryption."""

import json
from contextlib import contextmanager

import pytest
from sqlalchemy import event, update

from canvas_mcp.core.selfhost import custody
from canvas_mcp.core.selfhost.authz.store import AuthzStore
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.db.errors import StoreUnavailable
from canvas_mcp.core.selfhost.mcp_state import MCP_READ

from .stack import ALICE


@pytest.fixture
def connection(stack):
    account = stack.enroll(ALICE)
    client_id, tokens = stack.tokens_for(ALICE)
    assert stack.mcp_status(tokens["access_token"]) == 200
    return stack, account, client_id, tokens


@contextmanager
def statements(stack):
    seen = []

    def observe(conn, cursor, sql, parameters, context, executemany):
        # BEGIN is transaction control, not a data read or mutation.
        if not sql.strip().upper().startswith(("BEGIN", "COMMIT", "ROLLBACK")):
            seen.append(sql)

    event.listen(stack.store.database.engine, "before_cursor_execute", observe)
    try:
        yield seen
    finally:
        event.remove(stack.store.database.engine, "before_cursor_execute", observe)


def payload(response):
    assert response.status_code == 200, response.text
    text = response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        text = [
            line[5:].strip() for line in text.splitlines() if line.startswith("data:")
        ][-1]
    return json.loads(text)["result"]


@pytest.mark.parametrize("method", ["tools/list", "tools/call"])
def test_steady_request_reads_once_without_writing(connection, method):
    stack, account, _, tokens = connection
    params = {"name": "list_courses", "arguments": {}} if method == "tools/call" else {}
    for _ in range(3):
        with statements(stack) as seen:
            response = stack.rpc(tokens["access_token"], method, params)
        result = payload(response)
        assert not result.get("isError"), result
        assert len(seen) == 1 and "FROM oauth_grants g" in seen[0]
    assert MCP_READ.get() is None


@pytest.mark.parametrize("mutation", ["bad_signature", "junk", "missing"])
def test_unverified_input_never_reaches_the_database(connection, mutation):
    stack, _, _, tokens = connection
    token = tokens["access_token"]
    if mutation == "bad_signature":
        head, body, signature = token.split(".")
        token = f"{head}.{body}.{'A' if signature[0] != 'A' else 'B'}{signature[1:]}"
    elif mutation == "junk":
        token = "garbage"
    else:
        token = None
    with statements(stack) as seen:
        response = stack.rpc(token, "tools/list")
    assert response.status_code == 401 and seen == []


@pytest.mark.parametrize(
    "status,message", [("disabled", "disabled"), ("pending", "approval")]
)
def test_account_changes_are_immediate_without_a_cache_hook(
    connection, status, message
):
    stack, account, _, tokens = connection
    assert stack.mcp_status(tokens["access_token"]) == 200
    with stack.store.database.write() as conn:
        conn.execute(
            update(s.accounts)
            .where(s.accounts.c.id == account)
            .values(
                status=status,
                disabled_at=int(stack.clock()) if status == "disabled" else None,
            )
        )
    with statements(stack) as seen:
        response = stack.rpc(tokens["access_token"], "tools/list")
    assert response.status_code == 403 and message in response.text.lower()
    assert len(seen) == 1


def test_another_authz_instance_revokes_at_the_next_request(connection):
    stack, _, _, tokens = connection
    token = tokens["access_token"]
    assert stack.mcp_status(token) == 200
    grant = stack.authz.codec.decode(token).claims["grant"]
    other = AuthzStore(stack.store.database, clock=stack.clock)
    assert other.revoke_client_grant(grant)
    with statements(stack) as seen:
        response = stack.rpc(token, "tools/list")
    assert response.status_code == 401 and len(seen) == 1


def test_another_instance_epoch_bump_invalidates_immediately_and_refresh_recovers(
    connection,
):
    stack, _, client_id, tokens = connection
    assert stack.mcp_status(tokens["access_token"]) == 200
    other = AuthzStore(stack.store.database, clock=stack.clock)
    assert other.bump_jwt_epoch() == 1
    assert stack.mcp_status(tokens["access_token"]) == 401
    response = stack.refresh(client_id, tokens["refresh_token"])
    assert response.status_code == 200, response.text
    decoded = stack.authz.codec.decode(response.json()["access_token"])
    assert (
        decoded.epoch == 1 and stack.mcp_status(response.json()["access_token"]) == 200
    )


@pytest.mark.parametrize("epoch", [0, 2])
def test_valid_signature_at_a_different_epoch_does_not_authorize(connection, epoch):
    stack, _, _, tokens = connection
    stack.authz.bump_jwt_epoch()
    claims = stack.authz.codec.decode(tokens["access_token"]).claims
    token = stack.authz.codec.encode(
        account_key=claims["acct"],
        client_id=claims["client_id"],
        grant_id=claims["grant"],
        scopes=claims["scope"].split(),
        expires_at=claims["exp"],
        epoch=epoch,
    ).token
    with statements(stack) as seen:
        response = stack.rpc(token, "tools/list")
    assert response.status_code == 401 and len(seen) == 1


def test_database_outage_is_503_and_never_reuses_a_previous_read(
    connection, monkeypatch
):
    stack, _, _, tokens = connection
    assert stack.mcp_status(tokens["access_token"]) == 200

    def fail(*args):
        raise StoreUnavailable(kind="OperationalError")

    monkeypatch.setattr(stack.authz.store, "read_mcp_snapshot", fail)
    response = stack.rpc(tokens["access_token"], "tools/list")
    assert response.status_code == 503 and "could not be verified" in response.text
    assert MCP_READ.get() is None


def test_old_custody_notice_blocks_before_decryption_and_reack_restores(
    connection, monkeypatch
):
    stack, account, _, tokens = connection
    assert stack.whoami(tokens["access_token"]) == account
    info = stack.store.info(account)
    decrypt = stack.store.decrypt_snapshot
    calls = []
    monkeypatch.setattr(
        stack.store,
        "decrypt_snapshot",
        lambda *args: calls.append(args) or decrypt(*args),
    )
    monkeypatch.setattr(custody, "CUSTODY_NOTICE_VERSION", 2)
    with statements(stack) as seen:
        response = stack.rpc(
            tokens["access_token"],
            "tools/call",
            {"name": "list_courses", "arguments": {}},
        )
    result = payload(response)
    assert result["isError"] and "/account/token" in str(result)
    assert calls == [] and len(seen) == 1
    assert stack.store.info(account).credential_id == info.credential_id
    stack.store.acknowledge_custody(
        account, custody.CustodyAcknowledgement(2, int(stack.clock()))
    )
    assert stack.whoami(tokens["access_token"]) == account and len(calls) == 1
    assert stack.store.info(account).credential_generation == info.credential_generation


def test_generation_inconsistency_is_503_before_decryption(connection, monkeypatch):
    stack, account, _, tokens = connection
    with stack.store.database.write() as conn:
        conn.execute(
            update(s.canvas_credentials)
            .where(s.canvas_credentials.c.account_id == account)
            .values(generation=99)
        )
    monkeypatch.setattr(
        stack.store,
        "decrypt_snapshot",
        lambda *args: pytest.fail("inconsistent credential decrypted"),
    )
    assert stack.mcp_status(tokens["access_token"]) == 503


def test_decryption_failure_is_503_without_plaintext_or_ciphertext(
    connection, monkeypatch
):
    stack, _, _, tokens = connection

    def fail(*args):
        raise ValueError("sensitive ciphertext and token material")

    monkeypatch.setattr(stack.store, "decrypt_snapshot", fail)
    response = stack.rpc(tokens["access_token"], "tools/list")
    assert response.status_code == 503 and "sensitive" not in response.text


def test_touches_only_run_when_stale_then_return_to_one_read(connection):
    stack, account, _, tokens = connection
    stack.clock.advance(301)
    with statements(stack) as seen:
        assert stack.whoami(tokens["access_token"]) == account
    updates = [sql for sql in seen if sql.lstrip().upper().startswith("UPDATE")]
    assert len(updates) == 2
    with statements(stack) as seen:
        assert stack.whoami(tokens["access_token"]) == account
    assert len(seen) == 1


def test_preference_version_miss_reads_once_and_committed_change_is_immediate(
    connection,
):
    stack, account, _, tokens = connection
    # Even an empty save changes the version; a cold read cannot treat it as unsaved.
    first = stack.store.set_tool_prefs(account, [], via="operator")
    with statements(stack) as seen:
        assert stack.mcp_status(tokens["access_token"]) == 200
    assert first.version == 1 and len(seen) == 2
    with statements(stack) as seen:
        assert stack.mcp_status(tokens["access_token"]) == 200
    assert len(seen) == 1
    second = stack.store.set_tool_prefs(
        account, ["create_planner_note"], via="operator"
    )
    with statements(stack) as seen:
        assert stack.mcp_status(tokens["access_token"]) == 200
    assert second.version == 2 and len(seen) == 2
    assert stack.runtime.tool_prefs.enabled(account, 2) == frozenset(
        {"create_planner_note"}
    )
