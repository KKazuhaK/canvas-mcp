"""The single-query hot read enforces caller ownership and sees committed changes."""

from dataclasses import FrozenInstanceError

import pytest
from dbbackend import IS_POSTGRES, pg_database
from sqlalchemy import event, text

from canvas_mcp.core.selfhost.db import baseline_v1
from canvas_mcp.core.selfhost.db.engine import Database
from canvas_mcp.core.selfhost.db.snapshots import mcp_snapshot, session_snapshot
from canvas_mcp.core.selfhost.db.types import new_id


@pytest.fixture
def state(tmp_path):
    db = (
        pg_database(tmp_path / "snapshot")
        if IS_POSTGRES
        else Database.sqlite(tmp_path / "state.sqlite3")
    )
    db.prepare_storage()
    transaction = db.write if IS_POSTGRES else db.sqlite_migration
    with transaction() as conn:
        baseline_v1.create(conn, now=100)
        account_id, other_id, grant_id, credential_id = [new_id() for _ in range(4)]
        for identifier in (account_id, other_id):
            conn.execute(
                text(
                    "INSERT INTO accounts (id,status,admitted_via,created_at,updated_at) VALUES (:id,'active','operator',100,100)"
                ),
                {"id": identifier},
            )
        conn.execute(
            text(
                "INSERT INTO canvas_schools (host,origin,created_at,updated_at) VALUES ('canvas.example.edu','directory',100,100)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO oauth_grants (id,account_id,client_id,client_kind,redirect_host,scopes,resource,created_at,upstream_auth_at,expires_at) VALUES (:id,:account,'test-app','dcr','client.example.test','[\"Canvas.Access\"]','https://canvas.example.test/mcp',100,100,200)"
            ),
            {"id": grant_id, "account": account_id},
        )
        conn.execute(
            text(
                "INSERT INTO canvas_credentials (id,account_id,canvas_host,kind,is_primary,generation,key_id,nonce,ciphertext,canvas_user_id,canvas_user_name,created_at,updated_at,custody_notice_version,custody_ack_at) VALUES (:id,:account,'canvas.example.edu','pat',true,0,'k1',:nonce,:ciphertext,'1','Example',100,100,1,100)"
            ),
            {
                "id": credential_id,
                "account": account_id,
                "nonce": bytes(12),
                "ciphertext": bytes(17),
            },
        )
    try:
        yield db, account_id, other_id, grant_id, credential_id
    finally:
        db.dispose()


def test_one_select_returns_a_frozen_named_snapshot(state):
    db, account, _, grant, credential = state
    selects = []

    def observe(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            selects.append(statement)

    event.listen(db.engine, "before_cursor_execute", observe)
    with db.read() as conn:
        snapshot = mcp_snapshot(conn, account, grant)
    assert len(selects) == 1
    assert snapshot.credential_id == credential
    assert snapshot.credential_generation == snapshot.generation == 0
    assert snapshot.custody_notice_version == 1
    assert snapshot.status == "active"
    with pytest.raises(FrozenInstanceError):
        snapshot.status = "disabled"


def test_grant_id_is_not_enough_to_read_another_accounts_credential(state):
    db, _, other, grant, _ = state
    with db.read() as conn:
        assert mcp_snapshot(conn, other, grant) is None
        assert mcp_snapshot(conn, other, new_id()) is None


def test_epoch_revocation_and_settings_changes_are_visible_at_the_next_read(state):
    db, account, _, grant, _ = state
    with db.read() as conn:
        assert mcp_snapshot(conn, account, grant).revoked_at is None
    with db.write() as conn:
        conn.execute(
            text(
                "UPDATE oauth_grants SET revoked_at=110,revoked_reason='owner',revoked_by=NULL WHERE id=:id"
            ),
            {"id": grant},
        )
        conn.execute(
            text("UPDATE accounts SET session_epoch=1 WHERE id=:id"), {"id": account}
        )
        conn.execute(
            text("UPDATE server_state SET jwt_epoch=1,settings_revision=1 WHERE id=1")
        )
    with db.read() as conn:
        snapshot = mcp_snapshot(conn, account, grant)
        assert snapshot.revoked_at == 110
        assert (
            snapshot.session_epoch
            == snapshot.jwt_epoch
            == snapshot.settings_revision
            == 1
        )
        assert session_snapshot(conn, account).session_epoch == 1


def test_missing_credential_keeps_the_account_and_grant_snapshot(state):
    db, account, _, grant, credential = state
    with db.write() as conn:
        conn.execute(
            text("DELETE FROM canvas_credentials WHERE id=:id"), {"id": credential}
        )
    with db.read() as conn:
        snapshot = mcp_snapshot(conn, account, grant)
        assert snapshot.status == "active"
        assert snapshot.credential_id is None
        assert snapshot.key_id is None
