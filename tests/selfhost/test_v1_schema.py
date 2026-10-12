"""Integrity requirements of the reviewed v1 schema, on real engines."""

import pytest
from dbbackend import IS_POSTGRES, pg_database
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.db.engine import Database
from canvas_mcp.core.selfhost.db.migrations import runner as migrate
from canvas_mcp.core.selfhost.db.types import new_id


@pytest.fixture
def connection(tmp_path):
    db = (
        pg_database(tmp_path / "schema")
        if IS_POSTGRES
        else Database.sqlite(tmp_path / "schema.sqlite3")
    )
    db.prepare_storage()
    migrate.ensure_ready(db)
    try:
        with db.row_write() as conn:
            assert migrate.compare_schema(conn) == []
            yield conn
    finally:
        db.dispose()


def account(conn, **overrides):
    identifier = new_id()
    conn.execute(
        s.accounts.insert().values(
            id=identifier,
            status="active",
            admitted_via="operator",
            created_at=100,
            updated_at=100,
            **overrides,
        )
    )
    return identifier


def provider(conn):
    conn.execute(
        s.login_providers.insert().values(
            id="entra", protocol="entra", created_at=100, updated_at=100
        )
    )


def school(conn, host="canvas.example.edu"):
    conn.execute(
        s.canvas_schools.insert().values(
            host=host, origin="directory", created_at=100, updated_at=100
        )
    )


def credential(conn, account_id, **overrides):
    fields = {
        "id": new_id(),
        "account_id": account_id,
        "canvas_host": "canvas.example.edu",
        "kind": "pat",
        "is_primary": True,
        "generation": 0,
        "key_id": "k1",
        "nonce": bytes(12),
        "ciphertext": bytes(17),
        "canvas_user_id": "1",
        "canvas_user_name": "Example",
        "created_at": 100,
        "updated_at": 100,
        "custody_notice_version": 1,
        "custody_ack_at": 100,
    }
    fields.update(overrides)
    conn.execute(s.canvas_credentials.insert().values(**fields))
    return fields["id"]


def test_current_tables_with_a_lifecycle_and_registered_ciphertexts():
    expected = {
        "server_state",
        "settings",
        "login_providers",
        "canvas_schools",
        "accounts",
        "local_credentials",
        "external_identities",
        "account_write_tools",
        "canvas_credentials",
        "oauth_clients",
        "cimd_clients",
        "oauth_grants",
        "oauth_codes",
        "oauth_refresh_tokens",
        "login_states",
        "auth_events",
        "audit_log",
        "canvas_oauth_apps",
        "web_sessions",
        "account_quotas",
    }
    assert set(s.metadata.tables) == expected
    for table in s.metadata.tables.values():
        assert table.info["lifecycle"] in {
            "state",
            "durable",
            "history",
            "ephemeral",
            "reserved",
        }
        for column in table.columns:
            if column.name.endswith("ciphertext"):
                assert table.info["sealed"]["ciphertext"] == column.name


def test_every_ownership_foreign_key_has_an_index_prefix():
    for table in s.metadata.tables.values():
        candidate_keys = [list(table.primary_key.columns)]
        candidate_keys.extend(list(index.columns) for index in table.indexes)
        candidate_keys.extend(
            list(constraint.columns)
            for constraint in table.constraints
            if constraint.__class__.__name__ == "UniqueConstraint"
        )
        for foreign_key in table.foreign_keys:
            assert any(
                columns and columns[0] is foreign_key.parent
                for columns in candidate_keys
            ), (table.name, foreign_key.parent.name)


@pytest.mark.parametrize(
    "field,value",
    [
        ("custody_notice_version", None),
        ("custody_ack_at", None),
        ("custody_notice_version", 0),
        ("nonce", bytes(11)),
        ("ciphertext", bytes(16)),
        ("status", "unknown"),
        ("kind", "oauth"),
        ("invalid_since", 100),
    ],
)
def test_credential_constraints_reject_invalid_rows(connection, field, value):
    owner = account(connection)
    school(connection)
    with pytest.raises(IntegrityError), connection.begin_nested():
        credential(connection, owner, **{field: value})
    assert (
        connection.scalar(select(func.count()).select_from(s.canvas_credentials)) == 0
    )


def test_identity_has_one_provider_per_account_and_one_account_per_subject(connection):
    a, b = account(connection), account(connection)
    provider(connection)
    original = {
        "id": new_id(),
        "account_id": a,
        "provider_id": "entra",
        "issuer": "https://issuer.example.com",
        "subject": "a",
        "linked_at": 100,
    }
    connection.execute(s.external_identities.insert().values(**original))
    for overrides in ({"subject": "b"}, {"account_id": b}):
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(
                s.external_identities.insert().values(
                    **(original | {"id": new_id()} | overrides)
                )
            )


def test_provider_and_school_references_restrict_deletion(connection):
    owner = account(connection)
    provider(connection)
    school(connection)
    credential(connection, owner)
    connection.execute(
        s.external_identities.insert().values(
            id=new_id(),
            account_id=owner,
            provider_id="entra",
            issuer="https://issuer.example.com",
            subject="a",
            linked_at=100,
        )
    )
    for table in (s.login_providers, s.canvas_schools):
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(table.delete())


def test_account_cascade_keeps_history_and_reserved_tables_empty(connection):
    owner = account(connection)
    provider(connection)
    school(connection)
    credential(connection, owner)
    connection.execute(
        s.external_identities.insert().values(
            id=new_id(),
            account_id=owner,
            provider_id="entra",
            issuer="https://issuer.example.com",
            subject="a",
            linked_at=100,
        )
    )
    connection.execute(
        s.account_write_tools.insert().values(
            account_id=owner,
            tool_name="submit_assignment",
            enabled_at=100,
            enabled_via="api",
        )
    )
    connection.execute(
        s.auth_events.insert().values(
            at=100,
            account_id=owner,
            provider_id="entra",
            surface="account",
            outcome="success",
            reason="signed_in",
        )
    )
    connection.execute(
        s.audit_log.insert().values(
            at=100,
            actor_kind="account",
            actor_id=owner,
            subject_account_id=owner,
            action="account_created",
        )
    )
    connection.execute(s.accounts.delete().where(s.accounts.c.id == owner))
    for table in (s.external_identities, s.canvas_credentials, s.account_write_tools):
        assert connection.scalar(select(func.count()).select_from(table)) == 0
    for table in (s.auth_events, s.audit_log):
        assert connection.scalar(select(func.count()).select_from(table)) == 1
    for table in (s.canvas_oauth_apps, s.web_sessions, s.account_quotas):
        assert connection.scalar(select(func.count()).select_from(table)) == 0


def test_sqlite_strict_and_autoincrement_options(connection):
    if connection.dialect.name != "sqlite":
        return
    tables = connection.execute(
        text(
            "SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'canvas_mcp_alembic_version'"
        )
    ).all()
    assert len(tables) == 20
    for name, ddl in tables:
        assert "STRICT" in ddl, name
        if name in {"auth_events", "audit_log"}:
            assert "AUTOINCREMENT" in ddl
        if name in {
            "server_state",
            "settings",
            "canvas_schools",
            "account_write_tools",
            "oauth_refresh_tokens",
            "web_sessions",
            "account_quotas",
        }:
            assert "WITHOUT ROWID" in ddl, name
