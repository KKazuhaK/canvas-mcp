"""The shipped frozen baseline on the actual database engine."""

import uuid

import pytest
from dbbackend import IS_POSTGRES, pg_available, pg_database
from sqlalchemy import inspect

from canvas_mcp.core.selfhost.db.engine import Database
from canvas_mcp.core.selfhost.db.errors import TokenStoreError
from canvas_mcp.core.selfhost.db.migrations import baseline_v1
from canvas_mcp.core.selfhost.db.migrations.connections import sqlite_migration

TABLES = {
    "server_state",
    "settings",
    "login_providers",
    "canvas_schools",
    "accounts",
    "external_identities",
    "account_write_tools",
    "canvas_oauth_apps",
    "canvas_credentials",
    "oauth_clients",
    "cimd_clients",
    "oauth_grants",
    "oauth_codes",
    "oauth_refresh_tokens",
    "login_states",
    "auth_events",
    "audit_log",
    "web_sessions",
    "account_quotas",
}


@pytest.mark.parametrize("has_revision", [False, True])
def test_alembics_empty_version_table_is_allowed_but_an_existing_revision_is_not(
    tmp_path, has_revision
):
    db = (
        pg_database(tmp_path / "version")
        if IS_POSTGRES
        else Database.sqlite(tmp_path / "version.sqlite3")
    )
    db.prepare_storage()
    transaction = db.write if IS_POSTGRES else lambda: sqlite_migration(db)
    try:
        with transaction() as conn:
            conn.exec_driver_sql(
                "CREATE TABLE canvas_mcp_alembic_version(version_num VARCHAR(32) PRIMARY KEY)"
            )
            if has_revision:
                conn.exec_driver_sql(
                    "INSERT INTO canvas_mcp_alembic_version VALUES ('0003_oauth_authz')"
                )
        if has_revision:
            with pytest.raises(TokenStoreError, match="empty database"):
                with transaction() as conn:
                    baseline_v1.create(conn, now=100)
            with db.read() as conn:
                assert inspect(conn).get_table_names() == [baseline_v1.VERSION_TABLE]
        else:
            with transaction() as conn:
                baseline_v1.create(conn, now=100)
            with db.read() as conn:
                assert set(inspect(conn).get_table_names()) == TABLES | {
                    baseline_v1.VERSION_TABLE
                }
    finally:
        db.dispose()


def test_frozen_baseline_creates_strict_schema_and_only_server_state(tmp_path):
    db = Database.sqlite(tmp_path / "v1.sqlite3")
    try:
        db.prepare_storage()
        with sqlite_migration(db) as conn:
            identifier = baseline_v1.create(conn, now=100)
            assert uuid.UUID(identifier).version == 4
            assert set(inspect(conn).get_table_names()) == TABLES
            assert (
                conn.exec_driver_sql(
                    "SELECT compat_floor FROM server_state WHERE id=1"
                ).scalar_one()
                == 1
            )
            for table in TABLES - {"server_state"}:
                assert (
                    conn.exec_driver_sql("SELECT COUNT(*) FROM " + table).scalar_one()
                    == 0
                )
            ordinary = [
                row
                for row in conn.exec_driver_sql("PRAGMA table_list")
                if row[1] in TABLES
            ]
            assert len(ordinary) == 19
            assert all(row[5] == 1 for row in ordinary)
            assert sum(row[4] for row in ordinary) == 7
            assert conn.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        with pytest.raises(TokenStoreError, match="empty database"):
            with sqlite_migration(db) as conn:
                baseline_v1.create(conn, now=200)
        with db.read() as conn:
            assert (
                conn.exec_driver_sql(
                    "SELECT database_id FROM server_state"
                ).scalar_one()
                == identifier
            )
    finally:
        db.dispose()


def test_baseline_transaction_is_atomic(tmp_path):
    db = Database.sqlite(tmp_path / "v1.sqlite3")
    try:
        db.prepare_storage()
        with pytest.raises(RuntimeError):
            with sqlite_migration(db) as conn:
                baseline_v1.create(conn, now=100)
                raise RuntimeError("interrupted baseline")
        with db.read() as conn:
            assert inspect(conn).get_table_names() == []
    finally:
        db.dispose()


@pytest.mark.skipif(not pg_available(), reason="PostgreSQL URL not supplied")
def test_postgres_baseline_uses_native_types_and_reviewed_storage_policy(tmp_path):
    from dbbackend import pg_database

    db = pg_database(tmp_path / "v1")
    try:
        with db.write() as conn:
            identifier = baseline_v1.create(conn, now=100)
            assert uuid.UUID(identifier).version == 4
            assert set(inspect(conn).get_table_names()) == TABLES
            account_columns = {
                c["name"]: c["type"] for c in inspect(conn).get_columns("accounts")
            }
            assert str(account_columns["id"]) == "UUID"
            credential_columns = {
                c["name"]: c["type"]
                for c in inspect(conn).get_columns("canvas_credentials")
            }
            assert str(credential_columns["is_primary"]) == "BOOLEAN"
            assert str(credential_columns["ciphertext"]) == "BYTEA"
            rows = conn.exec_driver_sql(
                "SELECT relname, relpersistence, reloptions FROM pg_class "
                "WHERE relnamespace=current_schema()::regnamespace "
                "AND relkind IN ('r','p')"
            ).all()
            options = {row[0]: (row[1], row[2] or []) for row in rows}
            assert options["login_states"][0] == "u"
            for table in ("accounts", "canvas_credentials", "oauth_grants"):
                assert "fillfactor=90" in options[table][1]
            for table in ("login_states", "oauth_codes", "oauth_refresh_tokens"):
                assert "autovacuum_vacuum_scale_factor=0.05" in options[table][1]
            assert (
                conn.exec_driver_sql("SELECT COUNT(*) FROM settings").scalar_one() == 0
            )
    finally:
        db.dispose()
