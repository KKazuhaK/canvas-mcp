"""The shipped frozen baseline on the actual database engine."""

import uuid

import pytest
from dbbackend import pg_available
from sqlalchemy import inspect

from canvas_mcp.core.selfhost.db import baseline_v1
from canvas_mcp.core.selfhost.db.engine import Database
from canvas_mcp.core.selfhost.db.errors import TokenStoreError

TABLES = {
    'server_state', 'settings', 'login_providers', 'canvas_schools', 'accounts',
    'external_identities', 'account_write_tools', 'canvas_oauth_apps', 'canvas_credentials',
    'oauth_clients', 'cimd_clients', 'oauth_grants', 'oauth_codes', 'oauth_refresh_tokens',
    'login_states', 'auth_events', 'audit_log', 'web_sessions', 'account_quotas',
}


def test_frozen_baseline_creates_strict_schema_and_only_server_state(tmp_path):
    db = Database.sqlite(tmp_path / 'v1.sqlite3')
    try:
        db.prepare_storage()
        with db.sqlite_migration() as conn:
            identifier = baseline_v1.create(conn, now=100)
            assert uuid.UUID(identifier).version == 7
            assert set(inspect(conn).get_table_names()) == TABLES
            assert conn.exec_driver_sql('SELECT compat_floor FROM server_state WHERE id=1').scalar_one() == 1
            for table in TABLES - {'server_state'}:
                assert conn.exec_driver_sql('SELECT COUNT(*) FROM ' + table).scalar_one() == 0
            ordinary = [row for row in conn.exec_driver_sql('PRAGMA table_list') if row[1] in TABLES]
            assert len(ordinary) == 19
            assert all(row[5] == 1 for row in ordinary)
            assert sum(row[4] for row in ordinary) == 7
            assert conn.exec_driver_sql('PRAGMA foreign_key_check').all() == []
        with pytest.raises(TokenStoreError, match='empty database'):
            with db.sqlite_migration() as conn:
                baseline_v1.create(conn, now=200)
        with db.read() as conn:
            assert conn.exec_driver_sql('SELECT database_id FROM server_state').scalar_one() == identifier
    finally:
        db.dispose()


def test_baseline_transaction_is_atomic(tmp_path):
    db = Database.sqlite(tmp_path / 'v1.sqlite3')
    try:
        db.prepare_storage()
        with pytest.raises(RuntimeError):
            with db.sqlite_migration() as conn:
                baseline_v1.create(conn, now=100)
                raise RuntimeError('interrupted baseline')
        with db.read() as conn:
            assert inspect(conn).get_table_names() == []
    finally:
        db.dispose()

@pytest.mark.skipif(not pg_available(), reason='PostgreSQL URL not supplied')
def test_postgres_baseline_uses_native_types_and_reviewed_storage_policy(tmp_path):
    from dbbackend import pg_database

    db = pg_database(tmp_path / 'v1')
    try:
        with db.write() as conn:
            identifier = baseline_v1.create(conn, now=100)
            assert uuid.UUID(identifier).version == 7
            assert set(inspect(conn).get_table_names()) == TABLES
            account_columns = {c['name']: c['type'] for c in inspect(conn).get_columns('accounts')}
            assert str(account_columns['id']) == 'UUID'
            credential_columns = {c['name']: c['type'] for c in inspect(conn).get_columns('canvas_credentials')}
            assert str(credential_columns['is_primary']) == 'BOOLEAN'
            assert str(credential_columns['ciphertext']) == 'BYTEA'
            rows = conn.exec_driver_sql(
                "SELECT relname, relpersistence, reloptions FROM pg_class "
                "WHERE relnamespace=current_schema()::regnamespace "
                "AND relkind IN ('r','p')"
            ).all()
            options = {row[0]: (row[1], row[2] or []) for row in rows}
            assert options['login_states'][0] == 'u'
            for table in ('accounts', 'canvas_credentials', 'oauth_grants'):
                assert 'fillfactor=90' in options[table][1]
            for table in ('login_states', 'oauth_codes', 'oauth_refresh_tokens'):
                assert 'autovacuum_vacuum_scale_factor=0.05' in options[table][1]
            assert conn.exec_driver_sql('SELECT COUNT(*) FROM settings').scalar_one() == 0
    finally:
        db.dispose()
