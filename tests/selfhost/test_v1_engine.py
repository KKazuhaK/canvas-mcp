"""The actual SQLite pool, connection policy and pre-WAL file bootstrap."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from dbbackend import pg_available
from sqlalchemy.pool import QueuePool

from canvas_mcp.core.selfhost.db.engine import SQLITE_APPLICATION_ID, Database
from canvas_mcp.core.selfhost.db.errors import StoreUnavailable, TokenStoreError
from canvas_mcp.core.selfhost.db.migrations.connections import sqlite_migration


def test_new_file_has_incremental_vacuum_before_wal_and_checked_pragmas(tmp_path):
    db = Database.sqlite(tmp_path / "private" / "state.sqlite3")
    try:
        db.prepare_storage()
        with db.read() as conn:
            expected = {
                "auto_vacuum": 2,
                "application_id": SQLITE_APPLICATION_ID,
                "journal_mode": "wal",
                "foreign_keys": 1,
                "synchronous": 2,
                "trusted_schema": 0,
                "journal_size_limit": 67108864,
                "secure_delete": 2,
                "busy_timeout": 5000,
            }
            for name, value in expected.items():
                assert conn.exec_driver_sql("PRAGMA " + name).scalar_one() == value
        assert isinstance(db.engine.pool, QueuePool)
        assert db.engine.pool.size() == 4
    finally:
        db.dispose()


def test_pool_connections_can_move_between_worker_threads(tmp_path):
    db = Database.sqlite(tmp_path / "state.sqlite3")
    try:
        db.prepare_storage()

        def read(_):
            with db.read() as conn:
                return conn.exec_driver_sql("SELECT 42").scalar_one()

        with ThreadPoolExecutor(max_workers=12) as workers:
            assert list(workers.map(read, range(100))) == [42] * 100
    finally:
        db.dispose()


def test_foreign_keys_refuse_orphan_rows_and_failed_transaction_rolls_back(tmp_path):
    db = Database.sqlite(tmp_path / "state.sqlite3")
    try:
        db.prepare_storage()
        with db.write() as conn:
            conn.exec_driver_sql("CREATE TABLE parent(id INTEGER PRIMARY KEY) STRICT")
            conn.exec_driver_sql(
                "CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id)) STRICT"
            )
        with pytest.raises(StoreUnavailable):
            with db.write() as conn:
                conn.exec_driver_sql("INSERT INTO parent VALUES(1)")
                conn.exec_driver_sql("INSERT INTO child VALUES(1,2)")
        with db.read() as conn:
            assert conn.exec_driver_sql("SELECT COUNT(*) FROM parent").scalar_one() == 0
    finally:
        db.dispose()


def test_old_sqlite_is_refused_before_opening_database(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite3"
    monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 36, 0))
    with pytest.raises(TokenStoreError, match="SQLite 3.37"):
        Database.sqlite(path)
    assert not path.exists()


def test_migration_rebuild_preserves_children_and_never_leaks_foreign_keys_off(
    tmp_path,
):
    db = Database.sqlite(tmp_path / "state.sqlite3")
    try:
        db.prepare_storage()
        with db.write() as conn:
            conn.exec_driver_sql("CREATE TABLE parent(id INTEGER PRIMARY KEY) STRICT")
            conn.exec_driver_sql(
                "CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id) ON DELETE CASCADE) STRICT"
            )
            conn.exec_driver_sql("INSERT INTO parent VALUES(1)")
            conn.exec_driver_sql("INSERT INTO child VALUES(1,1)")
        with sqlite_migration(db) as conn:
            assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 0
            conn.exec_driver_sql(
                "CREATE TABLE replacement(id INTEGER PRIMARY KEY) STRICT"
            )
            conn.exec_driver_sql("INSERT INTO replacement SELECT * FROM parent")
            conn.exec_driver_sql("DROP TABLE parent")
            conn.exec_driver_sql("ALTER TABLE replacement RENAME TO parent")
        with db.read() as conn:
            assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
            assert conn.exec_driver_sql("SELECT parent_id FROM child").scalar_one() == 1
        with pytest.raises(TokenStoreError, match="foreign key validation"):
            with sqlite_migration(db) as conn:
                conn.exec_driver_sql("UPDATE child SET parent_id=2")
        with db.read() as conn:
            assert conn.exec_driver_sql("SELECT parent_id FROM child").scalar_one() == 1
    finally:
        db.dispose()


@pytest.mark.skipif(not pg_available(), reason="PostgreSQL URL not supplied")
def test_governance_waiters_queue_before_pool_checkout(tmp_path):
    from pathlib import Path
    from threading import Event

    from dbbackend import PG_URL

    from canvas_mcp.core.selfhost.db.url import parse_database_url

    db = Database(parse_database_url(PG_URL, Path("/data")))
    entered = Event()
    release = Event()

    def governance(index):
        with db.write() as conn:
            if index == 0:
                entered.set()
                assert release.wait(5)
            return conn.exec_driver_sql("SELECT 1").scalar_one()

    try:
        with ThreadPoolExecutor(max_workers=9) as workers:
            first = workers.submit(governance, 0)
            assert entered.wait(2)
            queued = [workers.submit(governance, n) for n in range(1, 9)]
            try:
                assert db.engine.pool.checkedout() == 1
                with db.read() as conn:
                    assert conn.exec_driver_sql("SELECT 1").scalar_one() == 1
                # The read completes while governance still holds its lock;
                # correctness must not depend on a workstation's sub-100ms latency.
                assert not first.done() and not release.is_set()
            finally:
                release.set()
            assert first.result(timeout=2) == 1
            assert [f.result(timeout=2) for f in queued] == [1] * 8
    finally:
        release.set()
        db.dispose()
