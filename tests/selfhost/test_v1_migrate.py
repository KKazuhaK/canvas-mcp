"""The real squashed graph, compatibility gate and atomic creation transaction."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from dbbackend import IS_POSTGRES, pg_database
from sqlalchemy import inspect, text

from canvas_mcp.core.selfhost.db import schema
from canvas_mcp.core.selfhost.db.engine import Database
from canvas_mcp.core.selfhost.db.errors import TokenStoreError
from canvas_mcp.core.selfhost.db.migrations import baseline_v1
from canvas_mcp.core.selfhost.db.migrations import runner as migrate


@pytest.fixture
def db(tmp_path):
    made = (
        pg_database(tmp_path / "migrate")
        if IS_POSTGRES
        else Database.sqlite(tmp_path / "migrate.sqlite3")
    )
    made.prepare_storage()
    try:
        yield made
    finally:
        made.dispose()


def test_graph_is_one_frozen_revision_and_metadata_matches_real_upgrade(db):
    assert migrate.known_revisions() == {"0001_v1_baseline"}
    assert migrate.head_revision() == baseline_v1.BASELINE_REVISION
    assert migrate.current(db).state == migrate.STATE_UNINITIALIZED
    migrate.ensure_ready(db)
    first = migrate.current(db)
    assert first.state == migrate.STATE_CURRENT and first.compat_floor == 1
    assert first.database_id is not None
    migrate.ensure_ready(db, auto=False)
    assert migrate.current(db) == first
    with db.read() as conn:
        assert migrate.compare_schema(conn) == []
        assert set(inspect(conn).get_table_names()) == set(schema.metadata.tables) | {
            schema.VERSION_TABLE
        }


def test_auto_migrate_off_does_not_partially_create_a_database(db):
    with pytest.raises(TokenStoreError, match="AUTO_MIGRATE"):
        migrate.ensure_ready(db, auto=False)
    with db.read() as conn:
        assert inspect(conn).get_table_names() == []


@pytest.mark.parametrize(
    "revision", ["0001_baseline_v4", "0002_accounts", "0003_oauth_authz", None]
)
def test_pre_v1_is_refused_without_adopting_or_touching_data(db, revision):
    with db.row_write() as conn:
        if revision is not None:
            conn.exec_driver_sql(
                "CREATE TABLE canvas_mcp_alembic_version (version_num VARCHAR(32) PRIMARY KEY)"
            )
            conn.execute(
                text("INSERT INTO canvas_mcp_alembic_version VALUES (:revision)"),
                {"revision": revision},
            )
        else:
            conn.exec_driver_sql("CREATE TABLE meta (key TEXT PRIMARY KEY,value TEXT)")
            conn.exec_driver_sql("INSERT INTO meta VALUES ('schema_version','4')")
        conn.exec_driver_sql("CREATE TABLE saved_data (ciphertext TEXT)")
        conn.exec_driver_sql("INSERT INTO saved_data VALUES ('unchanged')")
    assert migrate.current(db).state == migrate.STATE_PRE_V1
    with pytest.raises(TokenStoreError, match="pre-v1"):
        migrate.ensure_ready(db)
    with db.read() as conn:
        assert (
            conn.exec_driver_sql("SELECT ciphertext FROM saved_data").scalar_one()
            == "unchanged"
        )
        assert "server_state" not in inspect(conn).get_table_names()


@pytest.mark.parametrize("floor,expected", [(1, "newer"), (2, "too_new")])
def test_unknown_revision_runs_only_when_compatibility_floor_allows_it(
    db, floor, expected, caplog
):
    migrate.ensure_ready(db)
    with db.row_write() as conn:
        conn.execute(
            text("UPDATE server_state SET compat_floor=:floor"), {"floor": floor}
        )
        conn.exec_driver_sql(
            "UPDATE canvas_mcp_alembic_version SET version_num='9999_expand'"
        )
    assert migrate.current(db).state == expected
    if floor == 1:
        migrate.ensure_ready(db)
        assert "database is newer than this release" in caplog.text
    else:
        with pytest.raises(TokenStoreError, match="compatibility floor"):
            migrate.ensure_ready(db)
    with db.read() as conn:
        assert (
            conn.exec_driver_sql(
                "SELECT version_num FROM canvas_mcp_alembic_version"
            ).scalar_one()
            == "9999_expand"
        )
        assert (
            conn.exec_driver_sql("SELECT compat_floor FROM server_state").scalar_one()
            == floor
        )


def test_even_a_known_head_is_refused_if_its_floor_is_too_new(db):
    migrate.ensure_ready(db)
    with db.row_write() as conn:
        conn.exec_driver_sql("UPDATE server_state SET compat_floor=2")
    with pytest.raises(TokenStoreError, match="compatibility floor"):
        migrate.ensure_ready(db)


def test_failed_revision_rolls_back_tables_and_alembic_record(db, monkeypatch):
    original = baseline_v1.create

    def fail_after_creation(conn, *, now):
        original(conn, now=now)
        raise RuntimeError("interrupted revision")

    monkeypatch.setattr(baseline_v1, "create", fail_after_creation)
    with pytest.raises(RuntimeError, match="interrupted"):
        migrate.ensure_ready(db)
    assert migrate.current(db).state == migrate.STATE_UNINITIALIZED
    with db.read() as conn:
        assert inspect(conn).get_table_names() == []


def test_dry_run_executes_creation_and_rolls_back(db):
    before, after = migrate.upgrade(db, dry_run=True)
    assert before == after
    assert after.state == migrate.STATE_UNINITIALIZED
    migrate.upgrade(db)
    assert migrate.current(db).state == migrate.STATE_CURRENT


def test_two_concurrent_starters_create_one_database_identity(db, tmp_path):
    other = pg_database(tmp_path / "migrate") if IS_POSTGRES else Database(db.target)
    barrier = Barrier(2)

    def start(database):
        barrier.wait(timeout=3)
        migrate.ensure_ready(database)
        return migrate.current(database).database_id

    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            a, b = workers.submit(start, db), workers.submit(start, other)
            assert a.result(timeout=10) == b.result(timeout=10)
        assert migrate.current(db).state == migrate.STATE_CURRENT
    finally:
        other.dispose()


def test_missing_owned_table_is_unreadable_and_is_not_repaired_silently(db):
    migrate.ensure_ready(db)
    with db.row_write() as conn:
        conn.exec_driver_sql("DROP TABLE account_quotas")
    assert migrate.current(db).state == migrate.STATE_UNREADABLE
    with pytest.raises(TokenStoreError, match="unreadable"):
        migrate.ensure_ready(db)


@pytest.mark.parametrize("dialect", ["sqlite", "postgresql"])
def test_offline_upgrade_contains_frozen_ddl_and_no_legacy_tables(dialect):
    sql = migrate.render_sql(dialect)
    for table in schema.metadata.tables:
        assert "CREATE TABLE " + table + " " in sql
    assert "canvas_mcp_alembic_version" in sql and "0001_v1_baseline" in sql
    assert "CREATE TABLE meta " not in sql and "CREATE TABLE canvas_tokens " not in sql
