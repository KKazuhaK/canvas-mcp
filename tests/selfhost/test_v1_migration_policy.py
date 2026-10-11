"""Future revision behavior on seeded databases, without shipping another revision."""
# ruff: noqa: F811

import pathlib
import shutil
import sqlite3
import textwrap

import pytest
from dbbackend import IS_POSTGRES
from sqlalchemy import event, inspect, text

from canvas_mcp.core.selfhost.db.errors import StoreUnavailable, TokenStoreError
from canvas_mcp.core.selfhost.db.migrations import runner as migrate
from canvas_mcp.core.selfhost.db.types import new_id

from .test_v1_migrate import db  # noqa: F401


@pytest.fixture
def revision_graph(tmp_path, monkeypatch):
    directory = tmp_path / "revisions"
    directory.mkdir()
    (directory / "versions").mkdir()
    source = pathlib.Path(migrate.__file__).parent
    shutil.copyfile(source / "env.py", directory / "env.py")
    shutil.copyfile(
        source / "versions/0001_v1_baseline.py",
        directory / "versions/0001_v1_baseline.py",
    )
    monkeypatch.setattr(migrate, "_MIGRATIONS_DIR", directory)
    migrate._script.cache_clear()

    def add(
        body,
        *,
        contract=False,
        non_transactional=False,
        revision="0002_policy",
        down="0001_v1_baseline",
    ):
        script = f"""from alembic import op
import sqlalchemy as sa
from canvas_mcp.core.selfhost.db.migrations.policy import rebuild_sqlite_table, concurrent_index
revision = {revision!r}
down_revision = {down!r}
branch_labels = None
depends_on = None
CONTRACT = {contract!r}
NON_TRANSACTIONAL = {non_transactional!r}
def upgrade():
{textwrap.indent(textwrap.dedent(body).strip(), "    ")}
def downgrade():
    raise RuntimeError('restore a backup')
"""
        (directory / "versions" / (revision + ".py")).write_text(
            script, encoding="utf-8"
        )
        migrate._script.cache_clear()

    try:
        yield add
    finally:
        migrate._script.cache_clear()


@pytest.mark.skipif(IS_POSTGRES, reason="SQLite native rebuild")
def test_contract_automatically_backs_up_and_preserves_strict_rowid_indexes_and_sequence(
    db, revision_graph, monkeypatch
):  # noqa: F811
    migrate.ensure_ready(db)
    with db.row_write() as conn:
        conn.exec_driver_sql("ALTER TABLE audit_log ADD COLUMN obsolete TEXT")
        conn.exec_driver_sql("ALTER TABLE settings ADD COLUMN obsolete TEXT")
        conn.exec_driver_sql(
            "INSERT INTO audit_log(id,at,actor_kind,action) VALUES (900,1,'system','fixture')"
        )
        conn.exec_driver_sql("DELETE FROM audit_log WHERE id=900")
        original_indexes = conn.exec_driver_sql(
            "SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name IN ('settings','audit_log') ORDER BY name"
        ).all()
    revision_graph(
        """
        with rebuild_sqlite_table('audit_log') as batch:
            batch.drop_column('obsolete')
        with rebuild_sqlite_table('settings') as batch:
            batch.drop_column('obsolete')
        op.execute('UPDATE server_state SET compat_floor=2')
    """,
        contract=True,
    )
    monkeypatch.setattr(migrate, "SCHEMA_EPOCH", 2)
    migrate.ensure_ready(db)
    assert migrate.current(db).state == "current"
    backups = list(
        db.sqlite_path.parent.glob(db.sqlite_path.name + ".pre-0002_policy-*.bak")
    )
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as backup:
        assert backup.execute("SELECT compat_floor FROM server_state").fetchone() == (
            1,
        )
        assert backup.execute(
            "SELECT version_num FROM canvas_mcp_alembic_version"
        ).fetchone() == ("0001_v1_baseline",)
        assert "obsolete" in {
            row[1] for row in backup.execute("PRAGMA table_info(audit_log)")
        }
    with db.row_write() as conn:
        properties = {
            row["name"]: row
            for row in conn.exec_driver_sql("PRAGMA table_list").mappings()
        }
        assert (
            properties["audit_log"]["strict"] == properties["settings"]["strict"] == 1
        )
        assert properties["settings"]["wr"] == 1
        assert (
            "AUTOINCREMENT"
            in conn.exec_driver_sql(
                "SELECT sql FROM sqlite_master WHERE name='audit_log'"
            ).scalar_one()
        )
        assert (
            conn.exec_driver_sql(
                "SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name IN ('settings','audit_log') ORDER BY name"
            ).all()
            == original_indexes
        )
        conn.exec_driver_sql(
            "INSERT INTO audit_log(at,actor_kind,action) VALUES (2,'system','after')"
        )
        assert conn.exec_driver_sql("SELECT id FROM audit_log").scalar_one() > 900
        assert not conn.exec_driver_sql("PRAGMA foreign_key_check").all()
        assert migrate.compare_schema(conn) == []
    with db.read() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1


@pytest.mark.skipif(IS_POSTGRES, reason="SQLite automatic backups")
def test_failed_contract_keeps_backup_and_rolls_back_the_database(db, revision_graph):  # noqa: F811
    migrate.ensure_ready(db)
    revision_graph(
        """
        with rebuild_sqlite_table('settings') as batch:
            batch.add_column(sa.Column('temporary', sa.Text(), nullable=True))
        raise RuntimeError('interrupted contract')
    """,
        contract=True,
    )
    with pytest.raises(RuntimeError, match="interrupted contract"):
        migrate.ensure_ready(db)
    assert migrate.current(db).state == "behind"
    with db.read() as conn:
        assert "temporary" not in {
            column["name"] for column in inspect(conn).get_columns("settings")
        }
    assert len(list(db.sqlite_path.parent.glob("*.pre-0002_policy-*.bak"))) == 1


def test_expand_does_not_raise_floor_or_create_a_contract_backup(db, revision_graph):  # noqa: F811
    migrate.ensure_ready(db)
    revision_graph("op.create_index('ix_future_display', 'accounts', ['display_name'])")
    migrate.ensure_ready(db)
    assert migrate.current(db).compat_floor == 1
    if db.sqlite_path is not None:
        assert list(db.sqlite_path.parent.glob("*.bak")) == []


@pytest.mark.parametrize(
    "contract,floor,pattern",
    [
        (True, 1, "contract revision must raise"),
        (False, 2, "expand revision must preserve"),
        (True, 3, "unsupported compatibility floor"),
    ],
)
def test_floor_policy_failure_rolls_back_ddl_and_revision(
    db, revision_graph, monkeypatch, contract, floor, pattern
):
    migrate.ensure_ready(db)
    monkeypatch.setattr(migrate, "SCHEMA_EPOCH", 2)
    revision_graph(
        f"op.create_table('temporary_policy', sa.Column('id', sa.Integer(), primary_key=True))\n"
        f"op.execute('UPDATE server_state SET compat_floor={floor}')",
        contract=contract,
    )
    with pytest.raises(TokenStoreError, match=pattern):
        migrate.ensure_ready(db)
    with db.read() as conn:
        assert "temporary_policy" not in inspect(conn).get_table_names()
        assert (
            conn.exec_driver_sql("SELECT compat_floor FROM server_state").scalar_one()
            == 1
        )
        assert (
            conn.exec_driver_sql(
                "SELECT version_num FROM canvas_mcp_alembic_version"
            ).scalar_one()
            == "0001_v1_baseline"
        )


def test_contract_floor_raise_is_checked_on_each_backend(
    db, revision_graph, monkeypatch
):
    migrate.ensure_ready(db)
    monkeypatch.setattr(migrate, "SCHEMA_EPOCH", 2)
    revision_graph(
        "op.execute('UPDATE server_state SET compat_floor=2')", contract=True
    )
    migrate.ensure_ready(db)
    assert migrate.current(db).compat_floor == 2
    assert migrate.current(db).state == "current"


@pytest.mark.skipif(not IS_POSTGRES, reason="PostgreSQL concurrent DDL")
def test_nontransactional_failure_leaves_invalid_index_and_retry_repairs_it_under_lock(
    db, revision_graph
):  # noqa: F811
    from canvas_mcp.core.selfhost.db.migrations.connections import MIGRATION_LOCK_KEY

    migrate.ensure_ready(db)
    first, second = new_id(), new_id()
    with db.row_write() as conn:
        conn.execute(
            text(
                "INSERT INTO accounts(id,status,admitted_via,created_at,updated_at,display_name) VALUES (:id,'pending','approval',1,1,'duplicate')"
            ),
            [{"id": first}, {"id": second}],
        )
    revision_graph(
        "op.create_table('expanded', sa.Column('id', sa.Integer(), primary_key=True))"
    )
    revision_graph(
        f"""
        assert op.get_bind().execute(sa.text('SELECT pg_try_advisory_lock({MIGRATION_LOCK_KEY})')).scalar_one() is False
        concurrent_index('uq_future_display', 'accounts', ['display_name'], unique=True)
    """,
        revision="0003_policy",
        down="0002_policy",
        non_transactional=True,
    )
    application_sql = []

    def record(_conn, _cursor, statement, _parameters, _context, _many):
        application_sql.append(statement)

    event.listen(db.engine, "before_cursor_execute", record)
    try:
        with pytest.raises(StoreUnavailable, match="UniqueViolation"):
            migrate.ensure_ready(db)
        with db.read() as conn:
            assert (
                conn.exec_driver_sql(
                    "SELECT version_num FROM canvas_mcp_alembic_version"
                ).scalar_one()
                == "0002_policy"
            )
            assert "expanded" in inspect(conn).get_table_names()
            assert (
                conn.exec_driver_sql(
                    "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relname='uq_future_display'"
                ).scalar_one()
                is False
            )
        with db.row_write() as conn:
            conn.execute(text("DELETE FROM accounts WHERE id=:id"), {"id": second})
        migrate.ensure_ready(db)
        assert migrate.current(db).state == "current"
        with db.read() as conn:
            assert (
                conn.exec_driver_sql(
                    "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relname='uq_future_display'"
                ).scalar_one()
                is True
            )
    finally:
        event.remove(db.engine, "before_cursor_execute", record)
    assert not any(
        query.startswith(("CREATE ", "ALTER ", "DROP ")) for query in application_sql
    )


@pytest.mark.skipif(not IS_POSTGRES, reason="PostgreSQL nontransactional safety")
@pytest.mark.parametrize("mode", ["dry_run", "import"])
def test_nontransactional_plan_refuses_atomic_modes_before_any_revision(
    db, revision_graph, mode
):  # noqa: F811
    migrate.ensure_ready(db)
    revision_graph(
        "op.create_table('expanded', sa.Column('id', sa.Integer(), primary_key=True))"
    )
    revision_graph(
        "concurrent_index('ix_future_display', 'accounts', ['display_name'])",
        revision="0003_policy",
        down="0002_policy",
        non_transactional=True,
    )
    with pytest.raises(TokenStoreError, match="non-transactional"):
        migrate.ensure_ready(
            db,
            **(
                {"dry_run": True}
                if mode == "dry_run"
                else {"populate": lambda conn: None}
            ),
        )
    with db.read() as conn:
        assert "expanded" not in inspect(conn).get_table_names()
        assert (
            conn.exec_driver_sql(
                "SELECT version_num FROM canvas_mcp_alembic_version"
            ).scalar_one()
            == "0001_v1_baseline"
        )


@pytest.mark.skipif(not IS_POSTGRES, reason="PostgreSQL completed-index recovery")
def test_retry_recognizes_a_completed_index_after_the_version_transaction_failed(
    db, revision_graph
):
    migrate.ensure_ready(db)
    revision_graph(
        """
        concurrent_index('ix_future_display', 'accounts', ['display_name'])
        raise RuntimeError('interrupted version transaction')
    """,
        non_transactional=True,
    )
    with pytest.raises(RuntimeError, match="interrupted version"):
        migrate.ensure_ready(db)
    assert migrate.current(db).state == "behind"
    with db.read() as conn:
        assert "ix_future_display" in {
            index["name"] for index in inspect(conn).get_indexes("accounts")
        }
    revision_graph(
        "concurrent_index('ix_future_display', 'accounts', ['display_name'])",
        non_transactional=True,
    )
    migrate.ensure_ready(db)
    assert migrate.current(db).state == "current"


def test_policy_flags_are_exact_booleans_and_invalid_flags_do_not_upgrade(
    db, revision_graph
):
    migrate.ensure_ready(db)
    revision_graph(
        "op.create_table('unreviewed', sa.Column('id', sa.Integer()))", contract="yes"
    )
    with pytest.raises(TokenStoreError, match="booleans"):
        migrate.ensure_ready(db)
    with db.read() as conn:
        assert "unreviewed" not in inspect(conn).get_table_names()
