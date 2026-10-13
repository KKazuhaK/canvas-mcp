"""Native schema CLI and explicit SQLite-to-PostgreSQL transfer boundaries."""

from __future__ import annotations

import base64
import pathlib
import sqlite3

import pytest
from dbbackend import PG_URL, reset_public_schema
from sqlalchemy import func, inspect, select, text, update

from canvas_mcp.core.selfhost import token_admin
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.db.engine import Database
from canvas_mcp.core.selfhost.db.migrations import runner as migrate
from canvas_mcp.core.selfhost.db.migrations import transfer
from canvas_mcp.core.selfhost.db.url import parse_database_url
from canvas_mcp.core.selfhost.token_store import Keyring, TokenStore, TokenStoreError

from . import legacy_schemas as legacy
from .test_transfer_v1 import source as source  # shared native, fully populated fixture

KEYS = (
    "k2:"
    + base64.b64encode(b"2" * 32).decode()
    + ",k1:"
    + base64.b64encode(b"1" * 32).decode()
)
PASSWORD = "dbpw-that-must-not-print"


@pytest.fixture
def env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    monkeypatch.setenv("SELFHOST_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", KEYS)
    for name in (
        "DATABASE_URL",
        "DATABASE_AUTO_MIGRATE",
        "DATABASE_ALLOW_SQLITE_OUTSIDE_DATA_DIR",
    ):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def _db_path(data_dir: pathlib.Path) -> pathlib.Path:
    return data_dir / "canvas-mcp" / "tokens.sqlite3"


def dump(path: pathlib.Path) -> str:
    with sqlite3.connect(path) as conn:
        return "\n".join(conn.iterdump())


def seed(env: pathlib.Path) -> Database:
    db = Database.sqlite(_db_path(env))
    db.prepare_storage()
    migrate.ensure_ready(db)
    return db


class TestCurrent:
    def test_it_needs_no_keys_and_creates_no_database(self, env, monkeypatch, capsys):
        monkeypatch.delenv("CANVAS_TOKEN_KEYS")
        assert token_admin.main(["db", "current"]) == token_admin.EXIT_BEHIND
        out = capsys.readouterr().out
        assert "state: uninitialized" in out
        assert "alembic revision: (none)" in out
        assert f"head revision: {migrate.head_revision()}" in out
        assert f"backend: {_db_path(env)}" in out
        assert not _db_path(env).exists()

    @pytest.mark.parametrize("version", ["v1", "v2c", "v3", "v4"])
    def test_pre_v1_is_reported_and_never_adopted(self, env, capsys, version):
        legacy.build(_db_path(env), version)
        before = dump(_db_path(env))
        assert token_admin.main(["db", "current"]) == token_admin.EXIT_CONFIG
        assert "state: pre_v1" in capsys.readouterr().out
        assert dump(_db_path(env)) == before

    def test_current_prints_database_identity_and_compatibility_floor(
        self, env, capsys
    ):
        assert token_admin.main(["db", "upgrade"]) == 0
        capsys.readouterr()
        assert token_admin.main(["db", "current"]) == 0
        out = capsys.readouterr().out
        assert "state: current" in out and "compatibility floor: 3" in out
        assert "database id: (none)" not in out
        assert "schema version marker" not in out

    def test_unknown_newer_expand_is_compatible_but_never_migrated(self, env, capsys):
        db = seed(env)
        try:
            with db.write() as conn:
                conn.execute(
                    text(f"UPDATE {s.VERSION_TABLE} SET version_num='future_expand'")
                )
            assert token_admin.main(["db", "current"]) == 0
            assert "state: newer" in capsys.readouterr().out
            assert token_admin.main(["db", "upgrade"]) == 0
            assert "already compatible at future_expand" in capsys.readouterr().out
            assert migrate.current(db).alembic_revision == "future_expand"
        finally:
            db.dispose()

    def test_newer_contract_floor_is_refused(self, env, capsys):
        db = seed(env)
        try:
            with db.write() as conn:
                conn.execute(
                    update(s.server_state).values(compat_floor=migrate.SCHEMA_EPOCH + 1)
                )
            assert token_admin.main(["db", "current"]) == token_admin.EXIT_CONFIG
            assert "state: too_new" in capsys.readouterr().out
            assert token_admin.main(["db", "upgrade"]) == token_admin.EXIT_CONFIG
            assert "compatibility" in capsys.readouterr().err
        finally:
            db.dispose()


class TestUpgrade:
    @pytest.mark.parametrize("version", ["v1", "v2c", "v3", "v4"])
    def test_pre_v1_upgrade_refuses_without_backup_or_data_changes(
        self, env, tmp_path, capsys, version
    ):
        legacy.build(_db_path(env), version)
        before = dump(_db_path(env))
        backup = tmp_path / "refused-backup.sqlite3"
        assert (
            token_admin.main(["db", "upgrade", "--backup", str(backup)])
            == token_admin.EXIT_CONFIG
        )
        assert "pre-v1" in capsys.readouterr().err
        assert not backup.exists()
        assert dump(_db_path(env)) == before

    def test_fresh_upgrade_is_explicit_and_idempotent(self, env, capsys):
        assert token_admin.main(["db", "upgrade"]) == 0
        assert (
            f"upgraded: (none) -> {migrate.head_revision()}" in capsys.readouterr().out
        )
        before = dump(_db_path(env))
        assert token_admin.main(["db", "upgrade"]) == 0
        assert "already compatible" in capsys.readouterr().out
        assert dump(_db_path(env)) == before

    def test_backup_copies_the_native_database_and_never_overwrites(
        self, env, tmp_path, capsys
    ):
        db = seed(env)
        db.dispose()
        before = dump(_db_path(env))
        backup = tmp_path / "before.sqlite3"
        assert token_admin.main(["db", "upgrade", "--backup", str(backup)]) == 0
        assert "backup written" in capsys.readouterr().out
        assert dump(backup) == before
        assert (
            token_admin.main(["db", "upgrade", "--backup", str(backup)])
            == token_admin.EXIT_CONFIG
        )
        assert "already exists" in capsys.readouterr().err
        assert dump(backup) == before

    def test_dry_run_creates_no_fresh_database_or_backup(self, env, tmp_path, capsys):
        backup = tmp_path / "before.sqlite3"
        assert (
            token_admin.main(["db", "upgrade", "--dry-run", "--backup", str(backup)])
            == 0
        )
        assert "nothing was changed" in capsys.readouterr().out
        assert not _db_path(env).exists() and not backup.exists()

    def test_disabling_automatic_upgrade_requires_explicit_initialization(
        self, env, monkeypatch, capsys
    ):
        monkeypatch.setenv("DATABASE_AUTO_MIGRATE", "false")
        assert token_admin.main(["check"]) == token_admin.EXIT_CONFIG
        assert "db upgrade" in capsys.readouterr().err
        assert token_admin.main(["db", "upgrade"]) == 0
        capsys.readouterr()
        assert token_admin.main(["check"]) == 0
        assert "rows: 0" in capsys.readouterr().out

    def test_a_bad_url_or_flag_is_exit_2_and_never_echoed(
        self, env, monkeypatch, capsys
    ):
        monkeypatch.setenv("DATABASE_URL", f"mysql://root:{PASSWORD}@h/db")
        assert token_admin.main(["db", "current"]) == token_admin.EXIT_CONFIG
        captured = capsys.readouterr()
        assert "DATABASE_URL" in captured.err
        assert PASSWORD not in captured.err + captured.out
        monkeypatch.delenv("DATABASE_URL")
        monkeypatch.setenv("DATABASE_AUTO_MIGRATE", "perhaps")
        assert token_admin.main(["check"]) == token_admin.EXIT_CONFIG
        assert "DATABASE_AUTO_MIGRATE" in capsys.readouterr().err

    def test_unreachable_postgres_never_prints_connection_secrets(
        self, env, monkeypatch, capsys
    ):
        monkeypatch.setenv(
            "DATABASE_URL",
            f"postgresql+psycopg://u:{PASSWORD}@127.0.0.1:1/db?connect_timeout=1",
        )
        for argv in (["db", "current"], ["db", "upgrade"], ["check"]):
            assert token_admin.main(argv) == token_admin.EXIT_CONFIG
            captured = capsys.readouterr()
            assert PASSWORD not in captured.err + captured.out
            assert "127.0.0.1" not in captured.err + captured.out
            assert "unavailable" in captured.err

    def test_import_requires_postgres_without_opening_the_source(
        self, env, tmp_path, capsys
    ):
        missing = tmp_path / "missing.sqlite3"
        assert (
            token_admin.main(["db", "import-sqlite", str(missing)])
            == token_admin.EXIT_CONFIG
        )
        assert "writes to PostgreSQL" in capsys.readouterr().err
        assert not missing.exists() and not _db_path(env).exists()

    def test_populate_is_for_postgres(self, tmp_path):
        db = Database.sqlite(tmp_path / "x.sqlite3")
        try:
            with pytest.raises(TokenStoreError, match="PostgreSQL"):
                migrate.ensure_ready(db, auto=True, populate=lambda conn: None)
            assert not (tmp_path / "x.sqlite3").exists()
        finally:
            db.dispose()

    @pytest.mark.parametrize("command", ["upgrade", "import-sqlite"])
    def test_removed_lossy_import_flag_is_not_accepted(self, env, command):
        args = ["db", command]
        if command == "import-sqlite":
            args.append("unused.sqlite3")
        with pytest.raises(SystemExit) as caught:
            token_admin.main([*args, "--mark-undecryptable-invalid"])
        assert caught.value.code == 2


@pytest.mark.postgres
class TestImportIntoPostgres:
    @pytest.fixture(autouse=True)
    def _target(self, env, monkeypatch):
        reset_public_schema()
        monkeypatch.setenv("DATABASE_URL", PG_URL)

    def _db(self):
        return Database(parse_database_url(PG_URL, pathlib.Path("/data")))

    def test_native_tables_and_sealed_values_move_without_source_mutation(
        self, source, capsys
    ):
        origin, path, _, account, _ = source
        before = path.read_bytes()
        with origin.database.read() as conn:
            counts = {
                table.name: conn.execute(
                    select(func.count()).select_from(table)
                ).scalar_one()
                for table in transfer.copied_tables()
            }
        assert token_admin.main(["db", "import-sqlite", str(path)]) == 0
        out = capsys.readouterr().out
        for table, count in counts.items():
            assert f"{table}: {count} row(s)" in out
        assert "sealed values checked:" in out
        assert path.read_bytes() == before
        store = TokenStore(self._db(), Keyring.parse(KEYS))
        try:
            store.initialize(auto_migrate=False)
            assert store.get(account).api_token == origin.get(account).api_token
            assert migrate.current(store.database).state == migrate.STATE_CURRENT
            assert store.get_tool_prefs(account).enabled_write_tools == {
                "submit_assignment"
            }
        finally:
            store.close()

    def test_populated_target_is_never_overwritten(self, source, capsys):
        _, path, _, _, _ = source
        assert token_admin.main(["db", "import-sqlite", str(path)]) == 0
        capsys.readouterr()
        assert (
            token_admin.main(["db", "import-sqlite", str(path)])
            == token_admin.EXIT_CONFIG
        )
        assert "already holds" in capsys.readouterr().err

    def test_empty_native_schema_preserves_target_database_identity(
        self, source, capsys
    ):
        _, path, _, account, _ = source
        assert token_admin.main(["db", "upgrade"]) == 0
        capsys.readouterr()
        db = self._db()
        try:
            identifier = migrate.current(db).database_id
            assert token_admin.main(["db", "import-sqlite", str(path)]) == 0
            capsys.readouterr()
            assert migrate.current(db).database_id == identifier
            with db.read() as conn:
                assert (
                    conn.execute(
                        select(s.accounts.c.id).where(s.accounts.c.id == account)
                    ).scalar_one()
                    == account
                )
        finally:
            db.dispose()

    @pytest.mark.parametrize(
        "wrong",
        [
            "k1:" + base64.b64encode(b"9" * 32).decode(),
            "k2:" + base64.b64encode(b"2" * 32).decode(),
        ],
    )
    def test_wrong_material_or_missing_key_rolls_back_everything(
        self, source, monkeypatch, capsys, wrong
    ):
        _, path, _, _, _ = source
        before = path.read_bytes()
        monkeypatch.setenv("CANVAS_TOKEN_KEYS", wrong)
        assert (
            token_admin.main(["db", "import-sqlite", str(path)])
            == token_admin.EXIT_CONFIG
        )
        captured = capsys.readouterr()
        assert wrong not in captured.err + captured.out
        db = self._db()
        try:
            assert migrate.current(db).state == migrate.STATE_UNINITIALIZED
            assert not transfer.target_holds_rows(db)
            with db.read() as conn:
                assert inspect(conn).get_table_names() == []
        finally:
            db.dispose()
        assert path.read_bytes() == before

    def test_failure_after_copy_rolls_back_ddl_and_rows(
        self, source, monkeypatch, capsys
    ):
        _, path, _, _, _ = source

        def broken(*args, **kwargs):
            raise TokenStoreError(
                "simulated failure after the copy; nothing was imported"
            )

        monkeypatch.setattr(transfer, "verify", broken)
        assert (
            token_admin.main(["db", "import-sqlite", str(path)])
            == token_admin.EXIT_CONFIG
        )
        assert "simulated failure" in capsys.readouterr().err
        db = self._db()
        try:
            assert migrate.current(db).state == migrate.STATE_UNINITIALIZED
            assert not transfer.target_holds_rows(db)
        finally:
            db.dispose()

    @pytest.mark.parametrize("version", ["v1", "v4"])
    def test_pre_v1_source_is_never_adopted_in_a_private_copy(
        self, tmp_path, capsys, version
    ):
        path = tmp_path / "old.sqlite3"
        legacy.build(path, version)
        before = dump(path)
        assert (
            token_admin.main(["db", "import-sqlite", str(path)])
            == token_admin.EXIT_CONFIG
        )
        assert "pre-v1" in capsys.readouterr().err
        assert dump(path) == before
        db = self._db()
        try:
            assert migrate.current(db).state == migrate.STATE_UNINITIALIZED
        finally:
            db.dispose()

    def test_current_upgrade_and_postgres_backup_contract(self, capsys):
        assert token_admin.main(["db", "current"]) == token_admin.EXIT_BEHIND
        assert "state: uninitialized" in capsys.readouterr().out
        assert token_admin.main(["db", "upgrade"]) == 0
        capsys.readouterr()
        assert token_admin.main(["db", "current"]) == 0
        out = capsys.readouterr().out
        assert "postgresql+psycopg://" in out and "state: current" in out
        assert "canvas:" not in out
        assert (
            token_admin.main(["db", "upgrade", "--backup", "/tmp/x"])
            == token_admin.EXIT_CONFIG
        )
        assert "pg_dump" in capsys.readouterr().err
