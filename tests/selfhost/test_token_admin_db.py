"""token_admin ``db current``, ``db upgrade`` and ``db import-sqlite``."""

from __future__ import annotations

import base64
import pathlib
import sqlite3

import pytest
from dbbackend import PG_URL, reset_public_schema

from canvas_mcp.core.selfhost import token_admin
from canvas_mcp.core.selfhost.db import migrate
from canvas_mcp.core.selfhost.db.engine import Database
from canvas_mcp.core.selfhost.db.url import parse_database_url
from canvas_mcp.core.selfhost.token_store import (
    OPERATOR,
    Keyring,
    TokenStore,
    TokenStoreError,
)

from . import legacy_schemas as legacy

KEYS = "k2:" + base64.b64encode(bytes([2]) * 32).decode() + ",k1:" + base64.b64encode(bytes([1]) * 32).decode()
PASSWORD = "dbpw-that-must-not-print"


@pytest.fixture
def env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    monkeypatch.setenv("SELFHOST_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", KEYS)
    for name in ("DATABASE_URL", "DATABASE_AUTO_MIGRATE", "DATABASE_ALLOW_SQLITE_OUTSIDE_DATA_DIR"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def _db_path(data_dir: pathlib.Path) -> pathlib.Path:
    return data_dir / "canvas-mcp" / "tokens.sqlite3"


class TestCurrent:
    def test_it_needs_no_keys_and_creates_nothing_it_does_not_need(
        self, env, monkeypatch, capsys
    ) -> None:
        monkeypatch.delenv("CANVAS_TOKEN_KEYS")
        assert token_admin.main(["db", "current"]) == token_admin.EXIT_BEHIND
        out = capsys.readouterr().out
        assert "state: uninitialized" in out
        assert "alembic revision: (none)" in out
        assert f"head revision: {migrate.head_revision()}" in out
        assert f"backend: {_db_path(env)}" in out

    def test_a_legacy_file_is_reported_and_left_alone(self, env, capsys) -> None:
        legacy.build(_db_path(env), "v3")
        assert token_admin.main(["db", "current"]) == token_admin.EXIT_BEHIND
        out = capsys.readouterr().out
        assert "state: legacy" in out and "schema version marker: 3" in out
        conn = sqlite3.connect(str(_db_path(env)))
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        conn.close()
        assert "canvas_mcp_alembic_version" not in names
        assert "credential_generations" not in names

    def test_a_current_database_exits_zero(self, env, capsys) -> None:
        assert token_admin.main(["db", "upgrade"]) == 0
        capsys.readouterr()
        assert token_admin.main(["db", "current"]) == 0
        out = capsys.readouterr().out
        assert "state: current" in out and "schema version marker: 5" in out

    def test_a_newer_database_is_exit_2(self, env, capsys) -> None:
        legacy.build(_db_path(env), "v4")
        conn = sqlite3.connect(str(_db_path(env)))
        conn.execute("UPDATE meta SET value = '7' WHERE key = 'schema_version'")
        conn.commit()
        conn.close()
        assert token_admin.main(["db", "current"]) == token_admin.EXIT_CONFIG
        assert "state: newer" in capsys.readouterr().out
        assert token_admin.main(["db", "upgrade"]) == token_admin.EXIT_CONFIG
        assert "newer than this server supports" in capsys.readouterr().err


class TestUpgrade:
    def test_it_adopts_a_legacy_file_and_says_so(self, env, capsys) -> None:
        legacy.build(_db_path(env), "v2c")
        assert token_admin.main(["db", "upgrade"]) == 0
        assert f"upgraded: (none) -> {migrate.head_revision()}" in capsys.readouterr().out
        assert token_admin.main(["db", "upgrade"]) == 0
        assert "already current" in capsys.readouterr().out

    def test_the_backup_is_written_first(self, env, tmp_path, capsys) -> None:
        legacy.build(_db_path(env), "v3")
        backup = tmp_path / "before.sqlite3"
        assert token_admin.main(["db", "upgrade", "--backup", str(backup)]) == 0
        out = capsys.readouterr().out
        assert "backup written" in out
        conn = sqlite3.connect(str(backup))
        assert conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone() == ("3",)
        conn.close()
        assert token_admin.main(["db", "upgrade", "--backup", str(backup)]) == token_admin.EXIT_CONFIG
        assert "already exists" in capsys.readouterr().err

    def test_other_commands_migrate_first_unless_that_is_switched_off(
        self, env, monkeypatch, capsys
    ) -> None:
        legacy.build(_db_path(env), "v3")
        monkeypatch.setenv("DATABASE_AUTO_MIGRATE", "false")
        assert token_admin.main(["check"]) == token_admin.EXIT_CONFIG
        assert "db upgrade" in capsys.readouterr().err
        monkeypatch.delenv("DATABASE_AUTO_MIGRATE")
        assert token_admin.main(["check"]) == 0
        assert "rows: " in capsys.readouterr().out
        monkeypatch.setenv("DATABASE_AUTO_MIGRATE", "false")
        assert token_admin.main(["check"]) == 0  # current now

    def test_a_bad_url_or_flag_is_exit_2_and_never_echoed(self, env, monkeypatch, capsys) -> None:
        monkeypatch.setenv("DATABASE_URL", f"mysql://root:{PASSWORD}@h/db")
        assert token_admin.main(["db", "current"]) == token_admin.EXIT_CONFIG
        captured = capsys.readouterr()
        assert "DATABASE_URL" in captured.err
        assert PASSWORD not in captured.err + captured.out
        monkeypatch.delenv("DATABASE_URL")
        monkeypatch.setenv("DATABASE_AUTO_MIGRATE", "perhaps")
        assert token_admin.main(["check"]) == token_admin.EXIT_CONFIG
        assert "DATABASE_AUTO_MIGRATE" in capsys.readouterr().err

    def test_an_unreachable_postgres_is_exit_2_without_the_url(self, env, monkeypatch, capsys) -> None:
        monkeypatch.setenv(
            "DATABASE_URL", f"postgresql+psycopg://u:{PASSWORD}@127.0.0.1:1/db?connect_timeout=1"
        )
        for argv in (["db", "current"], ["db", "upgrade"], ["check"]):
            assert token_admin.main(argv) == token_admin.EXIT_CONFIG
            captured = capsys.readouterr()
            assert PASSWORD not in captured.err + captured.out
            assert "127.0.0.1" not in captured.err + captured.out
            assert "unavailable" in captured.err

    def test_import_needs_a_postgres_target(self, env, tmp_path, capsys) -> None:
        legacy.build(tmp_path / "old.sqlite3", "v4")
        assert token_admin.main(["db", "import-sqlite", str(tmp_path / "old.sqlite3")]) == (
            token_admin.EXIT_CONFIG
        )
        assert "writes to PostgreSQL" in capsys.readouterr().err


    def test_populate_is_for_postgres(self, tmp_path) -> None:
        db = Database.sqlite(tmp_path / "x.sqlite3")
        with pytest.raises(TokenStoreError, match="PostgreSQL"):
            migrate.ensure_ready(db, auto=True, populate=lambda conn: None)
        assert not (tmp_path / "x.sqlite3").exists()


@pytest.mark.postgres
class TestImportIntoPostgres:
    @pytest.fixture(autouse=True)
    def _target(self, env, monkeypatch) -> None:
        reset_public_schema()
        monkeypatch.setenv("DATABASE_URL", PG_URL)

    def _db(self) -> Database:
        return Database(parse_database_url(PG_URL, pathlib.Path("/data")))

    def _store(self) -> TokenStore:
        return TokenStore(self._db(), Keyring.parse(KEYS))

    def test_every_table_moves_and_every_token_decrypts(self, tmp_path, capsys) -> None:
        # A schema 4 file (accounts do not exist yet) ends as a schema 5 PostgreSQL
        # database: accounts and identities created, tokens re-encrypted, state kept.
        source = tmp_path / "old.sqlite3"
        seeded = legacy.build(source, "v4")
        before = source.read_bytes()
        assert token_admin.main(["db", "import-sqlite", str(source)]) == 0
        out = capsys.readouterr().out
        # principal_status is absorbed into accounts: it is neither a table nor a line.
        assert "principal_status:" not in out
        for line in (
            "canvas_tokens: 4 row(s)",
            "user_tool_prefs: 1 row(s)",
            "accounts: 3 row(s)",  # B, C (from principal_status) and A (a token only)
            "external_identities: 3 row(s)",
            "principal_status_events: 4 row(s)",
            "credential_generations: 2 row(s)",
            "auth_events: 0 row(s)",
        ):
            assert line in out
        assert "audit_log: 1 row(s)" in out  # the migration's own entry
        assert source.read_bytes() == before  # the source is never modified
        status = migrate.current(self._db())
        assert status.state == migrate.STATE_CURRENT and status.meta_version == "5"
        store = self._store()
        store.initialize(auto_migrate=False)
        accounts = {key: store.resolve_legacy_key(key) for key in (legacy.KEY_A, legacy.KEY_B, legacy.KEY_C)}
        assert all(accounts.values()) and len(set(accounts.values())) == 3
        for key, token in seeded.plaintexts.items():
            if key in accounts:
                row = store.get(accounts[key])
                assert row is not None and row.api_token == token
        # The unmapped principal is carried over unchanged (and still decrypts: the
        # import verified it) rather than dropped.
        assert store.count() == 4
        c = accounts[legacy.KEY_C]
        status_c = store.get_principal_status(c)
        assert status_c.disabled and status_c.session_epoch == 3 and status_c.credential_generation == 5
        assert [e.action for e in store.list_status_events(c)] == ["disabled", "enabled", "disabled"]
        # The history keeps counting after the copied ids.
        store.enable_principal(c, actor=OPERATOR)
        newest = store.list_status_events(c, limit=1)[0]
        assert newest.action == "enabled" and newest.id > 4

    def test_a_database_that_already_holds_data_is_never_overwritten(self, tmp_path, capsys) -> None:
        source = tmp_path / "old.sqlite3"
        legacy.build(source, "v4")
        assert token_admin.main(["db", "import-sqlite", str(source)]) == 0
        capsys.readouterr()
        assert token_admin.main(["db", "import-sqlite", str(source)]) == token_admin.EXIT_CONFIG
        assert "already holds data" in capsys.readouterr().err

    def test_an_empty_schema_is_filled_in_place(self, tmp_path, capsys) -> None:
        # `db upgrade` (or an earlier refusal) left a current schema without rows.
        source = tmp_path / "old.sqlite3"
        legacy.build(source, "v4")
        assert token_admin.main(["db", "upgrade"]) == 0
        assert migrate.current(self._db()).state == migrate.STATE_CURRENT
        assert token_admin.main(["db", "import-sqlite", str(source)]) == 0
        capsys.readouterr()
        store = self._store()
        store.initialize(auto_migrate=False)
        assert store.count() == 4

    def test_a_token_that_does_not_decrypt_rolls_everything_back(
        self, tmp_path, monkeypatch, capsys
    ) -> None:
        # k2 is the wrong key: the tokens sealed under it cannot be re-encrypted. The
        # failure is in the migration of the private copy and says so; PostgreSQL has
        # not been touched, not even its schema.
        source = tmp_path / "old.sqlite3"
        legacy.build(source, "v4")
        before = source.read_bytes()
        wrong = "k2:" + base64.b64encode(bytes([9]) * 32).decode() + ",k1:" + base64.b64encode(bytes([1]) * 32).decode()
        monkeypatch.setenv("CANVAS_TOKEN_KEYS", wrong)
        assert token_admin.main(["db", "import-sqlite", str(source)]) == token_admin.EXIT_CONFIG
        err = capsys.readouterr().err
        assert "could not be migrated to the current schema" in err
        assert "does not decrypt with CANVAS_TOKEN_KEYS" in err
        assert "Nothing was imported" in err
        assert "db upgrade" not in err  # that command would not help here
        assert "--mark-undecryptable-invalid" in err
        assert wrong not in err
        assert source.read_bytes() == before
        assert migrate.current(self._db()).state == migrate.STATE_UNINITIALIZED
        monkeypatch.setenv("CANVAS_TOKEN_KEYS", KEYS)
        store = self._store()
        store.initialize()
        assert store.count() == 0 and store.list_principal_statuses() == []

    def test_undecryptable_tokens_can_be_marked_invalid_during_the_import(
        self, tmp_path, monkeypatch, capsys
    ) -> None:
        source = tmp_path / "old.sqlite3"
        seeded = legacy.build(source, "v4")
        wrong = "k2:" + base64.b64encode(bytes([9]) * 32).decode() + ",k1:" + base64.b64encode(bytes([1]) * 32).decode()
        monkeypatch.setenv("CANVAS_TOKEN_KEYS", wrong)
        argv = ["db", "import-sqlite", str(source), "--mark-undecryptable-invalid"]
        assert token_admin.main(argv) == 0
        capsys.readouterr()
        monkeypatch.setenv("CANVAS_TOKEN_KEYS", wrong)
        store = TokenStore(self._db(), Keyring.parse(wrong))
        store.initialize(auto_migrate=False)
        a = store.resolve_legacy_key(legacy.KEY_A)  # sealed under k1: still readable
        row = store.get(a)
        assert row is not None and row.api_token == seeded.plaintexts[legacy.KEY_A]
        b = store.resolve_legacy_key(legacy.KEY_B)  # sealed under k2: marked invalid
        info = {e.principal_key: e for e in store.list_enrollments()}
        assert info[b].status == "invalid" and info[b].invalid_reason == "decrypt_failed"
        assert info[a].status == "active"
        # A principal the account migration does not map is marked the same way.
        assert info[legacy.KEY_OTHER].status == "invalid"

    def test_a_failure_inside_the_transaction_leaves_no_schema_behind(
        self, tmp_path, monkeypatch, capsys
    ) -> None:
        # The copy migrated fine; the PostgreSQL transaction fails after the schema
        # and every row were written. DDL is transactional: all of it is rolled back.
        from canvas_mcp.core.selfhost.db import transfer

        source = tmp_path / "old.sqlite3"
        legacy.build(source, "v4")

        def broken(*_args, **_kwargs) -> None:
            raise TokenStoreError("simulated failure after the copy; nothing was imported")

        monkeypatch.setattr(transfer, "_verify_tokens", broken)
        assert token_admin.main(["db", "import-sqlite", str(source)]) == token_admin.EXIT_CONFIG
        assert "simulated failure" in capsys.readouterr().err
        assert migrate.current(self._db()).state == migrate.STATE_UNINITIALIZED
        assert not transfer.target_holds_rows(self._db())

    def test_a_version_1_file_is_adopted_in_the_copy_and_imported(self, tmp_path, capsys) -> None:
        source = tmp_path / "old.sqlite3"
        seeded = legacy.build(source, "v1")
        assert token_admin.main(["db", "import-sqlite", str(source)]) == 0
        capsys.readouterr()
        store = self._store()
        store.initialize(auto_migrate=False)
        account = store.resolve_legacy_key(legacy.KEY_A)
        assert account is not None
        row = store.get(account)
        assert row is not None and row.api_token == seeded.plaintexts[legacy.KEY_A]
        assert migrate.current(self._db()).meta_version == "5"
        conn = sqlite3.connect(str(source))
        assert conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone() == ("1",)
        conn.close()

    def test_current_and_upgrade_work_on_postgres(self, capsys) -> None:
        assert token_admin.main(["db", "current"]) == token_admin.EXIT_BEHIND
        assert "state: uninitialized" in capsys.readouterr().out
        assert token_admin.main(["db", "upgrade"]) == 0
        capsys.readouterr()
        assert token_admin.main(["db", "current"]) == 0
        out = capsys.readouterr().out
        assert "postgresql+psycopg://" in out and "state: current" in out
        assert "canvas:" not in out  # no user name, password or query
        assert token_admin.main(["db", "upgrade", "--backup", "/tmp/x"]) == token_admin.EXIT_CONFIG
        assert "pg_dump" in capsys.readouterr().err
