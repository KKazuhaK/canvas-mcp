"""A database without data next to a SQLite file with data is refused, by data not schema.

Starting on such a database would drop the disablements stored in the SQLite file
and let a disabled user enroll again. The refusal must not be disarmed by anything
that only creates the schema (``db upgrade``, a read-only CLI command, an import
that failed): what counts is whether the target holds rows.
"""

from __future__ import annotations

import base64
import pathlib

import pytest
from dbbackend import PG_URL, reset_public_schema

from canvas_mcp.core.selfhost import token_admin
from canvas_mcp.core.selfhost.app import prepare_selfhost
from canvas_mcp.core.selfhost.db import migrate
from canvas_mcp.core.selfhost.db.engine import Database
from canvas_mcp.core.selfhost.db.transfer import refuse_silent_switch, target_holds_rows
from canvas_mcp.core.selfhost.db.url import default_sqlite_path
from canvas_mcp.core.selfhost.settings import (
    SelfhostConfigError,
    load_selfhost_settings,
)
from canvas_mcp.core.selfhost.token_store import (
    OPERATOR,
    Keyring,
    TokenStore,
    TokenStoreError,
)

from . import legacy_schemas as legacy

KEYS = "k1:" + base64.b64encode(bytes([1]) * 32).decode()
TENANT = "11111111-2222-3333-4444-555555555555"
OID = "aaaaaaaa-0000-4000-8000-00000000000a"
OTHER = "bbbbbbbb-0000-4000-8000-00000000000b"


def _settings_env(data_dir: pathlib.Path, **extra: str) -> dict[str, str]:
    return {
        "PUBLIC_BASE_URL": "https://canvas.example.test",
        "ENTRA_TENANT_ID": TENANT,
        "ENTRA_CLIENT_ID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "ENTRA_CLIENT_SECRET": "s3cret-value-of-entra-client",
        "OAUTH_JWT_SIGNING_KEY": "k" * 48,
        "ACCOUNT_SESSION_SECRET": base64.b64encode(bytes(range(32))).decode(),
        "CANVAS_TOKEN_KEYS": KEYS,
        "FASTMCP_HOME": str(data_dir / "fastmcp"),
        "SELFHOST_DATA_DIR": str(data_dir),
        **extra,
    }


def _other_url(data_dir: pathlib.Path) -> str:
    return "sqlite:///" + (data_dir / "other.sqlite3").as_posix()


def _disabled_legacy_file(data_dir: pathlib.Path) -> pathlib.Path:
    """The default SQLite file with one disabled user, as a pre-switch server left it."""
    path = default_sqlite_path(data_dir)
    store = TokenStore(path, Keyring.parse(KEYS))
    store.initialize()
    store.disable_principal(TENANT, OID, actor=OPERATOR, reason="operator_disabled")
    store.close()
    return path


@pytest.fixture
def env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    monkeypatch.setenv("SELFHOST_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", KEYS)
    for name in ("DATABASE_URL", "DATABASE_AUTO_MIGRATE", "DATABASE_ALLOW_SQLITE_OUTSIDE_DATA_DIR"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


class TestTheCheck:
    def test_a_target_that_does_not_exist_yet_is_refused(self, tmp_path) -> None:
        legacy_path = _disabled_legacy_file(tmp_path)
        target = Database.sqlite(tmp_path / "other.sqlite3")
        with pytest.raises(TokenStoreError, match="holds no data"):
            refuse_silent_switch(target, legacy_path)
        assert not (tmp_path / "other.sqlite3").exists()  # checking creates nothing

    def test_a_current_schema_without_rows_is_refused(self, tmp_path) -> None:
        legacy_path = _disabled_legacy_file(tmp_path)
        target = Database.sqlite(tmp_path / "other.sqlite3")
        migrate.ensure_ready(target, auto=True)
        assert migrate.current(target).state == migrate.STATE_CURRENT
        assert not target_holds_rows(target)
        with pytest.raises(TokenStoreError, match="holds no data"):
            refuse_silent_switch(target, legacy_path)

    def test_a_target_with_rows_is_the_operators_choice(self, tmp_path) -> None:
        legacy_path = _disabled_legacy_file(tmp_path)
        target = Database.sqlite(tmp_path / "other.sqlite3")
        store = TokenStore(target, Keyring.parse(KEYS))
        store.initialize()
        store.disable_principal(TENANT, OTHER, actor=OPERATOR, reason="operator_disabled")
        assert target_holds_rows(target)
        refuse_silent_switch(target, legacy_path)

    def test_a_missing_or_empty_legacy_file_is_harmless(self, tmp_path) -> None:
        target = Database.sqlite(tmp_path / "other.sqlite3")
        refuse_silent_switch(target, default_sqlite_path(tmp_path))  # no file
        legacy_path = default_sqlite_path(tmp_path)
        TokenStore(legacy_path, Keyring.parse(KEYS)).initialize()  # file, no rows
        refuse_silent_switch(target, legacy_path)

    def test_the_default_file_itself_is_never_a_switch(self, tmp_path) -> None:
        legacy_path = _disabled_legacy_file(tmp_path)
        refuse_silent_switch(Database.sqlite(legacy_path), legacy_path)

    def test_a_database_this_build_refuses_anyway_is_left_to_the_migration_check(
        self, tmp_path
    ) -> None:
        legacy_path = _disabled_legacy_file(tmp_path)
        target = Database.sqlite(tmp_path / "other.sqlite3")
        migrate.ensure_ready(target, auto=True)
        with target.write() as conn:
            conn.exec_driver_sql("UPDATE meta SET value = '999' WHERE key = 'schema_version'")
        assert migrate.current(target).state == migrate.STATE_NEWER
        refuse_silent_switch(target, legacy_path)  # ensure_ready says "newer" itself


class TestStartup:
    def test_an_empty_schema_does_not_disarm_the_server(self, env) -> None:
        _disabled_legacy_file(env)
        # What `token_admin db upgrade` (or a failed import) leaves: a schema, no rows.
        migrate.ensure_ready(Database.sqlite(env / "other.sqlite3"), auto=True)
        settings = load_selfhost_settings(_settings_env(env, DATABASE_URL=_other_url(env)))
        with pytest.raises(SelfhostConfigError) as refused:
            prepare_selfhost(settings)
        assert "holds no data" in " ".join(refused.value.problems)

    def test_a_missing_target_is_refused_before_anything_is_created(self, env) -> None:
        _disabled_legacy_file(env)
        settings = load_selfhost_settings(_settings_env(env, DATABASE_URL=_other_url(env)))
        with pytest.raises(SelfhostConfigError):
            prepare_selfhost(settings)
        assert not (env / "other.sqlite3").exists()

    def test_a_target_with_data_starts(self, env) -> None:
        _disabled_legacy_file(env)
        target = Database.sqlite(env / "other.sqlite3")
        store = TokenStore(target, Keyring.parse(KEYS))
        store.initialize()
        store.disable_principal(TENANT, OID, actor=OPERATOR, reason="operator_disabled")
        store.close()
        settings = load_selfhost_settings(_settings_env(env, DATABASE_URL=_other_url(env)))
        runtime = prepare_selfhost(settings)
        assert runtime.store.get_principal_status(f"entra:{TENANT}:{OID}").disabled
        runtime.store.close()

    def test_the_default_layout_starts_unchanged(self, env) -> None:
        _disabled_legacy_file(env)
        runtime = prepare_selfhost(load_selfhost_settings(_settings_env(env)))
        assert runtime.store.get_principal_status(f"entra:{TENANT}:{OID}").disabled
        runtime.store.close()


class TestOperatorCli:
    @pytest.fixture(autouse=True)
    def _target(self, env, monkeypatch) -> None:
        _disabled_legacy_file(env)
        monkeypatch.setenv("DATABASE_URL", _other_url(env))

    @pytest.mark.parametrize(
        "argv",
        [
            ["check"],
            ["list"],
            ["access"],
            ["history"],
            ["disable", TENANT, OTHER],
            ["enable", TENANT, OID],
            ["remove", TENANT, OID],
            ["rotate"],
        ],
    )
    def test_commands_refuse_an_empty_target_and_create_nothing(self, env, argv, capsys) -> None:
        assert token_admin.main(argv) == token_admin.EXIT_CONFIG
        assert "holds no data" in capsys.readouterr().err
        assert not (env / "other.sqlite3").exists()

    def test_a_disable_cannot_make_the_empty_target_look_populated(self, env, capsys) -> None:
        assert token_admin.main(["disable", TENANT, OTHER]) == token_admin.EXIT_CONFIG
        capsys.readouterr()
        settings = load_selfhost_settings(_settings_env(env, DATABASE_URL=_other_url(env)))
        with pytest.raises(SelfhostConfigError):
            prepare_selfhost(settings)

    def test_db_upgrade_works_but_leaves_the_server_refusing(self, env, capsys) -> None:
        assert token_admin.main(["db", "upgrade"]) == 0
        assert token_admin.main(["db", "current"]) == 0
        capsys.readouterr()
        settings = load_selfhost_settings(_settings_env(env, DATABASE_URL=_other_url(env)))
        with pytest.raises(SelfhostConfigError):
            prepare_selfhost(settings)


@pytest.mark.postgres
class TestPostgres:
    @pytest.fixture(autouse=True)
    def _target(self, env, monkeypatch) -> None:
        reset_public_schema()
        _disabled_legacy_file(env)
        monkeypatch.setenv("DATABASE_URL", PG_URL)

    def _prepare(self, env: pathlib.Path) -> None:
        prepare_selfhost(load_selfhost_settings(_settings_env(env, DATABASE_URL=PG_URL)))

    def test_an_empty_database_is_refused_and_import_is_the_way_across(self, env, capsys) -> None:
        with pytest.raises(SelfhostConfigError) as refused:
            self._prepare(env)
        assert "db import-sqlite" in " ".join(refused.value.problems)
        assert token_admin.main(["db", "import-sqlite", str(default_sqlite_path(env))]) == 0
        capsys.readouterr()
        self._prepare(env)

    def test_a_failed_import_leaves_the_server_refusing(self, env, monkeypatch, capsys) -> None:
        # A key ring that lacks the key id of a stored token: the data is rolled
        # back, the schema stays, and the server must still refuse.
        source = env / "old.sqlite3"
        legacy.build(source, "v4")
        assert token_admin.main(["db", "import-sqlite", str(source)]) == token_admin.EXIT_CONFIG
        capsys.readouterr()
        assert migrate.current(_pg()).state == migrate.STATE_CURRENT
        with pytest.raises(SelfhostConfigError):
            self._prepare(env)

    def test_a_read_only_command_leaves_the_server_refusing(self, env, capsys) -> None:
        assert token_admin.main(["list"]) == token_admin.EXIT_CONFIG
        assert token_admin.main(["db", "upgrade"]) == 0
        capsys.readouterr()
        with pytest.raises(SelfhostConfigError):
            self._prepare(env)


def _pg() -> Database:
    from canvas_mcp.core.selfhost.db.url import parse_database_url

    return Database(parse_database_url(PG_URL, pathlib.Path("/data")))
