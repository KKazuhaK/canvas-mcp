"""DATABASE_URL and the related settings: validation, redaction, fail-closed values."""

from __future__ import annotations

import base64
import logging
import sys
from pathlib import Path

import pytest

from canvas_mcp.core.selfhost.db.url import parse_database_url
from canvas_mcp.core.selfhost.settings import (
    SelfhostConfigError,
    load_selfhost_settings,
)

DATA = Path("/data")
PASSWORD = "pw0rd-must-never-show"
GOOD_PG = "postgresql+psycopg://canvas:s3cr3tpw@db.internal:5432/canvas_mcp"


def _env(**overrides: str | None) -> dict[str, str]:
    env = {
        "PUBLIC_BASE_URL": "https://canvas.example.test",
        "ENTRA_TENANT_ID": "11111111-2222-3333-4444-555555555555",
        "ENTRA_CLIENT_ID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "ENTRA_CLIENT_SECRET": "s3cret-value-of-entra-client",
        "OAUTH_JWT_SIGNING_KEY": "k" * 48,
        "ACCOUNT_SESSION_SECRET": base64.b64encode(bytes(range(32))).decode(),
        "CANVAS_TOKEN_KEYS": "k1:" + base64.b64encode(bytes(32)).decode(),
        "FASTMCP_HOME": "/data/fastmcp",
    }
    for key, value in overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return env


def _problems(**overrides: str | None) -> list[str]:
    with pytest.raises(SelfhostConfigError) as info:
        load_selfhost_settings(_env(**overrides))
    return info.value.problems


class TestDefault:
    def test_unset_and_empty_keep_the_sqlite_file_in_the_data_directory(self) -> None:
        for value in (None, "", "   "):
            settings = load_selfhost_settings(_env(DATABASE_URL=value))
            target = settings.database_target
            assert target.kind == "sqlite"
            assert target.sqlite_path == Path("/data/canvas-mcp/tokens.sqlite3")
            assert target.description == str(Path("/data/canvas-mcp/tokens.sqlite3"))
            assert settings.token_db_path == target.sqlite_path

    def test_migration_and_state_defaults(self) -> None:
        settings = load_selfhost_settings(_env())
        assert settings.auto_migrate is True
        assert settings.state_backend == "memory"


class TestPostgresUrls:
    def test_a_postgres_url_selects_postgres_and_hides_the_credentials(self) -> None:
        settings = load_selfhost_settings(_env(DATABASE_URL=GOOD_PG))
        target = settings.database_target
        assert target.kind == "postgresql"
        assert target.description == "postgresql+psycopg://db.internal:5432/canvas_mcp"
        for text in (repr(settings), repr(target), target.description):
            assert "s3cr3tpw" not in text and "canvas:" not in text

    def test_the_port_defaults_and_ipv6_hosts_are_bracketed_in_the_description(self) -> None:
        target = parse_database_url("postgresql+psycopg://u:p@db.internal/app", DATA)
        assert target.description == "postgresql+psycopg://db.internal:5432/app"
        v6 = parse_database_url("postgresql+psycopg://u:p@[::1]:5433/app", DATA)
        assert v6.description == "postgresql+psycopg://[::1]:5433/app"

    @pytest.mark.parametrize(
        "query",
        [
            "sslmode=verify-full",
            "sslmode=require&connect_timeout=10",
            "sslrootcert=/etc/ssl/ca.pem&sslmode=verify-ca",
            "application_name=canvas-mcp-2",
        ],
    )
    def test_the_allowlisted_query_parameters_are_accepted(self, query: str) -> None:
        target = parse_database_url(f"{GOOD_PG}?{query}", DATA)
        assert target.kind == "postgresql"
        assert "sslmode" not in target.description and "?" not in target.description

    @pytest.mark.parametrize(
        "query",
        [
            "options=-c%20statement_timeout%3D0",
            "sslmode=maybe",
            "connect_timeout=0",
            "connect_timeout=abc",
            "application_name=has%20space",
            "target_session_attrs=any",
            "host=/var/run/postgresql",
            "sslmode=require&sslmode=disable",
            "sslcert=",
        ],
    )
    def test_everything_else_in_the_query_is_refused(self, query: str) -> None:
        problems = _problems(DATABASE_URL=f"{GOOD_PG}?{query}")
        assert any("DATABASE_URL" in p for p in problems)

    @pytest.mark.parametrize(
        "url",
        [
            "postgresql://u:p@h/db",
            "postgres://u:p@h/db",
            "postgresql+psycopg2://u:p@h/db",
            "postgresql+asyncpg://u:p@h/db",
            "mysql://u:p@h/db",
            "postgresql+psycopg://u:p@/db",
            "postgresql+psycopg://u:p@h",
            "postgresql+psycopg://u:p@h/",
            "postgresql+psycopg://u:p@h1,h2/db",
            "postgresql+psycopg://u:p@ss@h/db",
            "postgresql+psycopg://u:p@h:notaport/db",
            "postgresql+psycopg://u:p@h/db#frag",
            "postgresql+psycopg://u:p@h/db/extra",
            "not a url",
            "db.internal",
        ],
    )
    def test_malformed_or_wrong_scheme_urls_are_refused_without_echoing_them(self, url: str) -> None:
        problems = _problems(DATABASE_URL=url)
        text = " ".join(problems)
        assert "DATABASE_URL" in text
        assert url not in text and ":p@" not in text

    def test_a_password_never_appears_in_any_message(self) -> None:
        url = f"postgresql+psycopg://canvas:{PASSWORD}@h/db?bogus=1"
        text = " ".join(_problems(DATABASE_URL=url))
        assert PASSWORD not in text and "pw0rd" not in text

    def test_redis_is_reserved_not_implemented(self) -> None:
        for url in ("redis://cache:6379/0", "rediss://cache:6380/0"):
            text = " ".join(_problems(DATABASE_URL=url))
            assert "Redis is reserved" in text and "cache" not in text


class TestSqliteUrls:
    def test_a_file_inside_the_data_directory_is_accepted(self) -> None:
        target = parse_database_url("sqlite:////data/canvas-mcp/other.sqlite3", DATA)
        assert target.kind == "sqlite" and target.sqlite_path == Path("/data/canvas-mcp/other.sqlite3")
        also = parse_database_url("sqlite+pysqlite:////data/x.db", DATA)
        assert also.sqlite_path == Path("/data/x.db")

    @pytest.mark.parametrize(
        "url",
        [
            "sqlite://",
            "sqlite:///:memory:",
            "sqlite:///relative/path.db",
            "sqlite:////data/x.db?mode=memory&uri=true",
            "sqlite:////data/x.db?uri=true",
            "sqlite:////data/../etc/x.db",
            "sqlite:///",
        ],
    )
    def test_memory_relative_query_and_dotdot_forms_are_refused(self, url: str) -> None:
        assert any("DATABASE_URL" in p for p in _problems(DATABASE_URL=url))

    def test_a_file_outside_the_data_directory_needs_an_explicit_opt_in(self) -> None:
        url = "sqlite:////srv/elsewhere/tokens.sqlite3"
        assert any("outside SELFHOST_DATA_DIR" in p for p in _problems(DATABASE_URL=url))
        settings = load_selfhost_settings(
            _env(DATABASE_URL=url, DATABASE_ALLOW_SQLITE_OUTSIDE_DATA_DIR="true")
        )
        assert settings.database_target.sqlite_path == Path("/srv/elsewhere/tokens.sqlite3")

    def test_the_opt_in_must_be_a_boolean(self) -> None:
        assert any(
            "DATABASE_ALLOW_SQLITE_OUTSIDE_DATA_DIR" in p
            for p in _problems(DATABASE_ALLOW_SQLITE_OUTSIDE_DATA_DIR="maybe")
        )


class TestMigrationAndStateSettings:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [("true", True), ("1", True), ("yes", True), ("", True), ("false", False), ("0", False), ("no", False)],
    )
    def test_auto_migrate_parsing(self, value: str, expected: bool) -> None:
        assert load_selfhost_settings(_env(DATABASE_AUTO_MIGRATE=value)).auto_migrate is expected

    def test_auto_migrate_garbage_is_a_problem(self) -> None:
        assert any("DATABASE_AUTO_MIGRATE" in p for p in _problems(DATABASE_AUTO_MIGRATE="sometimes"))

    def test_the_memory_backend_is_accepted_and_redis_fails_closed(self) -> None:
        assert load_selfhost_settings(_env(SELFHOST_STATE_BACKEND="memory")).state_backend == "memory"
        text = " ".join(_problems(SELFHOST_STATE_BACKEND="redis"))
        assert "reserved and not implemented" in text
        assert any("SELFHOST_STATE_BACKEND" in p for p in _problems(SELFHOST_STATE_BACKEND="etcd"))

    def test_every_problem_is_reported_together(self) -> None:
        problems = _problems(
            DATABASE_URL="mysql://x", DATABASE_AUTO_MIGRATE="??", SELFHOST_STATE_BACKEND="redis"
        )
        assert len(problems) == 3


class TestStartup:
    def test_missing_data_layer_packages_are_a_startup_problem(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from canvas_mcp.core.selfhost.app import _data_layer_problem

        settings = load_selfhost_settings(_env())
        assert _data_layer_problem(settings) is None
        monkeypatch.setitem(sys.modules, "alembic", None)
        assert "canvas-mcp[selfhost]" in (_data_layer_problem(settings) or "")
        monkeypatch.delitem(sys.modules, "alembic")
        pg = load_selfhost_settings(_env(DATABASE_URL=GOOD_PG))
        monkeypatch.setitem(sys.modules, "psycopg", None)
        assert "canvas-mcp[postgres]" in (_data_layer_problem(pg) or "")

    def test_an_empty_postgres_next_to_a_sqlite_file_with_data_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from canvas_mcp.core.selfhost.app import _refuse_silent_database_switch
        from canvas_mcp.core.selfhost.db import migrate
        from canvas_mcp.core.selfhost.token_store import (
            OPERATOR,
            Keyring,
            TokenStore,
            TokenStoreError,
        )

        keyring = Keyring.parse("k1:" + base64.b64encode(bytes(32)).decode())
        settings = load_selfhost_settings(_env(SELFHOST_DATA_DIR=str(tmp_path), DATABASE_URL=GOOD_PG))
        old = TokenStore(settings.token_db_path, keyring)
        old.initialize()
        pg_store = TokenStore.for_target(settings.database_target, keyring)
        state = {"value": migrate.STATE_UNINITIALIZED}
        monkeypatch.setattr(
            migrate,
            "current",
            lambda db: migrate.MigrationStatus("postgresql", None, None, "h", state["value"]),
        )
        # An empty legacy file is harmless.
        _refuse_silent_database_switch(settings, pg_store)
        old.disable_principal(
            "11111111-2222-3333-4444-555555555555",
            "aaaaaaaa-0000-4000-8000-00000000000a",
            actor=OPERATOR,
            reason="operator_disabled",
        )
        with pytest.raises(TokenStoreError) as refused:
            _refuse_silent_database_switch(settings, pg_store)
        message = str(refused.value)
        assert "db import-sqlite" in message and "s3cr3tpw" not in message
        # An initialised PostgreSQL database is the operator's choice: no objection.
        state["value"] = migrate.STATE_CURRENT
        _refuse_silent_database_switch(settings, pg_store)

    def test_the_url_never_reaches_the_log_or_an_error(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        from canvas_mcp.core.selfhost.app import prepare_selfhost

        url = f"postgresql+psycopg://canvas:{PASSWORD}@127.0.0.1:1/db?connect_timeout=1"
        settings = load_selfhost_settings(_env(SELFHOST_DATA_DIR=str(tmp_path), DATABASE_URL=url))
        caplog.set_level(logging.DEBUG)
        with pytest.raises(SelfhostConfigError) as refused:
            prepare_selfhost(settings)
        text = " ".join(refused.value.problems) + caplog.text
        assert PASSWORD not in text
        assert "127.0.0.1" not in text  # not even the host leaks through an error
