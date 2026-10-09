"""The SQL every repository statement compiles to, per dialect.

PostgreSQL only runs in CI (and locally when ``CANVAS_MCP_TEST_DATABASE_URL`` is
set), so these tests compile each statement for the PostgreSQL dialect and check
the properties the race-safety argument relies on, without a server: upserts
use ON CONFLICT, rows that are read and then written are locked with FOR UPDATE,
the writer lock is taken before any data statement, conditional updates carry
their version guards, and no value is ever inlined into the SQL text.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy.dialects import postgresql, sqlite

from canvas_mcp.core.selfhost.db import engine as db_engine
from canvas_mcp.core.selfhost.db.repos import Repositories

PG = postgresql.dialect()  # type: ignore[no-untyped-call]
LITE = sqlite.dialect()  # type: ignore[no-untyped-call]

SECRET_KEY = "entra:11111111-2222-3333-4444-555555555555:aaaaaaaa-0000-4000-8000-00000000000a"
SECRET_BLOB = b"ciphertext-that-must-never-be-inlined"


class _Result:
    rowcount = 1

    def all(self) -> list[Any]:
        return []

    def one_or_none(self) -> Any:
        return None

    def first(self) -> Any:
        return None

    def one(self) -> Any:
        return (None,) * 12

    def scalar_one(self) -> Any:
        return 0

    def scalar_one_or_none(self) -> Any:
        return None

    def __iter__(self) -> Any:
        return iter(())


class RecordingConnection:
    """Stands in for a Connection: records the compiled SQL and its parameters."""

    def __init__(self, dialect: Any) -> None:
        self.dialect = dialect
        self.statements: list[tuple[str, dict[str, Any]]] = []

    def execute(self, stmt: Any, *args: Any) -> _Result:
        compiled = stmt.compile(dialect=self.dialect)
        self.statements.append((str(compiled), dict(compiled.params)))
        return _Result()

    @property
    def sql(self) -> list[str]:
        return [s for s, _ in self.statements]


def _run_everything(dialect: Any, name: str) -> list[tuple[str, dict[str, Any]]]:
    repos = Repositories(name)  # type: ignore[arg-type]
    conn: Any = RecordingConnection(dialect)
    repos.tokens.row_for_get(conn, SECRET_KEY)
    repos.tokens.info(conn, SECRET_KEY)
    repos.tokens.list_all(conn)
    repos.tokens.count(conn)
    for keep in (True, False):
        repos.tokens.upsert(
            conn, tenant_id="t", object_id="o", key_id="k1", nonce=b"n" * 12, ciphertext=SECRET_BLOB,
            canvas_user_id="1", canvas_user_name="n", entra_display_name="d", entra_upn="u",
            canvas_host="h", principal_key=SECRET_KEY, status="active", now=5,
            expires_hint_at=4_000_000_000, keep_expiry_hint=keep,
        )
    repos.tokens.delete(conn, SECRET_KEY)
    repos.tokens.touch(conn, SECRET_KEY, 10, 5)
    repos.tokens.mark_invalid(
        conn, SECRET_KEY, reason="canvas_token_rejected", now=1, expected_updated_at=3, expected_generation=2
    )
    repos.tokens.restore_active(conn, SECRET_KEY, now=1, expected_updated_at=3, expected_generation=2)
    repos.tokens.mark_verified(conn, SECRET_KEY, now=1, older_than=0, expected_generation=2)
    repos.tokens.names(conn, SECRET_KEY)
    repos.tokens.rows_not_under_key(conn, "k1")
    repos.tokens.reseal(conn, tenant_id="t", object_id="o", key_id="k", nonce=b"n", ciphertext=SECRET_BLOB)
    repos.tokens.key_ids_in_use(conn)
    repos.tokens.probe_row(conn, "k1")
    repos.generations.bump(conn, SECRET_KEY, "enrolled", 5)
    repos.status.get(conn, SECRET_KEY, for_update=True)
    repos.status.get_with_generation(conn, SECRET_KEY)
    repos.status.list_all(conn)
    repos.status.count_active_owners(conn, exclude=SECRET_KEY)
    repos.status.gate_status(conn, SECRET_KEY)
    repos.status.insert_owner_seen(conn, SECRET_KEY, 5)
    repos.status.set_owner_flag(conn, SECRET_KEY, True, 5)
    repos.status.demote(conn, SECRET_KEY, 5)
    repos.status.upsert_disabled(conn, SECRET_KEY, reason="r", by="b", display_name="d", upn="u", now=5)
    repos.status.enable(conn, SECRET_KEY, 5)
    repos.events.append(conn, SECRET_KEY, "disabled", "actor", "reason", 1, 5)
    repos.events.list_events(conn, SECRET_KEY, 10)
    repos.prefs.get(conn, SECRET_KEY)
    repos.prefs.upsert(conn, SECRET_KEY, names_json="[]", stamps_json="{}", now=5, via="v")
    repos.meta.schema_version(conn)
    repos.meta.set_schema_version(conn, "4")
    return conn.statements


@pytest.mark.parametrize(("dialect", "name"), [(PG, "postgresql"), (LITE, "sqlite")])
class TestCompiledStatements:
    def test_every_statement_compiles_and_inlines_no_value(self, dialect: Any, name: str) -> None:
        statements = _run_everything(dialect, name)
        assert len(statements) > 30
        for sql, _ in statements:
            assert SECRET_KEY not in sql
            assert "ciphertext-that-must-never" not in sql
            assert "4000000000" not in sql  # the hint is bound, not inlined

    def test_upserts_are_one_statement_with_on_conflict(self, dialect: Any, name: str) -> None:
        sql = "\n".join(s for s, _ in _run_everything(dialect, name))
        assert sql.count("ON CONFLICT (principal_key) DO UPDATE SET") >= 4
        assert "ON CONFLICT (principal_key) DO UPDATE SET key_id = excluded.key_id" in sql

    def test_a_kept_expiry_hint_is_left_out_of_the_update_not_cased(
        self, dialect: Any, name: str
    ) -> None:
        upserts = [
            s
            for s, _ in _run_everything(dialect, name)
            if s.startswith("INSERT INTO canvas_tokens")
        ]
        assert len(upserts) == 2
        keep, replace = upserts
        assert "expires_hint_at = excluded.expires_hint_at" not in keep
        assert "expires_hint_at = excluded.expires_hint_at" in replace
        assert "CASE" not in keep and "CASE" not in replace

    def test_conditional_updates_carry_their_version_guards(self, dialect: Any, name: str) -> None:
        updates = [
            s
            for s, _ in _run_everything(dialect, name)
            if s.startswith("UPDATE canvas_tokens SET status")
            or s.startswith("UPDATE canvas_tokens SET last_verified_at")
        ]
        assert len(updates) == 3
        for sql in updates:
            assert "canvas_tokens.principal_key =" in sql
            assert "canvas_tokens.status =" in sql
        invalid, restore, verified = updates
        assert "canvas_tokens.updated_at =" in invalid and "canvas_tokens.updated_at =" in restore
        for sql in (invalid, restore, verified):
            # The generation guard is a correlated subquery over credential_generations.
            assert "FROM credential_generations" in sql
            assert "credential_generations.principal_key = canvas_tokens.principal_key" in sql
            assert "coalesce" in sql.lower()

    def test_the_token_row_and_its_generation_come_from_one_statement(
        self, dialect: Any, name: str
    ) -> None:
        reads = [s for s, _ in _run_everything(dialect, name) if "canvas_tokens.canvas_user_id" in s]
        assert reads and all("FROM credential_generations" in s for s in reads)
        status = [s for s, _ in _run_everything(dialect, name) if "credential_generation" in s and "anchor" in s]
        assert len(status) == 1 and "LEFT OUTER JOIN" in status[0]

    def test_the_generation_is_raised_in_place_never_set_from_a_stale_read(
        self, dialect: Any, name: str
    ) -> None:
        bump = next(
            s for s, _ in _run_everything(dialect, name) if s.startswith("INSERT INTO credential_generations")
        )
        assert "generation = (credential_generations.generation + " in bump

    def test_disable_raises_the_epoch_in_place(self, dialect: Any, name: str) -> None:
        sql = next(
            s for s, _ in _run_everything(dialect, name) if s.startswith("INSERT INTO principal_status ")
            and "session_epoch" in s and "disabled_reason" in s
        )
        assert "session_epoch = (principal_status.session_epoch + " in sql


class TestRowLocks:
    def test_rows_read_and_then_written_are_locked_on_postgresql(self) -> None:
        statements = _run_everything(PG, "postgresql")
        locked = [s for s, _ in statements if s.rstrip().endswith("FOR UPDATE")]
        assert any("FROM principal_status" in s and "principal_status.status" in s for s in locked)
        assert any("principal_status.principal_key =" in s and "is_owner" in s for s in locked)

    def test_sqlite_has_no_row_locks(self) -> None:
        assert not any("FOR UPDATE" in s for s, _ in _run_everything(LITE, "sqlite"))


class TestPostgresDialectSpecifics:
    def test_key_columns_sort_in_binary_order(self) -> None:
        sql = "\n".join(s for s, _ in _run_everything(PG, "postgresql"))
        assert "ORDER BY principal_status.principal_key" in sql
        from sqlalchemy.schema import CreateTable

        from canvas_mcp.core.selfhost.db import schema

        ddl = str(CreateTable(schema.canvas_tokens).compile(dialect=PG))
        assert 'tenant_id TEXT COLLATE "C" NOT NULL' in ddl
        assert "created_at BIGINT NOT NULL" in ddl

    def test_the_writer_lock_key_is_a_fixed_signed_64_bit_integer(self) -> None:
        assert -(2**63) <= db_engine.WRITER_LOCK_KEY < 2**63
        assert db_engine.WRITER_LOCK_KEY != db_engine.MIGRATION_LOCK_KEY
        assert db_engine._ADVISORY_XACT_SQL == f"SELECT pg_advisory_xact_lock({db_engine.WRITER_LOCK_KEY})"
        # sha256("canvas-mcp/token-store/writer") must stay the key forever: an older
        # and a newer server share the lock only if they derive the same number.
        assert db_engine.WRITER_LOCK_KEY == db_engine._advisory_key("canvas-mcp/token-store/writer")

    def test_a_postgres_write_takes_the_lock_before_any_other_statement(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from canvas_mcp.core.selfhost.db.url import parse_database_url

        executed: list[str] = []

        class FakeConn:
            def execution_options(self, **_: Any) -> FakeConn:
                return self

            def begin(self) -> Any:
                class Trans:
                    def commit(self) -> None:
                        executed.append("COMMIT")

                    def rollback(self) -> None:
                        executed.append("ROLLBACK")

                return Trans()

            def execute(self, stmt: Any, *_: Any) -> None:
                executed.append(str(stmt))

            def close(self) -> None:
                executed.append("CLOSE")

        from pathlib import Path

        db = db_engine.Database(
            parse_database_url("postgresql+psycopg://u:p@db.example:5432/app", Path("/data"))
        )
        monkeypatch.setattr(db._engine, "connect", lambda: FakeConn())  # type: ignore[attr-defined]
        with db.write() as conn:
            conn.execute("SELECT 1 /* data */")
        assert executed[0].startswith("SELECT pg_advisory_xact_lock(")
        assert executed[1].startswith("SELECT 1")
        assert executed[-2:] == ["COMMIT", "CLOSE"]
        executed.clear()
        with pytest.raises(RuntimeError), db.write():
            raise RuntimeError("boom")
        assert executed[-2:] == ["ROLLBACK", "CLOSE"]
