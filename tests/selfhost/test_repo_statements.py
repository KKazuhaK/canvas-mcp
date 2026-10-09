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

ACCOUNT_ID = "aaaaaaaa-0000-4000-8000-00000000000a"
SECRET_KEY = f"acct:{ACCOUNT_ID}"
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
            conn, principal_key=SECRET_KEY, key_id="k1", nonce=b"n" * 12, ciphertext=SECRET_BLOB,
            canvas_user_id="1", canvas_user_name="n", canvas_host="h", status="active", now=5,
            expires_hint_at=4_000_000_000, keep_expiry_hint=keep,
        )
    repos.tokens.delete(conn, SECRET_KEY)
    repos.tokens.touch(conn, SECRET_KEY, 10, 5)
    repos.tokens.mark_invalid(
        conn, SECRET_KEY, reason="canvas_token_rejected", now=1, expected_updated_at=3, expected_generation=2
    )
    repos.tokens.restore_active(conn, SECRET_KEY, now=1, expected_updated_at=3, expected_generation=2)
    repos.tokens.mark_verified(conn, SECRET_KEY, now=1, older_than=0, expected_generation=2)
    repos.tokens.exists(conn, SECRET_KEY)
    repos.tokens.rows_not_under_key(conn, "k1")
    repos.tokens.reseal(
        conn, principal_key=SECRET_KEY, key_id="k", nonce=b"n", ciphertext=SECRET_BLOB
    )
    repos.tokens.key_ids_in_use(conn)
    repos.tokens.probe_row(conn, "k1")
    repos.generations.bump(conn, SECRET_KEY, "enrolled", 5)
    repos.accounts.get(conn, ACCOUNT_ID, for_update=True)
    repos.accounts.get_with_generation(conn, ACCOUNT_ID)
    repos.accounts.list_all(conn)
    repos.accounts.count_active_owners(conn, exclude=ACCOUNT_ID)
    repos.accounts.count_pending(conn)
    repos.accounts.insert(
        conn, account_id=ACCOUNT_ID, status="active", role="user", role_source=None,
        admitted_via="rules", display_name="d", now=5,
    )
    repos.accounts.activate(conn, ACCOUNT_ID, admitted_via="approval", approved_by="b", now=5)
    repos.accounts.disable(conn, ACCOUNT_ID, reason="r", by="b", now=5)
    repos.accounts.enable(conn, ACCOUNT_ID, 5)
    repos.accounts.set_role(conn, ACCOUNT_ID, role="owner", source="rules", seen_at=5, now=5)
    repos.accounts.mark_role_seen(conn, ACCOUNT_ID, 5)
    repos.accounts.touch_login(conn, ACCOUNT_ID, display_name="d", now=5)
    repos.accounts.purge_pending(conn, 5)
    repos.identities.lookup(conn, "entra", "https://issuer", ACCOUNT_ID)
    repos.identities.insert(
        conn, account_id=ACCOUNT_ID, provider_id="entra", issuer="https://issuer",
        subject="s", username="u", email=None, email_verified=False, now=5,
    )
    repos.identities.touch(conn, "entra", "https://issuer", "s", username="u", now=5)
    repos.identities.for_account(conn, ACCOUNT_ID)
    repos.identities.all(conn)
    repos.identities.delete_for_accounts(conn, [ACCOUNT_ID])
    repos.auth_events.append(
        conn, now=5, account_id=ACCOUNT_ID, provider_id="entra", surface="account",
        outcome="success", reason="ok", ip="unknown", ua_hash=None,
    )
    repos.auth_events.list_for_account(conn, ACCOUNT_ID, 20)
    repos.auth_events.prune_before(conn, 5)
    repos.audit.append(
        conn, now=5, actor="operator", action="account_disabled", target=SECRET_KEY,
        reason=None, detail="{}",
    )
    repos.audit.list(conn, 100, 7)
    repos.events.append(conn, SECRET_KEY, "disabled", "actor", "reason", 1, 5)
    repos.events.list_events(conn, SECRET_KEY, 10)
    repos.prefs.get(conn, SECRET_KEY)
    repos.prefs.upsert(conn, SECRET_KEY, names_json="[]", stamps_json="{}", now=5, via="v")
    repos.meta.schema_version(conn)
    repos.meta.set_schema_version(conn, "5")
    return conn.statements


@pytest.mark.parametrize(("dialect", "name"), [(PG, "postgresql"), (LITE, "sqlite")])
class TestCompiledStatements:
    def test_every_statement_compiles_and_inlines_no_value(self, dialect: Any, name: str) -> None:
        statements = _run_everything(dialect, name)
        assert len(statements) > 50
        for sql, _ in statements:
            assert SECRET_KEY not in sql
            assert "ciphertext-that-must-never" not in sql
            assert "4000000000" not in sql  # the hint is bound, not inlined

    def test_upserts_are_one_statement_with_on_conflict(self, dialect: Any, name: str) -> None:
        sql = "\n".join(s for s, _ in _run_everything(dialect, name))
        assert sql.count("ON CONFLICT (principal_key) DO UPDATE SET") >= 4
        assert "ON CONFLICT (principal_key) DO UPDATE SET key_id = excluded.key_id" in sql
        # Saving a token has one conflict target: the account key is the primary key.
        assert "ON CONFLICT (tenant_id, object_id)" not in sql

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

    def test_disable_and_enable_raise_the_epoch_in_place(self, dialect: Any, name: str) -> None:
        raising = [
            s
            for s, _ in _run_everything(dialect, name)
            if s.startswith("UPDATE accounts SET") and "session_epoch" in s
        ]
        assert len(raising) == 2  # disable (and deny) and enable
        for sql in raising:
            assert "session_epoch=(accounts.session_epoch + " in sql  # never set from a stale read

    def test_activation_only_changes_a_pending_account(self, dialect: Any, name: str) -> None:
        activate = next(
            s
            for s, _ in _run_everything(dialect, name)
            if s.startswith("UPDATE accounts SET status") and "approved_at" in s
        )
        assert "accounts.status =" in activate  # the WHERE clause carries the expected status

    def test_the_identity_is_looked_up_by_its_unique_key(self, dialect: Any, name: str) -> None:
        lookup = next(
            s
            for s, _ in _run_everything(dialect, name)
            if s.startswith("SELECT external_identities.account_id")
        )
        for column in ("provider_id", "issuer", "subject"):
            assert f"external_identities.{column} =" in lookup


class TestRowLocks:
    def test_rows_read_and_then_written_are_locked_on_postgresql(self) -> None:
        statements = _run_everything(PG, "postgresql")
        locked = [s for s, _ in statements if s.rstrip().endswith("FOR UPDATE")]
        assert any("FROM accounts" in s and "accounts.status" in s and "accounts.id =" in s for s in locked)

    def test_sqlite_has_no_row_locks(self) -> None:
        assert not any("FOR UPDATE" in s for s, _ in _run_everything(LITE, "sqlite"))


class TestPostgresDialectSpecifics:
    def test_key_columns_sort_in_binary_order(self) -> None:
        sql = "\n".join(s for s, _ in _run_everything(PG, "postgresql"))
        assert "ORDER BY canvas_tokens.created_at, canvas_tokens.principal_key" in sql
        from sqlalchemy.schema import CreateTable

        from canvas_mcp.core.selfhost.db import schema

        ddl = str(CreateTable(schema.canvas_tokens).compile(dialect=PG))
        assert 'principal_key TEXT COLLATE "C" NOT NULL' in ddl
        assert "created_at BIGINT NOT NULL" in ddl
        accounts = str(CreateTable(schema.accounts).compile(dialect=PG))
        assert 'id TEXT COLLATE "C" NOT NULL' in accounts and "session_epoch BIGINT" in accounts

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
