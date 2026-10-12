"""Compile native repository statements for both database dialects.

Keep the concurrency and parameter-binding guarantees visible even when no
PostgreSQL server is available. Runtime transaction races are tested separately.
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
CREDENTIAL_ID = "bbbbbbbb-0000-4000-8000-00000000000b"
SECRET_BLOB = b"ciphertext-that-must-never-be-inlined"


class _Result:
    rowcount = 1

    def mappings(self) -> _Result:
        return self

    def scalars(self) -> _Result:
        return self

    def all(self) -> list[Any]:
        return []

    def one_or_none(self) -> Any:
        return None

    def scalar_one(self) -> Any:
        return 0

    def scalar_one_or_none(self) -> Any:
        return None

    def first(self) -> Any:
        from types import SimpleNamespace

        return SimpleNamespace(
            issuer="https://issuer", subject="s", provider_id="entra"
        )

    def __iter__(self) -> Any:
        return iter(())


class RecordingConnection:
    def __init__(self, dialect: Any) -> None:
        self.dialect = dialect
        self.statements: list[tuple[str, dict[str, Any]]] = []

    def execute(self, stmt: Any, *args: Any) -> _Result:
        compiled = stmt.compile(dialect=self.dialect)
        self.statements.append((str(compiled), dict(compiled.params)))
        return _Result()


def _run_everything(dialect: Any, name: str) -> list[tuple[str, dict[str, Any]]]:
    repos = Repositories(name)  # type: ignore[arg-type]
    conn: Any = RecordingConnection(dialect)
    repos.credentials.primary(conn, ACCOUNT_ID)
    repos.credentials.at_host(conn, ACCOUNT_ID, "canvas.example.edu")
    repos.credentials.ensure_school(
        conn, "canvas.example.edu", account_id=ACCOUNT_ID, now=5
    )
    repos.credentials.put(
        conn,
        identifier=CREDENTIAL_ID,
        account_id=ACCOUNT_ID,
        canvas_host="canvas.example.edu",
        generation=2,
        key_id="k1",
        nonce=b"n" * 12,
        ciphertext=SECRET_BLOB,
        canvas_user_id="1",
        canvas_user_name="n",
        now=5,
        expires_hint_at=4_000_000_000,
        custody_notice_version=1,
        custody_ack_at=5,
    )
    repos.credentials.mark_invalid(
        conn,
        ACCOUNT_ID,
        reason="canvas_token_rejected",
        now=10,
        expected_updated_at=5,
        expected_generation=2,
    )
    repos.credentials.restore_active(
        conn, ACCOUNT_ID, now=10, expected_updated_at=5, expected_generation=2
    )
    repos.credentials.mark_verified(
        conn, ACCOUNT_ID, now=10, older_than=8, expected_generation=2
    )
    repos.credentials.touch(conn, ACCOUNT_ID, 10, 8)
    repos.generations.bump(conn, ACCOUNT_ID, "enrolled", 5, writing=CREDENTIAL_ID)
    repos.accounts.get(conn, ACCOUNT_ID, for_update=True)
    repos.accounts.usable_owner_ids(
        conn, ["entra", "github"], exclude=ACCOUNT_ID, for_update=True
    )
    repos.accounts.activate(
        conn, ACCOUNT_ID, admitted_via="approval", approved_by="operator", now=5
    )
    repos.accounts.disable(conn, ACCOUNT_ID, reason="r", by="operator", now=5)
    repos.accounts.enable(conn, ACCOUNT_ID, 5)
    repos.accounts.end_sessions(conn, ACCOUNT_ID, 5)
    repos.identities.lookup(conn, "entra", "https://issuer", ACCOUNT_ID)
    repos.identities.touch(conn, "entra", "https://issuer", "s", username="u", now=5)
    repos.identities.touch(
        conn,
        "github",
        "https://github.com",
        "1",
        username="u",
        now=5,
        email="a@b.test",
        email_verified=True,
    )
    repos.identities.get_for_account(conn, CREDENTIAL_ID, ACCOUNT_ID, for_update=True)
    repos.identities.count_for_account(conn, ACCOUNT_ID)
    repos.identities.count_for_provider(conn, ACCOUNT_ID, "github")
    repos.identities.delete_one(conn, CREDENTIAL_ID, ACCOUNT_ID)
    repos.prefs.replace(
        conn, ACCOUNT_ID, stamps={"mark_module_item_done": 5}, now=5, via="account"
    )
    return conn.statements


@pytest.mark.parametrize(("dialect", "name"), [(PG, "postgresql"), (LITE, "sqlite")])
class TestCompiledStatements:
    def test_sensitive_values_are_bound(self, dialect: Any, name: str) -> None:
        statements = _run_everything(dialect, name)
        assert len(statements) >= 25
        params = [p for _, p in statements]
        assert any(SECRET_BLOB in p.values() for p in params)
        assert any(4_000_000_000 in p.values() for p in params)
        for sql, _ in statements:
            for value in (
                ACCOUNT_ID,
                CREDENTIAL_ID,
                "ciphertext-that-must-never",
                "4000000000",
            ):
                assert value not in sql

    def test_credential_replacement_preserves_id_and_creation_time(
        self, dialect: Any, name: str
    ) -> None:
        sql = next(
            s
            for s, _ in _run_everything(dialect, name)
            if s.startswith("INSERT INTO canvas_credentials")
        )
        insert_part, update_part = sql.split("DO UPDATE SET")
        assert "ON CONFLICT (id)" in insert_part
        assert "created_at =" not in update_part
        assert "expires_hint_at = excluded.expires_hint_at" in update_part

    def test_late_health_writes_are_bound_to_the_observed_generation(
        self, dialect: Any, name: str
    ) -> None:
        updates = [
            s
            for s, _ in _run_everything(dialect, name)
            if s.startswith("UPDATE canvas_credentials SET status")
            or s.startswith("UPDATE canvas_credentials SET last_verified_at")
        ]
        assert len(updates) == 3
        for sql in updates:
            assert "canvas_credentials.account_id =" in sql
            assert "canvas_credentials.generation =" in sql
            assert "canvas_credentials.status =" in sql
        for sql in updates[:2]:
            assert "canvas_credentials.updated_at =" in sql

    def test_versions_and_epochs_increment_in_sql(
        self, dialect: Any, name: str
    ) -> None:
        updates = [
            s
            for s, _ in _run_everything(dialect, name)
            if s.startswith("UPDATE accounts")
        ]
        for column, count in (
            ("credential_generation", 1),
            ("write_tools_version", 1),
            ("session_epoch", 3),
        ):
            raising = [s for s in updates if f"{column}=(accounts.{column} +" in s]
            assert len(raising) == count

    def test_activation_requires_pending_status(self, dialect: Any, name: str) -> None:
        sql = next(
            s
            for s, _ in _run_everything(dialect, name)
            if s.startswith("UPDATE accounts SET status") and "approved_at" in s
        )
        assert "accounts.status =" in sql.split("WHERE")[1]

    def test_identity_lookup_uses_its_provider_issuer_and_subject(
        self, dialect: Any, name: str
    ) -> None:
        sql = next(
            s
            for s, _ in _run_everything(dialect, name)
            if s.startswith("SELECT external_identities.account_id")
        )
        for column in ("provider_id", "issuer", "subject"):
            assert f"external_identities.{column} =" in sql

    def test_identity_mutations_are_scoped_to_the_account(
        self, dialect: Any, name: str
    ) -> None:
        statements = [s for s, _ in _run_everything(dialect, name)]
        scoped = [s for s in statements if "external_identities.id =" in s]
        assert len(scoped) == 3
        assert all("external_identities.account_id =" in s for s in scoped)
        counts = [
            s
            for s in statements
            if s.startswith("SELECT count(*)") and "external_identities" in s
        ]
        assert len(counts) == 2
        assert all("external_identities.account_id =" in s for s in counts)

    def test_touch_retains_email_when_provider_omits_it(
        self, dialect: Any, name: str
    ) -> None:
        plain, with_email = [
            s
            for s, _ in _run_everything(dialect, name)
            if s.startswith("UPDATE external_identities SET")
        ]
        assert "email" not in plain.split("WHERE")[0]
        assert "email=" in with_email.replace(" ", "")


class TestRowLocks:
    def test_governance_rows_take_no_key_update_locks_on_postgres(self) -> None:
        sql = [s for s, _ in _run_everything(PG, "postgresql")]
        locked = [s for s in sql if s.rstrip().endswith("FOR NO KEY UPDATE")]
        assert any("FROM accounts" in s for s in locked)
        assert any("FROM external_identities" in s for s in locked)
        # Health/usage writes skip busy credential rows instead of occupying a pool slot.
        assert sum("FOR NO KEY UPDATE SKIP LOCKED" in s for s in sql) == 2

    def test_sqlite_omits_row_locks(self) -> None:
        assert not any("FOR " in s for s, _ in _run_everything(LITE, "sqlite"))


class TestPostgresDialectSpecifics:
    def test_identifiers_are_native_uuids(self) -> None:
        from sqlalchemy.schema import CreateTable

        from canvas_mcp.core.selfhost.db import schema

        for table in (
            schema.accounts,
            schema.canvas_credentials,
            schema.external_identities,
        ):
            ddl = str(CreateTable(table).compile(dialect=PG))
            assert "id UUID NOT NULL" in ddl
        assert "account_id UUID NOT NULL" in str(
            CreateTable(schema.canvas_credentials).compile(dialect=PG)
        )

    def test_the_writer_lock_key_is_a_fixed_signed_64_bit_integer(self) -> None:
        assert -(2**63) <= db_engine.WRITER_LOCK_KEY < 2**63
        from canvas_mcp.core.selfhost.db.migrations.connections import (
            MIGRATION_LOCK_KEY,
        )

        assert db_engine.WRITER_LOCK_KEY != MIGRATION_LOCK_KEY
        assert (
            db_engine._ADVISORY_XACT_SQL
            == f"SELECT pg_advisory_xact_lock({db_engine.WRITER_LOCK_KEY})"
        )
        # sha256("canvas-mcp/token-store/writer") must stay the key forever: an older
        # and a newer server share the lock only if they derive the same number.
        assert db_engine.WRITER_LOCK_KEY == db_engine._advisory_key(
            "canvas-mcp/token-store/writer"
        )

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
            parse_database_url(
                "postgresql+psycopg://u:p@db.example:5432/app", Path("/data")
            )
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
