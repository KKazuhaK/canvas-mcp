"""Alembic adoption and upgrade of the token database.

SQLite files written by every pre-Alembic release (schema versions 1 to 4, six
historical shapes) must be adopted and carried to the account model (schema 5) without
losing a row: every token still decrypts under its account, every status, epoch, owner
role, history entry and credential generation survives, and a second start changes
nothing. Both backends: a fresh database matches ``schema.metadata`` exactly, a
database from a newer server is refused untouched, and ``DATABASE_AUTO_MIGRATE=false``
refuses a stale schema. The schema 4 -> 5 data migration has its own, deeper tests in
``test_account_migration.py``.
"""

from __future__ import annotations

import pathlib
import re
import sqlite3
import stat
import sys
from typing import Any

import pytest
from dbbackend import make_store, raw_sql

from canvas_mcp.core.selfhost.db import baseline_v4, migrate, schema
from canvas_mcp.core.selfhost.db.engine import Database
from canvas_mcp.core.selfhost.db.errors import TokenStoreError
from canvas_mcp.core.selfhost.token_store import SCHEMA_VERSION, TokenStore

from . import legacy_schemas as legacy
from .conftest import make_account

SNAPSHOT = pathlib.Path(__file__).parent / "ddl_postgresql_head.sql"


def _dump(path: pathlib.Path) -> dict[str, list[tuple[Any, ...]]]:
    """Every row of every table (the Alembic table aside), as plain tuples."""
    conn = sqlite3.connect(str(path))
    try:
        names = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                f" AND name != '{schema.VERSION_TABLE}' ORDER BY name"
            )
        ]
        return {n: sorted(conn.execute(f"SELECT * FROM {n}").fetchall(), key=repr) for n in names}
    finally:
        conn.close()


def _shape(path: pathlib.Path) -> dict[str, Any]:
    """Columns, indexes and table options: what must equal a freshly created file."""
    conn = sqlite3.connect(str(path))
    try:
        out: dict[str, Any] = {}
        tables = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                f" AND name != '{schema.VERSION_TABLE}'"
            )
        ]
        for name in sorted(tables):
            cols = sorted(
                (r[1], r[2].upper(), r[3], r[4], r[5])
                for r in conn.execute(f"PRAGMA table_info({name})")
            )
            indexes = sorted(
                (r[1], r[2])
                for r in conn.execute(f"PRAGMA index_list({name})")
                if not r[1].startswith("sqlite_autoindex")
            )
            sql = conn.execute("SELECT sql FROM sqlite_master WHERE name = ?", (name,)).fetchone()[0]
            out[name] = {
                "columns": cols,
                "indexes": indexes,
                "without_rowid": "WITHOUT ROWID" in sql.upper(),
                "autoincrement": "AUTOINCREMENT" in sql.upper(),
            }
        out["__objects__"] = sorted(
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'"
            )
        )
        return out
    finally:
        conn.close()


def _normalized(text: str) -> str:
    """Line endings and trailing blanks differ between checkouts and editors."""
    lines = text.replace("\r\n", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip()


def _store(path: pathlib.Path) -> TokenStore:
    return TokenStore(path, legacy.keyring())


def _account_of(store: TokenStore, legacy_key: str) -> str:
    """The account a pre-account principal key became."""
    key = store.resolve_legacy_key(legacy_key)
    assert key is not None, legacy_key
    return key


def _meta_version(path: pathlib.Path) -> str:
    conn = sqlite3.connect(str(path))
    try:
        return str(conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0])
    finally:
        conn.close()


def _alembic_revisions(path: pathlib.Path) -> list[str]:
    conn = sqlite3.connect(str(path))
    try:
        return [r[0] for r in conn.execute(f"SELECT version_num FROM {schema.VERSION_TABLE}")]
    finally:
        conn.close()


@pytest.fixture(scope="module")
def fresh_shape(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    path = tmp_path_factory.mktemp("fresh") / "fresh.sqlite3"
    TokenStore(path, legacy.keyring()).initialize()
    return _shape(path)


@pytest.mark.sqlite_only
@pytest.mark.parametrize("shape", legacy.SHAPES)
class TestAdoptingPreAlembicFiles:
    def test_every_token_still_decrypts_under_its_account_and_nothing_else_is_lost(
        self, tmp_path: pathlib.Path, shape: str
    ) -> None:
        path = tmp_path / "t.sqlite3"
        seeded = legacy.build(path, shape)
        before = _dump(path)

        store = _store(path)
        store.initialize()

        status = migrate.current(store.database)
        assert status.state == migrate.STATE_CURRENT
        assert status.alembic_revision == migrate.head_revision()
        assert _meta_version(path) == str(SCHEMA_VERSION) == "5"
        for legacy_key, token in seeded.plaintexts.items():
            key = legacy_key if not legacy_key.startswith("entra:") else _account_of(store, legacy_key)
            row = store.get(key)
            assert row is not None and row.api_token == token, legacy_key
        after = _dump(path)
        # Every table the old file had still has every row (re-keyed, with the same counts).
        for table, rows in before.items():
            if table in ("meta", "principal_status"):
                continue
            assert len(after[table]) == len(rows), table
        assert "principal_status" not in after
        assert len(after["accounts"]) == len(after["external_identities"])
        # Re-encrypted rows moved to the active key; nothing is left under the old one.
        assert {r[0] for r in raw_sql(store, "SELECT key_id FROM canvas_tokens")} == {"k2"}

    def test_status_epochs_owners_history_and_generations_survive(
        self, tmp_path: pathlib.Path, shape: str
    ) -> None:
        path = tmp_path / "t.sqlite3"
        seeded = legacy.build(path, shape)
        store = _store(path)
        store.initialize()
        key_c = _account_of(store, legacy.KEY_C) if legacy.KEY_C in seeded.plaintexts else None
        invalid = store.info(key_c) if key_c else None
        if invalid is not None:
            assert invalid.status == "invalid" and invalid.invalid_reason == "canvas_token_rejected"
        if seeded.has_status:
            key_b = _account_of(store, legacy.KEY_B)
            c = store.get_principal_status(_account_of(store, legacy.KEY_C))
            assert c.disabled and c.session_epoch == 3 and c.disabled_by == key_b
            assert store.get_principal_status(key_b).is_owner
            events = [
                (e.action, e.session_epoch)
                for e in store.list_status_events(_account_of(store, legacy.KEY_C))
            ]
            assert events == [("disabled", 3), ("enabled", 2), ("disabled", 1)]
        else:
            assert all(a.status.active and not a.status.is_owner for a in store.list_accounts())
        expected_generation = {"v4": {legacy.KEY_B: 2, legacy.KEY_C: 5}}.get(shape, {})
        for legacy_key in seeded.plaintexts:
            if not legacy_key.startswith("entra:"):
                continue
            key = _account_of(store, legacy_key)
            assert store.credential_generation(key) == expected_generation.get(legacy_key, 0)
        if shape in ("v2c", "v3", "v4"):
            prefs = store.get_tool_prefs(_account_of(store, legacy.KEY_B))
            assert prefs is not None and prefs.enabled_write_tools == {"send_message"}

    def test_the_schema_equals_a_freshly_created_one(
        self, tmp_path: pathlib.Path, shape: str, fresh_shape: dict[str, Any]
    ) -> None:
        path = tmp_path / "t.sqlite3"
        legacy.build(path, shape)
        _store(path).initialize()
        assert _shape(path) == fresh_shape
        # The live tables also match the metadata the queries are written against.
        db = Database.sqlite(path)
        with db.read() as conn:
            assert migrate.compare_schema(conn) == []

    def test_a_second_start_changes_nothing(self, tmp_path: pathlib.Path, shape: str) -> None:
        path = tmp_path / "t.sqlite3"
        legacy.build(path, shape)
        _store(path).initialize()
        rows, shape_after = _dump(path), _shape(path)
        for _ in range(2):
            _store(path).initialize()
        assert _dump(path) == rows and _shape(path) == shape_after
        assert _alembic_revisions(path) == [migrate.head_revision()]

    def test_rotation_works_on_the_adopted_file(self, tmp_path: pathlib.Path, shape: str) -> None:
        import base64

        from canvas_mcp.core.selfhost.token_store import Keyring

        path = tmp_path / "t.sqlite3"
        seeded = legacy.build(path, shape)
        new_ring = Keyring.parse(
            "k3:" + base64.b64encode(bytes([3]) * 32).decode()
            + ",k2:" + base64.b64encode(bytes([2]) * 32).decode()
            + ",k1:" + base64.b64encode(bytes([1]) * 32).decode()
        )
        store = TokenStore(path, new_ring)
        store.initialize()
        # The upgrade already moved every account's row from k1 to the then-active key k3;
        # the one row of a principal that is no account (carried over unchanged) is left
        # under k2 until a rotation.
        entra_keys = {r[0] for r in raw_sql(store, "SELECT key_id FROM canvas_tokens WHERE principal_key LIKE 'acct:%'")}
        assert entra_keys <= {"k3"}
        assert store.rotate() == (1 if legacy.KEY_OTHER in seeded.plaintexts else 0)
        assert {r[0] for r in raw_sql(store, "SELECT key_id FROM canvas_tokens")} == {"k3"}
        only_new = TokenStore(path, Keyring.parse("k3:" + base64.b64encode(bytes([3]) * 32).decode()))
        only_new.initialize()
        for legacy_key, token in seeded.plaintexts.items():
            key = legacy_key if not legacy_key.startswith("entra:") else _account_of(store, legacy_key)
            row = only_new.get(key)
            assert row is not None and row.api_token == token

    def test_the_previous_release_refuses_the_migrated_file(
        self, tmp_path: pathlib.Path, shape: str
    ) -> None:
        """Rollback is a restore of the backup: the old start-up steps refuse the new file.

        A release that read ``principal_status`` would find nothing and serve every
        disabled user, so the schema marker moved past what it supports.
        """
        path = tmp_path / "t.sqlite3"
        legacy.build(path, shape)
        _store(path).initialize()
        before = _dump(path)
        db = Database.sqlite(path)
        with pytest.raises(TokenStoreError, match="newer than this server supports"):
            with db.write() as conn:
                baseline_v4.ensure_sqlite_v4(conn)  # what the schema 4 server ran at start
        assert _dump(path) == before
        assert _meta_version(path) == "5"


def _old_columns(shape: str, table: str) -> list[str]:
    """The columns the table had in that historical shape (read from the frozen builder)."""
    return _SHAPE_COLUMNS[(shape, table)]


def _shape_columns() -> dict[tuple[str, str], list[str]]:
    import tempfile

    result: dict[tuple[str, str], list[str]] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for shape in legacy.SHAPES:
            path = pathlib.Path(tmp) / f"{shape}.sqlite3"
            legacy.build(path, shape)
            conn = sqlite3.connect(str(path))
            try:
                for (name,) in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall():
                    result[(shape, name)] = [r[1] for r in conn.execute(f"PRAGMA table_info({name})")]
            finally:
                conn.close()
    return result


_SHAPE_COLUMNS = _shape_columns()


@pytest.mark.sqlite_only
class TestRefusalsLeaveTheFileUntouched:
    @pytest.mark.parametrize("marker", ["6", "9999", "x", "4.5", ""])
    def test_a_newer_or_unreadable_marker_is_refused(self, tmp_path: pathlib.Path, marker: str) -> None:
        path = tmp_path / "t.sqlite3"
        legacy.build(path, "v4")
        conn = sqlite3.connect(str(path))
        conn.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", (marker,))
        conn.commit()
        conn.close()
        before, shape_before = _dump(path), _shape(path)
        with pytest.raises(TokenStoreError) as refused:
            _store(path).initialize()
        text = str(refused.value)
        assert "newer than this server supports" in text or "unreadable schema version" in text
        assert _dump(path) == before and _shape(path) == shape_before
        conn = sqlite3.connect(str(path))
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        conn.close()
        assert schema.VERSION_TABLE not in names  # nothing was recorded

    def test_an_unknown_alembic_revision_is_refused(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        legacy.build(path, "v4")
        _store(path).initialize()
        conn = sqlite3.connect(str(path))
        conn.execute(f"UPDATE {schema.VERSION_TABLE} SET version_num = '0099_from_the_future'")
        conn.commit()
        conn.close()
        before = _dump(path)
        with pytest.raises(TokenStoreError, match="newer server"):
            _store(path).initialize()
        assert _dump(path) == before
        assert _alembic_revisions(path) == ["0099_from_the_future"]

    def test_a_failure_in_the_middle_of_adoption_rolls_everything_back(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "t.sqlite3"
        legacy.build(path, "v1")
        before, shape_before = _dump(path), _shape(path)

        def explode(bind: Any) -> None:
            raise RuntimeError("injected failure after the columns were added")

        monkeypatch.setattr(baseline_v4, "_create_side_tables", explode)
        with pytest.raises(RuntimeError, match="injected"):
            _store(path).initialize()
        monkeypatch.undo()
        assert _dump(path) == before and _shape(path) == shape_before
        conn = sqlite3.connect(str(path))
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        conn.close()
        assert schema.VERSION_TABLE not in names
        # And the file still adopts cleanly afterwards.
        store = _store(path)
        store.initialize()
        assert store.get(_account_of(store, legacy.KEY_A)) is not None

    def test_a_half_migrated_file_at_the_baseline_is_completed(self, tmp_path: pathlib.Path) -> None:
        from alembic import command

        path = tmp_path / "t.sqlite3"
        legacy.build(path, "v4")
        db = Database.sqlite(path)
        with db.write() as conn:  # a server of the previous release: adopted, at the baseline
            command.upgrade(migrate._config(connection=conn), migrate.BASELINE_REVISION)
        conn2 = sqlite3.connect(str(path))
        conn2.execute("DROP TABLE principal_status_events")
        conn2.execute("UPDATE meta SET value = '2' WHERE key = 'schema_version'")
        conn2.commit()
        conn2.close()
        _store(path).initialize()
        assert _meta_version(path) == "5"
        assert "principal_status_events" in _dump(path)


@pytest.mark.sqlite_only
class TestManualMigrationMode:
    def test_a_stale_file_is_refused_until_it_is_upgraded(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        legacy.build(path, "v3")
        before = _dump(path)
        with pytest.raises(TokenStoreError, match="db upgrade"):
            _store(path).initialize(auto_migrate=False)
        assert _dump(path) == before
        _store(path).initialize()
        _store(path).initialize(auto_migrate=False)  # current now: fine

    def test_upgrade_can_write_a_private_backup_first(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        legacy.build(path, "v2c")
        backup = tmp_path / "backup.sqlite3"
        db = Database.sqlite(path)
        before_status, after_status = migrate.upgrade(
            db, backup_to=backup, keyring=legacy.keyring()
        )
        assert before_status.state == migrate.STATE_LEGACY
        assert after_status.state == migrate.STATE_CURRENT
        assert _meta_version(backup) == "2"  # the backup is the file as it was
        assert "principal_status" not in _dump(backup)
        if sys.platform != "win32":
            assert stat.S_IMODE(backup.stat().st_mode) == 0o600
        with pytest.raises(TokenStoreError, match="already exists"):
            migrate.upgrade(db, backup_to=backup, keyring=legacy.keyring())

    def test_current_reports_each_state_without_changing_anything(
        self, tmp_path: pathlib.Path
    ) -> None:
        empty = Database.sqlite(tmp_path / "new.sqlite3")
        assert migrate.current(empty).state == migrate.STATE_UNINITIALIZED
        path = tmp_path / "t.sqlite3"
        legacy.build(path, "v4")
        db = Database.sqlite(path)
        status = migrate.current(db)
        assert status.state == migrate.STATE_LEGACY and status.alembic_revision is None
        assert "alembic" not in " ".join(_dump(path))
        migrate.ensure_ready(db, keyring=legacy.keyring())
        assert migrate.current(db).state == migrate.STATE_CURRENT


class TestBothBackends:
    def test_a_fresh_database_matches_the_declared_schema(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path / "fresh.sqlite3", legacy.keyring())
        store.initialize()
        status = migrate.current(store.database)
        assert status.state == migrate.STATE_CURRENT
        assert status.meta_version == "5" and status.alembic_revision == migrate.head_revision()
        with store.database.read() as conn:
            assert migrate.compare_schema(conn) == []

    def test_starting_twice_is_idempotent(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        first = make_store(path, legacy.keyring())
        first.initialize()
        key_b = make_account(first, legacy.OID_B, tenant=legacy.TID, name="Bob")
        first.put(
            principal_key=key_b, api_token=legacy.TOKEN_B, canvas_user_id="2",
            canvas_user_name="Bob", canvas_host=legacy.HOST,
        )
        for _ in range(2):
            make_store(path, legacy.keyring()).initialize()
        again = make_store(path, legacy.keyring())
        again.initialize(auto_migrate=False)
        row = again.get(key_b)
        assert row is not None and row.api_token == legacy.TOKEN_B
        revisions = raw_sql(again, f"SELECT version_num FROM {schema.VERSION_TABLE}")
        assert [r[0] for r in revisions] == [migrate.head_revision()]

    @pytest.mark.parametrize("marker", ["6", "x"])
    def test_a_newer_marker_is_refused_and_nothing_is_recorded(
        self, tmp_path: pathlib.Path, marker: str
    ) -> None:
        path = tmp_path / "t.sqlite3"
        first = make_store(path, legacy.keyring())
        first.initialize()
        raw_sql(first, "UPDATE meta SET value = :v WHERE key = 'schema_version'", {"v": marker})
        with pytest.raises(TokenStoreError) as refused:
            make_store(path, legacy.keyring()).initialize()
        assert "newer than this server supports" in str(refused.value) or "unreadable" in str(
            refused.value
        )
        assert raw_sql(first, "SELECT value FROM meta WHERE key = 'schema_version'")[0][0] == marker

    def test_an_unknown_revision_is_refused(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.sqlite3"
        first = make_store(path, legacy.keyring())
        first.initialize()
        raw_sql(first, f"UPDATE {schema.VERSION_TABLE} SET version_num = '0099_from_the_future'")
        with pytest.raises(TokenStoreError, match="newer server"):
            make_store(path, legacy.keyring()).initialize()
        assert raw_sql(first, f"SELECT version_num FROM {schema.VERSION_TABLE}")[0][0] == (
            "0099_from_the_future"
        )

    def test_manual_mode_refuses_an_uninitialized_database_and_accepts_a_current_one(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "t.sqlite3"
        with pytest.raises(TokenStoreError, match="db upgrade"):
            make_store(path, legacy.keyring()).initialize(auto_migrate=False)
        make_store(path, legacy.keyring()).initialize()
        make_store(path, legacy.keyring()).initialize(auto_migrate=False)


class TestRevisionPolicy:
    def test_the_marker_never_decreases_and_the_head_matches_the_store(self) -> None:
        versions = list(migrate.revision_compat_versions().values())
        assert versions == sorted(versions)
        assert versions[-1] == SCHEMA_VERSION
        assert migrate.head_compat_version() == SCHEMA_VERSION

    @pytest.mark.parametrize(
        "revision", [migrate.BASELINE_REVISION, "0002_accounts", "0003_oauth_authz"]
    )
    def test_no_revision_has_a_downgrade(self, revision: str) -> None:
        from alembic.script import ScriptDirectory

        rev = migrate._script().get_revision(revision)
        assert rev is not None
        module: Any = rev.module
        with pytest.raises(NotImplementedError, match="restore the backup"):
            module.downgrade()
        assert isinstance(migrate._script(), ScriptDirectory)

    def test_there_is_one_linear_history_ending_at_the_authorization_server_tables(self) -> None:
        assert migrate.head_revision() == "0003_oauth_authz"
        assert migrate.known_revisions() == {
            migrate.BASELINE_REVISION,
            "0002_accounts",
            "0003_oauth_authz",
        }
        # 0003 only adds tables: an older server refuses the database through the
        # unknown revision, so the marker does not move.
        assert migrate.revision_compat_versions() == {
            migrate.BASELINE_REVISION: 4,
            "0002_accounts": 5,
            "0003_oauth_authz": 5,
        }

    def test_the_revision_that_re_encrypts_asks_for_a_backup(self) -> None:
        rev = migrate._script().get_revision("0002_accounts")
        assert rev is not None
        assert rev.module.BACKUP_BEFORE is True


class TestOfflineDdl:
    def test_the_postgresql_ddl_of_the_head_matches_the_snapshot(self) -> None:
        rendered = _normalized(migrate.render_sql("postgresql"))
        expected = _normalized(SNAPSHOT.read_text(encoding="utf-8"))
        assert rendered == expected, (
            "the PostgreSQL DDL changed; if intended, regenerate the snapshot with: "
            "python -c \"from canvas_mcp.core.selfhost.db.migrate import render_sql; "
            f"print(render_sql('postgresql'))\" > {SNAPSHOT.name}"
        )

    def test_the_ddl_has_every_table_with_c_collated_keys_and_bigint_times(self) -> None:
        sql = migrate.render_sql("postgresql")
        for table in schema.TABLE_NAMES:
            assert re.search(rf"CREATE TABLE {table} \(", sql), table
        assert "COLLATE \"C\"" in sql
        assert "expires_hint_at BIGINT" in sql
        assert "GENERATED BY DEFAULT AS IDENTITY" in sql
        assert "bytea" in sql.lower() or "BYTEA" in sql
