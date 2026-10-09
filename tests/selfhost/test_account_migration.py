"""Schema 4 -> 5: the account model migration, from a database built by release d40a2e1.

The fixture (``fixtures/schema4_d40a2e1.json``) was produced by the real code of that
release with a mixed key ring (``k2`` active, ``k1`` old). It holds legacy rows without a
school (v1 layout) under both keys, rows with a school, rows invalid for each reason
(one with a genuinely corrupted ciphertext), disabled principals with and without a
token, two owners, preferences, a credential generation whose token was deleted, a
status history and one opaque non-Entra key. Every guarantee of the migration is checked
against it on whichever backend the run uses.
"""

from __future__ import annotations

import base64
import hashlib
import os
import pathlib
import stat
import sys
from typing import Any

import pytest
from dbbackend import IS_POSTGRES, make_store, raw_sql

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.db import accounts_v5, baseline_v4, migrate, schema
from canvas_mcp.core.selfhost.db.accounts_v5 import (
    AccountMigrationReport,
    MigrationOptions,
)
from canvas_mcp.core.selfhost.db.errors import TokenStoreError
from canvas_mcp.core.selfhost.token_store import (
    Keyring,
    KeyringError,
    TokenDecryptionError,
    TokenStore,
)

from . import schema4
from .conftest import (  # noqa: F401 - fixtures of the package
    FakeAccounts,
    identity_service,
)
from .schema4 import Schema4, build_schema4, dump, keyring

PROBLEM_TABLES = ("canvas_tokens", "user_tool_prefs", "credential_generations")


class Rig:
    """A schema 4 database (stamped at the baseline) and a store over it, not yet upgraded."""

    def __init__(self, tmp_path: pathlib.Path, ring: Any = None) -> None:
        self.tmp_path = tmp_path
        self.fixture: Schema4 = schema4.load_fixture()
        self.store: TokenStore = make_store(tmp_path / "tokens.sqlite3", ring or keyring())
        self.store.database.prepare_storage()
        build_schema4(self.store.database, self.fixture)
        self.db = self.store.database

    def store_with(self, ring: Any) -> TokenStore:
        other = make_store(self.tmp_path / "tokens.sqlite3", ring)
        return other

    def dump(self, tables: tuple[str, ...] | None = None) -> dict[str, list[tuple[Any, ...]]]:
        return dump(self.db, tables)

    def revision(self) -> str | None:
        return migrate.current(self.db).alembic_revision

    def upgrade(self, **kw: Any) -> AccountMigrationReport:
        report = AccountMigrationReport()
        self.store.initialize(report=report, **kw)
        return report

    def key(self, name: str) -> str:
        key = self.store.resolve_legacy_key(self.fixture.key(name))
        assert key is not None, name
        return key


@pytest.fixture
def rig(tmp_path: pathlib.Path) -> Rig:
    return Rig(tmp_path)


def _entra_issuer(fixture: Schema4) -> str:
    return f"https://login.microsoftonline.com/{fixture.tenant_id}/v2.0"


class TestTheFixtureIsARealSchema4Database:
    def test_it_is_stamped_at_the_baseline_with_the_old_shape(self, rig: Rig) -> None:
        status = migrate.current(rig.db)
        assert status.alembic_revision == migrate.BASELINE_REVISION
        assert status.meta_version == "4" and status.state == migrate.STATE_BEHIND
        names = set(rig.dump())
        assert {"principal_status", "canvas_tokens", "credential_generations"} <= names
        assert "accounts" not in names
        assert raw_sql(rig.store, "SELECT COUNT(*) FROM canvas_tokens")[0][0] == 10

    def test_the_old_server_could_read_every_token(self, rig: Rig) -> None:
        """The fixture is honest: v1 rows decrypt with the v1 layout, v2 rows with v2."""
        ring = keyring()
        rows = raw_sql(
            rig.store,
            "SELECT principal_key, key_id, nonce, ciphertext, canvas_host, tenant_id, object_id,"
            " status, invalid_reason FROM canvas_tokens",
        )
        readable = 0
        for pkey, kid, nonce, ct, host, tid, oid, status, reason in rows:
            if status == "invalid" and reason == "decrypt_failed":
                continue
            aad = (
                accounts_v5.aad_v2(pkey, host, kid)
                if host is not None
                else accounts_v5.aad_v1(tid, oid, kid)
            )
            assert ring.decrypt(kid, bytes(nonce), bytes(ct), aad).decode() == rig.fixture.plaintexts[pkey]
            readable += 1
        assert readable == 9


class TestEverythingSurvives:
    def test_every_token_decrypts_to_the_same_plaintext_under_its_account(self, rig: Rig) -> None:
        rig.upgrade()
        checked = 0
        for legacy_key, token in rig.fixture.plaintexts.items():
            key = (
                legacy_key
                if legacy_key == rig.fixture.other_key
                else rig.store.resolve_legacy_key(legacy_key)
            )
            assert key is not None
            row = rig.store.get(key)
            assert row is not None and row.api_token == token, legacy_key
            checked += 1
        assert checked == 9

    def test_entra_rows_move_to_the_active_key_and_keep_their_metadata(self, rig: Rig) -> None:
        old = {
            row["principal_key"]: row for row in rig.fixture.rows("canvas_tokens")
        }
        rig.upgrade()
        for name, legacy_key in rig.fixture.principals.items():
            if legacy_key not in old:
                continue
            was = old[legacy_key]
            info = rig.store.info(rig.key(name))
            assert info is not None, name
            assert info.canvas_user_id == was["canvas_user_id"]
            assert info.canvas_user_name == was["canvas_user_name"]
            assert (info.created_at, info.updated_at, info.last_used_at) == (
                was["created_at"], was["updated_at"], was["last_used_at"],
            )
            assert (info.status, info.invalid_reason, info.invalid_since) == (
                was["status"], was["invalid_reason"], was["invalid_since"],
            )
            assert (info.last_verified_at, info.expires_hint_at) == (
                was["last_verified_at"], was["expires_hint_at"],
            )
            assert info.canvas_host == was["canvas_host"]
            if not (was["status"] == "invalid" and was["invalid_reason"] == "decrypt_failed"):
                assert info.key_id == "k2", name  # re-encrypted under the active key

    def test_layouts_follow_the_school_host(self, rig: Rig) -> None:
        rig.upgrade()
        ring = keyring()
        rows = raw_sql(
            rig.store,
            "SELECT principal_key, key_id, nonce, ciphertext, canvas_host FROM canvas_tokens"
            " WHERE principal_key LIKE 'acct:%'",
        )
        saw_v2 = saw_v3 = False
        for pkey, kid, nonce, ct, host in rows:
            if kid != "k2":
                continue  # the unreadable row carried over as it was
            if host is None:
                aad = accounts_v5.aad_v3(pkey, kid)
                saw_v3 = True
            else:
                aad = accounts_v5.aad_v2(pkey, host, kid)
                saw_v2 = True
            ring.decrypt(kid, bytes(nonce), bytes(ct), aad)
        assert saw_v2 and saw_v3

    def test_statuses_epochs_and_disablements_survive(self, rig: Rig) -> None:
        rig.upgrade()
        old = {row["principal_key"]: row for row in rig.fixture.rows("principal_status")}
        assert len(old) == 4
        for legacy_key, was in old.items():
            st = rig.store.get_principal_status(rig.store.resolve_legacy_key(legacy_key) or "")
            assert st.stored, legacy_key
            assert st.status == was["status"]
            assert st.session_epoch == was["session_epoch"]
            assert st.is_owner == bool(was["is_owner"])
            assert st.disabled_reason == was["disabled_reason"] and st.disabled_at == was["disabled_at"]
            if was["disabled_by"] is None:
                assert st.disabled_by is None
            elif was["disabled_by"] == "operator":
                assert st.disabled_by == "operator"
            else:
                assert st.disabled_by == rig.store.resolve_legacy_key(was["disabled_by"])
            if was["is_owner"]:
                assert st.role_source == "rules" and st.role_seen_at == was["owner_seen_at"]
        assert rig.store.count_active_owners() == 2

    def test_principals_with_no_status_row_become_ordinary_active_accounts(self, rig: Rig) -> None:
        rig.upgrade()
        for name in ("legacy", "school_k1", "rejected", "deleted"):
            st = rig.store.get_principal_status(rig.key(name))
            assert st.active and not st.is_owner and st.admitted_via == "rules", name

    def test_every_account_has_exactly_one_entra_identity_built_from_tenant_and_oid(
        self, rig: Rig
    ) -> None:
        rig.upgrade()
        accounts = rig.store.list_accounts()
        assert len(accounts) == 12
        for account in accounts:
            assert len(account.identities) == 1
            identity = account.identities[0]
            assert identity.provider_id == "entra"
            assert identity.issuer == _entra_issuer(rig.fixture)
            assert identity.email is None and not identity.email_verified
        by_legacy = {a.legacy_key: a for a in accounts}
        assert set(by_legacy) == set(rig.fixture.principals.values())
        assert by_legacy[rig.fixture.key("owner_one")].username == "owner_one@example.test"

    def test_preferences_generations_and_history_are_rekeyed_in_place(self, rig: Rig) -> None:
        old_prefs = rig.fixture.rows("user_tool_prefs")
        old_gens = {r["principal_key"]: r for r in rig.fixture.rows("credential_generations")}
        old_events = rig.fixture.rows("principal_status_events")
        rig.upgrade()
        prefs = rig.store.get_tool_prefs(rig.key("owner_one"))
        assert prefs is not None and prefs.enabled_write_tools == {"send_message", "create_announcement"}
        assert len(old_prefs) == 1
        for legacy_key, was in old_gens.items():
            key = rig.store.resolve_legacy_key(legacy_key)
            if key is None:
                assert not legacy_key.startswith("entra:")  # only an opaque key has no account
                continue
            # The credential generation is kept as it was: the plaintext did not change.
            assert rig.store.credential_generation(key) == was["generation"], legacy_key
        events = raw_sql(
            rig.store,
            "SELECT id, principal_key, action, actor, reason, session_epoch, at"
            " FROM principal_status_events WHERE action <> 'account_created' ORDER BY id",
        )
        assert [r[0] for r in events] == [e["id"] for e in old_events]  # ids and order
        for new, was in zip(events, old_events, strict=True):
            assert new[1] == rig.store.resolve_legacy_key(was["principal_key"])
            assert new[2:3] == (was["action"],) and new[4:] == (was["reason"], was["session_epoch"], was["at"])
            if was["actor"] in (None, "operator"):
                assert new[3] == was["actor"]
            else:
                assert new[3] == rig.store.resolve_legacy_key(was["actor"])

    def test_no_legacy_key_is_left_in_any_text_column(self, rig: Rig) -> None:
        rig.upgrade()
        for table, rows in rig.dump().items():
            if table in ("meta", "canvas_mcp_alembic_version"):
                continue
            for row in rows:
                for value in row:
                    if isinstance(value, str) and "entra:" in value:
                        # the only place the word may appear is the issuer URL host name
                        pytest.fail(f"{table} still holds {value[:40]!r}")

    def test_the_migration_is_recorded_in_the_audit_log(self, rig: Rig) -> None:
        rig.upgrade()
        entries = [e for e in rig.store.list_audit() if e.action == "schema_migrated"]
        assert len(entries) == 1
        assert entries[0].actor == "system"
        assert entries[0].detail["accounts"] == 12 and entries[0].detail["to_schema"] == 5

    def test_an_empty_database_gets_no_audit_row_and_needs_no_keys(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path / "empty.sqlite3", keyring())
        store.database.prepare_storage()
        migrate.upgrade(store.database)  # no keyring at all
        assert migrate.current(store.database).state == migrate.STATE_CURRENT
        assert store.list_audit() == []
        assert store.list_accounts() == []


class TestRowsThatAreNotEntraUsersOrCannotBeRead:
    def test_an_opaque_key_is_carried_over_unchanged_and_stays_unreachable(self, rig: Rig) -> None:
        report = rig.upgrade()
        assert report.unmapped_keys == [rig.fixture.other_key] and report.tokens_unmapped == 1
        row = rig.store.get(rig.fixture.other_key)
        assert row is not None and row.api_token == rig.fixture.plaintexts[rig.fixture.other_key]
        assert rig.store.get_principal_status(rig.fixture.other_key).missing  # no account: refused

    def test_an_unreadable_row_that_was_already_marked_is_carried_over_byte_for_byte(
        self, rig: Rig
    ) -> None:
        was = next(
            r for r in rig.fixture.rows("canvas_tokens")
            if r["principal_key"] == rig.fixture.key("corrupt")
        )
        report = rig.upgrade()
        assert report.tokens_carried_unreadable == 1
        key = rig.key("corrupt")
        raw = raw_sql(
            rig.store,
            "SELECT key_id, nonce, ciphertext, status, invalid_reason FROM canvas_tokens"
            " WHERE principal_key = :k",
            {"k": key},
        )[0]
        assert (raw[0], bytes(raw[1]), bytes(raw[2])) == (was["key_id"], was["nonce"], was["ciphertext"])
        assert (raw[3], raw[4]) == ("invalid", "decrypt_failed")
        with pytest.raises(TokenDecryptionError):
            rig.store.get(key)

    def test_the_server_starts_although_a_known_unreadable_row_shares_a_key_id(self, rig: Rig) -> None:
        rig.upgrade()
        # initialize() probes one healthy row per key id and skips the unreadable one.
        make_store(rig.tmp_path / "tokens.sqlite3", keyring()).initialize()

    def test_an_undecryptable_active_row_stops_the_upgrade_and_leaves_the_file_alone(
        self, rig: Rig
    ) -> None:
        victim = rig.fixture.key("school_k1")
        raw_sql(
            rig.store,
            "UPDATE canvas_tokens SET ciphertext = :c WHERE principal_key = :k",
            {"c": b"\x00" * 33, "k": victim},
        )
        before = rig.dump()
        with pytest.raises(TokenStoreError, match="does not decrypt"):
            rig.upgrade()
        assert rig.dump() == before
        assert rig.revision() == migrate.BASELINE_REVISION

    def test_the_operator_can_mark_such_rows_invalid_instead(self, rig: Rig) -> None:
        victim = rig.fixture.key("school_k1")
        raw_sql(
            rig.store,
            "UPDATE canvas_tokens SET ciphertext = :c WHERE principal_key = :k",
            {"c": b"\x00" * 33, "k": victim},
        )
        old_generation = {
            r["principal_key"]: r["generation"] for r in rig.fixture.rows("credential_generations")
        }.get(victim, 0)
        report = AccountMigrationReport()
        migrate.upgrade(
            rig.db, keyring=keyring(), mark_undecryptable_invalid=True, report=report
        )
        assert report.tokens_marked_invalid == 1
        key = rig.key("school_k1")
        info = rig.store.info(key)
        assert info is not None
        assert (info.status, info.invalid_reason) == ("invalid", "decrypt_failed")
        assert rig.store.credential_generation(key) == old_generation + 1  # raised, not reset
        # The other tokens were migrated as usual.
        row = rig.store.get(rig.key("legacy"))
        assert row is not None and row.api_token == rig.fixture.plaintexts[rig.fixture.key("legacy")]

    def test_the_automatic_start_never_applies_the_forgiving_flag(self, rig: Rig) -> None:
        raw_sql(
            rig.store,
            "UPDATE canvas_tokens SET ciphertext = :c WHERE principal_key = :k",
            {"c": b"\x00" * 33, "k": rig.fixture.key("school_k1")},
        )
        with pytest.raises(TokenStoreError):
            rig.store.initialize()  # DATABASE_AUTO_MIGRATE=true, the default
        assert rig.revision() == migrate.BASELINE_REVISION


class TestKeysAreNeeded:
    def test_a_missing_key_id_refuses_the_upgrade_and_leaves_the_file_alone(self, tmp_path: pathlib.Path) -> None:
        rig = Rig(tmp_path)
        before = rig.dump()
        only_k2 = rig.store_with(keyring(only="k2"))
        with pytest.raises(KeyringError, match="missing key id"):
            only_k2.initialize()
        assert rig.dump() == before and rig.revision() == migrate.BASELINE_REVISION

    def test_a_wrong_key_under_a_known_id_refuses_the_upgrade(self, tmp_path: pathlib.Path) -> None:
        rig = Rig(tmp_path)
        before = rig.dump()
        wrong = rig.store_with(
            Keyring.parse(
                "k2:" + base64.b64encode(bytes([9]) * 32).decode()
                + ",k1:" + base64.b64encode(bytes([8]) * 32).decode()
            )
        )
        with pytest.raises(TokenStoreError, match="does not decrypt"):
            wrong.initialize()
        assert rig.dump() == before and rig.revision() == migrate.BASELINE_REVISION

    def test_no_keyring_at_all_refuses_a_database_with_tokens(self, rig: Rig) -> None:
        before = rig.dump()
        with pytest.raises(TokenStoreError, match="needs CANVAS_TOKEN_KEYS"):
            migrate.upgrade(rig.db)
        assert rig.dump() == before and rig.revision() == migrate.BASELINE_REVISION

    def test_the_keys_in_a_different_order_work(self, tmp_path: pathlib.Path) -> None:
        rig = Rig(tmp_path)
        reordered = rig.store_with(keyring(order=("k1", "k2")))  # k1 becomes the active key
        reordered.initialize()
        migrated = {
            r[0]
            for r in raw_sql(
                reordered, "SELECT key_id FROM canvas_tokens WHERE principal_key LIKE 'acct:%'"
            )
        }
        assert "k1" in migrated  # re-encrypted under the key that is active now
        row = reordered.get(reordered.resolve_legacy_key(rig.fixture.key("school_k2")) or "")
        assert row is not None and row.api_token == rig.fixture.plaintexts[rig.fixture.key("school_k2")]


class TestDryRun:
    def test_it_reports_and_changes_nothing(self, rig: Rig) -> None:
        before = rig.dump()
        report = AccountMigrationReport()
        before_status, after_status = migrate.upgrade(
            rig.db, keyring=keyring(), dry_run=True, report=report
        )
        assert rig.dump() == before
        assert rig.revision() == migrate.BASELINE_REVISION
        assert before_status.state == after_status.state == migrate.STATE_BEHIND
        assert report.dry_run and report.ran
        assert (report.accounts, report.identities) == (12, 12)
        assert report.tokens_reencrypted == 8 and report.tokens_carried_unreadable == 1
        assert report.tokens_unmapped == 1 and report.owner_accounts == 2 and report.disabled_accounts == 2
        assert report.unmapped_keys == [rig.fixture.other_key]
        assert report.rows_rekeyed["user_tool_prefs"] == 1
        assert not list(rig.tmp_path.glob("*.bak"))  # no backup for a dry run
        text = "\n".join(report.lines())
        assert "accounts to create: 12" in text and rig.fixture.tenant_id not in text

    def test_a_dry_run_after_the_upgrade_is_a_no_op(self, rig: Rig) -> None:
        rig.upgrade()
        before = rig.dump()
        migrate.upgrade(rig.db, keyring=keyring(), dry_run=True)
        assert rig.dump() == before

    def test_a_dry_run_still_refuses_what_the_real_run_would_refuse(self, rig: Rig) -> None:
        with pytest.raises(TokenStoreError, match="needs CANVAS_TOKEN_KEYS"):
            migrate.upgrade(rig.db, dry_run=True)


class TestAtomicity:
    def test_a_failure_after_the_inserts_rolls_everything_back(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        before = rig.dump()

        def explode() -> None:
            raise RuntimeError("injected failure after the data was written")

        monkeypatch.setattr(accounts_v5, "_after_inserts", explode)
        with pytest.raises(RuntimeError, match="injected"):
            rig.upgrade()
        monkeypatch.undo()
        assert rig.dump() == before  # tables, rows and the alembic record unchanged
        status = migrate.current(rig.db)
        assert status.alembic_revision == migrate.BASELINE_REVISION and status.meta_version == "4"
        if not IS_POSTGRES:
            assert not list(rig.tmp_path.glob("*.bak"))  # the automatic copy is deleted again
        rig.upgrade()  # and it still migrates cleanly afterwards
        assert migrate.current(rig.db).state == migrate.STATE_CURRENT

    def test_a_failed_verification_rolls_back_too(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        before = rig.dump()
        original = accounts_v5._verify

        def tamper(bind: Any, plan: Any, *args: Any) -> None:
            bind.exec_driver_sql("UPDATE accounts SET session_epoch = session_epoch + 1")
            original(bind, plan, *args)

        monkeypatch.setattr(accounts_v5, "_verify", tamper)
        with pytest.raises(TokenStoreError, match="migration check failed"):
            rig.upgrade()
        monkeypatch.undo()
        assert rig.dump() == before

    def test_a_malformed_entra_key_aborts_the_migration(self, rig: Rig) -> None:
        raw_sql(
            rig.store,
            "UPDATE user_tool_prefs SET principal_key = 'entra:not-a-guid:x'",
        )
        before = rig.dump()
        with pytest.raises(TokenStoreError, match="malformed"):
            rig.upgrade()
        assert rig.dump() == before


@pytest.mark.sqlite_only
class TestTheAutomaticBackup:
    def test_a_populated_file_is_copied_first_and_the_copy_is_the_old_state(self, rig: Rig) -> None:
        before = rig.dump()
        report = rig.upgrade()
        backups = list(rig.tmp_path.glob("tokens.sqlite3.pre-0002-accounts-*.bak"))
        assert len(backups) == 1 and report.backup_path == str(backups[0])
        if sys.platform != "win32":
            assert stat.S_IMODE(backups[0].stat().st_mode) == 0o600
        assert dump(type(rig.db).sqlite(backups[0])) == before
        assert os.path.getsize(backups[0]) > 0

    def test_an_explicit_backup_replaces_the_automatic_one(self, rig: Rig) -> None:
        mine = rig.tmp_path / "mine.bak"
        migrate.upgrade(rig.db, keyring=keyring(), backup_to=mine)
        assert mine.exists()
        assert not list(rig.tmp_path.glob("*.pre-0002-accounts-*.bak"))

    def test_an_empty_file_is_not_copied(self, tmp_path: pathlib.Path) -> None:
        store = make_store(tmp_path / "new.sqlite3", keyring())
        store.initialize()
        assert not list(tmp_path.glob("*.bak"))

    def test_a_second_start_makes_no_new_copy(self, rig: Rig) -> None:
        rig.upgrade()
        make_store(rig.tmp_path / "tokens.sqlite3", keyring()).initialize()
        assert len(list(rig.tmp_path.glob("*.bak"))) == 1

    def test_the_copy_failing_refuses_the_upgrade_before_anything_is_written(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        before = rig.dump()

        def refuse(*_a: Any, **_k: Any) -> None:
            raise TokenStoreError("no space left for the backup")

        monkeypatch.setattr(migrate, "backup_sqlite", refuse)
        with pytest.raises(TokenStoreError, match="backup"):
            rig.upgrade()
        monkeypatch.undo()
        assert rig.dump() == before and rig.revision() == migrate.BASELINE_REVISION


class TestAfterTheUpgrade:
    def test_a_second_start_is_a_no_op_and_the_schema_matches_the_metadata(self, rig: Rig) -> None:
        rig.upgrade()
        rows = rig.dump()
        for _ in range(2):
            make_store(rig.tmp_path / "tokens.sqlite3", keyring()).initialize()
        assert rig.dump() == rows
        status = migrate.current(rig.db)
        assert status.meta_version == "5" and status.state == migrate.STATE_CURRENT
        with rig.db.read() as conn:
            assert migrate.compare_schema(conn) == []
        names = set(rows)
        assert "principal_status" not in names
        assert set(schema.TABLE_NAMES) <= names

    @pytest.mark.sqlite_only
    def test_the_previous_release_refuses_the_migrated_file(self, rig: Rig) -> None:
        rig.upgrade()
        before = rig.dump()
        with pytest.raises(TokenStoreError, match="newer than this server supports"):
            with rig.db.write() as conn:
                baseline_v4.ensure_sqlite_v4(conn)
        assert rig.dump() == before

    @pytest.mark.sqlite_only
    def test_a_stale_process_of_the_previous_release_fails_closed(self, rig: Rig) -> None:
        """What the old code would run per request cannot succeed: its tables are gone."""
        rig.upgrade()
        for sql in (
            "SELECT status FROM principal_status LIMIT 1",
            "SELECT tenant_id, object_id FROM canvas_tokens LIMIT 1",
        ):
            with pytest.raises(Exception, match="no such"):
                raw_sql(rig.store, sql)

    def test_the_upgrade_is_the_same_whichever_way_it_was_started(self, tmp_path: pathlib.Path) -> None:
        """Auto-migrate at start and ``db upgrade`` reach identical accounts and tokens."""
        a = Rig(tmp_path / "a")
        b = Rig(tmp_path / "b")
        a.upgrade()
        migrate.upgrade(b.db, keyring=keyring())

        def summary(rig: Rig) -> list[tuple[Any, ...]]:
            return sorted(
                (acc_.legacy_key, acc_.status.status, acc_.status.role, acc_.status.session_epoch)
                for acc_ in rig.store.list_accounts()
            )

        assert summary(a) == summary(b)


class TestBehaviourForExistingUsersIsUnchanged:
    """The same Entra claims reach the same token, on the MCP path and on /account."""

    @staticmethod
    def _claims(fixture: Schema4, name: str, *, roles: tuple[str, ...]) -> dict[str, Any]:
        oid = fixture.key(name).rsplit(":", 1)[1]
        from .conftest import CLIENT

        return {
            "tid": fixture.tenant_id, "azp": CLIENT, "oid": oid, "roles": list(roles),
            "iat": 1_800_000_000, "exp": 1_800_003_600, "name": name,
        }

    def _service(self, rig: Rig) -> Any:
        from canvas_mcp.core.selfhost.accounts import EntraClaimsPolicy
        from canvas_mcp.core.selfhost.identity import IdentityService

        from .conftest import CLIENT, POLICY

        return IdentityService(rig.store, EntraClaimsPolicy(rig.fixture.tenant_id, CLIENT), POLICY)

    def test_an_enrolled_user_resolves_to_the_account_that_holds_their_token(self, rig: Rig) -> None:
        rig.upgrade()
        service = self._service(rig)
        principal = service.resolve_request(self._claims(rig.fixture, "school_k1", roles=("Canvas.User",)))
        assert getattr(principal, "key", None) == rig.key("school_k1")
        row = rig.store.get(principal.key)  # type: ignore[union-attr]
        assert row is not None and row.api_token == rig.fixture.plaintexts[rig.fixture.key("school_k1")]
        signed = service.sign_in(self._claims(rig.fixture, "school_k1", roles=("Canvas.User",)))
        assert signed.principal_key == rig.key("school_k1") and not signed.owner  # type: ignore[union-attr]

    def test_no_new_account_is_made_for_a_migrated_user(self, rig: Rig) -> None:
        rig.upgrade()
        service = self._service(rig)
        before = len(rig.store.list_accounts())
        for name in ("legacy", "school_k2", "owner_one"):
            service.resolve_request(self._claims(rig.fixture, name, roles=("Canvas.User",)))
            service.sign_in(self._claims(rig.fixture, name, roles=("Canvas.User",)))
        assert len(rig.store.list_accounts()) == before

    def test_a_disabled_user_is_still_refused(self, rig: Rig) -> None:
        rig.upgrade()
        service = self._service(rig)
        denied = service.resolve_request(self._claims(rig.fixture, "disabled_row", roles=("Canvas.User",)))
        assert isinstance(denied, acc.Denied) and denied.code == acc.DENY_ACCESS_DISABLED
        refused = service.sign_in(self._claims(rig.fixture, "disabled_bare", roles=("Canvas.User",)))
        assert isinstance(refused, acc.Denied) and refused.code == acc.DENY_ACCESS_DISABLED

    def test_an_owner_is_still_an_owner_after_signing_in_with_the_owner_role(self, rig: Rig) -> None:
        rig.upgrade()
        service = self._service(rig)
        signed = service.sign_in(self._claims(rig.fixture, "owner_one", roles=("Canvas.Owner",)))
        assert signed.owner and signed.status.is_owner  # type: ignore[union-attr]
        assert rig.store.count_active_owners() == 2

    def test_an_owner_who_lost_the_role_keeps_it_only_while_another_owner_exists(self, rig: Rig) -> None:
        rig.upgrade()
        service = self._service(rig)
        losing = self._claims(rig.fixture, "owner_one", roles=("Canvas.User",))
        signed = service.sign_in(losing)
        assert not signed.owner  # type: ignore[union-attr]
        assert not rig.store.get_principal_status(rig.key("owner_one")).is_owner  # owner_two remains
        again = service.sign_in(self._claims(rig.fixture, "owner_two", roles=("Canvas.User",)))
        assert not again.owner  # type: ignore[union-attr]
        # owner_two is the last one: the stored role is kept, the admin pages are not granted.
        assert rig.store.get_principal_status(rig.key("owner_two")).is_owner

    def test_the_user_without_the_role_is_still_refused(self, rig: Rig) -> None:
        rig.upgrade()
        service = self._service(rig)
        denied = service.resolve_request(self._claims(rig.fixture, "legacy", roles=()))
        assert isinstance(denied, acc.Denied) and denied.code == acc.DENY_ACCESS_DENIED
        assert rig.store.get_principal_status(rig.key("legacy")).active  # not disabled by it


def test_the_frozen_aad_builders_equal_the_live_ones() -> None:
    from canvas_mcp.core.selfhost import token_store as live

    key = "acct:11111111-2222-4333-8444-555555555555"
    assert accounts_v5.aad_v2(key, "canvas.example.edu", "k1") == live._aad_v2(key, "canvas.example.edu", "k1")
    assert accounts_v5.aad_v3(key, "k1") == live._aad_v3(key, "k1")
    tid, oid = "11111111-2222-3333-4444-555555555555", "aaaaaaaa-0000-4000-8000-00000000000a"
    assert accounts_v5.aad_v1(tid, oid, "k1") == (
        b"canvas-mcp/canvas-token/v1\x1f" + f"{tid}\x1f{oid}\x1fk1".encode()
    )
    digest = hashlib.sha256(accounts_v5.aad_v3(key, "k1")).hexdigest()
    assert len(digest) == 64


def test_the_issuer_the_migration_writes_equals_the_one_the_login_derives() -> None:
    tid = "11111111-2222-3333-4444-555555555555"
    assert accounts_v5._ENTRA_ISSUER.format(tid=tid) == acc.entra_issuer(tid)


def test_the_migration_options_default_to_the_safe_behaviour() -> None:
    options = MigrationOptions()
    assert not options.dry_run and not options.mark_undecryptable_invalid and options.now is None
