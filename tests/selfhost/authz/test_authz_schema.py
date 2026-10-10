"""The tables of the authorization server: migration, transfer, the keyring, account disabling."""

from __future__ import annotations

import json
import pathlib

import pytest
from dbbackend import PG_URL, make_store, raw_sql, reset_public_schema

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.db import migrate, schema, transfer
from canvas_mcp.core.selfhost.db.repos import SIGN_IN_SURFACES, Repositories
from canvas_mcp.core.selfhost.token_store import (
    AUDIT_ACTIONS,
    OPERATOR,
    Keyring,
    KeyringError,
    TokenStore,
)

from ..conftest import OID_A, make_account
from .conftest import KEYS_RAW

AUTHZ_TABLES = (
    "oauth_clients",
    "cimd_clients",
    "oauth_grants",
    "oauth_codes",
    "oauth_refresh_tokens",
    "login_states",
)


def _grant_fields(account_id: str, grant_id: str = "11111111-1111-4111-8111-111111111111") -> dict:
    return {
        "id": grant_id,
        "account_id": account_id,
        "client_id": "22222222-2222-4222-8222-222222222222",
        "client_kind": "dcr",
        "client_name": "App",
        "client_host": None,
        "redirect_host": "claude.ai",
        "scopes": "Canvas.Access",
        "resource": "https://canvas.example.test/mcp",
        "created_at": 1_800_000_000,
        "last_used_at": None,
        "upstream_auth_at": 1_800_000_000,
        "expires_at": 1_800_000_000 + 86400,
    }


class TestSchema:
    def test_a_fresh_database_has_the_tables_and_matches_the_metadata(self, token_store) -> None:
        with token_store.database.read() as conn:
            assert migrate.compare_schema(conn) == []
            status = migrate.read_status(conn)
        assert status.alembic_revision == "0003_oauth_authz"
        assert status.state == migrate.STATE_CURRENT
        assert status.meta_version == "5"
        assert set(AUTHZ_TABLES) <= set(schema.TABLE_NAMES)

    def test_upgrading_from_the_account_model_adds_the_tables_and_nothing_else(
        self, tmp_path: pathlib.Path, keyring: Keyring
    ) -> None:
        store = make_store(tmp_path / "up.sqlite3", keyring)
        store.initialize()
        make_account(store, OID_A)
        before = raw_sql(store, "SELECT id, status FROM accounts")
        for name in AUTHZ_TABLES:
            raw_sql(store, f"DROP TABLE {name}")
        raw_sql(store, f"UPDATE {schema.VERSION_TABLE} SET version_num = '0002_accounts'")
        again = make_store(tmp_path / "up.sqlite3", keyring)
        again.initialize()
        assert raw_sql(again, "SELECT id, status FROM accounts") == before
        with again.database.read() as conn:
            assert migrate.compare_schema(conn) == []
        assert raw_sql(again, "SELECT COUNT(*) FROM oauth_grants")[0][0] == 0

    def test_the_tables_partition_into_copied_and_ephemeral(self) -> None:
        copied, ephemeral = set(transfer.COPIED_TABLES), set(transfer.EPHEMERAL_TABLES)
        assert not copied & ephemeral
        assert set(schema.TABLE_NAMES) == {"meta"} | copied | ephemeral
        assert ephemeral == {"oauth_codes", "login_states"}

    def test_grants_do_not_count_as_data_for_the_silent_switch_guard(self) -> None:
        # Grants never exist without accounts, which are already probed.
        assert not set(AUTHZ_TABLES) & set(transfer._DATA_TABLES)

    def test_the_sign_in_surfaces_are_the_account_and_mcp_ones(self) -> None:
        assert SIGN_IN_SURFACES == acc.SIGN_IN_SURFACES
        assert acc.SURFACE_OAUTH not in SIGN_IN_SURFACES

    def test_the_new_audit_actions_and_reasons_are_registered(self) -> None:
        assert {"grant_revoked", "grants_revoked_for_account", "jwt_key_rotated"} <= AUDIT_ACTIONS
        assert {
            "consent_granted",
            "consent_denied",
            "grant_created",
            "code_replay",
            "refresh_reuse",
            "reauth_required",
            "client_revoked",
        } <= acc.AUTH_REASONS

    @pytest.mark.parametrize(
        ("table", "bad"),
        [
            ("oauth_grants", {"client_kind": "other"}),
            ("oauth_grants", {"revoked_reason": "because"}),
        ],
    )
    def test_the_closed_vocabularies_are_enforced_by_the_database(
        self, token_store, table: str, bad: dict
    ) -> None:
        account = make_account(token_store, OID_A).removeprefix("acct:")
        repos = Repositories(token_store.database.kind)
        fields = {**_grant_fields(account), **bad}
        with pytest.raises(Exception):  # noqa: B017 - the driver's integrity error
            with token_store.database.write() as conn:
                repos.grants.insert(conn, **fields)


class TestKeyringDerive:
    def test_the_derived_key_is_deterministic_and_purpose_bound(self, keyring: Keyring) -> None:
        a = keyring.derive("k1", "purpose-a")
        assert a == keyring.derive("k1", "purpose-a")
        assert len(a) == 32
        assert a != keyring.derive("k1", "purpose-b")
        assert a != keyring.derive("k0", "purpose-a")
        assert len(keyring.derive("k1", "x", length=48)) == 48

    def test_two_keyrings_with_the_same_keys_agree(self) -> None:
        assert Keyring.parse(KEYS_RAW).derive("k1", "p") == Keyring.parse(KEYS_RAW).derive("k1", "p")

    def test_an_unknown_key_id_is_refused(self, keyring: Keyring) -> None:
        with pytest.raises(KeyringError):
            keyring.derive("nope", "p")

    def test_the_derived_key_is_not_a_stored_key_and_the_repr_hides_keys(self, keyring: Keyring) -> None:
        raw = bytes(range(32))
        assert keyring.derive("k1", "p") != raw
        assert "k1" in repr(keyring) and "_raw" not in repr(keyring)

    def test_encryption_still_round_trips(self, keyring: Keyring) -> None:
        kid, nonce, ciphertext = keyring.encrypt(b"secret", b"aad")
        assert keyring.decrypt(kid, nonce, ciphertext, b"aad") == b"secret"


class TestDisablingRevokesGrants:
    def _grant(self, store: TokenStore, account_key: str, grant_id: str) -> None:
        repos = Repositories(store.database.kind)
        with store.database.write() as conn:
            repos.grants.insert(conn, **_grant_fields(account_key.removeprefix("acct:"), grant_id))

    def test_disable_revokes_every_live_grant_in_the_same_transaction(self, token_store) -> None:
        key = make_account(token_store, OID_A)
        other = make_account(token_store, "bbbbbbbb-0000-4000-8000-00000000000b")
        self._grant(token_store, key, "11111111-1111-4111-8111-111111111111")
        self._grant(token_store, key, "11111111-1111-4111-8111-111111111112")
        self._grant(token_store, other, "11111111-1111-4111-8111-111111111113")

        assert token_store.disable_principal(key, actor=OPERATOR, reason="operator_disabled")

        rows = raw_sql(
            token_store, "SELECT id, revoked_at, revoked_reason, revoked_by FROM oauth_grants ORDER BY id"
        )
        assert [(r[1] is not None, r[2], r[3]) for r in rows] == [
            (True, "account_disabled", "operator"),
            (True, "account_disabled", "operator"),
            (False, None, None),
        ]
        entry = [e for e in token_store.list_audit() if e.action == "account_disabled"][0]
        assert entry.detail == {"grants_revoked": 2}

    def test_the_audit_detail_is_unchanged_when_there_is_nothing_to_revoke(self, token_store) -> None:
        key = make_account(token_store, OID_A)
        assert token_store.disable_principal(key, actor=OPERATOR, reason="operator_disabled")
        entry = [e for e in token_store.list_audit() if e.action == "account_disabled"][0]
        assert entry.detail == {}

    def test_an_oauth_event_is_not_part_of_the_sign_in_history(self, token_store) -> None:
        key = make_account(token_store, OID_A)
        token_store.record_auth_event(
            account_key=key,
            provider_id="local",
            surface=acc.SURFACE_OAUTH,
            outcome="success",
            reason="consent_granted",
        )
        token_store.record_auth_event(
            account_key=key,
            provider_id="entra",
            surface=acc.SURFACE_ACCOUNT,
            outcome="success",
            reason="ok",
        )
        assert [e.surface for e in token_store.list_auth_events(key)] == ["account"]
        assert raw_sql(token_store, "SELECT COUNT(*) FROM auth_events")[0][0] == 2


@pytest.mark.postgres
class TestTransferToPostgres:
    def test_registered_clients_grants_and_refresh_tokens_move_and_codes_do_not(
        self, tmp_path: pathlib.Path, keyring: Keyring
    ) -> None:
        from canvas_mcp.core.selfhost.db.engine import Database
        from canvas_mcp.core.selfhost.db.url import parse_database_url

        source = tmp_path / "src.sqlite3"
        # Always a SQLite file, whatever backend the run selected: it is the import source.
        store = TokenStore(source, keyring)
        store.initialize()
        key = make_account(store, OID_A)
        repos = Repositories("sqlite")
        with store.database.write() as conn:
            repos.clients.insert(
                conn, client_id="c1", info_json=json.dumps({"client_id": "c1"}),
                client_name="App", now=1, expires_at=2_000_000_000,
            )
            repos.grants.insert(conn, **_grant_fields(key.removeprefix("acct:")))
            repos.refresh.insert(
                conn, token_hash="a" * 64, grant_id=_grant_fields("x")["id"], parent_hash=None,
                now=1, expires_at=2_000_000_000,
            )
            repos.codes.insert(
                conn, code_hash="b" * 64, client_id="c1", account_id="x", redirect_uri="https://e/cb",
                redirect_uri_explicit=1, code_challenge="c" * 43, scopes="s", resource="r",
                client_kind="dcr", client_name="", client_host=None, redirect_host="e",
                upstream_auth_at=1, session_epoch=0, created_at=1, expires_at=2,
            )
        from canvas_mcp.core.selfhost.authz.store import AuthzStore

        authz = AuthzStore(store.database)
        authz.bump_jwt_epoch()
        assert authz.bump_jwt_epoch() == 2  # a rotate-jwt-key done twice before the move
        store.close()

        reset_public_schema()
        target = Database(parse_database_url(PG_URL, pathlib.Path("/data")))
        report = transfer.import_sqlite(target, source, keyring)
        # tokens that the rotations invalidated must not verify again on the new database
        assert AuthzStore(target).jwt_epoch() == 2
        assert report.counts["oauth_clients"] == 1
        assert report.counts["oauth_grants"] == 1
        assert report.counts["oauth_refresh_tokens"] == 1
        assert "oauth_codes" not in report.counts
        with target.read() as conn:
            from sqlalchemy import text

            assert conn.execute(text("SELECT COUNT(*) FROM oauth_codes")).scalar_one() == 0
            assert conn.execute(text("SELECT COUNT(*) FROM oauth_grants")).scalar_one() == 1
