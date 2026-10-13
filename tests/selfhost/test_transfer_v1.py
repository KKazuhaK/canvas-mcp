"""Real v1 transfer, native types, reserved rows and complete transactional rollback."""

import hashlib

import pytest
from dbbackend import pg_database
from sqlalchemy import insert, inspect, select, text, update

from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.db.migrations import runner, transfer
from canvas_mcp.core.selfhost.db.sealed import verify
from canvas_mcp.core.selfhost.db.types import new_id
from canvas_mcp.core.selfhost.login.local_accounts import (
    LOCAL_ISSUER,
    LocalAccounts,
    password_hash,
)
from canvas_mcp.core.selfhost.login.provider_store import ProviderConfigStore
from canvas_mcp.core.selfhost.token_store import (
    KeyringError,
    TokenStore,
    TokenStoreError,
)

from .test_sealed_v1 import NOW, keyring, populate_sealed


@pytest.fixture
def source(tmp_path):
    ring = keyring()
    path = tmp_path / "source.sqlite3"
    store = TokenStore(path, ring, clock=lambda: NOW)
    store.initialize()
    account, credential = populate_sealed(store, ring)
    store.set_tool_prefs(account, ["submit_assignment"])
    grant = new_id()
    with store.database.write() as conn:
        conn.execute(update(s.server_state).values(jwt_epoch=17, settings_revision=12))
        conn.execute(
            update(s.login_providers).values(
                display_name="School", sort_rank=3, configured=True
            )
        )
        conn.execute(
            insert(s.login_providers).values(
                id="local",
                protocol="local",
                configured=True,
                config_source="db",
                config={},
                created_at=NOW,
                updated_at=NOW,
            )
        )
        store._repos.identities.insert(
            conn,
            account_id=account,
            provider_id="local",
            issuer=LOCAL_ISSUER,
            subject=account,
            username="student.local",
            email=None,
            email_verified=False,
            now=NOW,
        )
        conn.execute(
            insert(s.local_credentials).values(
                account_id=account,
                password_hash=password_hash("transfer-local-password-0123456789"),
                created_at=NOW,
                updated_at=NOW,
            )
        )
        conn.execute(
            s.accounts.update()
            .where(s.accounts.c.id == account)
            .values(upn="student.local")
        )
        conn.execute(
            insert(s.account_login_policy).values(
                account_id=account, allow_multiple=True
            )
        )
        conn.execute(
            insert(s.account_allowed_login_providers).values(
                account_id=account, provider_id="local"
            )
        )
        conn.execute(
            insert(s.settings).values(
                key="schools.directory_search", value=False, updated_at=NOW
            )
        )
        conn.execute(
            insert(s.oauth_clients).values(
                id="client",
                info={"client_name": "Client", "test": [True, 1]},
                client_name="Client",
                created_at=NOW,
                expires_at=NOW + 1000,
            )
        )
        conn.execute(
            insert(s.cimd_clients).values(
                url="https://client.example/doc",
                doc={"redirect_uris": ["https://client.example/cb"]},
                fetched_at=NOW,
                fresh_until=NOW + 1000,
            )
        )
        conn.execute(
            insert(s.oauth_grants).values(
                id=grant,
                account_id=account,
                client_id="client",
                client_kind="dcr",
                scopes="Canvas.Access",
                resource="https://mcp.example/mcp",
                created_at=NOW,
                upstream_auth_at=NOW,
                expires_at=NOW + 1000,
            )
        )
        conn.execute(
            insert(s.oauth_refresh_tokens).values(
                token_hash=b"r" * 32, grant_id=grant, created_at=NOW
            )
        )
        conn.execute(
            insert(s.oauth_codes).values(
                code_hash=b"c" * 32,
                client_id="client",
                account_id=account,
                redirect_uri="https://client.example/cb",
                redirect_uri_explicit=True,
                code_challenge="challenge",
                scopes="Canvas.Access",
                resource="https://mcp.example/mcp",
                client_kind="dcr",
                upstream_auth_at=NOW,
                session_epoch=0,
                created_at=NOW,
                expires_at=NOW + 60,
            )
        )
        conn.execute(
            insert(s.login_states).values(
                kind="login",
                id_hash=b"l" * 32,
                payload=b"state",
                created_at=NOW,
                expires_at=NOW + 60,
            )
        )
        conn.execute(
            insert(s.auth_events),
            [
                {
                    "id": i + 10000,
                    "at": NOW,
                    "account_id": account,
                    "provider_id": "oidc:school",
                    "surface": "web",
                    "outcome": "success",
                    "reason": "ok",
                    "ua_hash": b"h" * 8,
                }
                for i in range(1005)
            ],
        )
        conn.execute(
            insert(s.audit_log).values(
                id=20000,
                at=NOW,
                actor_kind="system",
                action="test",
                target_kind="account",
                target_id=account,
                subject_account_id=account,
                detail={"native": [True, 1, "text"]},
            )
        )
        conn.execute(
            insert(s.web_sessions).values(
                id_hash=b"w" * 32,
                account_id=account,
                session_epoch=0,
                provider_id="oidc:school",
                issued_at=NOW,
                last_seen_at=NOW,
                expires_at=NOW + 1000,
                ua_hash=b"u" * 8,
            )
        )
        conn.execute(
            insert(s.account_quotas).values(
                account_id=account,
                quota_key="requests",
                limit_value=100,
                window_seconds=60,
                updated_at=NOW,
            )
        )
        conn.execute(
            insert(s.notification_preferences).values(
                account_id=account,
                enabled=True,
                email="student@example.test",
                locale="zh",
                updated_at=NOW,
            )
        )
        conn.execute(
            insert(s.notification_deliveries).values(
                id="d" * 64,
                account_id=account,
                credential_id=credential.credential_id,
                generation=credential.credential_generation,
                expires_at=NOW + 86400,
                stage="soon",
                status="sent",
                attempts=1,
                lease_until=NOW + 3600,
                updated_at=NOW,
            )
        )
    try:
        yield store, path, ring, account, credential
    finally:
        store.close()


@pytest.fixture
def target(tmp_path):
    db = pg_database(tmp_path / "target")
    try:
        yield db
    finally:
        db.dispose()


def digest(path):
    return hashlib.sha256(path.read_bytes()).digest()


@pytest.mark.postgres
def test_all_lifecycle_tables_copy_native_types_and_sequences_and_skip_ephemeral(
    source, target
):
    store, path, ring, account, credential = source
    runner.ensure_ready(target)
    before = runner.current(target).database_id
    with target.write() as conn:
        conn.execute(
            insert(s.login_providers),
            [
                {
                    "id": name,
                    "protocol": "oidc",
                    "display_name": "Target",
                    "sort_rank": 0,
                    "created_at": NOW,
                    "updated_at": NOW,
                }
                for name in ("oidc:school", "oidc:target")
            ],
        )
    checksum = digest(path)
    report = transfer.import_sqlite(target, path, ring)
    assert digest(path) == checksum
    assert report.sealed_values_checked == 4
    assert set(report.counts) == {table.name for table in transfer.copied_tables()}
    assert all(count >= 1 for count in report.counts.values())
    with store.database.read() as src, target.read() as dst:
        for table in transfer.copied_tables():
            actual = [dict(row) for row in dst.execute(select(table)).mappings()]
            if table is s.login_providers:
                actual = [row for row in actual if row["id"] != "oidc:target"]
            original = [dict(row) for row in src.execute(select(table)).mappings()]
            assert sorted(actual, key=repr) == sorted(original, key=repr), table.name
        assert dst.execute(select(s.oauth_codes)).first() is None
        assert dst.execute(select(s.login_states)).first() is None
        state = dst.execute(select(s.server_state)).mappings().one()
        assert (
            state["database_id"] == before != runner.current(store.database).database_id
        )
        assert (
            state["compat_floor"],
            state["jwt_epoch"],
            state["settings_revision"],
        ) == (3, 17, 13)
        assert verify(dst, ring, all_values=True) == 4
        assert (
            dst.execute(
                text("SELECT pg_typeof(id)::text FROM accounts LIMIT 1")
            ).scalar_one()
            == "uuid"
        )
        assert (
            dst.execute(
                text("SELECT pg_typeof(value)::text FROM settings LIMIT 1")
            ).scalar_one()
            == "jsonb"
        )
        assert (
            dst.execute(
                text("SELECT pg_typeof(configured)::text FROM login_providers LIMIT 1")
            ).scalar_one()
            == "boolean"
        )
        assert (
            dst.execute(
                text(
                    "SELECT pg_typeof(token_hash)::text FROM oauth_refresh_tokens LIMIT 1"
                )
            ).scalar_one()
            == "bytea"
        )
    with target.write() as conn:
        assert (
            conn.execute(
                insert(s.auth_events)
                .values(
                    at=NOW,
                    provider_id="entra",
                    surface="web",
                    outcome="denied",
                    reason="test",
                )
                .returning(s.auth_events.c.id)
            ).scalar_one()
            == 11005
        )
        assert (
            conn.execute(
                insert(s.audit_log)
                .values(at=NOW, actor_kind="system", action="test")
                .returning(s.audit_log.c.id)
            ).scalar_one()
            == 20001
        )
    # A copied hash, local identity and provider must work together on native PG,
    # not merely survive a byte-for-byte table comparison.
    local = LocalAccounts(ProviderConfigStore(target, ring))
    assert (
        local.authenticate(
            "student.local", "transfer-local-password-0123456789", now=NOW + 1
        ).id
        == account
    )


@pytest.mark.postgres
@pytest.mark.parametrize("initialized", [False, True])
def test_sealed_failure_rolls_back_schema_rows_settings_and_sequences(
    source, target, monkeypatch, initialized
):
    _, path, ring, _, _ = source
    if initialized:
        runner.ensure_ready(target)
    previous = runner.current(target)
    checksum = digest(path)

    def failure(conn, keys, **kwargs):
        raise KeyringError("injected sealed verification failure")

    monkeypatch.setattr(transfer, "verify", failure)
    with pytest.raises(KeyringError, match="injected"):
        transfer.import_sqlite(target, path, ring)
    assert runner.current(target) == previous and digest(path) == checksum
    with target.read() as conn:
        if initialized:
            assert not transfer._holds_rows(conn)
            assert conn.exec_driver_sql(
                "SELECT last_value,is_called FROM audit_log_id_seq"
            ).one() == (1, False)
            assert (
                conn.execute(select(s.server_state.c.settings_revision)).scalar_one()
                == 0
            )
        else:
            assert inspect(conn).get_table_names() == []


@pytest.mark.postgres
@pytest.mark.parametrize("reason", ["nonempty", "same_id", "ephemeral"])
def test_refusals_leave_target_untouched(source, target, reason):
    store, path, ring, _, _ = source
    runner.ensure_ready(target)
    with target.write() as conn:
        if reason == "nonempty":
            conn.execute(
                insert(s.settings).values(
                    key="schools.directory_search", value=True, updated_at=NOW
                )
            )
        elif reason == "same_id":
            conn.execute(
                update(s.server_state).values(
                    database_id=runner.current(store.database).database_id
                )
            )
        else:
            conn.execute(
                insert(s.login_states).values(
                    kind="login",
                    id_hash=b"a" * 32,
                    payload=b"state",
                    created_at=NOW,
                    expires_at=NOW + 60,
                )
            )
    previous = runner.current(target)
    with pytest.raises(TokenStoreError, match="already holds data|same database_id"):
        transfer.import_sqlite(target, path, ring)
    assert runner.current(target) == previous
    with target.read() as conn:
        assert conn.execute(select(s.accounts)).first() is None


@pytest.mark.postgres
def test_silent_switch_refuses_empty_initialized_target_until_import(source, target):
    _, path, ring, _, _ = source
    runner.ensure_ready(target)
    assert transfer.sqlite_has_rows(path)
    with pytest.raises(TokenStoreError, match="holds no data"):
        transfer.refuse_silent_switch(target, path)
    transfer.import_sqlite(target, path, ring)
    transfer.refuse_silent_switch(target, path)


def test_pre_v1_copy_is_refused_and_source_unchanged(tmp_path):
    import sqlite3

    path = tmp_path / "old.sqlite3"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY,value TEXT)")
        conn.execute("INSERT INTO meta VALUES ('schema_version','4')")
    checksum = digest(path)
    assert transfer.sqlite_has_rows(path)
    with pytest.raises(TokenStoreError, match="pre-v1"), transfer._private_copy(path):
        pass
    assert digest(path) == checksum
