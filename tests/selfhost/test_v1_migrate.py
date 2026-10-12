"""The real squashed graph, compatibility gate and atomic creation transaction."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from dbbackend import IS_POSTGRES, pg_database
from sqlalchemy import insert, inspect, select, text

from canvas_mcp.core.selfhost.db import schema
from canvas_mcp.core.selfhost.db.engine import Database
from canvas_mcp.core.selfhost.db.errors import TokenStoreError
from canvas_mcp.core.selfhost.db.migrations import baseline_v1
from canvas_mcp.core.selfhost.db.migrations import runner as migrate
from canvas_mcp.core.selfhost.db.types import new_id


@pytest.fixture
def db(tmp_path):
    made = (
        pg_database(tmp_path / "migrate")
        if IS_POSTGRES
        else Database.sqlite(tmp_path / "migrate.sqlite3")
    )
    made.prepare_storage()
    try:
        yield made
    finally:
        made.dispose()


def test_graph_preserves_frozen_baseline_and_metadata_matches_real_upgrade(db):
    assert migrate.known_revisions() == {
        "0001_v1_baseline",
        "0002_local_credentials",
        "0003_account_login_policy",
    }
    assert migrate.head_revision() == "0003_account_login_policy"
    assert migrate.current(db).state == migrate.STATE_UNINITIALIZED
    migrate.ensure_ready(db)
    first = migrate.current(db)
    assert first.state == migrate.STATE_CURRENT and first.compat_floor == 2
    assert first.database_id is not None
    migrate.ensure_ready(db, auto=False)
    assert migrate.current(db) == first
    with db.read() as conn:
        assert migrate.compare_schema(conn) == []
        assert set(inspect(conn).get_table_names()) == set(schema.metadata.tables) | {
            schema.VERSION_TABLE
        }


def test_auto_migrate_off_does_not_partially_create_a_database(db):
    with pytest.raises(TokenStoreError, match="AUTO_MIGRATE"):
        migrate.ensure_ready(db, auto=False)
    with db.read() as conn:
        assert inspect(conn).get_table_names() == []


def test_beta5_upgrade_preserves_accounts_provider_ciphertext_and_database_identity(db):
    account_id = new_id()
    with db.row_write() as conn:
        migrate._apply(conn, "0001_v1_baseline")
        conn.execute(
            text(
                "INSERT INTO accounts(id,status,role,role_source,admitted_via,display_name,created_at,updated_at) VALUES (:id,'active','owner','bootstrap','bootstrap','Owner',1,1)"
            ),
            {"id": account_id},
        )
        conn.execute(
            insert(schema.login_providers).values(
                id="entra",
                protocol="entra",
                configured=True,
                config_source="db",
                config={"client_id": "preserved-client"},
                secret_key_id="k1",
                secret_nonce=b"n" * 12,
                secret_ciphertext=b"old encrypted secret",
                created_at=1,
                updated_at=1,
            )
        )
        old_account_columns = [
            column["name"] for column in inspect(conn).get_columns("accounts")
        ]
        old_provider_columns = [
            column["name"] for column in inspect(conn).get_columns("login_providers")
        ]
        account_query = text(
            "SELECT " + ",".join(old_account_columns) + " FROM accounts"
        )
        provider_query = text(
            "SELECT " + ",".join(old_provider_columns) + " FROM login_providers"
        )
        accounts = conn.execute(account_query).all()
        providers = conn.execute(provider_query).all()
    before = migrate.current(db)
    assert before.state == migrate.STATE_BEHIND
    migrate.ensure_ready(db)
    after = migrate.current(db)
    assert after.state == migrate.STATE_CURRENT
    assert after.database_id == before.database_id
    with db.read() as conn:
        assert conn.execute(account_query).all() == accounts
        assert conn.execute(provider_query).all() == providers
        assert conn.execute(select(schema.local_credentials)).all() == []
        assert migrate.compare_schema(conn) == []


def _seed_beta6_accounts(db, *, conflicting_subject=False):
    identifiers = [new_id(), new_id()]
    with db.row_write() as conn:
        migrate._apply(conn, "0002_local_credentials")
        for identifier in identifiers:
            conn.execute(
                text(
                    "INSERT INTO accounts(id,status,role,admitted_via,display_name,created_at,updated_at) "
                    "VALUES (:id,'active','user','operator','Preserved',1,1)"
                ),
                {"id": identifier},
            )
        for provider in ("local", "oidc:one", "oidc:two"):
            conn.execute(
                text(
                    "INSERT INTO login_providers(id,protocol,configured,created_at,updated_at) "
                    "VALUES (:id,:protocol,:enabled,1,1)"
                ),
                {
                    "id": provider,
                    "protocol": "local" if provider == "local" else "oidc",
                    "enabled": True,
                },
            )
        conn.execute(
            text(
                "INSERT INTO local_credentials(account_id,username,password_hash,created_at,updated_at) "
                "VALUES (:id,'existing.local',:hash,1,1)"
            ),
            {"id": identifiers[0], "hash": "x" * 80},
        )
        for provider, identifier, subject in (
            ("local", identifiers[0], identifiers[0]),
            ("oidc:one", identifiers[0], "same-subject"),
            (
                "oidc:two",
                identifiers[1] if conflicting_subject else identifiers[0],
                "same-subject",
            ),
        ):
            conn.execute(
                text(
                    "INSERT INTO external_identities(id,account_id,provider_id,issuer,subject,username,email,email_verified,linked_at) "
                    "VALUES (:id,:account,:provider,:issuer,:subject,'existing.local','shared@example.test',:verified,1)"
                ),
                {
                    "id": new_id(),
                    "account": identifier,
                    "provider": provider,
                    "issuer": "urn:canvas-mcp:local"
                    if provider == "local"
                    else "https://custom.test",
                    "subject": subject,
                    "verified": True,
                },
            )
    return identifiers


def test_beta6_populated_upgrade_preserves_local_name_hash_and_oidc_aliases(db):
    identifiers = _seed_beta6_accounts(db)
    before = migrate.current(db)
    migrate.ensure_ready(db)
    assert migrate.current(db).database_id == before.database_id
    with db.read() as conn:
        assert (
            conn.execute(
                select(schema.accounts.c.upn).where(
                    schema.accounts.c.id == identifiers[0]
                )
            ).scalar_one()
            == "existing.local"
        )
        assert (
            conn.execute(select(schema.local_credentials.c.password_hash)).scalar_one()
            == "x" * 80
        )
        assert "username" not in {
            column["name"] for column in inspect(conn).get_columns("local_credentials")
        }
        assert (
            conn.execute(
                select(schema.external_identities.c.username).where(
                    schema.external_identities.c.provider_id == "local"
                )
            ).scalar_one()
            is None
        )
        assert len(conn.execute(select(schema.external_identities)).all()) == 3
        assert len(conn.execute(select(schema.external_identity_owners)).all()) == 2
        assert migrate.compare_schema(conn) == []


def test_beta6_conflicting_canonical_owners_roll_back_entire_contract(db):
    _seed_beta6_accounts(db, conflicting_subject=True)
    before = migrate.current(db)
    with pytest.raises((RuntimeError, TokenStoreError), match="multiple accounts"):
        migrate.ensure_ready(db)
    assert migrate.current(db) == before
    with db.read() as conn:
        assert "upn" not in {
            column["name"] for column in inspect(conn).get_columns("accounts")
        }
        assert (
            conn.execute(text("SELECT username FROM local_credentials")).scalar_one()
            == "existing.local"
        )
        assert "external_identity_owners" not in inspect(conn).get_table_names()
    if not IS_POSTGRES:
        assert list(
            db.sqlite_path.parent.glob(
                db.sqlite_path.name + ".pre-0003_account_login_policy-*.bak"
            )
        )


@pytest.mark.parametrize(
    "revision", ["0001_baseline_v4", "0002_accounts", "0003_oauth_authz", None]
)
def test_pre_v1_is_refused_without_adopting_or_touching_data(db, revision):
    with db.row_write() as conn:
        if revision is not None:
            conn.exec_driver_sql(
                "CREATE TABLE canvas_mcp_alembic_version (version_num VARCHAR(32) PRIMARY KEY)"
            )
            conn.execute(
                text("INSERT INTO canvas_mcp_alembic_version VALUES (:revision)"),
                {"revision": revision},
            )
        else:
            conn.exec_driver_sql("CREATE TABLE meta (key TEXT PRIMARY KEY,value TEXT)")
            conn.exec_driver_sql("INSERT INTO meta VALUES ('schema_version','4')")
        conn.exec_driver_sql("CREATE TABLE saved_data (ciphertext TEXT)")
        conn.exec_driver_sql("INSERT INTO saved_data VALUES ('unchanged')")
    assert migrate.current(db).state == migrate.STATE_PRE_V1
    with pytest.raises(TokenStoreError, match="pre-v1"):
        migrate.ensure_ready(db)
    with db.read() as conn:
        assert (
            conn.exec_driver_sql("SELECT ciphertext FROM saved_data").scalar_one()
            == "unchanged"
        )
        assert "server_state" not in inspect(conn).get_table_names()


@pytest.mark.parametrize("floor,expected", [(2, "newer"), (3, "too_new")])
def test_unknown_revision_runs_only_when_compatibility_floor_allows_it(
    db, floor, expected, caplog
):
    migrate.ensure_ready(db)
    with db.row_write() as conn:
        conn.execute(
            text("UPDATE server_state SET compat_floor=:floor"), {"floor": floor}
        )
        conn.exec_driver_sql(
            "UPDATE canvas_mcp_alembic_version SET version_num='9999_expand'"
        )
    assert migrate.current(db).state == expected
    if floor == 2:
        migrate.ensure_ready(db)
        assert "database is newer than this release" in caplog.text
    else:
        with pytest.raises(TokenStoreError, match="compatibility floor"):
            migrate.ensure_ready(db)
    with db.read() as conn:
        assert (
            conn.exec_driver_sql(
                "SELECT version_num FROM canvas_mcp_alembic_version"
            ).scalar_one()
            == "9999_expand"
        )
        assert (
            conn.exec_driver_sql("SELECT compat_floor FROM server_state").scalar_one()
            == floor
        )


def test_even_a_known_head_is_refused_if_its_floor_is_too_new(db):
    migrate.ensure_ready(db)
    with db.row_write() as conn:
        conn.exec_driver_sql("UPDATE server_state SET compat_floor=3")
    with pytest.raises(TokenStoreError, match="compatibility floor"):
        migrate.ensure_ready(db)


def test_failed_revision_rolls_back_tables_and_alembic_record(db, monkeypatch):
    original = baseline_v1.create

    def fail_after_creation(conn, *, now):
        original(conn, now=now)
        raise RuntimeError("interrupted revision")

    monkeypatch.setattr(baseline_v1, "create", fail_after_creation)
    with pytest.raises(RuntimeError, match="interrupted"):
        migrate.ensure_ready(db)
    assert migrate.current(db).state == migrate.STATE_UNINITIALIZED
    with db.read() as conn:
        assert inspect(conn).get_table_names() == []


def test_dry_run_executes_creation_and_rolls_back(db):
    before, after = migrate.upgrade(db, dry_run=True)
    assert before == after
    assert after.state == migrate.STATE_UNINITIALIZED
    migrate.upgrade(db)
    assert migrate.current(db).state == migrate.STATE_CURRENT


def test_two_concurrent_starters_create_one_database_identity(db, tmp_path):
    other = pg_database(tmp_path / "migrate") if IS_POSTGRES else Database(db.target)
    barrier = Barrier(2)

    def start(database):
        barrier.wait(timeout=3)
        migrate.ensure_ready(database)
        return migrate.current(database).database_id

    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            a, b = workers.submit(start, db), workers.submit(start, other)
            assert a.result(timeout=10) == b.result(timeout=10)
        assert migrate.current(db).state == migrate.STATE_CURRENT
    finally:
        other.dispose()


def test_missing_owned_table_is_unreadable_and_is_not_repaired_silently(db):
    migrate.ensure_ready(db)
    with db.row_write() as conn:
        conn.exec_driver_sql("DROP TABLE account_quotas")
    assert migrate.current(db).state == migrate.STATE_UNREADABLE
    with pytest.raises(TokenStoreError, match="unreadable"):
        migrate.ensure_ready(db)


@pytest.mark.parametrize("dialect", ["sqlite", "postgresql"])
def test_offline_upgrade_contains_frozen_ddl_and_no_legacy_tables(dialect):
    sql = migrate.render_sql(dialect, revision="0002_local_credentials")
    for table in set(schema.metadata.tables) - {
        "external_identity_owners",
        "account_login_policy",
        "account_allowed_login_providers",
    }:
        assert "CREATE TABLE " + table + " " in sql
    assert "canvas_mcp_alembic_version" in sql and "0001_v1_baseline" in sql
    assert "CREATE TABLE meta " not in sql and "CREATE TABLE canvas_tokens " not in sql
    with pytest.raises(RuntimeError, match="online migration connection"):
        migrate.render_sql(dialect)
