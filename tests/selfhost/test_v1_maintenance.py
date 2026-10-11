"""Bounded deletion, retained account history and native PostgreSQL job locks."""

import asyncio
from dataclasses import replace
from itertools import count

import pytest
from dbbackend import IS_POSTGRES
from sqlalchemy import event, insert, select, text, update

from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.db.types import new_id
from canvas_mcp.core.selfhost.maintenance import (
    DAY,
    MaintenanceRunner,
    MaintenanceScheduler,
)
from canvas_mcp.core.selfhost.token_store import OPERATOR, AccessActionRefused

from .test_server_settings import db  # noqa: F401
from .test_v1_store import account, put, stores  # noqa: F401

NOW = 1_800_000_000


def job(runner, name):
    return next(job for job in runner.jobs(NOW) if job.name == name)


def runner_for(database):
    return MaintenanceRunner(database, cimd_stale_max=7 * DAY, now=lambda: NOW)


def states(conn, total, expiry=NOW - 1):
    conn.execute(
        insert(s.login_states),
        [
            {
                "kind": "login",
                "id_hash": index.to_bytes(32, "big"),
                "payload": b"state",
                "created_at": NOW - 100,
                "expires_at": expiry,
            }
            for index in range(total)
        ],
    )


def test_plain_chunk_is_bounded_and_uses_two_step_delete(db):  # noqa: F811
    runner = runner_for(db)
    size = 2000 if IS_POSTGRES else 500
    with db.write() as conn:
        states(conn, size + 1)
    statements = []

    def observe(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(db.engine, "before_cursor_execute", observe)
    try:
        first = runner.chunk(job(runner, "login_states"), now=NOW)
    finally:
        event.remove(db.engine, "before_cursor_execute", observe)
    assert first.deleted == size and first.more
    deletion = next(
        statement for statement in statements if statement.startswith("DELETE")
    )
    assert "SELECT" not in deletion and "expires_at" in deletion
    assert runner.chunk(job(runner, "login_states"), now=NOW).deleted == 1


def test_due_predicate_is_rechecked_in_delete(db):  # noqa: F811
    with db.write() as conn:
        states(conn, 1)
    runner = runner_for(db)
    selected_job = job(runner, "login_states")
    # Change the candidate between selection and deletion in the same transaction.
    changed = False

    def observe(conn, cursor, statement, parameters, context, executemany):
        nonlocal changed
        if statement.startswith("DELETE FROM login_states") and not changed:
            changed = True
            conn.execute(update(s.login_states).values(expires_at=NOW + 1))

    event.listen(db.engine, "before_cursor_execute", observe)
    try:
        assert runner.chunk(selected_job, now=NOW).deleted == 0
    finally:
        event.remove(db.engine, "before_cursor_execute", observe)
    with db.read() as conn:
        assert conn.execute(select(s.login_states)).one().expires_at == NOW + 1


def test_history_walk_skips_earlier_clock_skew_without_stopping(db):  # noqa: F811
    runner = runner_for(db)
    with db.write() as conn:
        conn.execute(
            insert(s.auth_events),
            [
                {
                    "at": NOW if index == 1 else NOW - 100 * DAY,
                    "provider_id": "entra",
                    "surface": "account",
                    "outcome": "success",
                    "reason": "ok",
                }
                for index in range(7)
            ],
        )
    selected = replace(job(runner, "auth_events"), batch=3)
    first = runner.chunk(selected, now=NOW)
    assert first.deleted == 2 and first.more
    second = runner.chunk(selected, now=NOW, cursor=first.cursor)
    assert second.deleted == 3 and second.more
    third = runner.chunk(selected, now=NOW, cursor=second.cursor)
    assert third.deleted == 1 and not third.more
    with db.read() as conn:
        assert conn.execute(select(s.auth_events.c.at)).all() == [(NOW,)]


def test_default_audit_retention_keeps_history_forever(db):  # noqa: F811
    assert "audit" not in {job.name for job in runner_for(db).jobs(NOW)}
    with db.write() as conn:
        conn.execute(
            insert(s.settings).values(
                key="retention.audit_days", value=7, updated_at=NOW
            )
        )
    assert job(runner_for(db), "audit").walk


def test_metadata_cull_registry_covers_every_job_and_no_refresh_job(db):  # noqa: F811
    jobs = runner_for(db).jobs(NOW)
    declared = {
        table.info["cull"]
        for table in s.metadata.tables.values()
        if "cull" in table.info
    }
    covered = {job.table.info["cull"] for job in jobs}
    assert covered == declared - {"audit"}
    assert all(job.table is not s.oauth_refresh_tokens for job in jobs)
    assert all(job.batch == 200 for job in jobs if job.table is s.oauth_grants)


def test_orphan_school_repeats_reference_and_policy_checks(db):  # noqa: F811
    with db.write() as conn:
        conn.execute(
            insert(s.canvas_schools),
            [
                {
                    "host": host,
                    "origin": "operator",
                    "allow_private": private,
                    "featured_rank": rank,
                    "created_at": 100,
                    "updated_at": 100,
                }
                for host, private, rank in [
                    ("orphan.example", False, None),
                    ("private.example", True, None),
                    ("featured.example", False, 1),
                ]
            ],
        )
    runner = runner_for(db)
    assert runner.chunk(job(runner, "orphan_schools"), now=NOW).deleted == 1
    with db.read() as conn:
        assert set(conn.execute(select(s.canvas_schools.c.host)).scalars()) == {
            "private.example",
            "featured.example",
        }


def test_pending_purge_caps_at_100_and_audits_each_account(db):  # noqa: F811
    with db.write() as conn:
        conn.execute(
            insert(s.accounts),
            [
                {
                    "id": new_id(),
                    "status": "pending",
                    "admitted_via": "approval",
                    "created_at": 100,
                    "updated_at": 100,
                }
                for _ in range(101)
            ],
        )
    runner = runner_for(db)
    result = runner.chunk(job(runner, "pending"), now=NOW)
    assert result.deleted == 100 and not result.more
    with db.read() as conn:
        audit = conn.execute(select(s.audit_log)).all()
        assert len(audit) == 100
        assert all(
            row.action == "pending_purged"
            and row.subject_account_id == row.target_id
            and row.detail == {}
            for row in audit
        )
        assert len(conn.execute(select(s.accounts)).all()) == 1


def test_account_delete_cascades_credentials_identities_and_keeps_history(stores):  # noqa: F811
    one, _, _ = stores
    key = account(one)
    put(one, key)
    with one.database.write() as conn:
        conn.execute(
            insert(s.auth_events).values(
                at=NOW,
                account_id=key,
                provider_id="oidc:school",
                surface="account",
                outcome="success",
                reason="ok",
            )
        )
    assert one.delete_account(key)
    assert not one.delete_account(key)
    with one.database.read() as conn:
        assert conn.execute(select(s.accounts)).first() is None
        assert conn.execute(select(s.canvas_credentials)).first() is None
        assert conn.execute(select(s.external_identities)).first() is None
        assert conn.execute(select(s.auth_events.c.account_id)).scalar_one() == key
        audit = conn.execute(
            select(s.audit_log).where(s.audit_log.c.action == "account_deleted")
        ).one()
        assert (
            audit.actor_kind == "operator"
            and audit.subject_account_id == audit.target_id == key
        )
        assert audit.detail == {
            "credentials_removed": 1,
            "identities_removed": 1,
            "grants_removed": 0,
        }


def test_account_delete_last_owner_and_nonoperator_are_refused(stores):  # noqa: F811
    one, _, _ = stores
    key = account(one)
    assert one.promote_owner(key, actor=OPERATOR)
    with pytest.raises(AccessActionRefused) as error:
        one.delete_account(key)
    assert error.value.code == AccessActionRefused.LAST_OWNER
    with pytest.raises(AccessActionRefused):
        one.delete_account(key, actor=key)
    assert one.get_principal_status(key).role == "owner"
    assert not any(row.action == "account_deleted" for row in list(one.iter_audit()))


def test_operator_account_delete_cli_validates_uuid_and_retains_audit(stores, capsys):  # noqa: F811
    from canvas_mcp.core.selfhost.token_admin import _build_parser, _run

    one, _, _ = stores
    key = account(one)
    parser = _build_parser()
    assert _run(parser.parse_args(["accounts", "delete", "acct:" + key]), one) == 2
    assert one.get_principal_status(key).status == "active"
    assert _run(parser.parse_args(["accounts", "delete", key]), one) == 0
    assert _run(parser.parse_args(["accounts", "delete", key]), one) == 1
    output = capsys.readouterr()
    assert "deleted 1 account" in output.out
    assert sum(row.action == "account_deleted" for row in list(one.iter_audit())) == 1


def test_grant_retention_deletes_refresh_only_by_cascade(stores):  # noqa: F811
    from canvas_mcp.core.selfhost.authz import tokens
    from canvas_mcp.core.selfhost.authz.store import AuthzStore

    from .test_v1_races import code

    one, _, _ = stores
    key = account(one)
    authz = AuthzStore(one.database, clock=lambda: NOW)
    hashed = code(authz, key)
    grant_id = new_id()
    authz.exchange_code(
        code_hash=hashed,
        client_id="client",
        grant_id=grant_id,
        refresh_hash=tokens.hash_secret("retention refresh"),
    )
    runner = runner_for(one.database)
    assert runner.chunk(job(runner, "expired_grants"), now=NOW).deleted == 0
    with one.database.write() as conn:
        conn.execute(update(s.oauth_grants).values(expires_at=NOW - 31 * DAY))
    assert runner.chunk(job(runner, "expired_grants"), now=NOW).deleted == 1
    with one.database.read() as conn:
        assert conn.execute(select(s.oauth_refresh_tokens)).first() is None
        assert conn.execute(select(s.oauth_grants)).first() is None
        # Code replay tombstones are a separate retention job.
        assert conn.execute(select(s.oauth_codes)).first() is not None


@pytest.mark.asyncio
async def test_pending_chunk_failure_rolls_back_codes_accounts_and_audit(db):  # noqa: F811
    from sqlalchemy.exc import IntegrityError

    account_id = new_id()
    with db.write() as conn:
        conn.execute(
            insert(s.accounts).values(
                id=account_id,
                status="pending",
                admitted_via="approval",
                created_at=100,
                updated_at=100,
            )
        )
    runner = runner_for(db)
    selected = job(runner, "pending")
    runner.jobs = lambda _: (selected,)

    def fail(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO audit_log"):
            raise IntegrityError("fixture failure", None, Exception("secret value"))

    event.listen(db.engine, "before_cursor_execute", fail)
    try:
        assert await runner.run() == {"pending": 0}
    finally:
        event.remove(db.engine, "before_cursor_execute", fail)
    with db.read() as conn:
        assert conn.execute(select(s.accounts.c.id)).scalar_one() == account_id
        assert conn.execute(select(s.audit_log)).first() is None


@pytest.mark.skipif(not IS_POSTGRES, reason="native PostgreSQL advisory locks")
def test_busy_job_skips_without_waiting_or_deleting(db):  # noqa: F811
    runner = runner_for(db)
    selected = job(runner, "login_states")
    with db.write() as conn:
        states(conn, 1)
    with db.row_write() as conn:
        conn.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": selected.lock_key}
        )
        assert runner.chunk(selected, now=NOW).deleted == 0
    assert runner.chunk(selected, now=NOW).deleted == 1


@pytest.mark.asyncio
async def test_runner_stops_job_at_budget_and_resumes_next_run(db):  # noqa: F811
    with db.write() as conn:
        states(conn, 5)
    runner = runner_for(db)
    selected = replace(job(runner, "login_states"), batch=2)
    runner.jobs = lambda _: (selected,)
    ticks = count(0, 20)
    runner.clock = lambda: next(ticks)
    assert await runner.run() == {"login_states": 2}
    assert await runner.run() == {"login_states": 2}
    runner.clock = lambda: 100
    assert await runner.run() == {"login_states": 1}


@pytest.mark.asyncio
async def test_scheduler_is_hourly_and_does_not_overlap_a_long_run():
    clock = [0]
    started = []
    unblock = asyncio.Event()

    async def callback():
        started.append(True)
        await unblock.wait()

    scheduler = MaintenanceScheduler(callback, clock=lambda: clock[0])
    scheduler.schedule()
    await asyncio.sleep(0)
    clock[0] = 7200
    scheduler.schedule()
    assert len(started) == 1
    unblock.set()
    await asyncio.gather(*scheduler.background)
    await asyncio.sleep(0)
    scheduler.schedule()
    await asyncio.gather(*scheduler.background)
    assert len(started) == 2
