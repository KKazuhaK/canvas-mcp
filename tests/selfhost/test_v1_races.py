"""Transaction lock order on both sides of each controlled PostgreSQL race."""

from concurrent.futures import ThreadPoolExecutor, TimeoutError
from threading import Event

import pytest
from dbbackend import IS_POSTGRES
from sqlalchemy import insert, select

from canvas_mcp.core.selfhost.authz import tokens
from canvas_mcp.core.selfhost.authz.models import ExchangeOutcome
from canvas_mcp.core.selfhost.authz.store import AuthzStore
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.db.types import new_id
from canvas_mcp.core.selfhost.maintenance import DAY, MaintenanceRunner
from canvas_mcp.core.selfhost.token_store import DISABLE_REASON_OPERATOR, OPERATOR

from .test_v1_store import account, put, stores  # noqa: F401

NOW = 1_800_000_000


def pause_at(name, entered, release):
    def pause(point):
        if point == name:
            entered.set()
            assert release.wait(4), "transaction was not released"

    return pause


def code(authz, key):
    hashed = tokens.hash_secret("race code")
    assert authz.create_code(
        code_hash=hashed,
        client_id="client",
        client_kind="dcr",
        client_name="App",
        client_host=None,
        account_id=key,
        redirect_uri="https://client.example/callback",
        redirect_uri_explicit=True,
        redirect_host="client.example",
        code_challenge="challenge",
        scopes=("Canvas.Access",),
        resource="https://mcp.example/mcp",
        upstream_auth_at=NOW,
        session_epoch=0,
    )
    return hashed


@pytest.mark.skipif(not IS_POSTGRES, reason="native PostgreSQL row lock order")
@pytest.mark.parametrize("action", ["delete", "disable", "revoke_all"])
@pytest.mark.parametrize("first", ["exchange", "governance"])
def test_governance_and_first_code_exchange_do_not_deadlock(stores, action, first):  # noqa: F811
    one, two, _ = stores
    key = account(one)
    authz = AuthzStore(one.database, clock=lambda: NOW)
    other = AuthzStore(two.database, clock=lambda: NOW)
    hashed = code(authz, key)
    entered, release = Event(), Event()
    grant_id = new_id()

    def exchange():
        return authz.exchange_code(
            code_hash=hashed,
            client_id="client",
            grant_id=grant_id,
            refresh_hash=tokens.hash_secret("race refresh"),
        )

    def governance():
        if action == "delete":
            return two.delete_account(key)
        if action == "disable":
            return two.disable_principal(
                key, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR
            )
        return other.revoke_all_for_account(key, reason="admission_lost")

    if first == "exchange":
        authz.pause_hook = pause_at("after_code_consume", entered, release)
        start, follow = exchange, governance
    else:
        two._pause_hook = other.pause_hook = pause_at(
            "after_account_codes_deleted", entered, release
        )
        start, follow = governance, exchange
    with ThreadPoolExecutor(max_workers=2) as workers:
        leading = workers.submit(start)
        try:
            assert entered.wait(3)
            trailing = workers.submit(follow)
            with pytest.raises(TimeoutError):
                trailing.result(timeout=0.05)
        finally:
            release.set()
        first_result = leading.result(timeout=6)
        second_result = trailing.result(timeout=6)
    exchanged = first_result if first == "exchange" else second_result
    assert (exchanged.outcome == ExchangeOutcome.WON) == (first == "exchange")
    with one.database.read() as conn:
        grant = conn.execute(
            select(s.oauth_grants).where(s.oauth_grants.c.id == grant_id)
        ).first()
        if action == "delete" or first == "governance":
            assert grant is None
        else:
            assert grant.revoked_at is not None


@pytest.mark.skipif(not IS_POSTGRES, reason="native PostgreSQL school and FK locks")
@pytest.mark.parametrize("first", ["put", "cull"])
def test_school_cull_and_credential_put_cannot_lose_the_parent(stores, first):  # noqa: F811
    one, two, _ = stores
    key = account(one)
    host = "race.example.edu"
    with one.database.write() as conn:
        conn.execute(
            insert(s.canvas_schools).values(
                host=host,
                origin="enrollment",
                created_at=NOW - 2 * DAY,
                updated_at=NOW - 2 * DAY,
            )
        )
    entered, release = Event(), Event()
    runner = MaintenanceRunner(two.database, cimd_stale_max=7 * DAY, now=lambda: NOW)
    job = next(job for job in runner.jobs(NOW) if job.name == "orphan_schools")

    def cull():
        return runner.chunk(job, now=NOW)

    if first == "put":
        one._pause_hook = pause_at("after_school_upsert", entered, release)
        with ThreadPoolExecutor(max_workers=1) as workers:
            pending = workers.submit(put, one, key, host)
            try:
                assert entered.wait(3)
                assert cull().deleted == 0
            finally:
                release.set()
            pending.result(timeout=6)
    else:
        runner.pause = pause_at("before_orphan_schools_delete", entered, release)
        with ThreadPoolExecutor(max_workers=2) as workers:
            pending = workers.submit(cull)
            try:
                assert entered.wait(3)
                saved = workers.submit(put, one, key, host)
                with pytest.raises(TimeoutError):
                    saved.result(timeout=0.05)
            finally:
                release.set()
            assert pending.result(timeout=6).deleted == 1
            saved.result(timeout=6)
    with one.database.read() as conn:
        assert conn.execute(select(s.canvas_schools.c.host)).scalar_one() == host
        assert (
            conn.execute(select(s.canvas_credentials.c.canvas_host)).scalar_one()
            == host
        )
