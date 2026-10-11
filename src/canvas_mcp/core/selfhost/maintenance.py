"""Traffic-triggered, bounded v1 housekeeping; no schema or data upgrades."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import partial
from typing import Any

from sqlalchemy import and_, delete, exists, false, insert, select, text, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.elements import ColumnElement

from ..logging import log_warning
from .db import schema as s
from .db.engine import Database
from .db.errors import StoreUnavailable
from .db.settings_repo import read_settings
from .db.workers import run_store

DAY = 86400
MAINTENANCE_INTERVAL_SECONDS = 3600
Maintenance = Callable[[], Awaitable[None]]


class MaintenanceScheduler:
    """One non-overlapping background pass per process, at most hourly."""

    def __init__(
        self,
        callback: Maintenance | None,
        *,
        clock: Callable[[], float] = time.monotonic,
        interval: float = MAINTENANCE_INTERVAL_SECONDS,
    ) -> None:
        self.callback = callback
        self.clock = clock
        self.interval = interval
        self.last_run: float | None = None
        self.background: set[asyncio.Task[None]] = set()

    def schedule(self) -> None:
        now = self.clock()
        if (
            self.callback is None
            or self.background
            or (self.last_run is not None and now - self.last_run < self.interval)
        ):
            return
        self.last_run = now
        task = asyncio.ensure_future(self._run())
        self.background.add(task)
        task.add_done_callback(self.background.discard)

    async def _run(self) -> None:
        try:
            assert self.callback is not None
            await self.callback()
        except Exception:  # noqa: BLE001 - never expose exception text to a request
            log_warning("selfhost maintenance failed")


@dataclass(frozen=True)
class Job:
    name: str
    table: Any
    due: ColumnElement[bool]
    order: Any
    lock_key: int
    batch: int
    walk: bool = False
    governance: bool = False
    cutoff: int = 0


@dataclass(frozen=True)
class Chunk:
    deleted: int = 0
    cursor: int = 0
    more: bool = False


class MaintenanceRunner:
    def __init__(
        self,
        database: Database,
        *,
        cimd_stale_max: int,
        now: Callable[[], float] = time.time,
        clock: Callable[[], float] = time.monotonic,
        pause: Callable[[str], None] | None = None,
    ) -> None:
        self.database = database
        self.cimd_stale_max = cimd_stale_max
        self.now = now
        self.clock = clock
        self.pause = pause or (lambda _: None)
        self.last_optimize: float | None = None

    def jobs(self, now: int) -> tuple[Job, ...]:
        with self.database.read() as conn:
            settings = read_settings(conn)
        batch = 2000 if self.database.kind == "postgresql" else 500
        schools = s.canvas_schools
        orphan = and_(
            schools.c.featured_rank.is_(None),
            schools.c.allow_private == false(),
            schools.c.updated_at < now - DAY,
            ~exists(
                select(s.canvas_credentials.c.id).where(
                    s.canvas_credentials.c.canvas_host == schools.c.host
                )
            ),
            ~exists(
                select(s.canvas_oauth_apps.c.id).where(
                    s.canvas_oauth_apps.c.canvas_host == schools.c.host
                )
            ),
        )
        definitions = [
            (
                "login_states",
                s.login_states,
                s.login_states.c.expires_at < now,
                s.login_states.c.expires_at,
                batch,
            ),
            (
                "codes",
                s.oauth_codes,
                s.oauth_codes.c.expires_at < now - 3600,
                s.oauth_codes.c.expires_at,
                batch,
            ),
            (
                "revoked_grants",
                s.oauth_grants,
                s.oauth_grants.c.revoked_at < now - 30 * DAY,
                s.oauth_grants.c.revoked_at,
                200,
            ),
            (
                "expired_grants",
                s.oauth_grants,
                s.oauth_grants.c.expires_at < now - 30 * DAY,
                s.oauth_grants.c.expires_at,
                200,
            ),
            (
                "clients",
                s.oauth_clients,
                s.oauth_clients.c.expires_at < now,
                s.oauth_clients.c.expires_at,
                batch,
            ),
            (
                "cimd",
                s.cimd_clients,
                s.cimd_clients.c.fetched_at < now - self.cimd_stale_max - DAY,
                s.cimd_clients.c.fetched_at,
                batch,
            ),
            (
                "auth_events",
                s.auth_events,
                s.auth_events.c.at
                < now - int(settings["retention.auth_events_days"]) * DAY,
                s.auth_events.c.id,
                batch,
            ),
            (
                "audit",
                s.audit_log,
                s.audit_log.c.at < now - int(settings["retention.audit_days"]) * DAY,
                s.audit_log.c.id,
                batch,
            ),
            (
                "pending",
                s.accounts,
                and_(
                    s.accounts.c.status == "pending",
                    s.accounts.c.created_at < now - 30 * DAY,
                ),
                s.accounts.c.created_at,
                100,
            ),
            ("orphan_schools", schools, orphan, schools.c.host, batch),
        ]
        return tuple(
            Job(
                name,
                table,
                due,
                order,
                0x434D5000 + index,
                size,
                walk=name in ("auth_events", "audit"),
                governance=name == "pending",
                cutoff=now
                - int(
                    settings[
                        "retention.auth_events_days"
                        if name == "auth_events"
                        else "retention.audit_days"
                    ]
                )
                * DAY,
            )
            for index, (name, table, due, order, size) in enumerate(definitions)
            if name != "audit" or settings["retention.audit_days"] > 0
        )

    def chunk(self, job: Job, *, now: int, cursor: int = 0) -> Chunk:
        db = self.database
        transaction = db.write if job.governance else db.row_write
        with transaction() as conn:
            if (
                db.kind == "postgresql"
                and not conn.execute(
                    text("SELECT pg_try_advisory_xact_lock(:key)"),
                    {"key": job.lock_key},
                ).scalar_one()
            ):
                return Chunk(cursor=cursor)
            table = job.table
            keys = tuple(table.primary_key.columns)
            fields = (*keys, table.c.at) if job.walk else keys
            stmt = (
                select(*fields).where(table.c.id > cursor)
                if job.walk
                else select(*fields).where(job.due)
            )
            stmt = stmt.order_by(job.order, *keys).limit(job.batch)
            # Pending candidates must not take account locks before code locks.
            if db.kind == "postgresql" and not job.governance:
                stmt = stmt.with_for_update(skip_locked=True)
            rows = conn.execute(stmt).all()
            if not rows:
                return Chunk(cursor=cursor)
            ids = [tuple(row[: len(keys)]) for row in rows]
            membership = (
                keys[0].in_([key[0] for key in ids])
                if len(keys) == 1
                else tuple_(*keys).in_(ids)
            )
            self.pause("before_" + job.name + "_delete")
            if job.governance:
                conn.execute(
                    delete(s.oauth_codes).where(
                        s.oauth_codes.c.account_id.in_([key[0] for key in ids])
                    )
                )
            deleted_ids = conn.execute(
                delete(table).where(membership, job.due).returning(*keys)
            ).all()
            if job.governance:
                for (account_id,) in deleted_ids:
                    conn.execute(
                        insert(s.audit_log).values(
                            at=now,
                            actor_kind="system",
                            subject_account_id=account_id,
                            action="pending_purged",
                            target_kind="account",
                            target_id=account_id,
                            detail={},
                        )
                    )
            more = len(rows) == job.batch and not job.governance
            if job.walk:
                cursor = rows[-1][0]
                # Clock skew in an earlier row must not prematurely end the walk.
                more = more and rows[-1][-1] < job.cutoff
            return Chunk(len(deleted_ids), cursor, more)

    async def run(self) -> dict[str, int]:
        now = int(self.now())
        try:
            jobs = await run_store(lambda: self.jobs(now))
        except (StoreUnavailable, ValueError):
            log_warning("selfhost maintenance configuration unavailable")
            return {}
        removed: dict[str, int] = {}
        for job in jobs:
            started = self.clock()
            budget = 10 if self.database.kind == "postgresql" else 2
            cursor = 0
            removed[job.name] = 0
            while True:
                try:
                    result = await run_store(
                        partial(self.chunk, job, now=now, cursor=cursor)
                    )
                except (StoreUnavailable, IntegrityError):
                    log_warning("selfhost maintenance job stopped", job=job.name)
                    break
                removed[job.name] += result.deleted
                cursor = result.cursor
                if not result.more or self.clock() - started >= budget:
                    break
                if self.database.kind == "sqlite":
                    await asyncio.sleep(0.05)
        if self.database.kind == "sqlite":
            try:
                await run_store(lambda: self.housekeeping(sum(removed.values())))
            except StoreUnavailable:
                log_warning("selfhost maintenance housekeeping stopped")
        return removed

    def housekeeping(self, deleted: int) -> None:
        with self.database.best_effort_write() as conn:
            if deleted > 1000:
                conn.execute(text("PRAGMA incremental_vacuum(2000)"))
            now = self.clock()
            if self.last_optimize is None or now - self.last_optimize >= DAY:
                conn.execute(text("PRAGMA optimize"))
                self.last_optimize = now
