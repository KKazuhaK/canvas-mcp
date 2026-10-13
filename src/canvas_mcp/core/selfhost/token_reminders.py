"""Bounded email reminders with shared SQL claims, independent of web traffic."""

from __future__ import annotations

import asyncio
import datetime as dt
import time
from collections.abc import Callable, Mapping
from functools import partial
from typing import Any

import anyio
from sqlalchemy import case, exists, insert, or_, select, update

from ..logging import log_warning
from .db import schema as s
from .db.settings_repo import read_settings
from .db.workers import run_store
from .email_translations import TEMPLATES
from .mail import MailStore, send_message

INTERVAL = 3600
LEASE = 300
MAX_ATTEMPTS = 3


class ReminderRunner:
    def __init__(
        self,
        store: MailStore,
        *,
        base_url: str,
        now: Callable[[], float] = time.time,
        sender: Callable[..., None] = send_message,
    ) -> None:
        self.store = store
        self.base_url = base_url
        self.now = now
        self.sender = sender

    def candidates(self, days: int) -> list[Mapping[str, Any]]:
        now = int(self.now())
        c, a, p = s.canvas_credentials, s.accounts, s.notification_preferences
        expiry = case(
            (c.c.expiry_source == "canvas", c.c.access_expires_at),
            else_=c.c.expires_hint_at,
        )
        d = s.notification_deliveries
        grace = case((c.c.expiry_source == "canvas", 0), else_=86400)
        stage = case((expiry + grace <= now, "expired"), else_="soon")
        already_handled = exists(
            select(d.c.id).where(
                d.c.credential_id == c.c.id,
                d.c.generation == c.c.generation,
                d.c.expires_at == expiry,
                d.c.stage == stage,
                or_(
                    d.c.status == "sent",
                    d.c.attempts >= MAX_ATTEMPTS,
                    d.c.lease_until > now,
                ),
            )
        ).correlate(c)
        with self.store.database.read() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    select(
                        c.c.id,
                        c.c.account_id,
                        c.c.generation,
                        c.c.expiry_source,
                        expiry.label("expiry"),
                        p.c.email,
                        p.c.locale,
                    )
                    .select_from(
                        c.join(a, c.c.account_id == a.c.id).join(
                            p, p.c.account_id == a.c.id
                        )
                    )
                    .where(
                        a.c.status == "active",
                        c.c.status == "active",
                        c.c.is_primary.is_(True),
                        p.c.enabled.is_(True),
                        ~already_handled,
                        expiry <= now + days * 86400,
                        expiry >= now - 7 * 86400,
                    )
                    .order_by(expiry, c.c.id)
                    .limit(100)
                ).mappings()
            ]

    def claim(
        self,
        row: Mapping[str, Any],
        *,
        stage: str,
        expiry: int,
        revision: int | None = None,
    ) -> tuple[str, int] | None:
        now = int(self.now())
        identifier = self.store.delivery_id(row, stage, expiry)
        c, a, p, d = (
            s.canvas_credentials,
            s.accounts,
            s.notification_preferences,
            s.notification_deliveries,
        )
        actual_expiry = case(
            (c.c.expiry_source == "canvas", c.c.access_expires_at),
            else_=c.c.expires_hint_at,
        )
        with self.store.database.write() as conn:
            if (
                revision is not None
                and conn.execute(
                    select(s.server_state.c.settings_revision)
                ).scalar_one()
                != revision
            ):
                return None
            config_row = conn.execute(
                select(s.mail_settings.c.config)
            ).scalar_one_or_none()
            if config_row is None or not config_row.get("enabled"):
                return None
            standing = conn.execute(
                select(c.c.id, c.c.expiry_source)
                .select_from(
                    c.join(a, c.c.account_id == a.c.id).join(
                        p, p.c.account_id == a.c.id
                    )
                )
                .where(
                    c.c.id == row["id"],
                    c.c.generation == row["generation"],
                    c.c.status == "active",
                    c.c.is_primary.is_(True),
                    a.c.status == "active",
                    p.c.enabled.is_(True),
                    p.c.email == row["email"],
                    p.c.locale == row["locale"],
                    actual_expiry == expiry,
                )
            ).first()
            if not standing:
                return None
            settings = read_settings(conn)
            canonical = settings["site.public_base_url"]
            if canonical and canonical != self.base_url:
                return None
            grace = 0 if standing.expiry_source == "canvas" else 86400
            if expiry > now + int(
                settings["notifications.token_reminder_days"]
            ) * 86400 or (stage == "expired") != (expiry + grace <= now):
                return None
            old = conn.execute(select(d).where(d.c.id == identifier)).mappings().first()
            if old and (
                old["status"] == "sent"
                or old["attempts"] >= MAX_ATTEMPTS
                or old["lease_until"] > now
            ):
                return None
            attempt = int(old["attempts"]) + 1 if old else 1
            values = {
                "account_id": row["account_id"],
                "credential_id": row["id"],
                "generation": row["generation"],
                "expires_at": expiry,
                "stage": stage,
                "status": "claimed",
                "attempts": attempt,
                "lease_until": now + LEASE,
                "updated_at": now,
            }
            if old:
                conn.execute(update(d).where(d.c.id == identifier).values(**values))
            else:
                conn.execute(insert(d).values(id=identifier, **values))
        return identifier, attempt

    def finish(self, identifier: str, attempt: int, *, success: bool) -> None:
        now = int(self.now())
        d = s.notification_deliveries
        with self.store.database.write() as conn:
            conn.execute(
                update(d)
                .where(
                    d.c.id == identifier,
                    d.c.status == "claimed",
                    d.c.attempts == attempt,
                )
                .values(
                    status="sent" if success else "failed",
                    lease_until=now + INTERVAL,
                    updated_at=now,
                )
            )

    async def run(self) -> int:
        settings = await run_store(self.store.load)
        if not settings.config["enabled"]:
            return 0
        sent = 0
        for row in await run_store(self.candidates, settings.config["reminder_days"]):
            expiry = int(row["expiry"])
            grace = 0 if row["expiry_source"] == "canvas" else 86400
            stage = "expired" if expiry + grace <= self.now() else "soon"
            current = await run_store(self.store.load)
            if not current.config["enabled"]:
                break
            claim = await run_store(
                partial(
                    self.claim,
                    row,
                    stage=stage,
                    expiry=expiry,
                    revision=current.revision,
                )
            )
            if claim is None:
                continue
            identifier, attempt = claim
            timestamp = dt.datetime.fromtimestamp(expiry, tz=dt.UTC)
            date = (
                timestamp.isoformat()
                if row["expiry_source"] == "canvas"
                else timestamp.date().isoformat()
            )
            messages = TEMPLATES.get(row["locale"], TEMPLATES["en"])
            subject = messages[stage]
            body = messages["body"].format(date=date, url=self.base_url)
            success = False
            try:
                await anyio.to_thread.run_sync(
                    partial(
                        self.sender,
                        current,
                        row["email"],
                        subject=subject,
                        body=body,
                        message_id=identifier,
                    )
                )
                success = True
                sent += 1
            except Exception:  # noqa: BLE001 - SMTP exception text may contain addresses or secrets
                log_warning("Canvas expiry reminder delivery failed")
            await run_store(partial(self.finish, identifier, attempt, success=success))
        return sent

    async def enabled(self) -> bool:
        public = await run_store(self.store.public)
        return bool(public["config"]["enabled"])

    async def loop(self, *, immediately: bool = False) -> None:
        while True:
            if not immediately:
                await asyncio.sleep(INTERVAL)
            immediately = False
            try:
                await self.run()
            except Exception:  # noqa: BLE001 - keep the next scheduled pass alive, never log secrets
                log_warning("Canvas expiry reminder pass failed")
