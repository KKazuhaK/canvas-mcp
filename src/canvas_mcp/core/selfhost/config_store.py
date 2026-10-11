"""Governed runtime configuration writes, independent of schema migrations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from sqlalchemy import func, insert, select, update
from sqlalchemy.engine import Connection

from .config_snapshot import (
    ConfigSnapshots,
    _validate_addresses_sync,
    provider_defaults,
    school_display_name,
)
from .db import schema as s
from .db.settings_repo import (
    SettingsAccessDenied,
    SettingsConflict,
    read_settings,
    save_setting,
)
from .profile import PilotProfileViolation
from .schools import (
    MAX_FEATURED,
    School,
    SchoolPolicy,
    check_public_host,
    is_blocked_hostname,
    parse_hostname,
)
from .server_settings import validate_provider_names


@dataclass
class SchoolRemovalConfirmation(Exception):
    affected: Mapping[str, int]


class ConfigStore:
    def __init__(self, snapshots: ConfigSnapshots, *, pilot: bool = False) -> None:
        self.snapshots = snapshots
        self.database = snapshots.database
        self._pilot = pilot

    @property
    def pilot(self) -> bool:
        return self._pilot or self.snapshots.pilot

    @staticmethod
    def _authorize(conn: Connection, actor: str | None, revision: int, now: int) -> int:
        if type(revision) is not int or revision < 0:
            raise ValueError("invalid revision")
        if actor is not None:
            row = conn.execute(
                select(s.accounts.c.status, s.accounts.c.role).where(
                    s.accounts.c.id == actor
                )
            ).one_or_none()
            if (
                row is None
                or row._mapping["status"] != "active"
                or row._mapping["role"] != "owner"
            ):
                raise SettingsAccessDenied
        result = conn.execute(
            update(s.server_state)
            .where(
                s.server_state.c.id == 1, s.server_state.c.settings_revision == revision
            )
            .values(
                settings_revision=s.server_state.c.settings_revision + 1, updated_at=now
            )
            .returning(s.server_state.c.settings_revision)
        ).scalar_one_or_none()
        if result is None:
            raise SettingsConflict
        return int(result)

    @staticmethod
    def _audit(
        conn: Connection,
        actor: str | None,
        now: int,
        action: str,
        kind: str,
        target: str,
        detail: dict,
    ) -> None:
        conn.execute(
            insert(s.audit_log).values(
                at=now,
                actor_kind="operator" if actor is None else "account",
                actor_id=actor,
                action=action,
                target_kind=kind,
                target_id=target,
                detail=detail,
            )
        )

    def names(
        self,
        changes: Mapping[str, object],
        *,
        revision: int,
        actor: str | None,
        now: int,
    ) -> int:
        with self.database.write() as conn:
            new_revision = self._authorize(conn, actor, revision, now)
            rows = (
                conn.execute(
                    select(s.login_providers).where(s.login_providers.c.configured)
                )
                .mappings()
                .all()
            )
            defaults = {
                r["id"]: provider_defaults(r["id"])[0]
                for r in rows
                if r["id"] in self.snapshots.providers.ids
            }
            current = {r["id"]: r["display_name"] for r in rows}
            names = validate_provider_names(defaults, current, changes)
            for identifier in changes:
                conn.execute(
                    update(s.login_providers)
                    .where(s.login_providers.c.id == identifier)
                    .values(
                        display_name=names[identifier], updated_at=now, updated_by=actor
                    )
                )
                self._audit(
                    conn,
                    actor,
                    now,
                    "sign_in_method_renamed",
                    "provider",
                    identifier,
                    {"old": current[identifier], "new": names[identifier]},
                )
        self.snapshots.get(new_revision)
        return new_revision

    def setting(
        self,
        key: str,
        value: object,
        *,
        revision: int,
        actor: str | None,
        now: int,
        reset: bool = False,
    ) -> int:
        with self.database.write() as conn:
            new_revision = save_setting(
                conn,
                key,
                value,
                expected_revision=revision,
                actor_id=actor,
                now=now,
                reset=reset,
            )
            if (
                self.pilot
                and key == "schools.directory_search"
                and read_settings(conn)[key]
            ):
                raise PilotProfileViolation(
                    "Directory search is disabled by SELFHOST_PROFILE=pilot"
                )
        self.snapshots.get(new_revision)
        return new_revision

    async def validate_school(self, host: object, name: object = "") -> School:
        parsed = parse_hostname(host) if isinstance(host, str) else None
        if parsed is None:
            raise ValueError("school_invalid")
        display = school_display_name(name)
        exception = next(
            (
                school
                for school in self.snapshots.current.schools.private
                if school.host == parsed
            ),
            None,
        )
        if exception is not None:
            return School(parsed, exception.api_url, display, True)
        if is_blocked_hostname(parsed):
            raise ValueError("school_invalid")
        verdict = await check_public_host(parsed, self.snapshots.resolve_host)
        if verdict != "ok":
            raise ValueError(
                "school_unresolvable"
                if verdict == "unresolvable"
                else "school_address_blocked"
            )
        return School(parsed, f"https://{parsed}/api/v1", display)

    def schools(
        self,
        schools: Sequence[School],
        *,
        revision: int,
        actor: str | None,
        now: int,
        confirmed: Sequence[str] = (),
        grant_private: bool = False,
    ) -> tuple[int, dict[str, int]]:
        if self.pilot and len(schools) != 1:
            raise PilotProfileViolation(
                "SELFHOST_PROFILE=pilot requires exactly one featured school"
            )
        if grant_private and actor is not None:
            raise SettingsAccessDenied
        if any(
            parse_hostname(school.host) != school.host
            or school_display_name(school.name) != school.name
            for school in schools
        ):
            raise ValueError("invalid school")
        if len(schools) > MAX_FEATURED or len(
            {school.host for school in schools}
        ) != len(schools):
            raise ValueError("duplicate or excessive schools")
        with self.database.write() as conn:
            new_revision = self._authorize(conn, actor, revision, now)
            old = (
                conn.execute(
                    select(s.canvas_schools)
                    .where(s.canvas_schools.c.featured_rank.is_not(None))
                    .order_by(s.canvas_schools.c.featured_rank, s.canvas_schools.c.host)
                )
                .mappings()
                .all()
            )
            old_hosts, new_hosts = (
                [r["host"] for r in old],
                [school.host for school in schools],
            )
            removed = set(old_hosts) - set(new_hosts)
            affected = self._counts(conn, removed)
            blocked = {
                host: count
                for host, count in affected.items()
                if count
                and not next(r["allow_private"] for r in old if r["host"] == host)
            }
            if not read_settings(conn)["schools.directory_search"] and set(
                blocked
            ) - set(confirmed):
                raise SchoolRemovalConfirmation(blocked)
            conn.execute(
                update(s.canvas_schools)
                .where(s.canvas_schools.c.featured_rank.is_not(None))
                .values(featured_rank=None, updated_at=now, updated_by=actor)
            )
            for rank, school in enumerate(schools, 1):
                row = conn.execute(
                    select(s.canvas_schools.c.allow_private).where(
                        s.canvas_schools.c.host == school.host
                    )
                ).one_or_none()
                # An exception can be removed while DNS validation is running. Never trust
                # a stale validation snapshot to restore that privileged flag.
                if (
                    school.allow_private
                    and not grant_private
                    and (row is None or not row._mapping["allow_private"])
                ):
                    raise SettingsConflict
                if school.allow_private and grant_private:
                    if row is None or not row._mapping["allow_private"]:
                        self._audit(
                            conn,
                            None,
                            now,
                            "school_access_changed",
                            "school",
                            school.host,
                            {"old": False, "new": True},
                        )
                values = {
                    "display_name": school.name,
                    "featured_rank": rank,
                    "updated_at": now,
                    "updated_by": actor,
                }
                if school.allow_private and grant_private:
                    values["allow_private"] = True
                if row is None:
                    conn.execute(
                        insert(s.canvas_schools).values(
                            host=school.host,
                            origin="operator",
                            created_at=now,
                            created_by=actor,
                            **values,
                        )
                    )
                else:
                    conn.execute(
                        update(s.canvas_schools)
                        .where(s.canvas_schools.c.host == school.host)
                        .values(**values)
                    )
            renamed = [
                school.host
                for school in schools
                if any(
                    r["host"] == school.host and r["display_name"] != school.name
                    for r in old
                )
            ]
            self._audit(
                conn,
                actor,
                now,
                "featured_schools_changed",
                "setting",
                "featured_schools",
                {
                    "added": [host for host in new_hosts if host not in old_hosts],
                    "removed": sorted(removed),
                    "renamed": renamed,
                    "reordered": [host for host in new_hosts if host in old_hosts]
                    != [host for host in old_hosts if host in new_hosts],
                    "affected_enrollments": affected,
                },
            )
        self.snapshots.get(new_revision)
        return new_revision, affected

    @staticmethod
    def _counts(conn: Connection, hosts: Sequence[str] | set[str]) -> dict[str, int]:
        result = dict.fromkeys(hosts, 0)
        rows = conn.execute(
            select(s.canvas_credentials.c.canvas_host, func.count().label("count"))
            .where(s.canvas_credentials.c.canvas_host.in_(hosts))
            .group_by(s.canvas_credentials.c.canvas_host)
        ).mappings()
        result.update({r["canvas_host"]: int(r["count"]) for r in rows})
        return result

    def counts(self, hosts: Sequence[str]) -> dict[str, int]:
        with self.database.read() as conn:
            return self._counts(conn, hosts)

    def allow_private(
        self, host: str, enabled: bool, *, revision: int, now: int
    ) -> int:
        if parse_hostname(host) != host or type(enabled) is not bool:
            raise ValueError("invalid school access")
        if (
            not enabled
            and self.snapshots.current.schools.featured_school(host) is not None
        ):
            if is_blocked_hostname(host):
                raise ValueError(
                    "remove the featured private school before withdrawing its exception"
                )
            _validate_addresses_sync(
                SchoolPolicy((School(host, f"https://{host}/api/v1", host),), False),
                self.snapshots.resolve_host,
            )
        with self.database.write() as conn:
            new_revision = self._authorize(conn, None, revision, now)
            old = conn.execute(
                select(s.canvas_schools.c.allow_private).where(
                    s.canvas_schools.c.host == host
                )
            ).scalar_one_or_none()
            if old is None:
                conn.execute(
                    insert(s.canvas_schools).values(
                        host=host,
                        origin="operator",
                        allow_private=enabled,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                conn.execute(
                    update(s.canvas_schools)
                    .where(s.canvas_schools.c.host == host)
                    .values(allow_private=enabled, updated_at=now)
                )
            self._audit(
                conn,
                None,
                now,
                "school_access_changed",
                "school",
                host,
                {"old": bool(old), "new": enabled},
            )
        self.snapshots.get(new_revision)
        return new_revision
