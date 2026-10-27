"""Immutable database-owned configuration, keyed by the committed global revision."""

from __future__ import annotations

import asyncio
import logging
import threading
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from dataclasses import dataclass
from types import MappingProxyType

import anyio
from sqlalchemy import or_, select, true

from .db import schema as s
from .db.engine import Database
from .db.errors import StoreUnavailable
from .db.settings_repo import TypedSettings
from .login.account_policy import POLICY_KEY, parse_policy
from .login.config import LoginProvidersConfig
from .login.provider_icon import validate_icon_reference
from .routes import auth_login
from .schools import (
    MAX_FEATURED,
    MAX_SCHOOL_NAME,
    HostResolver,
    School,
    SchoolPolicy,
    check_public_host,
    is_blocked_hostname,
    parse_hostname,
    system_resolve,
)
from .server_settings import SETTINGS, provider_display_name, validate_setting

logger = logging.getLogger("canvas_mcp.selfhost.account")


@dataclass(frozen=True)
class ProviderDisplay:
    id: str
    protocol: str
    icon: str
    configured: bool
    default_name: str
    display_name: str | None
    effective_name: str
    rank: int
    icon_data: str | None = None

    @property
    def start_path(self) -> str:
        return "/account/sign-in" if self.id == "local" else auth_login(self.id)


@dataclass(frozen=True)
class ConfigSnapshot:
    revision: int
    schools: SchoolPolicy
    providers: tuple[ProviderDisplay, ...]
    settings: TypedSettings
    warnings: tuple[str, ...]

    def name(self, identifier: str) -> str:
        return next(
            (p.effective_name for p in self.providers if p.id == identifier), identifier
        )


CURRENT_CONFIG: ContextVar[ConfigSnapshot | None] = ContextVar(
    "selfhost_config", default=None
)


def school_display_name(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("school name must be a string")
    value = unicodedata.normalize("NFC", value)
    if any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in value):
        raise ValueError("invalid school name")
    value = value.strip()
    if len(value) > MAX_SCHOOL_NAME:
        raise ValueError("invalid school name")
    return value


def provider_defaults(identifier: str) -> tuple[str, str, str]:
    if identifier == "hub":
        return "MCPHub", "hub", "key"
    if identifier == "local":
        return "Local account", "local", "key"
    if identifier in {"entra", "google", "github"}:
        return (
            {"entra": "Microsoft", "google": "Google", "github": "GitHub"}[identifier],
            identifier,
            "microsoft" if identifier == "entra" else identifier,
        )
    if identifier.startswith("oidc:"):
        return identifier.removeprefix("oidc:"), "oidc", "key"
    raise ValueError("unsupported sign-in provider")


async def _validate_addresses(policy: SchoolPolicy, resolver: HostResolver) -> None:
    for school in policy.featured:
        if (
            not school.allow_private
            and await check_public_host(school.host, resolver) != "ok"
        ):
            raise ValueError("featured school address is unavailable or blocked")


def _validate_addresses_sync(policy: SchoolPolicy, resolver: HostResolver) -> None:
    if not policy.featured:
        return
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        anyio.run(_validate_addresses, policy, resolver)
    else:
        # prepare_selfhost is synchronous and may be called from an async client
        # test or embedding application. Do not nest an event loop on its thread.
        with ThreadPoolExecutor(max_workers=1) as executor:
            executor.submit(anyio.run, _validate_addresses, policy, resolver).result()


class ConfigSnapshots:
    """One always-loaded snapshot; a failed refresh is never served or cached."""

    def __init__(
        self,
        database: Database,
        providers: LoginProvidersConfig | None,
        *,
        resolve_host: HostResolver = system_resolve,
        active_base_url: str | None = None,
    ) -> None:
        self.database = database
        self.providers = providers
        self.resolve_host = resolve_host
        self.active_base_url = active_base_url
        self.pilot = False
        self._lock = threading.Lock()
        self._current = self._build()

    def enable_pilot(self) -> None:
        from .profile import validate_pilot_schools

        validate_pilot_schools(self._current.schools)
        self.pilot = True

    @property
    def current(self) -> ConfigSnapshot:
        return self._current

    def revision(self) -> int:
        with self.database.read() as conn:
            return int(
                conn.execute(
                    select(s.server_state.c.settings_revision).where(
                        s.server_state.c.id == 1
                    )
                ).scalar_one()
            )

    def get(self, revision: int) -> ConfigSnapshot:
        if self._current.revision >= revision:
            return self._current
        with self._lock:
            if self._current.revision < revision:
                fresh = self._build()
                if fresh.revision < revision:
                    raise StoreUnavailable(kind="ConfigurationRevision")
                self._current = fresh
            return self._current

    def _build(self) -> ConfigSnapshot:
        try:
            for _ in range(3):
                snapshot = self._read()
                if snapshot is not None:
                    if (
                        self.active_base_url is not None
                        and snapshot.settings["site.public_base_url"]
                        != self.active_base_url
                    ):
                        raise StoreUnavailable(kind="SiteAddressRestartRequired")
                    if self.pilot:
                        from .profile import validate_pilot_schools

                        validate_pilot_schools(snapshot.schools)
                    _validate_addresses_sync(snapshot.schools, self.resolve_host)
                    if snapshot.warnings:
                        logger.warning(
                            "No Canvas school is offered; manage schools in Admin > Settings"
                        )
                    return snapshot
        except StoreUnavailable:
            raise
        except Exception:
            raise StoreUnavailable(kind="ConfigurationValidation") from None
        raise StoreUnavailable(kind="ConfigurationRevision")

    def _read(self) -> ConfigSnapshot | None:
        state = s.server_state
        revision = state.c.settings_revision.label("revision")
        with self.database.read() as conn:
            settings = (
                conn.execute(
                    select(revision, s.settings.c.key, s.settings.c.value)
                    .select_from(state.outerjoin(s.settings, true()))
                    .where(state.c.id == 1)
                )
                .mappings()
                .all()
            )
            providers = (
                conn.execute(
                    select(
                        revision,
                        s.login_providers.c.id,
                        s.login_providers.c.protocol,
                        s.login_providers.c.display_name,
                        s.login_providers.c.configured,
                        s.login_providers.c.sort_rank,
                        s.login_providers.c.icon_data,
                    )
                    .select_from(state.outerjoin(s.login_providers, true()))
                    .where(state.c.id == 1)
                    .order_by(s.login_providers.c.sort_rank, s.login_providers.c.id)
                )
                .mappings()
                .all()
            )
            schools = (
                conn.execute(
                    select(
                        revision,
                        s.canvas_schools.c.host,
                        s.canvas_schools.c.display_name,
                        s.canvas_schools.c.featured_rank,
                        s.canvas_schools.c.allow_private,
                    )
                    .select_from(
                        state.outerjoin(
                            s.canvas_schools,
                            or_(
                                s.canvas_schools.c.featured_rank.is_not(None),
                                s.canvas_schools.c.allow_private,
                            ),
                        )
                    )
                    .where(state.c.id == 1)
                    .order_by(s.canvas_schools.c.featured_rank, s.canvas_schools.c.host)
                )
                .mappings()
                .all()
            )
        if not settings or not providers or not schools:
            raise ValueError("missing server state")
        revisions = {
            row["revision"] for rows in (settings, providers, schools) for row in rows
        }
        if len(revisions) != 1:
            return None
        values = {key: spec.default for key, spec in SETTINGS.items()}
        for row in settings:
            key = row["key"]
            if key is None:
                continue
            if key == POLICY_KEY:
                parse_policy(row["value"])
                continue
            if key not in SETTINGS:
                logger.warning("Ignoring an unknown server setting")
                continue
            values[key] = validate_setting(key, row["value"])
        displays = []
        configured_names: set[str] = set()
        for row in providers:
            identifier = row["id"]
            if identifier is None:
                continue
            default, protocol, icon = provider_defaults(identifier)
            name = provider_display_name(row["display_name"])
            configured = bool(
                row["configured"]
                and (self.providers is None or identifier in self.providers.ids)
            )
            effective = name or default
            if configured:
                if (
                    effective.casefold() in configured_names
                    or row["protocol"] != protocol
                ):
                    raise ValueError("invalid configured provider")
                configured_names.add(effective.casefold())
            displays.append(
                ProviderDisplay(
                    identifier,
                    protocol,
                    icon,
                    configured,
                    default,
                    name,
                    effective,
                    row["sort_rank"],
                    validate_icon_reference(row["icon_data"]),
                )
            )
        if (
            self.providers is not None
            and {p.id for p in displays if p.configured} != self.providers.ids
        ):
            raise ValueError("missing configured provider")
        featured, private = [], []
        for row in schools:
            host = row["host"]
            if host is None:
                continue
            if parse_hostname(host) != host or (
                is_blocked_hostname(host) and not row["allow_private"]
            ):
                raise ValueError("invalid school host")
            name = school_display_name(row["display_name"])
            school = School(
                host,
                f"https://{host}/api/v1",
                name,
                allow_private=bool(row["allow_private"]),
            )
            if row["allow_private"]:
                private.append(school)
            if row["featured_rank"] is not None:
                featured.append(school)
        if len(featured) > MAX_FEATURED:
            raise ValueError("too many featured schools")
        policy = SchoolPolicy(
            tuple(featured), bool(values["schools.directory_search"]), tuple(private)
        )
        warnings = (
            ("no_schools_offered",)
            if not policy.featured and not policy.search_enabled and not policy.private
            else ()
        )
        return ConfigSnapshot(
            revisions.pop(),
            policy,
            tuple(displays),
            TypedSettings(MappingProxyType(values)),
            warnings,
        )
