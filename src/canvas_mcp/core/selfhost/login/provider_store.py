"""Governed database configuration and sealed secrets for sign-in providers."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, exists, select, update

from ..config_store import ConfigStore
from ..db import schema as s
from ..db.engine import Database
from ..db.repos import Repositories
from ..db.sealed import SEALED, SealKeys
from .config import MAX_PROVIDERS
from .provider_config import (
    ProviderConfiguration,
    ProviderConfigurationError,
    validate_provider,
)

_SEALED = next(entry for entry in SEALED if entry.table is s.login_providers)
_UNCHANGED = object()


@dataclass(frozen=True)
class ProviderSnapshot:
    revision: int
    providers: tuple[ProviderConfiguration, ...]
    local_installed: bool = False


class ProviderConfigStore:
    def __init__(
        self,
        database: Database,
        keys: SealKeys,
        *,
        validate: Callable[[ProviderSnapshot], object] | None = None,
    ) -> None:
        self.database = database
        self.keys = keys
        self.repos = Repositories(database.kind)
        self.validate = validate

    @staticmethod
    def _public(row: Any) -> dict[str, Any]:
        config = validate_provider(row["id"], row["config"], None).config
        return {
            "id": row["id"],
            "protocol": row["protocol"],
            "config_source": row["config_source"],
            "enabled": bool(row["configured"]),
            "auto_link_email": bool(row["auto_link_email"]),
            "icon_data": row["icon_data"],
            "rank": row["sort_rank"],
            "config": dict(config),
            "secret_present": row["secret_ciphertext"] is not None,
        }

    def list_public(self) -> tuple[dict[str, Any], ...]:
        with self.database.read() as conn:
            return tuple(
                self._public(row)
                for row in conn.execute(
                    select(s.login_providers)
                    .where(s.login_providers.c.config_source == "db")
                    .order_by(s.login_providers.c.sort_rank, s.login_providers.c.id)
                ).mappings()
            )

    def public_snapshot(self) -> tuple[int, tuple[dict[str, Any], ...]]:
        """One statement binds redacted registrations to their configuration revision."""
        with self.database.read() as conn:
            rows = (
                conn.execute(
                    select(s.server_state.c.settings_revision, s.login_providers)
                    .select_from(
                        s.server_state.outerjoin(
                            s.login_providers, s.login_providers.c.config_source == "db"
                        )
                    )
                    .where(s.server_state.c.id == 1)
                    .order_by(s.login_providers.c.sort_rank, s.login_providers.c.id)
                )
                .mappings()
                .all()
            )
            if not rows:
                raise ProviderConfigurationError("provider_configuration_unavailable")
            return int(rows[0]["settings_revision"]), tuple(
                self._public(row) for row in rows if row["id"] is not None
            )

    def _decode(self, row: Any) -> ProviderConfiguration:
        try:
            if row["id"] == "local" and row["config_source"] == "db":
                return validate_provider("local", row["config"], None)
            if row["config_source"] != "db" or row["secret_ciphertext"] is None:
                raise ValueError
            secret = self.keys.decrypt(
                row["secret_key_id"],
                bytes(row["secret_nonce"]),
                bytes(row["secret_ciphertext"]),
                _SEALED.aad(row),
            ).decode("utf-8")
            return validate_provider(row["id"], row["config"], secret)
        except Exception:
            raise ProviderConfigurationError(
                "provider_configuration_unavailable"
            ) from None

    def load_enabled(self) -> tuple[ProviderConfiguration, ...]:
        return self.load_snapshot().providers

    def load_snapshot(self) -> ProviderSnapshot:
        """Read credentials and their revision in one SQL statement snapshot."""
        with self.database.read() as conn:
            return self._snapshot_in(conn)

    def _snapshot_in(self, conn: Connection) -> ProviderSnapshot:
        local = s.login_providers.alias("local_registration")
        local_installed = exists(
            select(local.c.id).where(
                local.c.id == "local", local.c.config_source == "db"
            )
        ).label("local_installed")
        rows = (
            conn.execute(
                select(
                    s.server_state.c.settings_revision,
                    s.login_providers,
                    local_installed,
                )
                .select_from(
                    s.server_state.outerjoin(
                        s.login_providers, s.login_providers.c.configured
                    )
                )
                .where(s.server_state.c.id == 1)
                .order_by(s.login_providers.c.sort_rank, s.login_providers.c.id)
            )
            .mappings()
            .all()
        )
        if not rows:
            raise ProviderConfigurationError("provider_configuration_unavailable")
        return ProviderSnapshot(
            int(rows[0]["settings_revision"]),
            tuple(self._decode(row) for row in rows if row["id"] is not None),
            bool(rows[0]["local_installed"]),
        )

    def validate_in(self, conn: Connection) -> None:
        """Validate the whole proposed registration set before its transaction commits."""
        if self.validate is not None:
            from ..settings import SelfhostConfigError

            try:
                self.validate(self._snapshot_in(conn))
            except SelfhostConfigError:
                raise ProviderConfigurationError() from None

    @staticmethod
    def setup_available_in(conn: Connection) -> bool:
        """A DB-owned row is a durable marker, even after provider disablement."""
        initialized = exists(
            select(s.login_providers.c.id).where(
                (s.login_providers.c.config_source == "db")
                | s.login_providers.c.configured
            )
        ) | exists(select(s.accounts.c.id))
        return not bool(conn.execute(select(initialized)).scalar_one())

    def setup_available(self) -> bool:
        with self.database.read() as conn:
            return self.setup_available_in(conn)

    def initialize(
        self, *, config: object, client_secret: object, revision: int, now: int
    ) -> int:
        return self.save(
            "entra",
            config=config,
            client_secret=client_secret,
            enabled=True,
            rank=0,
            revision=revision,
            actor=None,
            now=now,
            _initial=True,
        )

    def save(
        self,
        identifier: str,
        *,
        config: object,
        client_secret: object,
        enabled: bool,
        rank: int,
        revision: int,
        actor: str | None,
        now: int,
        auto_link_email: bool | None = None,
        icon_data: object = _UNCHANGED,
        _initial: bool = False,
        _connection: Connection | None = None,
    ) -> int:
        value = validate_provider(identifier, config, client_secret)
        from .provider_icon import validate_icon

        parsed_icon = validate_icon(icon_data) if icon_data is not _UNCHANGED else None
        if (
            type(enabled) is not bool
            or auto_link_email is not None
            and type(auto_link_email) is not bool
            or identifier == "local"
            and auto_link_email is True
            or type(rank) is not int
            or not 0 <= rank < MAX_PROVIDERS
        ):
            raise ProviderConfigurationError()
        with (
            self.database.write() if _connection is None else nullcontext(_connection)
        ) as conn:
            if _initial and not self.setup_available_in(conn):
                raise ProviderConfigurationError("installation_already_initialized")
            new_revision = ConfigStore._authorize(conn, actor, revision, now)
            old = (
                conn.execute(
                    select(s.login_providers).where(
                        s.login_providers.c.id == identifier
                    )
                )
                .mappings()
                .one_or_none()
            )
            if value.client_secret is None and identifier != "local":
                if old is None or old["secret_ciphertext"] is None:
                    raise ProviderConfigurationError("provider_secret_required")
                self._decode(old)  # Refuse retaining a damaged or unknown-key secret.
            identities = (
                conn.execute(
                    select(s.external_identities.c.issuer)
                    .where(s.external_identities.c.provider_id == identifier)
                    .distinct()
                )
                .scalars()
                .all()
            )
            if identities and (
                any(issuer != value.issuer for issuer in identities)
                or old is not None
                and old["config"] is not None
                and old["config"].get("client_id") != value.config.get("client_id")
            ):
                raise ProviderConfigurationError("provider_identity_binding_changed")
            active = set(
                conn.execute(
                    select(s.login_providers.c.id).where(s.login_providers.c.configured)
                ).scalars()
            )
            current = set(active)
            local_owners_before = self.repos.accounts.local_owner_ids(
                conn, sorted(current)
            )
            if enabled:
                active.add(identifier)
            else:
                active.discard(identifier)
            if len(active) > MAX_PROVIDERS:
                raise ProviderConfigurationError("too_many_providers")
            if local_owners_before and not self.repos.accounts.local_owner_ids(
                conn, sorted(active)
            ):
                raise ProviderConfigurationError("last_local_owner")
            if (
                active != current
                and self.repos.accounts.count_usable_owners(conn, sorted(current)) > 0
                and not self.repos.accounts.count_usable_owners(conn, sorted(active))
            ):
                raise ProviderConfigurationError("last_owner")
            if (
                identifier == "entra"
                and old is not None
                and old["config"]
                and old["config"].get("owner_role", "Canvas.Owner")
                != value.config["owner_role"]
                and self.repos.accounts.count_active_owners(conn) > 0
                and not self.repos.accounts.count_usable_owners(
                    conn, sorted(active - {"entra"})
                )
            ):
                raise ProviderConfigurationError("last_owner")
            self.repos.providers.ensure(conn, identifier, now=now)
            updates: dict[str, Any] = {
                "config_source": "db",
                "protocol": value.protocol,
                "config": dict(value.config),
                "configured": enabled,
                "sort_rank": rank,
                "configured_at": now if enabled else None,
                "updated_at": now,
                "updated_by": actor,
            }
            if value.client_secret is not None:
                kid, nonce, ciphertext = self.keys.encrypt(
                    value.client_secret.encode("utf-8"),
                    _SEALED.aad({"id": identifier}, key_id=self.keys.active_key_id),
                )
                updates.update(
                    secret_key_id=kid, secret_nonce=nonce, secret_ciphertext=ciphertext
                )
            if auto_link_email is not None:
                updates["auto_link_email"] = auto_link_email
            if icon_data is not _UNCHANGED:
                updates["icon_data"] = parsed_icon
            conn.execute(
                update(s.login_providers)
                .where(s.login_providers.c.id == identifier)
                .values(**updates)
            )
            ConfigStore._audit(
                conn,
                actor,
                now,
                "sign_in_provider_configured",
                "provider",
                identifier,
                {
                    "enabled": enabled,
                    "auto_link_email": auto_link_email
                    if auto_link_email is not None
                    else bool(old and old["auto_link_email"]),
                    "secret_replaced": value.client_secret is not None,
                    "custom_icon": bool(
                        parsed_icon
                        if icon_data is not _UNCHANGED
                        else old and old["icon_data"]
                    ),
                },
            )
            if _connection is None:
                self.validate_in(conn)
        return new_revision
