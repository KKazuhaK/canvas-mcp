"""Immutable login generations pinned to individual account requests."""

from __future__ import annotations

import threading
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..account_core import AccountCore
    from ..identity import IdentityService
    from ..settings import SelfhostSettings
    from .flows import ExternalSignIn
    from .provider_store import ProviderConfigStore
    from .registry import LoginRuntime


@dataclass(frozen=True)
class LoginBundle:
    revision: int | None
    logins: LoginRuntime
    identity: IdentityService
    external: ExternalSignIn


CURRENT_LOGIN: ContextVar[tuple[object, LoginBundle] | None] = ContextVar(
    "canvas_mcp_login_generation", default=None
)


class DatabaseLoginRuntime:
    def __init__(
        self,
        app: AccountCore,
        settings: SelfhostSettings,
        providers: ProviderConfigStore,
        initial: LoginBundle,
    ) -> None:
        self.app = app
        self.settings = settings
        self.providers = providers
        self.current = initial
        self._lock = threading.Lock()

    def get(self) -> LoginBundle:
        """Refresh without publishing a partially rebuilt or stale generation."""
        from ..accounts import EntraClaimsPolicy
        from ..identity import IdentityService
        from .flows import ExternalSignIn
        from .provider_config import ProviderConfigurationError
        from .provider_settings import settings_from_database
        from .registry import build_login_runtime

        with self._lock:
            for _ in range(3):
                saved = self.providers.load_snapshot()
                if saved.revision == self.current.revision:
                    return self.current
                snapshot = self.app.snapshots.get(saved.revision)
                if snapshot.revision != saved.revision:
                    continue
                settings = settings_from_database(self.settings, saved)
                previous = self.current.logins
                logins = build_login_runtime(
                    settings,
                    flow_store=previous.flow_store,
                    clock=self.app.clock,
                    snapshots=self.app.snapshots,
                    http=previous.http,
                )
                for identifier in logins.order:
                    if identifier in previous.start_buckets:
                        logins.start_buckets[identifier] = previous.start_buckets[
                            identifier
                        ]
                identity = IdentityService(
                    self.app.store,
                    EntraClaimsPolicy(settings.tenant_id, settings.client_id),
                    settings.access_policy,
                    login_providers=logins.accepted_pids,
                    expected_revision=saved.revision,
                )
                bundle = LoginBundle(
                    saved.revision, logins, identity, ExternalSignIn(self.app, logins)
                )
                # A write during construction must not publish the superseded values.
                if self.app.snapshots.revision() != saved.revision:
                    continue
                self.current = bundle
                return bundle
        raise ProviderConfigurationError("provider_configuration_unavailable")
