"""The configured sign-in providers on one common OIDC/OAuth ceremony.

Every deployment builds Entra, Google, GitHub or generic OIDC providers over the
same safe HTTP client, cookie binding, one-time state store and start-rate buckets.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol

from ..accounts import PROVIDER_ENTRA, PROVIDER_GITHUB, PROVIDER_GOOGLE
from ..limits import RateLimiters, TokenBucketLimiter, build_rate_limiters
from .config import LoginProvidersConfig
from .entra import ENTRA_CALLBACK_PATH, ENTRA_START_PATH, build_entra_provider
from .github import GitHubLoginProvider
from .google import build_google_provider
from .http import SafeHttp
from .oidc import build_oidc_provider
from .protocol import LoginProvider

if TYPE_CHECKING:
    import httpx

    from ..config_snapshot import ConfigSnapshots
    from ..login_state import LoginStateStore
    from ..settings import SelfhostSettings

#: A backstop on how many ceremony rows can pile up per provider, not a per-client throttle: the
#: process cannot tell source addresses apart (it sits behind the proxy and has no trusted-proxy
#: setting), so one bucket for everybody must be far above what any one proxied address is allowed
#: to start (the proxy examples allow 30 a minute per IP). Each start writes one row that lives ten
#: minutes, so a refill of 10 a second bounds the table at about 6000 live rows per provider.
START_BURST = 600
START_REFILL_PER_SECOND = 10.0


class ProviderConfigSource(Protocol):
    """Resolve a configured provider per lookup; DB-owned secrets stay reserved."""

    def resolve(self, provider_id: str) -> LoginProvider | None: ...


class EnvProviderConfigSource(Mapping[str, LoginProvider]):
    """Read-only providers built from this process's validated environment."""

    def __init__(self, providers: Mapping[str, LoginProvider]) -> None:
        self._providers = MappingProxyType(dict(providers))

    def resolve(self, provider_id: str) -> LoginProvider | None:
        return self._providers.get(provider_id)

    def __getitem__(self, provider_id: str) -> LoginProvider:
        provider = self.resolve(provider_id)
        if provider is None:
            raise KeyError(provider_id)
        return provider

    def __iter__(self) -> Iterator[str]:
        return iter(self._providers)

    def __len__(self) -> int:
        return len(self._providers)


@dataclass(frozen=True)
class ProviderEntry:
    """One line of the sign-in page and of ``/api/v1/providers``."""

    id: str
    kind: str
    name: str
    icon: str
    start_path: str


@dataclass
class LoginRuntime:
    config: LoginProvidersConfig
    providers: Mapping[str, LoginProvider]
    flow_store: LoginStateStore
    http: SafeHttp
    snapshots: ConfigSnapshots | None = None
    start_buckets: dict[str, TokenBucketLimiter] = field(default_factory=dict)

    @property
    def order(self) -> tuple[str, ...]:
        return self.config.order

    @property
    def linking_enabled(self) -> bool:
        return self.config.linking_enabled

    @property
    def accepted_pids(self) -> frozenset[str]:
        """The provider ids a session cookie may carry."""
        return self.config.ids

    @property
    def single(self) -> bool:
        return self.config.single

    def entries(self) -> list[ProviderEntry]:
        """Every provider, in the configured order."""
        from ..config_snapshot import CURRENT_CONFIG

        snapshot = CURRENT_CONFIG.get() or (
            self.snapshots.current if self.snapshots else None
        )
        out: list[ProviderEntry] = []
        for provider_id in self.config.order:
            provider = self.providers[provider_id]
            out.append(
                ProviderEntry(
                    provider.id,
                    provider.kind,
                    snapshot.name(provider_id) if snapshot else provider.display.name,
                    provider.display.icon,
                    provider.start_path,
                )
            )
        return out

    def entry(self, provider_id: str) -> ProviderEntry | None:
        return next((e for e in self.entries() if e.id == provider_id), None)

    def provider_paths(self) -> list[str]:
        """The exact start and callback paths of every configured provider."""
        paths: list[str] = []
        for provider in self.providers.values():
            paths.extend((provider.start_path, provider.callback_path))
        return paths


def build_login_runtime(
    settings: SelfhostSettings,
    *,
    flow_store: LoginStateStore,
    clock: Callable[[], float] = time.time,
    rate_limiters: RateLimiters | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    snapshots: ConfigSnapshots | None = None,
    http: SafeHttp | None = None,
) -> LoginRuntime:
    """Build every configured provider, including Entra-only deployments."""
    config = settings.login_providers
    http = http or SafeHttp(transport=transport)
    policy = settings.access_policy
    base = settings.public_base_url
    limiters = rate_limiters or build_rate_limiters("memory")
    providers: dict[str, LoginProvider] = {}
    for provider_id in config.order:
        built: Any
        if provider_id == PROVIDER_ENTRA:
            built = build_entra_provider(
                tenant_id=settings.tenant_id,
                client_id=settings.client_id,
                client_secret=settings.client_secret,
                public_base_url=base,
                http=http,
                parse_groups=policy.has_group_rule(),
                clock=clock,
            )
        elif provider_id == PROVIDER_GOOGLE:
            assert config.google is not None
            domains = policy.google_domains()
            built = build_google_provider(
                config.google,
                public_base_url=base,
                http=http,
                domain_hint=domains[0] if len(domains) == 1 else None,
                clock=clock,
            )
        elif provider_id == PROVIDER_GITHUB:
            assert config.github is not None
            built = GitHubLoginProvider(
                config.github,
                public_base_url=base,
                http=http,
                orgs=policy.github_orgs(),
                teams=policy.github_teams(),
            )
        else:
            oidc = config.oidc_by_id()[provider_id]
            built = build_oidc_provider(
                oidc,
                public_base_url=base,
                http=http,
                claim_names=policy.oidc_claim_names(provider_id),
                clock=clock,
            )
        providers[provider_id] = built
    return LoginRuntime(
        config=config,
        providers=EnvProviderConfigSource(providers),
        flow_store=flow_store,
        http=http,
        snapshots=snapshots,
        start_buckets={
            provider_id: limiters.token_bucket(
                START_BURST, START_REFILL_PER_SECOND, clock
            )
            for provider_id in providers
        },
    )


__all__ = [
    "ENTRA_CALLBACK_PATH",
    "ENTRA_START_PATH",
    "LoginRuntime",
    "ProviderConfigSource",
    "EnvProviderConfigSource",
    "ProviderEntry",
    "build_login_runtime",
]
