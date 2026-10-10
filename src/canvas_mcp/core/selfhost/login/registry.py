"""The providers a running server offers, wired from the settings.

:func:`build_login_runtime` returns ``None`` for an Entra-only deployment, so ``account_web``
keeps the exact code path it always had. For anything else it builds the Google, GitHub and
generic OpenID Connect providers (sharing one :class:`~.http.SafeHttp`), a descriptor for Entra
when it is listed, a start-rate bucket per provider and the one-time store that holds the
ceremonies (``login_states``, the same table the authorization server's transactions use).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..accounts import PROVIDER_ENTRA, PROVIDER_GITHUB, PROVIDER_GOOGLE
from ..limits import RateLimiters, TokenBucketLimiter, build_rate_limiters
from .config import LoginProvidersConfig
from .entra import (
    ENTRA_ALIAS_START_PATH,
    ENTRA_CALLBACK_PATH,
    ENTRA_START_PATH,
    EntraDescriptor,
)
from .github import GitHubLoginProvider
from .google import build_google_provider
from .http import SafeHttp
from .oidc import build_oidc_provider
from .protocol import LoginProvider

if TYPE_CHECKING:
    import httpx

    from ..login_state import LoginStateStore
    from ..settings import SelfhostSettings

#: Sign-in starts per minute and provider, for the whole process. Each start writes one row that
#: lives ten minutes, so this bounds the table at a few hundred rows per provider.
START_BURST = 30
START_REFILL_PER_SECOND = 0.5


@dataclass(frozen=True)
class ProviderEntry:
    """One line of the sign-in page and of ``/account/api/providers``."""

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
    entra: EntraDescriptor | None = None
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
        out: list[ProviderEntry] = []
        for provider_id in self.config.order:
            if provider_id == PROVIDER_ENTRA:
                assert self.entra is not None
                out.append(
                    ProviderEntry(
                        PROVIDER_ENTRA, self.entra.kind, self.entra.display.name,
                        self.entra.display.icon, self.entra.start_path,
                    )
                )
                continue
            provider = self.providers[provider_id]
            out.append(
                ProviderEntry(
                    provider.id, provider.kind, provider.display.name, provider.display.icon,
                    provider.start_path,
                )
            )
        return out

    def entry(self, provider_id: str) -> ProviderEntry | None:
        return next((e for e in self.entries() if e.id == provider_id), None)

    def provider_paths(self) -> list[str]:
        """The start and callback paths of the non-Entra providers (exact, no parameters)."""
        paths: list[str] = []
        for provider in self.providers.values():
            paths.extend((provider.start_path, provider.callback_path))
        return paths


def build_login_runtime(
    settings: SelfhostSettings,
    *,
    flow_store: LoginStateStore | None,
    clock: Callable[[], float] = time.time,
    rate_limiters: RateLimiters | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> LoginRuntime | None:
    """The runtime for ``SELFHOST_LOGIN_PROVIDERS``, or None when Entra is the only provider."""
    config = settings.login_providers
    if config.order == (PROVIDER_ENTRA,):
        return None
    assert flow_store is not None, "sign-in providers other than Entra need the local authorization server"
    http = SafeHttp(transport=transport)
    policy = settings.access_policy
    base = settings.public_base_url
    limiters = rate_limiters or build_rate_limiters("memory")
    providers: dict[str, LoginProvider] = {}
    for provider_id in config.order:
        built: Any
        if provider_id == PROVIDER_ENTRA:
            continue
        if provider_id == PROVIDER_GOOGLE:
            assert config.google is not None
            domains = policy.google_domains()
            built = build_google_provider(
                config.google, public_base_url=base, http=http,
                domain_hint=domains[0] if len(domains) == 1 else None, clock=clock,
            )
        elif provider_id == PROVIDER_GITHUB:
            assert config.github is not None
            built = GitHubLoginProvider(
                config.github, public_base_url=base, http=http,
                orgs=policy.github_orgs(), teams=policy.github_teams(),
            )
        else:
            oidc = config.oidc_by_id()[provider_id]
            built = build_oidc_provider(
                oidc, public_base_url=base, http=http,
                claim_names=policy.oidc_claim_names(provider_id), clock=clock,
            )
        providers[provider_id] = built
    entra = None
    if config.entra_enabled:
        entra = EntraDescriptor(start_path=ENTRA_ALIAS_START_PATH)
    return LoginRuntime(
        config=config,
        providers=providers,
        flow_store=flow_store,
        http=http,
        entra=entra,
        start_buckets={
            provider_id: limiters.token_bucket(START_BURST, START_REFILL_PER_SECOND, clock)
            for provider_id in providers
        },
    )


__all__ = [
    "ENTRA_CALLBACK_PATH",
    "ENTRA_START_PATH",
    "LoginRuntime",
    "ProviderEntry",
    "build_login_runtime",
]
