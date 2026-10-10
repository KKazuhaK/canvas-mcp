"""Wiring of the authorization server: everything it shares, built from the settings.

:func:`build_authz_runtime` is called once, in ``prepare_selfhost``, when
``SELFHOST_AUTH_MODE=local``. It reuses the token store's ``Database`` (the same engine,
so on SQLite the process-wide write lock is shared) and the keyring that is already parsed.

The runtime object is also what ``/account`` receives (``account_web`` types it only under
``TYPE_CHECKING``): the consent service, the grant operations behind the connected-apps
pages, and the hooks that keep the grant status cache honest when an account changes.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from ...logging import log_warning
from ..principal_access import PrincipalAccessCache
from ..settings import SelfhostSettings
from ..token_store import Keyring, TokenStore
from . import fastmcp_compat as compat
from .clients import CimdResolver, ClientDirectory, Fetcher
from .consent import ConsentService
from .grants import GrantService, GrantStatusCache
from .models import REVOKE_ADMISSION_LOST, GrantRecord
from .store import AuthzStore
from .tokens import AccessTokenCodec, EpochSource
from .transactions import BINDING_COOKIE, SqlLoginStateStore
from .urls import audience_of, issuer_of


@dataclass
class AuthzRuntime:
    """The pieces of the local authorization server that more than one module uses."""

    settings: SelfhostSettings
    store: AuthzStore
    codec: AccessTokenCodec
    epoch: EpochSource
    clients: ClientDirectory
    grants: GrantService
    cache: GrantStatusCache
    txns: SqlLoginStateStore
    consent: ConsentService
    issuer: str
    audience: str
    clock: Callable[[], float] = time.time
    #: The cookie that ties an authorization request to the browser that started it.
    binding_cookie: str = BINDING_COOKIE

    # -- what /account uses -------------------------------------------------------------------

    @property
    def account_hooks(self) -> AuthzRuntime:
        """What ``/account`` receives: the consent service, the grant operations and the cache hooks."""
        return self

    def account_changed(self, account_key: str) -> None:
        """An owner disabled, enabled, approved or denied an account: forget cached grant status."""
        self.cache.invalidate_account(account_key.removeprefix("acct:"))

    async def admission_lost(self, account_key: str) -> int:
        """The person signed in again and the admission rules no longer admit them: end their apps.

        Best effort for the caller: it logs and goes on, because the sign-in is already refused.
        """
        try:
            return await self.grants.revoke_all_for_account(account_key, REVOKE_ADMISSION_LOST)
        except Exception:  # noqa: BLE001 - the refusal of the sign-in must not turn into an error page
            log_warning("oauth_admission_lost", reason="revocation_failed")
            return 0

    async def list_own_grants(self, account_key: str) -> list[GrantRecord]:
        return await self.grants.list_grants(account_key)

    async def revoke_own_grant(self, grant_id: str, account_key: str) -> bool:
        return await self.grants.revoke_own(grant_id, account_key)

    async def owner_revoke_grant(self, grant_id: str, actor_key: str) -> bool:
        return await self.grants.owner_revoke(grant_id, actor_key)

    def bump_jwt_epoch(self) -> int:
        """Invalidate every access token issued so far (this process at once, others within 30 s)."""
        epoch = self.store.bump_jwt_epoch()
        self.epoch.invalidate()
        return epoch


def build_authz_runtime(
    settings: SelfhostSettings,
    token_store: TokenStore,
    keyring: Keyring,
    access: PrincipalAccessCache | None = None,
    *,
    clock: Callable[[], float] = time.time,
    fetch: Fetcher | None = None,
    pause_hook: Callable[[str], None] | None = None,
) -> AuthzRuntime:
    """Build the local authorization server's shared state. ``fetch`` replaces the CIMD fetcher (tests)."""
    authz = settings.authz
    base = settings.public_base_url
    issuer = issuer_of(base)
    audience = audience_of(base, settings.mcp_path)
    scopes = (settings.api_scope,)
    store = AuthzStore(token_store.database, clock=clock, settings=authz, pause_hook=pause_hook)
    epoch = EpochSource(store.jwt_epoch)
    codec = AccessTokenCodec(
        keyring, epoch.get, issuer=issuer, audience=audience, scopes=scopes, clock=clock
    )
    cache = GrantStatusCache(float(authz.grant_status_cache_s))
    grants = GrantService(store, codec, cache, authz, clock=clock)
    allowlist = tuple(settings.allowed_client_redirect_uris)
    resolver = CimdResolver(
        store, authz, allowlist, scopes, fetch=fetch or compat.fetch_client_metadata, clock=clock
    )
    clients = ClientDirectory(store, resolver, allowlist, scopes, clock=clock)
    txns = SqlLoginStateStore(token_store.database, clock=clock)
    consent = ConsentService(store, txns, clients, issuer=issuer, clock=clock)
    _ = access  # the request path reads account status through the access cache elsewhere
    return AuthzRuntime(
        settings=settings,
        store=store,
        codec=codec,
        epoch=epoch,
        clients=clients,
        grants=grants,
        cache=cache,
        txns=txns,
        consent=consent,
        issuer=issuer,
        audience=audience,
        clock=clock,
    )
