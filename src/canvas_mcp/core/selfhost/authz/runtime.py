"""Wire the built-in authorization server over the shared database and keyring."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ...logging import log_warning
from ..db.workers import run_store
from ..pagination import DEFAULT_LIMIT, Page
from ..settings import SelfhostSettings
from ..token_store import Keyring, TokenStore
from . import fastmcp_compat as compat
from .clients import CimdResolver, ClientDirectory, Fetcher
from .consent import ConsentService
from .grants import GrantService
from .models import REVOKE_ADMISSION_LOST, GrantRecord
from .store import AuthzStore
from .tokens import AccessTokenCodec
from .transactions import BINDING_COOKIE, SqlLoginStateStore
from .urls import audience_of, issuer_of

if TYPE_CHECKING:
    from ..app import SelfhostRuntime
    from .server import LocalAuthorizationServer


@dataclass
class AuthzRuntime:
    """The pieces of the local authorization server that more than one module uses."""

    settings: SelfhostSettings
    store: AuthzStore
    codec: AccessTokenCodec
    clients: ClientDirectory
    grants: GrantService
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
        """What ``/account`` receives: the consent service, the grant operations."""
        return self

    async def admission_lost(self, account_key: str) -> int:
        """The person signed in again and the admission rules no longer admit them: end their apps.

        Best effort for the caller: it logs and goes on, because the sign-in is already refused.
        """
        try:
            return await self.grants.revoke_all_for_account(
                account_key, REVOKE_ADMISSION_LOST
            )
        except Exception:  # noqa: BLE001 - the refusal of the sign-in must not turn into an error page
            log_warning("oauth_admission_lost", reason="revocation_failed")
            return 0

    async def grants_page(
        self, account_key: str, *, cursor: str | None = None, limit: int = DEFAULT_LIMIT
    ) -> Page[GrantRecord]:
        return await run_store(
            lambda: self.store.grants_page(
                account_key=account_key, cursor=cursor, limit=limit
            )
        )

    async def revoke_own_grant(self, grant_id: str, account_key: str) -> bool:
        return await self.grants.revoke_own(grant_id, account_key)

    async def owner_revoke_grant(self, grant_id: str, actor_key: str) -> bool:
        return await self.grants.owner_revoke(grant_id, actor_key)

    def bump_jwt_epoch(self) -> int:
        """Invalidate existing access tokens on every instance at the next request."""
        return self.store.bump_jwt_epoch()


def build_authz_runtime(
    settings: SelfhostSettings,
    token_store: TokenStore,
    keyring: Keyring,
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
    store = AuthzStore(
        token_store.database, clock=clock, settings=authz, pause_hook=pause_hook
    )
    codec = AccessTokenCodec(
        keyring, issuer=issuer, audience=audience, scopes=scopes, clock=clock
    )
    grants = GrantService(store, codec, authz, clock=clock)
    allowlist = tuple(settings.allowed_client_redirect_uris)
    resolver = CimdResolver(
        store,
        authz,
        allowlist,
        scopes,
        fetch=fetch or compat.fetch_client_metadata,
        clock=clock,
    )
    clients = ClientDirectory(store, resolver, allowlist, scopes, clock=clock)
    txns = SqlLoginStateStore(token_store.database, clock=clock)
    consent = ConsentService(store, txns, clients, issuer=issuer, clock=clock)
    return AuthzRuntime(
        settings=settings,
        store=store,
        codec=codec,
        clients=clients,
        grants=grants,
        txns=txns,
        consent=consent,
        issuer=issuer,
        audience=audience,
        clock=clock,
    )


def build_auth_provider(
    settings: SelfhostSettings, runtime: SelfhostRuntime
) -> LocalAuthorizationServer:
    """Use the built-in authorization server for every self-hosted deployment."""
    from .server import LocalAuthorizationServer

    return LocalAuthorizationServer(settings, runtime.authz)
