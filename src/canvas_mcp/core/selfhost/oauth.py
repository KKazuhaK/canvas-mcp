"""The FastMCP OAuth provider that signs MCP clients in through Entra ID."""

from __future__ import annotations

import weakref
from typing import Any

from fastmcp.server.auth.providers.azure import AzureProvider
from key_value.aio.stores.filetree import FileTreeStore
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper
from key_value.aio.wrappers.ttl_clamp import TTLClampWrapper

from .settings import SelfhostSettings

# How long a dynamically registered client (POST /register) is remembered.
# FastMCP stores these records with no lifetime at all, and anyone on the
# internet can create them, so without a limit they pile up on the data volume
# for ever. A client that outlives this simply registers again.
DCR_CLIENT_TTL_SECONDS = 30 * 24 * 3600

# Upper bound for every other record. FastMCP always passes its own lifetime
# for those (transactions 15 min, codes 5 min, tokens up to the refresh
# lifetime of about a year), so this only keeps a runaway value from sticking.
_MAX_RECORD_TTL_SECONDS = 10 * 365 * 24 * 3600

# The file store behind each provider, so the periodic cleanup can reach it
# without depending on FastMCP's private attribute names after startup.
_FILE_STORES: weakref.WeakKeyDictionary[Any, FileTreeStore] = weakref.WeakKeyDictionary()


def build_entra_auth_provider(settings: SelfhostSettings) -> AzureProvider:
    """Build the provider for the MCP endpoint (no network access at build time).

    - ``jwt_signing_key`` is passed as ``str``: FastMCP stretches it for the
      token signature and also decodes it to derive its storage key, which
      fails for raw bytes. It is separate from the Entra client secret, so
      rotating the secret does not sign every client out.
    - No ``client_storage`` is passed, so the default encrypted file store
      under ``FASTMCP_HOME`` keeps the upstream tokens across restarts; it is
      then given a lifetime for client registrations (see
      :func:`limit_client_record_lifetime`).
    - Consent stays on and client redirect URIs are limited to the allowlist.
    """
    provider = AzureProvider(
        client_id=settings.client_id,
        client_secret=settings.client_secret,
        tenant_id=settings.tenant_id,
        required_scopes=[settings.api_scope],
        base_url=settings.public_base_url,
        issuer_url=settings.public_base_url,
        redirect_path="/auth/callback",
        allowed_client_redirect_uris=list(settings.allowed_client_redirect_uris),
        jwt_signing_key=settings.oauth_jwt_signing_key,
        require_authorization_consent=True,
        enable_cimd=True,
    )
    limit_client_record_lifetime(provider)
    return provider


def limit_client_record_lifetime(provider: AzureProvider) -> None:
    """Make dynamically registered clients expire instead of living for ever.

    ``POST /register`` is open to anyone and FastMCP writes one file per call
    with no lifetime, in the same volume as the Canvas token database. The
    provider's own encrypted file store is kept (same directory, same key, so
    existing state survives) and a clamp is slipped in between the encryption
    layer and the files: entries written without a lifetime get
    ``DCR_CLIENT_TTL_SECONDS``; entries that carry one keep it.

    Fails closed: if a FastMCP upgrade moves the storage, startup stops here
    rather than silently going back to records that never expire.
    """
    storage = getattr(provider, "_client_storage", None)
    inner = getattr(storage, "key_value", None)
    if not isinstance(storage, FernetEncryptionWrapper) or not isinstance(inner, FileTreeStore):
        raise RuntimeError(
            "the FastMCP OAuth proxy no longer keeps its state in an encrypted "
            "file store; the registration lifetime cannot be applied"
        )
    storage.key_value = TTLClampWrapper(
        inner,
        min_ttl=0,
        max_ttl=_MAX_RECORD_TTL_SECONDS,
        missing_ttl=DCR_CLIENT_TTL_SECONDS,
    )
    _FILE_STORES[provider] = inner


async def cull_expired_oauth_state(provider: Any) -> None:
    """Delete expired records (client registrations, transactions, codes) from disk.

    The file store only drops an expired record when something reads that exact
    key again, which never happens for abandoned ``/authorize`` transactions
    and one-off registrations.
    """
    try:
        store = _FILE_STORES.get(provider)
    except TypeError:  # not something that can be weakly referenced: not ours
        return
    if store is not None:
        await store.cull()
