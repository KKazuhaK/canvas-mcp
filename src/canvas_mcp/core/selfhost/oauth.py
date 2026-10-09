"""The FastMCP OAuth provider that signs MCP clients in through Entra ID."""

from __future__ import annotations

import hashlib
import weakref
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from fastmcp.server.auth.jwt_issuer import derive_jwt_key
from fastmcp.server.auth.providers.azure import AzureProvider
from key_value.aio.protocols import AsyncKeyValue
from key_value.aio.stores.filetree import (
    FileTreeStore,
    FileTreeV1CollectionSanitizationStrategy,
    FileTreeV1KeySanitizationStrategy,
)
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

# These two salts, the directory layout and the Fernet wrapping below are what
# FastMCP's own default store used before this mode started building its own.
# They are kept byte for byte so state written by an older release (upstream
# Entra tokens, client registrations) is still readable after an upgrade.
# tests/test_fastmcp_compat.py proves the equivalence against FastMCP itself.
_JWT_KEY_SALT = "fastmcp-jwt-signing-key"
_STORAGE_KEY_SALT = "fastmcp-storage-encryption-key"
_STORAGE_SUBDIRECTORY = "oauth-proxy"

# The file store behind each provider, so the periodic cleanup can reach it
# without depending on any FastMCP attribute after startup.
_STORES: weakref.WeakKeyDictionary[Any, OAuthStorage] = weakref.WeakKeyDictionary()


class OAuthStorage:
    """The OAuth proxy's encrypted, lifetime-limited file store, built here.

    Layers, outermost first: Fernet encryption of every value, a TTL clamp
    (entries written without a lifetime get ``DCR_CLIENT_TTL_SECONDS``;
    entries that carry one keep it), then one JSON file per record under
    ``<FASTMCP_HOME>/oauth-proxy/<key fingerprint>/``. A different signing key
    therefore reads a different directory instead of failing to decrypt.
    """

    def __init__(self, fastmcp_home: Path, jwt_signing_key: str) -> None:
        signing_key = derive_jwt_key(
            low_entropy_material=jwt_signing_key, salt=_JWT_KEY_SALT
        )
        encryption_key = derive_jwt_key(
            high_entropy_material=signing_key.decode(), salt=_STORAGE_KEY_SALT
        )
        fingerprint = hashlib.sha256(encryption_key).hexdigest()[:12]
        self.directory = fastmcp_home / _STORAGE_SUBDIRECTORY / fingerprint
        self.directory.mkdir(parents=True, exist_ok=True)
        self.files = FileTreeStore(
            data_directory=self.directory,
            key_sanitization_strategy=FileTreeV1KeySanitizationStrategy(self.directory),
            collection_sanitization_strategy=FileTreeV1CollectionSanitizationStrategy(
                self.directory
            ),
        )
        self.store: AsyncKeyValue = FernetEncryptionWrapper(
            key_value=TTLClampWrapper(
                self.files,
                min_ttl=0,
                max_ttl=_MAX_RECORD_TTL_SECONDS,
                missing_ttl=DCR_CLIENT_TTL_SECONDS,
            ),
            fernet=Fernet(key=encryption_key),
            # A record sealed under another key is a miss (the client signs in
            # again), never a crash.
            raise_on_decryption_error=False,
        )

    async def cull(self) -> None:
        """Delete every expired record from disk."""
        await self.files.cull()


def build_entra_auth_provider(settings: SelfhostSettings) -> AzureProvider:
    """Build the provider for the MCP endpoint (no network access at build time).

    - ``jwt_signing_key`` is passed as ``str``: FastMCP stretches it for the
      token signature. It is separate from the Entra client secret, so
      rotating the secret does not sign every client out.
    - ``client_storage`` is our own :class:`OAuthStorage` (the public
      parameter), so upstream Entra tokens persist across restarts under
      ``FASTMCP_HOME`` and client registrations expire.
    - Consent stays on and client redirect URIs are limited to the allowlist.
    """
    storage = OAuthStorage(settings.fastmcp_home, settings.oauth_jwt_signing_key)
    provider = AzureProvider(
        client_id=settings.client_id,
        client_secret=settings.client_secret,
        tenant_id=settings.tenant_id,
        required_scopes=[settings.api_scope],
        base_url=settings.public_base_url,
        issuer_url=settings.public_base_url,
        redirect_path="/auth/callback",
        allowed_client_redirect_uris=list(settings.allowed_client_redirect_uris),
        client_storage=storage.store,
        jwt_signing_key=settings.oauth_jwt_signing_key,
        require_authorization_consent=True,
        enable_cimd=True,
    )
    _STORES[provider] = storage
    return provider


def oauth_storage_of(provider: Any) -> OAuthStorage | None:
    """The :class:`OAuthStorage` built for ``provider``, or None if not ours."""
    try:
        return _STORES.get(provider)
    except TypeError:  # not something that can be weakly referenced: not ours
        return None


async def cull_expired_oauth_state(provider: Any) -> None:
    """Delete expired records (client registrations, transactions, codes) from disk.

    The file store only drops an expired record when something reads that exact
    key again, which never happens for abandoned ``/authorize`` transactions
    and one-off registrations.
    """
    storage = oauth_storage_of(provider)
    if storage is not None:
        await storage.cull()
