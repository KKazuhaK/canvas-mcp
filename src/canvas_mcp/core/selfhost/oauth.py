"""The FastMCP OAuth provider that signs MCP clients in through Entra ID."""

from __future__ import annotations

from fastmcp.server.auth.providers.azure import AzureProvider

from .settings import SelfhostSettings


def build_entra_auth_provider(settings: SelfhostSettings) -> AzureProvider:
    """Build the provider for the MCP endpoint (no network access at build time).

    - ``jwt_signing_key`` is passed as ``str``: FastMCP stretches it for the
      token signature and also decodes it to derive its storage key, which
      fails for raw bytes. It is separate from the Entra client secret, so
      rotating the secret does not sign every client out.
    - No ``client_storage`` is passed, so the default encrypted file store
      under ``FASTMCP_HOME`` keeps the upstream tokens across restarts.
    - Consent stays on and client redirect URIs are limited to the allowlist.
    """
    return AzureProvider(
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
