"""Microsoft Entra ID on the common, cookie-bound OpenID Connect flow."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any

from ..accounts import (
    PROVIDER_ENTRA,
    Denied,
    EntraClaimsPolicy,
    ExternalClaims,
    entra_external_claims,
    entra_issuer,
)
from ..routes import auth_callback, auth_login
from .http import SafeHttp
from .oidc import OidcLoginProvider, OidcProfile
from .protocol import ProviderDisplay, SignInRejected

ENTRA_START_PATH = auth_login(PROVIDER_ENTRA)
ENTRA_CALLBACK_PATH = auth_callback(PROVIDER_ENTRA)


def build_entra_provider(
    *,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    public_base_url: str,
    http: SafeHttp,
    parse_groups: bool,
    clock: Callable[[], float] = time.time,
) -> OidcLoginProvider:
    """Use ID-token claims only; no custom Entra API scope or refresh token is requested."""
    issuer = entra_issuer(tenant_id)
    policy = EntraClaimsPolicy(tenant_id, client_id)

    def reduce(_ext: ExternalClaims, claims: Mapping[str, Any]) -> ExternalClaims:
        ext = entra_external_claims(claims, policy, parse_groups=parse_groups)
        if isinstance(ext, Denied):
            raise SignInRejected(ext.code)
        return ext

    return OidcLoginProvider(
        provider_id=PROVIDER_ENTRA,
        display=ProviderDisplay("Microsoft", "microsoft"),
        start_path=ENTRA_START_PATH,
        callback_path=ENTRA_CALLBACK_PATH,
        public_base_url=public_base_url,
        issuer=issuer,
        client_id=client_id,
        client_secret=client_secret,
        scopes=("openid", "profile", "email"),
        http=http,
        profile=OidcProfile(
            accepted_issuers=frozenset({issuer}),
            stored_issuer=issuer,
            response_issuer=issuer,
            always_prompt="select_account",
            extra_params={"response_mode": "query"},
            reduce=reduce,
        ),
        token_auth_method="client_secret_post",
        userinfo=False,
        clock=clock,
    )
