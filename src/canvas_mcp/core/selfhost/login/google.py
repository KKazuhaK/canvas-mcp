"""Google sign-in: an OpenID Connect provider with Google's own rules.

Facts this relies on (Google's OpenID Connect documentation):

* discovery is at ``https://accounts.google.com/.well-known/openid-configuration`` and its
  ``issuer`` is ``https://accounts.google.com``; ID tokens carry that issuer *or* the legacy
  ``accounts.google.com``, and both are accepted; the identity is always stored under the
  https spelling;
* the authorization response carries ``iss`` ("always returned"), which is checked (RFC 9207);
* ``sub`` never changes and is never reused; the e-mail address can change and is not a key;
* ``hd`` (the Google Workspace or Cloud domain) is in the ID token only for members of such an
  organisation. The ``hd`` *request* parameter is a user-interface hint and is never trusted;
  the rule ``google:domain:<hd>`` reads the ID token's claim and also needs ``email_verified``;
* ``prompt=select_account`` makes Google ask which account to use.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import Any

from ..accounts import GOOGLE_ISSUER, PROVIDER_GOOGLE, ExternalClaims
from ..routes import auth_callback, auth_login
from .config import GoogleConfig
from .http import SafeHttp
from .oidc import OidcLoginProvider, OidcProfile, clean_text
from .protocol import ProviderDisplay

GOOGLE_START_PATH = auth_login(PROVIDER_GOOGLE)
GOOGLE_CALLBACK_PATH = auth_callback(PROVIDER_GOOGLE)
GOOGLE_SCOPES = ("openid", "email", "profile")
_GOOGLE_ISSUERS = frozenset({GOOGLE_ISSUER, "accounts.google.com"})


def _reduce(ext: ExternalClaims, claims: Mapping[str, Any]) -> ExternalClaims:
    """Add ``hd`` (lower case) and show the address as the sign-in name."""
    hd = claims.get("hd")
    return replace(
        ext,
        hd=clean_text(hd, 253).lower() if isinstance(hd, str) else "",
        username=ext.email or ext.username,
    )


def build_google_provider(
    config: GoogleConfig,
    *,
    public_base_url: str,
    http: SafeHttp,
    domain_hint: str | None = None,
    clock: Callable[[], float] = time.time,
) -> OidcLoginProvider:
    """The Google provider. ``domain_hint`` is sent as ``hd`` (a hint only) when exactly one
    ``google:domain`` rule exists."""
    return OidcLoginProvider(
        provider_id=PROVIDER_GOOGLE,
        display=ProviderDisplay("Google", "google"),
        start_path=GOOGLE_START_PATH,
        callback_path=GOOGLE_CALLBACK_PATH,
        public_base_url=public_base_url,
        issuer=GOOGLE_ISSUER,
        client_id=config.client_id,
        client_secret=config.client_secret,
        scopes=GOOGLE_SCOPES,
        http=http,
        profile=OidcProfile(
            accepted_issuers=_GOOGLE_ISSUERS,
            stored_issuer=GOOGLE_ISSUER,
            response_issuer=GOOGLE_ISSUER,
            iss_required=True,
            always_prompt="select_account",
            extra_params={"hd": domain_hint} if domain_hint else {},
            reduce=_reduce,
        ),
        userinfo=False,
        clock=clock,
    )
