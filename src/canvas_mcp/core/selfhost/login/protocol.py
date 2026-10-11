"""What a sign-in provider is, as far as the ceremony is concerned.

The protocol layer returns neutral :class:`~..accounts.ExternalClaims` and nothing else: no
account, no role, no admission. Who may use the server is decided afterwards by
:class:`~..identity.IdentityService` from those claims and the configured rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from ..accounts import ExternalClaims
from .metadata import ProviderUnavailable

IconName = Literal["microsoft", "google", "github", "key"]

#: What a refused ceremony step is called (a closed set; never provider text).
REJECT_CODES = ("provider_error", "sign_in_unverified", "sign_in_incomplete")


@dataclass(frozen=True)
class ProviderDisplay:
    """How the sign-in page shows a provider: a name and a built-in icon (never a remote image)."""

    name: str
    icon: IconName


class SignInRejected(Exception):
    """The provider's answer cannot be used. ``code`` is one of :data:`REJECT_CODES`."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code if code in REJECT_CODES else "provider_error"


class LoginProvider(Protocol):
    """A provider the server can send a browser to and take a verified identity back from."""

    id: str
    #: ``oidc`` for OpenID Connect, ``oauth2`` for plain OAuth 2.0 (GitHub).
    kind: str
    display: ProviderDisplay
    start_path: str
    callback_path: str
    #: The exact redirect URI registered at the provider: ``PUBLIC_BASE_URL`` plus ``callback_path``.
    redirect_uri: str
    #: The ``iss`` the authorization response must carry (RFC 9207), if the provider has one.
    response_issuer: str | None

    async def prepare(self) -> None:
        """Make the provider's metadata available; :class:`ProviderUnavailable` if it cannot be."""

    def requires_iss(self) -> bool:
        """Whether an authorization response without ``iss`` must be refused (mix-up defence)."""

    def authorize_url(
        self, *, state: str, nonce: str, code_challenge: str, reauth: bool
    ) -> str:
        """The URL to send the browser to. ``reauth`` forces the provider to ask the person again."""

    async def finish(self, *, code: str, code_verifier: str, nonce: str) -> ExternalClaims:
        """Exchange the code and return the verified identity, or raise :class:`SignInRejected`."""


__all__ = [
    "REJECT_CODES",
    "IconName",
    "LoginProvider",
    "ProviderDisplay",
    "ProviderUnavailable",
    "SignInRejected",
]
