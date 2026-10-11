"""Entra, as the sign-in page lists it.

Entra keeps its own ceremony in ``account_web`` (``/account/login`` and ``/account/callback``,
the sealed login cookie, the redirect URI registered in the Entra app). This module only
describes it, so the registry can show it next to the other providers.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..accounts import PROVIDER_ENTRA
from .protocol import ProviderDisplay

ENTRA_START_PATH = "/account/login"
ENTRA_ALIAS_START_PATH = "/account/login/entra"
ENTRA_CALLBACK_PATH = "/account/callback"


@dataclass(frozen=True)
class EntraDescriptor:
    """The Entra entry of the provider list."""

    #: ``/account/login`` when Entra is the only provider, ``/account/login/entra`` otherwise.
    start_path: str = ENTRA_START_PATH
    id: str = PROVIDER_ENTRA
    kind: str = "oidc"
    display: ProviderDisplay = ProviderDisplay("Microsoft", "microsoft")
    callback_path: str = ENTRA_CALLBACK_PATH
