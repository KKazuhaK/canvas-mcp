"""Public v1 paths, shared without loading the HTTP or database dependencies."""

from __future__ import annotations

import re
from urllib.parse import urlencode

AUTH_LOGIN = "/auth/login"
API_PREFIX = "/api/v1"
ACCOUNT_PREFIX = "/account"
SIGN_IN_PAGE = ACCOUNT_PREFIX + "/sign-in"
_OIDC_SLUG = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")


def provider_route_key(provider: str) -> str:
    """Translate a stored provider id into its distinct browser route key."""
    if provider in ("entra", "google", "github"):
        return provider
    if provider.startswith("oidc:") and _OIDC_SLUG.fullmatch(provider[5:]):
        return "oidc/" + provider[5:]
    raise ValueError("invalid provider id")


def route_provider(key: str) -> str | None:
    if key in ("entra", "google", "github"):
        return key
    if key.startswith("oidc/") and _OIDC_SLUG.fullmatch(key[5:]):
        return "oidc:" + key[5:]
    return None


def auth_login(provider: str) -> str:
    return AUTH_LOGIN + "/" + provider_route_key(provider)


def auth_callback(provider: str) -> str:
    return "/auth/callback/" + provider_route_key(provider)


def redirect_uri(base: str, provider: str) -> str:
    return base.rstrip("/") + auth_callback(provider)


def consent_page(txn: str) -> str:
    return ACCOUNT_PREFIX + "/consent?" + urlencode({"txn": txn})
