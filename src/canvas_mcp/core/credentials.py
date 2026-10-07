"""Per-request credential context for HTTP transport.

When the server runs in HTTP mode, each request carries its own Canvas API
token via the X-Canvas-Token header. The Canvas API URL is pinned by server
configuration (CANVAS_API_URL), never supplied by the client. This module
uses Python's contextvars to thread the per-request token through the async
call stack without modifying any tool signatures.

In stdio mode, the ContextVar remains unset (None), and the client falls
back to the global .env-based configuration. To keep that fallback from
leaking the server's own token in HTTP mode, an additional ``_http_request_active``
marker distinguishes "HTTP request with no token" (must fail closed) from
"stdio mode" (env fallback is intended).
"""

import hashlib
import hmac
import secrets
from contextvars import ContextVar, Token
from dataclasses import dataclass


@dataclass(frozen=True)
class RequestCredentials:
    """Canvas API credentials for a single HTTP request."""

    api_token: str
    api_url: str


@dataclass(frozen=True)
class RequestPrincipal:
    """The verified identity behind one request (self-hosted Entra mode)."""

    key: str
    tenant_id: str
    object_id: str
    display_name: str
    upn: str
    roles: frozenset[str]
    is_owner: bool


# Random per-process key: derives opaque cache keys from Canvas tokens in the
# legacy HTTP mode without ever keeping or logging the token itself.
_PROCESS_KEY = secrets.token_bytes(32)

LEGACY_MISSING_CREDENTIALS_MESSAGE = "Canvas token required for HTTP request"

_request_credentials: ContextVar[RequestCredentials | None] = ContextVar(
    "request_credentials", default=None
)

_http_request_active: ContextVar[bool] = ContextVar(
    "http_request_active", default=False
)

_request_principal: ContextVar[RequestPrincipal | None] = ContextVar(
    "request_principal", default=None
)

_missing_credentials_message: ContextVar[str | None] = ContextVar(
    "missing_credentials_message", default=None
)


def get_request_credentials() -> RequestCredentials | None:
    """Get the current request's Canvas credentials, or None for stdio mode."""
    return _request_credentials.get()


def set_request_credentials(creds: RequestCredentials) -> None:
    """Set Canvas credentials for the current async context."""
    _request_credentials.set(creds)


def clear_request_credentials() -> None:
    """Clear credentials after request completes."""
    _request_credentials.set(None)


def is_http_request_active() -> bool:
    """Return True while handling an HTTP request.

    Used to fail closed: in HTTP mode a missing per-request token must never
    fall back to the server's own credentials.
    """
    return _http_request_active.get()


def set_http_request_active(active: bool = True) -> None:
    """Mark whether the current async context is handling an HTTP request."""
    _http_request_active.set(active)


def get_request_principal() -> RequestPrincipal | None:
    """Return the verified identity of the current request, if any."""
    return _request_principal.get()


def set_request_principal(principal: RequestPrincipal | None) -> Token[RequestPrincipal | None]:
    """Set the verified identity for the current async context."""
    return _request_principal.set(principal)


def set_missing_credentials_message(message: str | None) -> Token[str | None]:
    """Set the text returned when an HTTP request has no Canvas token."""
    return _missing_credentials_message.set(message)


def missing_credentials_message() -> str:
    """Text for the fail-closed "no Canvas token on this request" error."""
    return _missing_credentials_message.get() or LEGACY_MISSING_CREDENTIALS_MESSAGE


def current_principal_key() -> str:
    """An opaque key for whoever is making the current request.

    The verified principal key when there is one; otherwise, for a legacy HTTP
    request, a keyed hash of the caller's Canvas token (stable within this
    process, never containing the token); otherwise ``"local"`` (stdio).
    Every process-global cache that holds user-derived data is keyed by this.
    """
    principal = _request_principal.get()
    if principal is not None:
        return principal.key
    creds = _request_credentials.get()
    if creds is not None:
        digest = hmac.new(_PROCESS_KEY, creds.api_token.encode(), hashlib.sha256)
        return "token:" + digest.hexdigest()[:32]
    return "local"


def clear_http_request_context() -> None:
    """Clear all per-request HTTP context after the request completes."""
    _request_credentials.set(None)
    _http_request_active.set(False)
    _request_principal.set(None)
    _missing_credentials_message.set(None)
