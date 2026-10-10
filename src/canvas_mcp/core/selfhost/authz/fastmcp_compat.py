"""The only module that imports FastMCP and MCP SDK internals.

The authorization server is built on the public ``OAuthProvider`` base of FastMCP and the
SDK's provider protocol (``mcp.server.auth.provider``), but a few things it needs are
not exported: the endpoint handlers, the SSRF-pinned fetcher, the CIMD document model, the
redirect helper. They are imported here and nowhere else (``test_authz_compat_contract.py``
checks the rest of the package by parsing its imports), and exposed as small functions, so
a change in a FastMCP or SDK release is a change in this file.

``tests/selfhost/authz/test_authz_compat_contract.py`` pins each thing relied on, and runs
against the locked versions (what CI installs) as well as the newest ones. The module
docstring of that test lists the facts; the comments below say which one each wrapper uses.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from fastmcp.server.auth.auth import TokenHandler
from fastmcp.server.auth.cimd import CIMDDocument
from fastmcp.server.auth.handlers.authorize import AuthorizationHandler
from fastmcp.server.auth.redirect_validation import (
    build_client_redirect,
    is_redirect_uri_allowed_for_application_type,
)
from fastmcp.server.auth.ssrf import SSRFError, SSRFFetchError, ssrf_safe_fetch_response
from mcp.server.auth.middleware.client_auth import ClientAuthenticator
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import Response

Endpoint = Callable[[Request], Awaitable[Response]]

#: A client metadata document is a few hundred bytes; anything bigger is refused.
MAX_DOCUMENT_BYTES = 5120

# Codes that say why a client metadata document could not be used (a closed set).
FETCH_SSRF_BLOCKED = "ssrf_blocked"
FETCH_TIMEOUT = "timeout"
FETCH_HTTP_STATUS = "http_status"
FETCH_FAILED = "fetch_failed"
DOC_INVALID = "invalid_document"
DOC_CLIENT_ID_MISMATCH = "client_id_mismatch"
DOC_UNSUPPORTED_AUTH_METHOD = "unsupported_auth_method"


# -- endpoints -----------------------------------------------------------------------


def authorization_endpoint(provider: Any, *, base_url: str, issuer_url: str) -> Endpoint:
    """FastMCP's ``/authorize`` handler: the SDK's, plus ``iss`` on every error redirect.

    Pinned: it answers an unknown client with 400 and no ``Location``, and a provider
    that raises ``AuthorizeError`` gets a 302 with ``error``, ``state`` and exactly one
    ``iss`` equal to ``issuer_url`` byte for byte.
    """
    handler = AuthorizationHandler(provider=provider, base_url=base_url, issuer_url=issuer_url)
    return handler.handle


def token_endpoint(provider: Any) -> Endpoint:
    """FastMCP's ``/token`` handler (the SDK's, with ``invalid_grant`` as HTTP 401).

    Pinned: it authenticates a public client (method ``none``) without a secret, maps
    ``invalid_grant`` to 401 and an unknown client to 401 ``invalid_client``, and does
    **not** look at the ``resource`` form field (our wrapper does).
    """
    handler = TokenHandler(provider=provider, client_authenticator=ClientAuthenticator(provider))
    return handler.handle


def resource_url_of(provider: Any, mcp_path: str) -> str:
    """The resource URL FastMCP derives for ``mcp_path`` (what it advertises as ``resource``)."""
    url = provider._get_resource_url(mcp_path)
    return "" if url is None else str(url)


def client_redirect(url: str, params: Mapping[str, str], *, iss: str) -> str:
    """``url`` with ``params`` appended and exactly one ``iss`` (RFC 9207).

    Pinned: an ``iss`` already in the registered redirect URI is replaced, not
    duplicated, and the rest of its query is kept byte for byte.
    """
    return build_client_redirect(url, dict(params), iss=iss)


def redirect_allowed_for_application_type(uri: str, application_type: str | None) -> bool:
    """RFC 7591 ``application_type`` rules: ``web`` needs https off loopback; ``native`` may use loopback http."""
    return is_redirect_uri_allowed_for_application_type(uri, application_type)


# -- client metadata documents -------------------------------------------------------


class MetadataFetchError(Exception):
    """A client metadata document could not be fetched; ``code`` says why (closed set)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class FetchedDocument:
    status: int
    headers: Mapping[str, str]
    content: bytes


async def fetch_client_metadata(url: str, timeout_s: float) -> FetchedDocument:
    """GET ``url`` through FastMCP's SSRF-pinned fetcher.

    https only, a non-root path, DNS resolved and checked before any connection (private,
    loopback and link-local addresses are refused) and the connection pinned to the
    checked address, no redirects, at most 5 KB, ``timeout_s`` for the whole fetch. The
    name resolution inside has no timeout of its own: the caller bounds the whole call.
    """
    try:
        response = await ssrf_safe_fetch_response(
            url,
            require_path=True,
            max_size=MAX_DOCUMENT_BYTES,
            timeout=timeout_s,
            overall_timeout=timeout_s,
            request_headers={"Accept": "application/json"},
            allowed_status_codes={200},
        )
    except SSRFError:
        raise MetadataFetchError(FETCH_SSRF_BLOCKED) from None
    except SSRFFetchError as exc:
        text = str(exc)
        if text.startswith("HTTP "):
            raise MetadataFetchError(FETCH_HTTP_STATUS) from None
        if "imeout" in text:
            raise MetadataFetchError(FETCH_TIMEOUT) from None
        if text.startswith("Response too large"):
            raise MetadataFetchError(DOC_INVALID) from None
        raise MetadataFetchError(FETCH_FAILED) from None
    return FetchedDocument(
        status=response.status_code,
        headers={str(k).lower(): str(v) for k, v in response.headers.items()},
        content=response.content,
    )


class DocumentRejected(Exception):
    """A fetched client metadata document is not acceptable; ``code`` says why."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ClientDocument:
    """What the authorization server reads from a client metadata document."""

    client_id: str
    client_name: str | None
    redirect_uris: tuple[str, ...]
    grant_types: tuple[str, ...]
    response_types: tuple[str, ...]
    scope: str | None


def validate_client_document(raw: Mapping[str, Any], url: str) -> ClientDocument:
    """Structural validation of a client metadata document fetched from ``url``.

    The ``client_id`` in the document must equal the URL exactly (not after trimming a
    slash). Only the public method ``none`` is supported: shared-secret methods are
    refused by the model, ``private_key_jwt`` by this server.
    """
    if raw.get("client_id") != url:
        raise DocumentRejected(DOC_CLIENT_ID_MISMATCH)
    method = raw.get("token_endpoint_auth_method", "none")
    if method != "none":
        raise DocumentRejected(DOC_UNSUPPORTED_AUTH_METHOD)
    try:
        doc = CIMDDocument.model_validate(dict(raw))
    except ValidationError:
        raise DocumentRejected(DOC_INVALID) from None
    return ClientDocument(
        client_id=url,
        client_name=doc.client_name,
        redirect_uris=tuple(doc.redirect_uris),
        grant_types=tuple(doc.grant_types),
        response_types=tuple(doc.response_types),
        scope=doc.scope,
    )
