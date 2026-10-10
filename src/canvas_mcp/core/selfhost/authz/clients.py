"""OAuth clients: dynamically registered ones and Client ID Metadata Documents (CIMD).

Every client is a **public** client (token endpoint method ``none``). A client id is
either a uuid minted by ``POST /register`` (a *registered* client, kept in
``oauth_clients``) or the https URL of a metadata document the client hosts (CIMD, what
claude.ai and Claude Code use; the last good copy is kept in ``cimd_clients``).

**Redirect URIs** are the thing that decides where an authorization code is delivered, so
they are checked twice: against what the client declared (its registration or its document)
**and** against the operator's allowlist ``OAUTH_ALLOWED_REDIRECT_URIS``. Both go through
:func:`~.urls.redirect_matches` (exact, except loopback ports). The allowlist is applied at
registration, to every redirect URI in a fetched document and again on every load, so
narrowing it takes effect for clients that registered earlier.

**CIMD fetching** is the one place this server makes an outbound request on behalf of an
unauthenticated caller, so it is bounded: the SSRF-pinned fetcher (https only, resolved
addresses checked and pinned, 5 KB, no redirects), a ``CIMD_FETCH_TIMEOUT_S`` budget around
the whole call (name resolution included), one fetch at a time per URL however many
requests wait for it, and a per-host and an overall budget per minute. A fresh document is
required to *start* an authorization; to *refresh a token* the last good copy may be used
if the document cannot be fetched, for up to ``CIMD_STALE_MAX`` (so a slow or blocking CDN
does not disconnect everyone).
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Awaitable, Callable, Collection
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

import anyio
import anyio.to_thread
from mcp.server.auth.provider import RegistrationError
from mcp.shared.auth import InvalidRedirectUriError, OAuthClientInformationFull
from pydantic import AnyHttpUrl, AnyUrl, PrivateAttr, ValidationError

from ...logging import log_info, log_warning
from ..db.errors import StoreUnavailable
from ..limits import InMemorySlidingWindowLimiter
from ..settings import AuthzSettings
from . import fastmcp_compat as compat
from .models import CLIENT_KIND_CIMD, CLIENT_KIND_DCR, CimdSnapshot
from .store import AuthzStore
from .urls import host_of, is_loopback_host, redirect_matches, redirect_uri_syntax_ok

#: What a lookup is for. ``authorize`` (the default, the strict one) needs a fresh CIMD
#: document; ``token`` (``/token`` and ``/revoke``) may use the last good copy.
PURPOSE_AUTHORIZE = "authorize"
PURPOSE_TOKEN = "token"
LOOKUP_PURPOSE: ContextVar[str] = ContextVar("canvas_mcp_authz_lookup_purpose", default=PURPOSE_AUTHORIZE)
#: Set to a list by the endpoint wrappers; ``get_client`` appends when the database was
#: unreachable, so an outage is answered 503 instead of "unknown client".
LOOKUP_OUTAGE: ContextVar[list[bool] | None] = ContextVar("canvas_mcp_authz_lookup_outage", default=None)

#: A registration lives this long (it is extended to the end of its last grant).
DCR_TTL_SECONDS = 30 * 86400
MAX_REDIRECT_URIS = 10
MAX_CLIENT_NAME_CHARS = 200
MAX_REGISTRATION_JSON_BYTES = 8192
_ALLOWED_GRANTS = frozenset({"authorization_code", "refresh_token"})
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_BIDI_AND_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]")

# CIMD freshness and budgets.
CIMD_MIN_FRESH = 60
CIMD_MAX_FRESH = 3600
CIMD_DEFAULT_FRESH = 3600
CIMD_FAILURE_BACKOFF_SECONDS = 60
CIMD_HOST_FETCHES_PER_MINUTE = 10
CIMD_TOTAL_FETCHES_PER_MINUTE = 60
CIMD_FETCH_GRACE_SECONDS = 0.5
MAX_CIMD_URL_CHARS = 512

# Closed codes for a document that could not be used (see also ``fastmcp_compat``).
CIMD_BUDGET = "budget"
CIMD_REDIRECTS_NOT_ALLOWED = "cimd_redirects_not_allowed"


def clean_label(value: str | None, limit: int = 100) -> str:
    """Display text for an app name: no control, zero-width or bidi-override characters, collapsed
    whitespace, at most ``limit`` characters. The result is still untrusted text to escape."""
    if not value:
        return ""
    text = _BIDI_AND_CONTROL.sub(" ", value)
    return " ".join(text.split())[:limit]


class PublicClient(OAuthClientInformationFull):
    """A registered or CIMD client, with redirect matching that follows the operator's allowlist."""

    _kind: str = PrivateAttr(default=CLIENT_KIND_DCR)
    _allowlist: tuple[str, ...] = PrivateAttr(default=())
    _client_host: str | None = PrivateAttr(default=None)

    @classmethod
    def build(
        cls,
        data: dict[str, Any],
        *,
        kind: str,
        allowlist: tuple[str, ...],
        client_host: str | None = None,
    ) -> PublicClient:
        client = cls.model_validate(data)
        client._kind = kind
        client._allowlist = allowlist
        client._client_host = client_host
        return client

    @property
    def kind(self) -> str:
        return self._kind

    @property
    def client_host(self) -> str | None:
        return self._client_host

    @property
    def display_name(self) -> str:
        """The name to show a person: the verified host of a CIMD client, else the cleaned self-asserted name."""
        if self._kind == CLIENT_KIND_CIMD and self._client_host:
            return self._client_host
        return clean_label(self.client_name)

    def _allowed(self, candidate: str) -> bool:
        return any(redirect_matches(candidate, entry) for entry in self._allowlist)

    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        registered = [str(u) for u in self.redirect_uris or []]
        if redirect_uri is None:
            # Only an unambiguous, non-loopback https URI that the operator allows.
            usable = [
                u
                for u in registered
                if redirect_uri_syntax_ok(u) and not is_loopback_host(host_of(u)) and self._allowed(u)
            ]
            if len(registered) == 1 and len(usable) == 1:
                return AnyUrl(usable[0])
            raise InvalidRedirectUriError(
                "redirect_uri must be specified unless the client has exactly one registered URI"
            )
        candidate = str(redirect_uri)
        if (
            not redirect_uri_syntax_ok(candidate)
            or not any(redirect_matches(candidate, r) for r in registered)
            or not self._allowed(candidate)
        ):
            raise InvalidRedirectUriError("Redirect URI is not registered for this client")
        return redirect_uri


# -- registration ----------------------------------------------------------------------


def validate_dcr_metadata(
    info: OAuthClientInformationFull, allowlist: Collection[str], server_scopes: Collection[str]
) -> RegistrationError | None:
    """Why this registration must be refused, or None. Fixed descriptions, never the input."""

    def bad(error: str, description: str) -> RegistrationError:
        return RegistrationError(error=error, error_description=description)  # type: ignore[arg-type]

    uris = [str(u) for u in info.redirect_uris or []]
    if not uris or len(uris) > MAX_REDIRECT_URIS:
        return bad("invalid_redirect_uri", "Between 1 and 10 redirect URIs are required.")
    for uri in uris:
        if (
            not redirect_uri_syntax_ok(uri)
            or not any(redirect_matches(uri, entry) for entry in allowlist)
            or not compat.redirect_allowed_for_application_type(uri, info.application_type)
        ):
            return bad("invalid_redirect_uri", "A redirect URI is not allowed on this server.")
    grants = set(info.grant_types or [])
    if "authorization_code" not in grants or not grants <= _ALLOWED_GRANTS:
        return bad(
            "invalid_client_metadata",
            "grant_types must be authorization_code, optionally with refresh_token.",
        )
    responses = set(info.response_types or [])
    if "code" not in responses or not responses <= {"code"}:
        return bad("invalid_client_metadata", "response_types must be code.")
    if info.application_type not in (None, "web", "native"):
        return bad("invalid_client_metadata", "application_type must be web or native.")
    if info.client_name is not None and len(info.client_name) > MAX_CLIENT_NAME_CHARS:
        return bad("invalid_client_metadata", "client_name is too long.")
    scopes = set((info.scope or "").split())
    if scopes and not scopes <= set(server_scopes):
        return bad("invalid_client_metadata", "The requested scope is not available.")
    return None


def make_public(info: OAuthClientInformationFull, default_scope: str) -> None:
    """Turn a validated registration into a public client, in place.

    The registration handler echoes this very object in its 201 response, so changing it
    here is what the client is told: no secret, method ``none``, nothing we do not keep.
    """
    info.token_endpoint_auth_method = "none"
    info.client_secret = None
    info.client_secret_expires_at = None
    info.scope = info.scope or default_scope
    for name in ("jwks", "jwks_uri", "contacts", "software_id", "software_version",
                 "client_uri", "logo_uri", "tos_uri", "policy_uri"):
        setattr(info, name, None)


# -- CIMD ------------------------------------------------------------------------------


@dataclass(frozen=True)
class CimdClientData:
    """A client metadata document reduced to what this server uses (and stores)."""

    url: str
    client_name: str | None
    redirect_uris: tuple[str, ...]
    grant_types: tuple[str, ...]
    scope: str
    fetched_at: int
    fresh_until: int

    def to_json(self) -> str:
        return json.dumps(
            {
                "client_id": self.url,
                "client_name": self.client_name,
                "redirect_uris": list(self.redirect_uris),
                "grant_types": list(self.grant_types),
                "scope": self.scope,
            },
            separators=(",", ":"),
        )


def cimd_url_ok(url: str) -> bool:
    """A client id that can be a CIMD URL: canonical https with a path, no query, fragment or user info."""
    if not isinstance(url, str) or not url.startswith("https://") or len(url) > MAX_CIMD_URL_CHARS:
        return False
    if any(ch in url for ch in ("?", "#", "@", " ", "\\", "*")) or not url.isascii():
        return False
    try:
        parsed = AnyHttpUrl(url)
    except ValidationError:
        return False
    if str(parsed) != url or parsed.path in (None, "", "/"):
        return False
    return not any(seg in (".", "..") for seg in (parsed.path or "").split("/"))


def _freshness(headers: dict[str, str] | Any) -> tuple[int, bool]:
    """Seconds a fetched document stays fresh (clamped), and whether it said ``no-store``."""
    control = str(headers.get("cache-control", "")).lower()
    if "no-store" in control:
        return 0, True
    match = re.search(r"max-age\s*=\s*(\d{1,9})", control)
    if match:
        seconds = int(match.group(1))
    else:
        seconds = CIMD_DEFAULT_FRESH
    return max(CIMD_MIN_FRESH, min(CIMD_MAX_FRESH, seconds)), False


Fetcher = Callable[[str, float], Awaitable[compat.FetchedDocument]]


#: A fetch that ended this many seconds before a request was recorded still counts as made for it.
CONSENT_FETCH_SLACK_S = 10


class CimdResolver:
    """Resolve a client id URL to its (validated) metadata document. Never raises."""

    def __init__(
        self,
        store: AuthzStore,
        settings: AuthzSettings,
        allowlist: tuple[str, ...],
        server_scopes: tuple[str, ...],
        *,
        fetch: Fetcher = compat.fetch_client_metadata,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = store
        self._settings = settings
        self._allowlist = allowlist
        self._scopes = server_scopes
        self._fetch = fetch
        self._clock = clock
        self._monotonic = monotonic
        self._inflight: dict[str, asyncio.Future[tuple[CimdClientData | None, str | None]]] = {}
        self._failed_until: dict[str, float] = {}
        per_host = InMemorySlidingWindowLimiter(CIMD_HOST_FETCHES_PER_MINUTE, 60, 1024, monotonic)
        overall = InMemorySlidingWindowLimiter(CIMD_TOTAL_FETCHES_PER_MINUTE, 60, 4, monotonic)
        self._per_host, self._overall = per_host, overall

    # -- reading ------------------------------------------------------------------------

    def _from_snapshot(self, snapshot: CimdSnapshot) -> CimdClientData | None:
        """The stored document, checked against the *current* allowlist and scopes."""
        try:
            data = json.loads(snapshot.doc_json)
            uris = [u for u in data["redirect_uris"] if self._redirect_allowed(u)]
            scope = " ".join(s for s in str(data["scope"]).split() if s in self._scopes)
            grants = tuple(g for g in data["grant_types"] if g in _ALLOWED_GRANTS)
            if not uris or not scope or "authorization_code" not in grants:
                return None
            name = data.get("client_name")
            return CimdClientData(
                url=snapshot.url,
                client_name=name if isinstance(name, str) else None,
                redirect_uris=tuple(uris),
                grant_types=grants,
                scope=scope,
                fetched_at=snapshot.fetched_at,
                fresh_until=snapshot.fresh_until,
            )
        except (ValueError, KeyError, TypeError):
            return None

    def _redirect_allowed(self, uri: object) -> bool:
        return (
            isinstance(uri, str)
            and redirect_uri_syntax_ok(uri)
            and any(redirect_matches(uri, entry) for entry in self._allowlist)
        )

    async def snapshot_only(self, url: str, not_before: int = 0) -> CimdClientData | None:
        """The stored document, without any fetch, if ``/authorize`` can have relied on it (consent).

        ``not_before`` is when the request began. The copy is good if it was fetched since, or if
        it was still fresh at that moment (then ``/authorize`` used it without fetching: the
        document is shared by every user of the app, so most requests find a copy that an earlier
        request fetched). A copy that was already stale then, and was not refreshed since, is not
        something ``/authorize`` could have verified. ``CONSENT_FETCH_SLACK_S`` covers a fetch that
        finished just before the request was written down.
        """
        if not self._settings.cimd_enabled or not cimd_url_ok(url):
            return None
        snapshot = await anyio.to_thread.run_sync(self._store.cimd_snapshot, url)
        if snapshot is None:
            return None
        if snapshot.fetched_at < not_before - CONSENT_FETCH_SLACK_S and snapshot.fresh_until <= not_before:
            return None
        return self._from_snapshot(snapshot)

    async def get(self, url: str, purpose: str = PURPOSE_AUTHORIZE) -> CimdClientData | None:
        if not self._settings.cimd_enabled or not cimd_url_ok(url):
            return None
        now = int(self._clock())
        snapshot = await anyio.to_thread.run_sync(self._store.cimd_snapshot, url)
        stored = None if snapshot is None else self._from_snapshot(snapshot)
        if snapshot is not None and stored is not None and now < snapshot.fresh_until:
            return stored
        usable_stale = (
            purpose == PURPOSE_TOKEN
            and snapshot is not None
            and stored is not None
            and now - snapshot.fetched_at <= self._settings.cimd_stale_max
        )
        if usable_stale and self._monotonic() < self._failed_until.get(url, 0.0):
            return stored  # a fetch failed a moment ago: do not put another on the hot path
        data, error = await self._refresh(url)
        if data is not None:
            return data
        if usable_stale:
            log_warning("cimd_stale_served", reason=error or compat.FETCH_FAILED)
            return stored
        return None

    # -- fetching ------------------------------------------------------------------------

    async def _refresh(self, url: str) -> tuple[CimdClientData | None, str | None]:
        """One fetch at a time per URL; everybody waiting gets its result."""
        future = self._inflight.get(url)
        if future is None:
            future = asyncio.ensure_future(self._fetch_and_store(url))
            self._inflight[url] = future

            def forget(_done: object, key: str = url) -> None:
                self._inflight.pop(key, None)

            future.add_done_callback(forget)
        return await asyncio.shield(future)

    async def _fetch_and_store(self, url: str) -> tuple[CimdClientData | None, str | None]:
        host = host_of(url)
        if not self._per_host.allow(("host", host)) or not self._overall.allow(("all",)):
            return await self._failed(url, CIMD_BUDGET)
        timeout = float(self._settings.cimd_fetch_timeout_s)
        try:
            with anyio.fail_after(timeout + CIMD_FETCH_GRACE_SECONDS):
                fetched = await self._fetch(url, timeout)
        except TimeoutError:
            return await self._failed(url, compat.FETCH_TIMEOUT)
        except compat.MetadataFetchError as exc:
            return await self._failed(url, exc.code)
        except Exception:  # noqa: BLE001 - nothing from a fetch may escape as an exception
            return await self._failed(url, compat.FETCH_FAILED)
        try:
            data = self._accept(url, fetched)
        except compat.DocumentRejected as exc:
            return await self._failed(url, exc.code)
        stored = await anyio.to_thread.run_sync(
            lambda: self._store.upsert_cimd(
                url, data.to_json(), fetched_at=data.fetched_at, fresh_until=data.fresh_until
            )
        )
        self._failed_until.pop(url, None)
        log_info("cimd_fetch", result="ok", stored=stored)
        return data, None

    async def _failed(self, url: str, code: str) -> tuple[None, str]:
        self._failed_until[url] = self._monotonic() + CIMD_FAILURE_BACKOFF_SECONDS
        if len(self._failed_until) > 4096:
            self._failed_until.clear()
        log_warning("cimd_fetch", reason=code)
        await anyio.to_thread.run_sync(self._store.record_cimd_error, url, code)
        return None, code

    def _accept(self, url: str, fetched: compat.FetchedDocument) -> CimdClientData:
        """Validate a fetched document against everything this server requires."""
        if len(fetched.content) > compat.MAX_DOCUMENT_BYTES:
            raise compat.DocumentRejected(compat.DOC_INVALID)
        try:
            raw = json.loads(fetched.content.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise compat.DocumentRejected(compat.DOC_INVALID) from None
        if not isinstance(raw, dict):
            raise compat.DocumentRejected(compat.DOC_INVALID)
        doc = compat.validate_client_document(raw, url)
        grants = tuple(g for g in doc.grant_types if g in _ALLOWED_GRANTS)
        if "authorization_code" not in grants or "code" not in doc.response_types:
            raise compat.DocumentRejected(compat.DOC_INVALID)
        if doc.scope is None:
            scope = " ".join(self._scopes)
        else:
            scope = " ".join(s for s in doc.scope.split() if s in self._scopes)
        if not scope:
            raise compat.DocumentRejected(compat.DOC_INVALID)
        uris = tuple(u for u in doc.redirect_uris if self._redirect_allowed(u))
        if not uris:
            raise compat.DocumentRejected(CIMD_REDIRECTS_NOT_ALLOWED)
        seconds, no_store = _freshness(fetched.headers)
        now = int(self._clock())
        return CimdClientData(
            url=url,
            client_name=clean_label(doc.client_name, MAX_CLIENT_NAME_CHARS) or None,
            redirect_uris=uris,
            grant_types=grants,
            scope=scope,
            fetched_at=now,
            # A document that said no-store is never served as fresh: every authorization
            # fetches it again. The copy kept is only the last known good one.
            fresh_until=now if no_store else now + seconds,
        )


# -- the directory ----------------------------------------------------------------------


class ClientDirectory:
    """``client id -> PublicClient``: registered clients from the database, CIMD ones through the resolver."""

    def __init__(
        self,
        store: AuthzStore,
        cimd: CimdResolver,
        allowlist: tuple[str, ...],
        server_scopes: tuple[str, ...],
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._cimd = cimd
        self._allowlist = allowlist
        self._scopes = server_scopes
        self._clock = clock

    async def get(self, client_id: str) -> PublicClient | None:
        """The client, or None. Never raises: an unreadable database is noted for the caller."""
        try:
            purpose = LOOKUP_PURPOSE.get()
            if _UUID_RE.fullmatch(client_id):
                return await self.get_registered(client_id)
            if client_id.startswith("https://"):
                data = await self._cimd.get(client_id, purpose)
                return None if data is None else self._cimd_client(data)
            return None
        except StoreUnavailable:
            outage = LOOKUP_OUTAGE.get()
            if outage is not None:
                outage.append(True)
            log_warning("oauth_client_lookup", reason="store_unavailable")
            return None
        except Exception:  # noqa: BLE001 - get_client must never raise
            log_warning("oauth_client_lookup", reason="error")
            return None

    async def get_registered(self, client_id: str) -> PublicClient | None:
        record = await anyio.to_thread.run_sync(self._store.get_client_record, client_id)
        if record is None or record.expires_at < int(self._clock()):
            return None
        try:
            info = json.loads(record.info_json)
            info["client_id"] = client_id
            # The allowlist may have narrowed since this client registered.
            uris = [u for u in info.get("redirect_uris", []) if self._redirect_allowed(u)]
            if not uris:
                return None
            info["redirect_uris"] = uris
            info["token_endpoint_auth_method"] = "none"
            info["client_secret"] = None
            scope = " ".join(s for s in str(info.get("scope") or "").split() if s in self._scopes)
            info["scope"] = scope or " ".join(self._scopes)
            return PublicClient.build(info, kind=CLIENT_KIND_DCR, allowlist=self._allowlist)
        except (ValueError, TypeError, ValidationError):
            return None

    def _redirect_allowed(self, uri: object) -> bool:
        return (
            isinstance(uri, str)
            and redirect_uri_syntax_ok(uri)
            and any(redirect_matches(uri, entry) for entry in self._allowlist)
        )

    def _cimd_client(self, data: CimdClientData) -> PublicClient:
        return PublicClient.build(
            {
                "client_id": data.url,
                "client_name": data.client_name,
                "redirect_uris": list(data.redirect_uris),
                "grant_types": list(data.grant_types),
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": data.scope,
                "application_type": "native",
            },
            kind=CLIENT_KIND_CIMD,
            allowlist=self._allowlist,
            client_host=host_of(data.url),
        )

    async def get_for_consent(self, client_id: str, not_before: int) -> PublicClient | None:
        """The client as the consent page needs it: from the database only, never a fetch.

        A CIMD document must have been fetched no earlier than the request it belongs to,
        so a consent can only ever approve what ``/authorize`` just verified.
        """
        try:
            if _UUID_RE.fullmatch(client_id):
                return await self.get_registered(client_id)
            data = await self._cimd.snapshot_only(client_id, not_before)
            return None if data is None else self._cimd_client(data)
        except StoreUnavailable:
            raise
        except Exception:  # noqa: BLE001
            return None
