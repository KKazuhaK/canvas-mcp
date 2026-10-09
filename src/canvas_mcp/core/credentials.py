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
import threading
from collections import OrderedDict
from collections.abc import Callable
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RequestCredentials:
    """Canvas API credentials for a single HTTP request.

    The token is left out of ``repr()`` so a log line, an exception message or
    a traceback that formats this object cannot leak it.
    """

    api_token: str = field(repr=False)
    api_url: str


@dataclass(frozen=True)
class RequestPrincipal:
    """The verified identity behind one request (self-hosted mode).

    ``key`` is the account key ``acct:<uuid>``: everything the server stores or caches
    for a person is keyed by it. ``provider_id``, ``issuer`` and ``subject`` name the
    external identity the request authenticated with (today only Entra: the issuer is
    derived from the tenant and the subject is the object id), and ``account_id`` is the
    bare UUID. ``tenant_id`` and ``object_id`` are the Entra-only fields the credential
    gate cross-checks against the verified token.
    """

    key: str
    tenant_id: str
    object_id: str
    display_name: str
    upn: str
    roles: frozenset[str]
    is_owner: bool
    provider_id: str = "entra"
    issuer: str = ""
    subject: str = ""
    account_id: str = ""


@dataclass
class RequestTokenState:
    """Mutable health of the caller's Canvas token, shared by everything in one request.

    A ContextVar holds one instance per request, so concurrent sub-requests of a
    ``gather`` (which each run in a copy of the context) all see the same object:
    once one of them finds the token dead, the others stop sending requests.
    ``token_version`` is the ``updated_at`` of the stored row the request used.
    """

    token_version: int | None = None
    dead: bool = False
    message: str | None = None
    # The credential generation the request's token was read under (see
    # ``note_credential_generation``); None outside the self-hosted mode.
    credential_generation: int | None = None


@dataclass(frozen=True)
class RequestToolPrefs:
    """The write tools the caller has switched on at /account, for one request.

    ``readable`` False means the preferences could not be read; ``enabled`` is
    then empty, so every write tool stays off (fail closed).
    """

    enabled: frozenset[str] = frozenset()
    readable: bool = True


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


_request_token_state: ContextVar[RequestTokenState | None] = ContextVar(
    "request_token_state", default=None
)

# The generation of the stored Canvas credential this request was authorized
# with (self-hosted mode only). None for stdio and the upstream HTTP modes.
_request_credential_generation: ContextVar[int | None] = ContextVar(
    "request_credential_generation", default=None
)


_request_tool_prefs: ContextVar[RequestToolPrefs | None] = ContextVar(
    "request_tool_prefs", default=None
)

# The scratch space of one request of a verified principal whose course state is
# request-local (``SELFHOST_COURSE_STATE=request_local``); None otherwise. It is a
# plain dict created once per request by the request middleware, so every task the
# request starts shares it, and it is dropped with the request.
_request_local_principal_state: ContextVar[dict[str, Any] | None] = ContextVar(
    "request_local_principal_state", default=None
)


def get_request_tool_prefs() -> RequestToolPrefs | None:
    """The caller's write-tool preferences for this request; None if none were loaded."""
    return _request_tool_prefs.get()


def set_request_tool_prefs(prefs: RequestToolPrefs | None) -> Token[RequestToolPrefs | None]:
    """Publish (or clear) the caller's write-tool preferences for this request."""
    return _request_tool_prefs.set(prefs)


# Initialized per HTTP request, never a shared mutable ContextVar default.
_request_course_labels: ContextVar[dict[str, str] | None] = ContextVar(
    "request_course_labels", default=None
)


def get_request_course_labels() -> dict[str, str] | None:
    """Course labels read under the current request's Canvas credential."""
    return _request_course_labels.get()


def get_request_credentials() -> RequestCredentials | None:
    """Get the current request's Canvas credentials, or None for stdio mode."""
    return _request_credentials.get()


def set_request_credentials(creds: RequestCredentials) -> None:
    """Set Canvas credentials for the current async context."""
    _request_credentials.set(creds)
    _request_course_labels.set({})


def clear_request_credentials() -> None:
    """Clear credentials after request completes."""
    _request_credentials.set(None)
    _request_credential_generation.set(None)
    _request_course_labels.set(None)


def is_http_request_active() -> bool:
    """Return True while handling an HTTP request.

    Used to fail closed: in HTTP mode a missing per-request token must never
    fall back to the server's own credentials.
    """
    return _http_request_active.get()


def set_http_request_active(active: bool = True) -> None:
    """Mark whether the current async context is handling an HTTP request."""
    _http_request_active.set(active)
    _request_course_labels.set({} if active else None)


def uses_request_local_course_state() -> bool:
    """True when course metadata must live and die with the current request.

    That is every HTTP request without a verified principal (the upstream
    ``X-Canvas-Token`` / access-key / Easy Auth modes), and every request of a
    verified principal in the self-hosted ``entra-oauth`` mode when it runs with
    ``SELFHOST_COURSE_STATE=request_local`` (the default). Each such request
    resolves course aliases and labels under its own Canvas credential and
    publishes nothing into process-wide state. Only ``entra-oauth`` with the
    explicit opt-in ``SELFHOST_COURSE_STATE=per_principal`` keeps a per-principal
    course cache across requests, and stdio (no HTTP request) keeps its single
    process-wide cache.
    """
    if not _http_request_active.get():
        return False
    return _request_principal.get() is None or _request_local_principal_state.get() is not None


def set_request_local_principal_state(enabled: bool) -> Token[dict[str, Any] | None]:
    """Start (or leave off) the request-local state of the current principal.

    Called by the request middleware right after it publishes the verified
    principal, with ``True`` for ``SELFHOST_COURSE_STATE=request_local``. A
    principal published without this call keeps per-principal state.
    """
    return _request_local_principal_state.set({} if enabled else None)


def request_local_principal_state() -> dict[str, Any] | None:
    """The current request's scratch space, or None when state is per principal.

    Anything a process-wide cache would keep for a principal across requests
    (course-policy decisions, pseudonym maps, discussion hints) goes in here
    instead while it is not None: it ends with the request.
    """
    if _request_principal.get() is None:
        return None
    return _request_local_principal_state.get()


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


def get_request_token_state() -> RequestTokenState | None:
    """The shared token-health object of the current request, if one was started."""
    return _request_token_state.get()


def set_request_token_state(state: RequestTokenState | None) -> Token[RequestTokenState | None]:
    """Start (or clear) the shared token-health object for the current request."""
    return _request_token_state.set(state)


# -- credential generations (self-hosted mode) ----------------------------------
#
# A principal's *credential generation* is a number the token store raises every
# time the lifecycle of that principal's Canvas credential changes: a token is
# saved or replaced, removed, found dead, restored, or the principal is disabled
# or enabled again. Everything the server remembers on behalf of a principal
# (course lists, course-policy decisions, pseudonyms, health verdicts, pending
# write confirmations) is keyed by it, so state learned under one credential can
# never be served under another, even for the same Entra identity at the same
# school. The number only ever grows; the store keeps it when a token is deleted.
#
# This registry is the *process's* view of the newest generation it has heard of.
# The store reports into it after each committed change (from any thread, so it
# only records), and the request middleware reports what it read from the
# database. A request that holds an older generation than the registry knows is
# *stale*: it still runs with the credential it started with, but it must not
# publish anything into shared state.

_MAX_TRACKED_GENERATIONS = 8192
_generation_lock = threading.Lock()
_known_generations: OrderedDict[str, int] = OrderedDict()
_pending_purges: list[str] = []
_purge_listeners: list[Callable[[str], None]] = []


def register_credential_purge_listener(listener: Callable[[str], None]) -> None:
    """Call ``listener(principal_key)`` when a principal's credential generation rises.

    Listeners drop in-memory state for that principal (all of its generations'
    keys start with the principal key). They run on the thread that calls
    :func:`run_pending_credential_purges`, which the request middleware does on the
    event loop, never on the store's worker threads.
    """
    if listener not in _purge_listeners:
        _purge_listeners.append(listener)


def note_credential_generation(principal_key: str, generation: int) -> bool:
    """Record that ``principal_key`` has reached ``generation``; True if it rose.

    Safe from any thread. Only ever raises the recorded value. When it rises
    above an earlier value, the principal is queued for
    :func:`run_pending_credential_purges`.
    """
    with _generation_lock:
        known = _known_generations.get(principal_key)
        if known is not None and generation <= known:
            _known_generations.move_to_end(principal_key)
            return False
        _known_generations[principal_key] = generation
        _known_generations.move_to_end(principal_key)
        while len(_known_generations) > _MAX_TRACKED_GENERATIONS:
            _known_generations.popitem(last=False)
        # A first sighting is not a change: there is nothing older to drop.
        if known is not None:
            _pending_purges.append(principal_key)
        return known is not None


def run_pending_credential_purges() -> None:
    """Let every listener drop the state of principals whose generation rose."""
    with _generation_lock:
        keys = list(dict.fromkeys(_pending_purges))
        _pending_purges.clear()
    for key in keys:
        for listener in list(_purge_listeners):
            try:
                listener(key)
            except Exception:  # noqa: BLE001 - hygiene must never fail a request
                continue


def known_credential_generation(principal_key: str) -> int | None:
    """The newest generation this process has heard of for a principal, if any."""
    with _generation_lock:
        return _known_generations.get(principal_key)


def reset_credential_generations() -> None:
    """Forget every recorded generation (tests, and after restoring a database)."""
    with _generation_lock:
        _known_generations.clear()
        _pending_purges.clear()


def get_request_credential_generation() -> int | None:
    """The credential generation the current request was authorized under."""
    return _request_credential_generation.get()


def set_request_credential_generation(
    generation: int | None,
) -> Token[int | None]:
    """Publish (or clear) the credential generation of the current request."""
    return _request_credential_generation.set(generation)


def request_credential_is_stale() -> bool:
    """True if the credential generation of this request has been superseded.

    Only meaningful with a verified principal and a known generation; everything
    else (stdio, the upstream HTTP modes) is never stale. A stale request keeps
    the credential it started with, but must not write to state that later
    requests share.
    """
    principal = _request_principal.get()
    generation = _request_credential_generation.get()
    if principal is None or generation is None:
        return False
    known = known_credential_generation(principal.key)
    return known is not None and generation < known


def current_principal_key() -> str:
    """An opaque key for whoever is making the current request.

    With a verified principal (the self-hosted mode) this is the principal key
    plus the Canvas API URL the request is routed to plus the credential
    generation (``g<n>``), so one user's cached Canvas data can never be served
    after a switch to another school, after the Canvas token is replaced (it may
    belong to a different Canvas account or carry other permissions), removed or
    found dead, or after the principal is disabled and enabled again. For a
    legacy HTTP request it is a keyed hash of the caller's Canvas token (stable
    within this process, never containing the token); otherwise ``"local"``
    (stdio). Every process-global cache that holds user-derived data is keyed
    by this. Audit events use the identity-only ``principal.key`` instead.
    """
    principal = _request_principal.get()
    if principal is not None:
        creds = _request_credentials.get()
        if creds is None:
            return principal.key
        generation = _request_credential_generation.get() or 0
        return f"{principal.key}|{creds.api_url.rstrip('/').lower()}|g{generation}"
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
    _request_token_state.set(None)
    _request_tool_prefs.set(None)
    _request_credential_generation.set(None)
    _request_local_principal_state.set(None)
    _request_course_labels.set(None)
