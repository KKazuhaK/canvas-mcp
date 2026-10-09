"""Per-request identity and Canvas credentials for the self-hosted mode.

A pure ASGI middleware that runs inside FastMCP's authentication, so
``scope['user']`` already holds the outcome of verifying the bearer token. For
the MCP endpoint it re-checks the verified Entra claims against the operator's
policy, looks up the caller's own Canvas token in the encrypted store, and
publishes both through the request ContextVars that the Canvas client reads.
Nothing here trusts a request header, and nothing outlives the request.

A row whose token is marked invalid (Canvas rejected it, it could not be
decrypted, or an administrator revoked it) gets no credentials at all: the
request carries the re-enroll message instead, so not one Canvas request is made
with that token. Each request also starts a shared token-health object, so a
token found dead part-way through (see :mod:`canvas_mcp.core.token_health`) stops
the rest of that request's Canvas calls.

Before any of that, the caller's access status is checked (see
:mod:`.principal_access`): a principal an administrator disabled gets a 403 for
every MCP request, whatever token it presents, so an already issued or freshly
refreshed token buys nothing. If the status cannot be read, the request is refused
(503) rather than let through. The check is cached for a few seconds, so a change
made by another process is noticed within that time; a request already past the
check is not interrupted.

The caller's own write-tool switches (what they turned on at ``/account``) are
loaded into the request too, for the credential gate; if they cannot be read,
no write tool is enabled for that request.

The Canvas school comes only from the caller's own stored row, mapped through
the operator's :class:`SchoolPolicy`. A host the current settings no longer
allow is treated as "not enrolled": no Canvas call is ever made for it, and
nothing falls back to the server's default school.
"""

from __future__ import annotations

import functools
import json
import re
from collections.abc import Mapping
from typing import Any, Protocol

import anyio.to_thread
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from starlette.types import ASGIApp, Receive, Scope, Send

from .. import audit
from ..credentials import (
    RequestCredentials,
    RequestTokenState,
    RequestToolPrefs,
    clear_http_request_context,
    set_http_request_active,
    set_missing_credentials_message,
    set_request_credentials,
    set_request_principal,
    set_request_token_state,
    set_request_tool_prefs,
)
from ..logging import log_error, log_warning
from .identity import ClaimsDenied, ClaimsPolicy, evaluate_entra_claims
from .principal_access import access_disabled_message, access_unavailable_message
from .schools import SchoolPolicy
from .token_store import (
    REASON_DECRYPT_FAILED,
    REASON_REVOKED_BY_ADMIN,
    STATUS_INVALID,
    PrincipalStatus,
    TokenDecryptionError,
)

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_NO_CLAIMS_MESSAGE = "Your sign-in carries no identity claims. Reconnect the connector."


class StoredTokenLike(Protocol):
    """What the middleware needs from a stored row: the Canvas token and its school."""

    @property
    def api_token(self) -> str: ...

    @property
    def canvas_host(self) -> str | None: ...


class TokenInvalidator(Protocol):
    """The slice of the token-health service the middleware uses."""

    async def mark_invalid(
        self, principal_key: str, reason: str, *, expected_updated_at: int | None = None
    ) -> bool: ...


class ToolPrefsReader(Protocol):
    """The slice of the preferences cache the middleware uses (synchronous)."""

    def enabled(self, principal_key: str) -> frozenset[str]: ...


class AccessChecker(Protocol):
    """The slice of the access cache the middleware uses (synchronous)."""

    def status(self, principal_key: str) -> PrincipalStatus: ...

    def invalidate(self, principal_key: str | None = None) -> None: ...


class OwnerLedger(Protocol):
    """The slice of the token store that records an owner role seen to be gone."""

    def demote_owner(self, principal_key: str, *, evidence_issued_at: int) -> bool: ...


class CanvasTokenReader(Protocol):
    """The slice of the token store the middleware uses (synchronous methods)."""

    def get(self, tenant_id: str, object_id: str) -> StoredTokenLike | None: ...

    def touch(self, tenant_id: str, object_id: str, *, min_interval_seconds: int = 300) -> None: ...


def not_enrolled_message(account_url: str) -> str:
    return (
        "No Canvas access token is enrolled for your Microsoft account on this server. "
        f"Open {account_url} in a browser, sign in with Microsoft, and add your Canvas "
        "access token there (never paste it into this chat). Then try again."
    )


def unreadable_token_message(account_url: str) -> str:
    return (
        "Your stored Canvas access token could not be read. "
        f"Open {account_url} and enroll it again."
    )


def token_rejected_message(account_url: str) -> str:
    """Canvas rejected the stored token: the model relays this to the user."""
    return (
        "Canvas rejected your stored access token (it was revoked, expired, or "
        f"regenerated). Open {account_url}, sign in, and enroll a new Canvas token "
        "there (never paste it into this chat). Your other settings are kept."
    )


def token_revoked_message(account_url: str) -> str:
    """The server administrator marked the stored token invalid."""
    return (
        "The server administrator marked your stored Canvas access token as invalid. "
        f"Open {account_url}, sign in, and enroll a new Canvas token there "
        "(never paste it into this chat). Your other settings are kept."
    )


def invalid_token_message(account_url: str, reason: str | None) -> str:
    """The message for a row whose status is invalid, by the reason recorded."""
    if reason == REASON_DECRYPT_FAILED:
        return unreadable_token_message(account_url)
    if reason == REASON_REVOKED_BY_ADMIN:
        return token_revoked_message(account_url)
    return token_rejected_message(account_url)


async def _send_json(send: Send, status: int, message: str) -> None:
    body = json.dumps({"error": message}).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ],
    })
    await send({"type": "http.response.body", "body": body})


def _is_mcp_path(path: str, mcp_path: str) -> bool:
    return path == mcp_path or path.startswith(mcp_path + "/")


class SelfhostRequestContextMiddleware:
    """Publish the verified identity and the caller's Canvas token for one request."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        mcp_path: str,
        policy: ClaimsPolicy,
        store: CanvasTokenReader,
        schools: SchoolPolicy,
        account_url: str,
        health: TokenInvalidator | None = None,
        tool_prefs: ToolPrefsReader | None = None,
        access: AccessChecker | None = None,
        owners: OwnerLedger | None = None,
    ) -> None:
        self.app = app
        self.mcp_path = mcp_path
        self.policy = policy
        self.store = store
        self.schools = schools
        self.account_url = account_url
        self.health = health
        self.tool_prefs = tool_prefs
        self.access = access
        self.owners = owners

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Every HTTP request is an HTTP request: no code path may fall back to
        # a server credential, whichever route it reaches.
        set_http_request_active(True)
        try:
            if not _is_mcp_path(scope.get("path", ""), self.mcp_path):
                await self.app(scope, receive, send)
                return

            user = scope.get("user")
            if not isinstance(user, AuthenticatedUser):
                # Not authenticated: FastMCP's RequireAuthMiddleware answers
                # with the 401 and the resource_metadata challenge.
                await self.app(scope, receive, send)
                return

            claims = getattr(user.access_token, "claims", None)
            if not isinstance(claims, Mapping):
                log_warning("MCP request denied", reason="no_claims")
                await _send_json(send, 403, _NO_CLAIMS_MESSAGE)
                return

            verdict = evaluate_entra_claims(claims, self.policy, token_kind="access")
            if isinstance(verdict, ClaimsDenied):
                oid = claims.get("oid")
                log_warning(
                    "MCP request denied",
                    reason=verdict.reason,
                    entra_oid=oid.lower() if isinstance(oid, str) and _GUID_RE.match(oid) else None,
                )
                await _send_json(send, 403, verdict.message)
                return

            refusal = await self._access_refusal(verdict, claims)
            if refusal is not None:
                await _send_json(send, refusal[0], refusal[1])
                return

            set_request_principal(verdict)
            set_request_token_state(RequestTokenState())
            set_request_tool_prefs(await self._load_tool_prefs(verdict.key))
            await self._attach_canvas_credentials(
                verdict.tenant_id, verdict.object_id, verdict.key
            )
            await self.app(scope, receive, send)
        finally:
            clear_http_request_context()

    async def _access_refusal(
        self, verdict: Any, claims: Mapping[str, Any]
    ) -> tuple[int, str] | None:
        """``(status, message)`` if this principal may not use the server, else None."""
        if self.access is None:
            return None
        try:
            status = await anyio.to_thread.run_sync(self.access.status, verdict.key)
        except Exception:  # noqa: BLE001 - fail closed; the error text is not logged
            log_error("principal access check failed", entra_oid=verdict.object_id)
            return 503, access_unavailable_message()
        if status.disabled:
            log_warning(
                "MCP request denied", reason="principal_disabled", entra_oid=verdict.object_id
            )
            return 403, access_disabled_message()
        await self._note_owner_role_gone(verdict, claims, status)
        return None

    async def _note_owner_role_gone(
        self, verdict: Any, claims: Mapping[str, Any], status: PrincipalStatus
    ) -> None:
        """Lower the stored owner flag when a verified token proves the role is gone.

        Only ever lowers it, and only on a token issued after the last recorded
        sign-in (see ``TokenStore.demote_owner``). Never raises.
        """
        if self.owners is None or not status.is_owner or verdict.is_owner:
            return
        issued = claims.get("iat")
        if not isinstance(issued, int | float) or isinstance(issued, bool):
            return
        try:
            changed = await anyio.to_thread.run_sync(
                functools.partial(
                    self.owners.demote_owner, verdict.key, evidence_issued_at=int(issued)
                )
            )
            if changed:
                audit.log_principal_event(
                    "owner_lost", verdict.key, reason="access_token_roles"
                )
                if self.access is not None:
                    self.access.invalidate(verdict.key)
        except Exception:  # noqa: BLE001 - bookkeeping must never change the answer
            pass

    async def _load_tool_prefs(self, principal_key: str) -> RequestToolPrefs:
        """The write tools this caller switched on; nothing enabled when they cannot be read."""
        if self.tool_prefs is None:
            return RequestToolPrefs()
        try:
            enabled = await anyio.to_thread.run_sync(self.tool_prefs.enabled, principal_key)
        except Exception:  # noqa: BLE001 - fail closed; the error text is not logged
            log_error("write-tool preferences unreadable")
            return RequestToolPrefs(readable=False)
        return RequestToolPrefs(enabled=enabled)

    async def _attach_canvas_credentials(
        self, tenant_id: str, object_id: str, principal_key: str
    ) -> None:
        try:
            row: Any = await anyio.to_thread.run_sync(self.store.get, tenant_id, object_id)
        except Exception as exc:
            # The exception text is never logged: it can sit next to key or
            # token material.
            log_error("stored Canvas token unreadable", entra_oid=object_id)
            if isinstance(exc, TokenDecryptionError):
                # Only a failed decryption invalidates the row; a locked or
                # failing database says nothing about the token.
                await self._record_unreadable(principal_key, exc.updated_at)
            message = unreadable_token_message(self.account_url)
            set_missing_credentials_message(message)
            self._mark_request_dead(message)
            return

        if row is None:
            set_missing_credentials_message(not_enrolled_message(self.account_url))
            return

        if getattr(row, "status", None) == STATUS_INVALID:
            # Canvas rejected this token, an administrator revoked it, or it
            # could not be decrypted before: mount no credentials, so this
            # request makes no Canvas call, and say how to fix it.
            message = invalid_token_message(
                self.account_url, getattr(row, "invalid_reason", None)
            )
            set_missing_credentials_message(message)
            self._mark_request_dead(message)
            return

        school = self.schools.resolve_stored(getattr(row, "canvas_host", None))
        if school is None:
            # The settings no longer offer this user's school (or a legacy row
            # has no default school to belong to): fail closed. The host is
            # not logged, and touch() is deliberately not called.
            log_warning("stored Canvas school not allowed", entra_oid=object_id)
            set_missing_credentials_message(not_enrolled_message(self.account_url))
            return

        set_request_credentials(
            RequestCredentials(api_token=row.api_token, api_url=school.api_url)
        )
        version = getattr(row, "updated_at", None)
        set_request_token_state(
            RequestTokenState(token_version=version if isinstance(version, int) else None)
        )
        try:
            await anyio.to_thread.run_sync(self.store.touch, tenant_id, object_id)
        except Exception:
            pass  # last-used bookkeeping must never fail a request

    async def _record_unreadable(self, principal_key: str, version: int | None) -> None:
        """A stored token that cannot be decrypted is marked invalid (decrypt_failed).

        Only the exact row that failed is marked (``version`` is its
        ``updated_at``): a replacement the user saved in the meantime must not be
        invalidated by a request that read the old row. Without a version
        nothing is changed.
        """
        if self.health is None or version is None:
            return
        try:
            await self.health.mark_invalid(
                principal_key, REASON_DECRYPT_FAILED, expected_updated_at=version
            )
        except Exception:  # noqa: BLE001 - recording must never change the answer
            pass

    @staticmethod
    def _mark_request_dead(message: str) -> None:
        set_request_token_state(RequestTokenState(dead=True, message=message))
