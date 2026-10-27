"""Publish identity and credentials from the authenticated request snapshot."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from starlette.types import ASGIApp, Receive, Scope, Send

from ..credentials import (
    RequestCredentials,
    RequestPrincipal,
    RequestTokenState,
    RequestToolPrefs,
    clear_http_request_context,
    get_request_credentials,
    note_credential_generation,
    run_pending_credential_purges,
    set_http_request_active,
    set_missing_credentials_message,
    set_request_credential_generation,
    set_request_credentials,
    set_request_local_principal_state,
    set_request_principal,
    set_request_token_state,
    set_request_tool_prefs,
)
from ..error_codes import CREDENTIAL_INVALID, PERMISSION_DENIED
from ..logging import log_error, log_warning
from . import custody
from .accounts import (
    DENY_ACCESS_DENIED,
    DENY_ACCESS_DISABLED,
    DENY_BAD_SUBJECT,
    DENY_PENDING_APPROVAL,
    Denied,
    account_id_of,
    denied,
    valid_account_key,
)
from .authz.fastmcp_compat import AuthenticatedUser
from .config_snapshot import CURRENT_CONFIG, ConfigSnapshots
from .db.snapshots import McpSnapshot
from .db.workers import run_store
from .mcp_state import MCP_READ, MCP_UNAVAILABLE, McpRead
from .principal_access import access_unavailable_message, snapshot_status
from .settings import COURSE_STATE_PER_PRINCIPAL, COURSE_STATE_REQUEST_LOCAL
from .token_store import (
    REASON_DECRYPT_FAILED,
    REASON_REVOKED_BY_ADMIN,
    STATUS_INVALID,
)
from .usage import USAGE_INTERVAL_SECONDS, UsageDeduplicator

_NO_CLAIMS_MESSAGE = "Your sign-in carries no identity claims. Reconnect the connector."


class RequestIdentity(Protocol):
    """The slice of the identity service the middleware uses (synchronous)."""

    def resolve_request(
        self, claims: Mapping[str, Any]
    ) -> RequestPrincipal | Denied: ...


class LocalClaimsResolver:
    """Resolve verified local claims from this request's account snapshot."""

    def __init__(self, issuer: str) -> None:
        self._issuer = issuer

    def resolve_request(self, claims: Mapping[str, Any]) -> RequestPrincipal | Denied:
        acct = claims.get("acct")
        if (
            claims.get("token_use") != "access"
            or claims.get("iss") != self._issuer
            or claims.get("sub") != acct
            or not isinstance(acct, str)
            or not valid_account_key(acct)
        ):
            return denied(DENY_BAD_SUBJECT)
        read = MCP_READ.get()
        if (
            read is None
            or read.account_id != acct
            or read.grant_id != claims.get("grant")
        ):
            return denied(DENY_BAD_SUBJECT)
        status = snapshot_status(read)
        if status.disabled:
            return denied(DENY_ACCESS_DISABLED)
        if status.pending:
            return denied(DENY_PENDING_APPROVAL)
        if not status.active:
            return denied(DENY_ACCESS_DENIED)
        return RequestPrincipal(
            key=acct,
            display_name=status.display_name,
            is_owner=status.is_owner,
            provider_id="local",
            issuer=self._issuer,
            subject=acct,
            account_id=account_id_of(acct),
        )


class TokenInvalidator(Protocol):
    """The slice of the token-health service the middleware uses."""

    async def mark_invalid(
        self,
        principal_key: str,
        reason: str,
        *,
        expected_updated_at: int | None = None,
        expected_generation: int | None = None,
    ) -> bool: ...


class ToolPrefsReader(Protocol):
    """The slice of the preferences cache the middleware uses (synchronous)."""

    def enabled(self, principal_key: str, version: int) -> frozenset[str]: ...


class CanvasTokenReader(Protocol):
    def decrypt_snapshot(self, account_id: str, snapshot: McpSnapshot) -> str: ...

    def touch(self, principal_key: str, *, min_interval_seconds: int = 300) -> None: ...


def not_enrolled_message(account_url: str) -> str:
    return (
        "No Canvas access token is enrolled for your account on this server. "
        f"Open {account_url} in a browser, sign in, and add your Canvas "
        "access token there (never paste it into this chat). Then try again."
    )


def school_not_offered_message(account_url: str) -> str:
    return (
        "Your Canvas school is no longer offered by this server. "
        f"Choose an offered school at {account_url}/token or contact the server owner."
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
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        }
    )
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
        identity: RequestIdentity,
        store: CanvasTokenReader,
        snapshots: ConfigSnapshots,
        account_url: str,
        health: TokenInvalidator | None = None,
        tool_prefs: ToolPrefsReader | None = None,
        touch_grant: Callable[[str], None],
        clock: Callable[[], float] = time.time,
        course_state: str = COURSE_STATE_REQUEST_LOCAL,
    ) -> None:
        self.app = app
        # Anything but the explicit opt-in keeps the course state request-local.
        self.request_local_state = course_state != COURSE_STATE_PER_PRINCIPAL
        self.mcp_path = mcp_path
        self.identity = identity
        self.store = store
        self.snapshots = snapshots
        self.account_url = account_url
        self.health = health
        self.tool_prefs = tool_prefs
        self.touch_grant = touch_grant
        self.clock = clock
        self.usage = UsageDeduplicator(clock=clock)

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

            if MCP_UNAVAILABLE.get():
                await _send_json(send, 503, access_unavailable_message())
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

            try:
                resolved = await run_store(self.identity.resolve_request, claims)
            except Exception:  # noqa: BLE001 - fail closed; the error text is not logged
                log_error("principal access check failed")
                await _send_json(send, 503, access_unavailable_message())
                return
            if isinstance(resolved, Denied):
                acct = claims.get("acct")
                log_warning(
                    "MCP request denied",
                    reason=resolved.code,
                    account=acct
                    if isinstance(acct, str) and valid_account_key(acct)
                    else None,
                )
                await _send_json(send, 403, resolved.message)
                return
            principal = resolved

            set_request_principal(principal)
            set_request_local_principal_state(self.request_local_state)
            set_request_token_state(RequestTokenState())
            read = MCP_READ.get()
            if read is None or read.account_id != principal.key:
                await _send_json(send, 503, access_unavailable_message())
                return
            snapshot = read.snapshot
            try:
                CURRENT_CONFIG.set(
                    await run_store(self.snapshots.get, snapshot.settings_revision)
                )
            except Exception:
                await _send_json(send, 503, access_unavailable_message())
                return
            self._publish_generation(principal.key, snapshot.credential_generation)
            if not await self._attach_canvas_credentials(principal.key, snapshot):
                await _send_json(send, 503, unreadable_token_message(self.account_url))
                return
            set_request_tool_prefs(
                await self._load_tool_prefs(principal.key, snapshot.write_tools_version)
            )
            await self.app(scope, receive, send)
            try:
                await self._touch_usage(read)
            except Exception:
                pass  # last-use bookkeeping never changes a completed response
        finally:
            clear_http_request_context()

    async def _load_tool_prefs(
        self, principal_key: str, version: int
    ) -> RequestToolPrefs:
        """The write tools this caller switched on; nothing enabled when they cannot be read."""
        if self.tool_prefs is None:
            return RequestToolPrefs()
        try:
            enabled = await run_store(self.tool_prefs.enabled, principal_key, version)
        except Exception:  # noqa: BLE001 - fail closed; the error text is not logged
            log_error("write-tool preferences unreadable")
            return RequestToolPrefs(readable=False)
        return RequestToolPrefs(enabled=enabled)

    async def _touch_usage(self, read: McpRead) -> None:
        snapshot, stale = read.snapshot, int(self.clock()) - USAGE_INTERVAL_SECONDS
        if (
            snapshot.grant_used_at is None or snapshot.grant_used_at < stale
        ) and self.usage.take("grant", read.grant_id):
            await run_store(self.touch_grant, read.grant_id)
        if (
            get_request_credentials() is not None
            and snapshot.credential_id is not None
            and (
                snapshot.credential_used_at is None
                or snapshot.credential_used_at < stale
            )
            and self.usage.take("credential", snapshot.credential_id)
        ):
            await run_store(self.store.touch, read.account_id)

    async def _attach_canvas_credentials(
        self, principal_key: str, snapshot: McpSnapshot
    ) -> bool:
        generation = snapshot.credential_generation
        if snapshot.credential_id is None:
            set_missing_credentials_message(
                not_enrolled_message(self.account_url), CREDENTIAL_INVALID
            )
            return True
        if snapshot.credential_status == STATUS_INVALID:
            message = invalid_token_message(self.account_url, snapshot.invalid_reason)
            set_missing_credentials_message(message, CREDENTIAL_INVALID)
            self._mark_request_dead(message, generation)
            return True
        config = CURRENT_CONFIG.get()
        school = (
            None
            if config is None
            else config.schools.resolve_stored(snapshot.canvas_host)
        )
        if school is None:
            set_missing_credentials_message(
                school_not_offered_message(self.account_url), PERMISSION_DENIED
            )
            return True
        if (
            snapshot.custody_notice_version is None
            or snapshot.custody_notice_version < custody.CUSTODY_NOTICE_VERSION
        ):
            set_missing_credentials_message(
                custody.custody_ack_required_message(self.account_url),
                PERMISSION_DENIED,
            )
            return True
        if snapshot.generation != generation:
            log_error("stored Canvas credential generation mismatch")
            return False
        try:
            token = self.store.decrypt_snapshot(principal_key, snapshot)
        except Exception:
            log_error("stored Canvas token unreadable", account=principal_key)
            await self._record_unreadable(
                principal_key, snapshot.credential_updated_at, generation
            )
            return False
        set_request_credentials(
            RequestCredentials(api_token=token, api_url=school.api_url)
        )
        set_request_token_state(
            RequestTokenState(
                token_version=snapshot.credential_updated_at,
                credential_generation=generation,
            )
        )
        return True

    @staticmethod
    def _publish_generation(principal_key: str, value: object) -> int | None:
        """Make the credential generation of this request known; returns it (None if absent).

        Raising the process's view drops what other requests of this principal
        cached under an older generation. Runs on the event loop, never on the
        store's worker threads.
        """
        if not isinstance(value, int) or isinstance(value, bool):
            return None
        note_credential_generation(principal_key, value)
        run_pending_credential_purges()
        set_request_credential_generation(value)
        return value

    async def _record_unreadable(
        self, principal_key: str, version: int | None, generation: int | None = None
    ) -> None:
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
                principal_key,
                REASON_DECRYPT_FAILED,
                expected_updated_at=version,
                expected_generation=generation,
            )
        except Exception:  # noqa: BLE001 - recording must never change the answer
            pass

    @staticmethod
    def _mark_request_dead(message: str, generation: int | None = None) -> None:
        set_request_token_state(
            RequestTokenState(
                dead=True, message=message, credential_generation=generation
            )
        )
