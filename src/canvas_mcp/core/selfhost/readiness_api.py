"""``GET /api/v1/readiness``: does this person's connection to the Portal actually work?

An integrating hub (MCPHub) may be signed in through the Portal's OAuth without the
person ever saving a Canvas token. It asks this endpoint, with the very access token it
uses for MCP calls, and gets one of the states of the service readiness contract
(version 1): ``ready``, ``needs_setup``, ``degraded``, ``expiring``, ``expired`` or
``revoked``. The rule is that every answer agrees with what ``/mcp`` would do for the
same account right now.

* Authentication is not done here. The route sits behind FastMCP's own bearer
  authentication, the one in front of ``/mcp``, so exactly the tokens ``/mcp`` accepts are
  accepted: the Portal's own access tokens and those of a trusted external issuer (MCPHub),
  with the same checks (signature, audience, scope, lifetime, signing epoch, a live grant)
  and the same account resolution. The handler reads that outcome (``scope["user"]``,
  ``MCP_READ``) and so makes no verification or account read of its own. No token or a
  token ``/mcp`` would not accept is 401; a verified person the server does not admit is
  403, as on ``/mcp``. Cookies are never read.
* The state is derived from the one authenticated read of the account (grant, account and
  primary credential, :class:`McpSnapshot`), in the order ``/mcp`` decides: a usable token
  wins; with none (or an invalid one) browser sync is used when ``/mcp`` would accept the
  binding, and its stored data is judged by the matching, age and status rules a tool call
  meets (:func:`probe_core`).
* Read-only. Nothing is written and Canvas is never called. The saved token is decrypted
  only to find out whether ``/mcp`` could read it; the plaintext is dropped at once.
* The body carries no token, no part of one, and nothing about another account. No CORS
  headers are sent and ``OPTIONS`` is not served.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ..browser_source import probe_core
from . import account_core as web
from . import custody
from .account_api import _JSON_HEADERS, _clean, _ts
from .accounts import DENY_ACCESS_DISABLED, DENY_PENDING_APPROVAL, Denied
from .authz.fastmcp_compat import AuthenticatedUser
from .browser_store import (
    Binding,
    BrowserSyncStore,
    binding_accepted,
    browser_source_for,
    token_usable_for_mcp,
)
from .db.errors import StoreUnavailable
from .db.snapshots import McpSnapshot
from .db.workers import run_store
from .mcp_state import MCP_READ, MCP_REFUSED, MCP_UNAVAILABLE, McpRead
from .request_context import LocalClaimsResolver
from .routes import ACCOUNT_PREFIX, API_PREFIX
from .token_store import (
    REASON_CANVAS_TOKEN_REJECTED,
    REASON_DECRYPT_FAILED,
    REASON_REVOKED_BY_ADMIN,
    STATUS_INVALID,
)

logger = logging.getLogger("canvas_mcp.selfhost.readiness")

READINESS_PATH = f"{API_PREFIX}/readiness"
TOKEN_PAGE = f"{ACCOUNT_PREFIX}/token"
BROWSER_PAGE = f"{ACCOUNT_PREFIX}/browser-extension"
CONTRACT_VERSION = 1
SET_UP_LABEL = "Set up Canvas token"
REPLACE_LABEL = "Replace Canvas token"
BROWSER_LABEL = "Open browser sync"

_INVALID_SUMMARIES = {
    REASON_CANVAS_TOKEN_REJECTED: "Canvas rejected your saved token. Save a new one.",
    REASON_REVOKED_BY_ADMIN: "An administrator revoked your saved Canvas token. Save a new one.",
    REASON_DECRYPT_FAILED: "Your saved Canvas token could not be read. Save it again.",
}
_DENIED_CODES = {
    DENY_ACCESS_DISABLED: "access_disabled",
    DENY_PENDING_APPROVAL: "pending_approval",
}


def _ago(seconds: int) -> str:
    minutes = max(0, seconds) // 60
    if minutes < 60:
        return f"{max(1, minutes)} min ago"
    if minutes < 48 * 60:
        return f"{minutes // 60} h ago"
    return f"{minutes // 1440} days ago"


class ReadinessApi:
    """The readiness endpoint over one account application."""

    def __init__(self, app: web.AccountCore, browser: BrowserSyncStore) -> None:
        self.app = app
        self.browser = browser
        self.identity = LocalClaimsResolver(app.authz.issuer)
        self._warned_plain_http = False

    def routes(self) -> list[Route]:
        return [web.any_method_route(READINESS_PATH, self._endpoint)]

    # -- responses ------------------------------------------------------------------

    @staticmethod
    def _respond(
        status: int, payload: object, headers: Mapping[str, str] | None = None
    ) -> Response:
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
        return Response(
            body.encode("utf-8"),
            status_code=status,
            headers={**_JSON_HEADERS, **(headers or {})},
        )

    def _error(self, status: int, code: str, headers: Mapping[str, str] | None = None) -> Response:
        return self._respond(status, {"error": {"code": code}}, headers)

    def _unauthorized(self) -> Response:
        return self._error(401, "not_authenticated", {"WWW-Authenticate": 'Bearer realm="canvas-mcp"'})

    def _action(self, label: str, page: str) -> dict[str, str] | None:
        """A button on the Portal's public address. The contract allows https only: a plain
        http base (never a real deployment) offers none, and says so once in the log. The
        summaries never refer to a button, so they stay true without it."""
        url = self.app.base + page
        if url.startswith("https://"):
            return {"label": label, "url": url}
        if not self._warned_plain_http:
            self._warned_plain_http = True
            logger.warning(
                "PUBLIC_BASE_URL is not https: readiness answers carry no action link"
            )
        return None

    def _state(
        self,
        state: str,
        summary: str,
        *,
        action_label: str | None = None,
        page: str = TOKEN_PAGE,
        expires_at: int | None = None,
    ) -> Response:
        body: dict[str, Any] = {
            "version": CONTRACT_VERSION,
            "state": state,
            "summary": _clean(summary, 200),
        }
        action = self._action(action_label, page) if action_label else None
        if action is not None:
            body["action"] = action
        stamp = _ts(expires_at)
        if stamp is not None:
            body["expires_at"] = stamp
        body["checked_at"] = datetime.fromtimestamp(
            int(self.app.clock()), tz=UTC
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        return self._respond(200, body)

    # -- the request ----------------------------------------------------------------

    async def _endpoint(self, request: Request) -> Response:
        try:
            if request.method != "GET":
                return self._error(405, "method_not_allowed", {"Allow": "GET"})
            # What /mcp's middleware checks first, in the same order.
            if MCP_UNAVAILABLE.get():
                return self._error(503, "token_store_unavailable")
            if MCP_REFUSED.get() is not None:
                return self._error(403, "forbidden")
            user = request.scope.get("user")
            if not isinstance(user, AuthenticatedUser):
                return self._unauthorized()
            claims = getattr(user.access_token, "claims", None)
            if not isinstance(claims, Mapping):
                return self._error(403, "forbidden")
            resolved = self.identity.resolve_request(claims)
            if isinstance(resolved, Denied):
                return self._error(403, _DENIED_CODES.get(resolved.code, "forbidden"))
            read = MCP_READ.get()
            if read is None or read.account_id != resolved.key:
                return self._error(503, "token_store_unavailable")
            return await self._answer(read)
        except (StoreUnavailable, web._StoreUnavailable):
            return self._error(503, "token_store_unavailable")
        except Exception as exc:  # noqa: BLE001 - never leak details
            logger.error("readiness request failed: %s", type(exc).__name__)
            return self._error(500, "internal_error")

    async def _answer(self, read: McpRead) -> Response:
        snapshot = read.snapshot
        try:
            config = await run_store(self.app.snapshots.get, snapshot.settings_revision)
        except Exception:  # noqa: BLE001 - /mcp answers 503 for any failure here
            return self._error(503, "token_store_unavailable")
        now = int(self.app.clock())

        # /mcp reads browser sync only when there is no usable token: ask the same code.
        if not token_usable_for_mcp(snapshot.credential_id, snapshot.credential_status):
            binding = await self._binding(read.account_id)
            if binding is not None and binding_accepted(binding, config, snapshot):
                return await self._browser_state(binding, config, now)
        return self._token_state(read.account_id, snapshot, config, now)

    async def _binding(self, account_id: str) -> Binding | None:
        """The account's active binding. A failure other than an outage reads as none, as in
        ``/mcp``, which then falls back to the token's own answer."""
        try:
            binding = await run_store(self.browser.active_binding, account_id)
        except StoreUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error("browser binding unreadable: %s", type(exc).__name__)
            return None
        return binding if binding is not None and binding.canvas_host is not None else None

    # -- the Canvas token -------------------------------------------------------------

    def _token_state(
        self, account_id: str, snapshot: McpSnapshot, config: Any, now: int
    ) -> Response:
        if snapshot.credential_id is None:
            return self._state(
                "needs_setup",
                "No Canvas token is saved yet. Save one to use the Canvas tools.",
                action_label=SET_UP_LABEL,
            )
        # Only an expiry that Canvas itself reported counts, as on the account page.
        expiry = (
            snapshot.access_expires_at if snapshot.expiry_source == "canvas" else None
        )
        if (
            expiry is not None
            and expiry <= now
            and snapshot.invalid_reason != REASON_REVOKED_BY_ADMIN
        ):
            return self._state(
                "expired",
                "Your Canvas token has expired. Save a new one.",
                action_label=REPLACE_LABEL,
                expires_at=expiry,
            )
        if snapshot.credential_status == STATUS_INVALID:
            summary = _INVALID_SUMMARIES.get(
                snapshot.invalid_reason or "",
                "Your saved Canvas token no longer works. Save a new one.",
            )
            return self._state("revoked", summary, action_label=REPLACE_LABEL)
        # The checks /mcp makes before it uses a token, in its order.
        if config.schools.resolve_stored(snapshot.canvas_host) is None:
            return self._state(
                "needs_setup",
                "Your Canvas school is no longer offered on this server.",
                action_label=SET_UP_LABEL,
            )
        if (
            snapshot.custody_notice_version is None
            or snapshot.custody_notice_version < custody.CUSTODY_NOTICE_VERSION
        ):
            return self._state(
                "needs_setup",
                "Accept the token storage notice to use the Canvas tools.",
                action_label=SET_UP_LABEL,
            )
        if not self._readable(account_id, snapshot):
            return self._state(
                "revoked", _INVALID_SUMMARIES[REASON_DECRYPT_FAILED], action_label=REPLACE_LABEL
            )
        days = int(config.settings["notifications.token_reminder_days"])
        if expiry is not None and expiry - now <= days * 86400:
            return self._state(
                "expiring",
                "Your Canvas token expires soon. Replace it before it stops working.",
                action_label=REPLACE_LABEL,
                expires_at=expiry,
            )
        return self._state(
            "ready",
            "Your Canvas token is saved and Canvas has not rejected it.",
            expires_at=expiry,
        )

    def _readable(self, account_id: str, snapshot: McpSnapshot) -> bool:
        """Whether ``/mcp`` could use the stored token: same generation, and it decrypts.

        ``/mcp`` marks a token it cannot read as invalid; this only looks.
        """
        if snapshot.generation != snapshot.credential_generation:
            return False
        try:
            self.app.store.decrypt_snapshot(account_id, snapshot)
        except Exception:  # noqa: BLE001 - any failure means /mcp cannot read it either
            return False
        return True

    # -- browser sync -------------------------------------------------------------------

    async def _browser_state(self, binding: Binding, config: Any, now: int) -> Response:
        """``/mcp`` answers from this binding: judge the data by what a tool call would meet."""
        source = browser_source_for(self.browser, binding, config)
        core = await probe_core(source, now=now)
        miss = core.miss
        if miss is None:
            age = 0 if core.oldest is None else now - core.oldest
            if age > source.fresh_seconds:
                return self._state(
                    "degraded",
                    f"Canvas data comes from browser sync, last updated {_ago(age)} — open Canvas to refresh",
                    action_label=BROWSER_LABEL,
                    page=BROWSER_PAGE,
                )
            return self._state(
                "ready", "Canvas data comes from browser sync and is up to date."
            )
        if miss.kind == "expired":
            days = max(1, source.max_age_seconds // 86400)
            return self._state(
                "expired",
                f"Browser sync data is more than {days} days old and is not used. Open Canvas to refresh.",
                action_label=BROWSER_LABEL,
                page=BROWSER_PAGE,
            )
        if miss.kind == "status":
            status = miss.stored_status
            if status in (401, 403):
                return self._state(
                    "revoked",
                    f"Canvas refused the browser sync data (HTTP {status}). Sign in to Canvas in your browser, then sync again.",
                    action_label=BROWSER_LABEL,
                    page=BROWSER_PAGE,
                )
            return self._state(
                "needs_setup",
                f"Canvas could not provide data to browser sync (HTTP {status}). Open Canvas to sync again.",
                action_label=BROWSER_LABEL,
                page=BROWSER_PAGE,
            )
        return self._state(
            "needs_setup",
            "Browser sync has not uploaded your Canvas data yet. Open Canvas to sync.",
            action_label=BROWSER_LABEL,
            page=BROWSER_PAGE,
        )


def build_readiness_routes(app: web.AccountCore, browser: BrowserSyncStore) -> list[Route]:
    """The ``/api/v1/readiness`` route over an existing account application."""
    return ReadinessApi(app, browser).routes()
