"""``GET /api/v1/readiness``: does this person's connection to the Portal actually work?

An integrating hub (MCPHub) may be signed in through the Portal's OAuth without the
person ever saving a Canvas token. It asks this endpoint, with the very access token it
uses for MCP calls, and gets one of the states of the service readiness contract
(version 1): ``ready``, ``needs_setup``, ``expiring``, ``expired`` or ``revoked``.
(``degraded`` is never sent: the Portal has no partly-working state.)

* Authentication is the bearer access token only, verified by
  :meth:`AuthzRuntime.verify_access_token`, the same function that guards ``/mcp``
  (signature, issuer, audience, scope, lifetime, signing epoch, grant not revoked, account
  present). Cookies are never read, so a browser session is no credential here. Missing or
  invalid: 401 with no detail.
* Read-only. The answer comes from the Portal's own records (the saved credential and the
  Canvas verdict the Portal already stored); Canvas is never called, nothing is written
  and no use timestamp is touched.
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

from . import account_core as web
from . import custody
from .account_api import _JSON_HEADERS, _clean, _ts
from .authz.server import MAX_ACCESS_TOKEN_CHARS
from .db.errors import StoreUnavailable
from .db.workers import run_store
from .mcp_state import McpRead
from .principal_access import snapshot_status
from .routes import ACCOUNT_PREFIX, API_PREFIX
from .token_store import (
    REASON_CANVAS_TOKEN_REJECTED,
    REASON_DECRYPT_FAILED,
    REASON_REVOKED_BY_ADMIN,
    STATUS_INVALID,
    EnrollmentInfo,
)

logger = logging.getLogger("canvas_mcp.selfhost.readiness")

READINESS_PATH = f"{API_PREFIX}/readiness"
TOKEN_PAGE = f"{ACCOUNT_PREFIX}/token"
CONTRACT_VERSION = 1
SET_UP_LABEL = "Set up Canvas token"
REPLACE_LABEL = "Replace Canvas token"

_INVALID_SUMMARIES = {
    REASON_CANVAS_TOKEN_REJECTED: "Canvas rejected your saved token. Save a new one.",
    REASON_REVOKED_BY_ADMIN: "An administrator revoked your saved Canvas token. Save a new one.",
    REASON_DECRYPT_FAILED: "Your saved Canvas token could not be read. Save it again.",
}


def _bearer(request: Request) -> str | None:
    """The token of a well-formed ``Authorization: Bearer <token>`` header, else None."""
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token or token != token.strip():
        return None
    if " " in token or len(token) > MAX_ACCESS_TOKEN_CHARS:
        return None
    return token


class ReadinessApi:
    """The readiness endpoint over one account application."""

    def __init__(self, app: web.AccountCore) -> None:
        self.app = app

    def routes(self) -> list[Route]:
        return [web.any_method_route(READINESS_PATH, self._endpoint)]

    # -- responses ------------------------------------------------------------------

    @staticmethod
    def _respond(
        status: int, payload: object, headers: Mapping[str, str] | None = None
    ) -> Response:
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
        return Response(
            body.encode("utf-8"), status_code=status, headers={**_JSON_HEADERS, **(headers or {})}
        )

    def _unauthorized(self) -> Response:
        return self._respond(
            401,
            {"error": {"code": "not_authenticated"}},
            {"WWW-Authenticate": 'Bearer realm="canvas-mcp"'},
        )

    def _action(self, label: str) -> dict[str, str] | None:
        url = self.app.base + TOKEN_PAGE
        # The contract allows https only; a plain-http base (never a real deployment) offers no button.
        return {"label": label, "url": url} if url.startswith("https://") else None

    def _state(
        self,
        state: str,
        summary: str,
        *,
        action_label: str | None = None,
        expires_at: int | None = None,
    ) -> Response:
        body: dict[str, Any] = {
            "version": CONTRACT_VERSION,
            "state": state,
            "summary": _clean(summary, 200),
        }
        action = self._action(action_label) if action_label else None
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
                return self._respond(
                    405, {"error": {"code": "method_not_allowed"}}, {"Allow": "GET"}
                )
            token = _bearer(request)
            if token is None:
                return self._unauthorized()
            verified = await self.app.authz.verify_access_token(token)
            if verified is None or verified.claims.get("federated"):
                return self._unauthorized()
            read = McpRead(
                verified.claims["acct"], verified.claims["grant"], verified.snapshot
            )
            return await self._answer(read)
        except (StoreUnavailable, web._StoreUnavailable):
            return self._respond(503, {"error": {"code": "token_store_unavailable"}})
        except Exception as exc:  # noqa: BLE001 - never leak details
            logger.error("readiness request failed: %s", type(exc).__name__)
            return self._respond(500, {"error": {"code": "internal_error"}})

    async def _answer(self, read: McpRead) -> Response:
        status = snapshot_status(read)
        if status.disabled:
            return self._state(
                "revoked", "Your access to this server was disabled by an administrator."
            )
        if status.pending:
            return self._state(
                "needs_setup", "Your account is waiting for approval by the server owner."
            )
        if not status.active:
            return self._state("revoked", "Your access to this server is not active.")

        info: EnrollmentInfo | None = await run_store(self.app.store.info, read.account_id)
        if info is None:
            return self._state(
                "needs_setup",
                "No Canvas token is saved yet. Save one to use the Canvas tools.",
                action_label=SET_UP_LABEL,
            )
        config = await run_store(self.app.snapshots.get, read.snapshot.settings_revision)
        now = int(self.app.clock())
        # Only an expiry that Canvas itself reported counts, as on the account page.
        expiry = info.access_expires_at if info.expiry_source == "canvas" else None

        if (
            expiry is not None
            and expiry <= now
            and info.invalid_reason != REASON_REVOKED_BY_ADMIN
        ):
            return self._state(
                "expired",
                "Your Canvas token has expired. Save a new one.",
                action_label=REPLACE_LABEL,
                expires_at=expiry,
            )
        if info.status == STATUS_INVALID:
            summary = _INVALID_SUMMARIES.get(
                info.invalid_reason or "", "Your saved Canvas token no longer works. Save a new one."
            )
            return self._state("revoked", summary, action_label=REPLACE_LABEL)
        if info.custody_notice_version < custody.CUSTODY_NOTICE_VERSION:
            return self._state(
                "needs_setup",
                "Accept the token storage notice to use the Canvas tools.",
                action_label=SET_UP_LABEL,
            )
        if config.schools.resolve_stored(info.canvas_host) is None:
            return self._state(
                "needs_setup",
                "Your Canvas school is no longer offered on this server.",
                action_label=SET_UP_LABEL,
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


def build_readiness_routes(app: web.AccountCore) -> list[Route]:
    """The ``/api/v1/readiness`` route over an existing account application."""
    return ReadinessApi(app).routes()
