"""The JSON API of the account UI, ``/account/api`` (self-hosted multi-user mode).

It serves the single-page UI with the data and the actions the server-rendered
``/account`` pages have today. It is not a second sign-in or a second set of rules:

* Authentication is the same sealed ``__Host-cmcp_session`` cookie, re-checked against
  the stored account on every request (a disabled account, a changed session epoch or a
  deleted account is signed out). The sign-in itself stays the server-side OIDC
  redirect (``/account/login`` and ``/account/callback``).
* Every mutation needs the session's CSRF token in an ``X-CSRF-Token`` header, an
  ``Origin`` equal to the public base URL, and (when the browser sends it)
  ``Sec-Fetch-Site: same-origin``. The school search is a GET but also needs the token,
  because it makes outbound calls and spends the per-account search budget. There are
  no CORS headers and ``OPTIONS`` is refused, so a page on another origin can neither
  read nor preflight anything.
* The security-critical sequences (enrolling a token, re-checking it, saving the
  write-tool switches, the owner's access actions) are the very methods the HTML pages
  call (see :mod:`.account_ops`); the rate limiters, the access cache, the health
  service and the audit events are the same objects. The owner is re-checked in the
  store's own transaction.
* Responses are JSON, ``no-store``, and carry a closed error code (``{"error":
  {"code": ..., "params": {...}}}``). No body ever holds Entra text, Canvas text, a
  token or an exception message.

Only the features that exist are served. Linked identities are not; ``GET /me`` says so in
``features``. The consent screen and the connected apps (``/consent``,
``/me/grants``, ``/admin/accounts/{id}/grants``, ``/admin/grants/{id}``) belong to the
server's own authorization server (``SELFHOST_AUTH_MODE=local``): the routes are always in
the route table (the web app and the server must list the same ones), but every one of them
answers ``not_found`` before anything else when that mode is off, and ``features.consent``
and ``features.connected_apps`` are false. The consent endpoints are the pages' own
``ConsentService`` (:mod:`.authz.consent`): the same checks decide both UIs. They need the
``__Host-cmcp_bind`` cookie of the browser that started the request, so an id copied into
another browser is refused. The decision answers ``{"redirect_to": ...}`` and the page
navigates there itself; it is never a form post, so the page's ``form-action`` does not apply.
"""

from __future__ import annotations

import json
import logging
import math
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

import anyio.to_thread
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from canvas_mcp.core.selfhost import account_web as web
from canvas_mcp.core.selfhost.account_ops import Refusal, WriteToolsSnapshot
from canvas_mcp.core.selfhost.accounts import PROVIDER_ENTRA, valid_account_key
from canvas_mcp.core.selfhost.schools import (
    MAX_QUERY_CHARS,
    MIN_QUERY_CHARS,
    DirectoryError,
    is_blocked_hostname,
)
from canvas_mcp.core.selfhost.token_store import (
    DISABLE_REASON_ADMIN,
    DISABLE_REASON_DENIED,
    DISABLE_REASON_OPERATOR,
    INVALID_REASONS,
    OPERATOR_ACTOR,
    REASON_REVOKED_BY_ADMIN,
    STATUS_INVALID,
    SYSTEM_ACTOR,
    AuditEntry,
    EnrollmentInfo,
    PrincipalStatus,
    TokenStoreError,
)
from canvas_mcp.core.selfhost.tool_prefs import (
    OTHER_GROUP,
    WRITE_TOOL_GROUPS,
    user_can_enable,
)
from canvas_mcp.core.tool_policy import TOOL_EFFECTS, Effect

if TYPE_CHECKING:
    from canvas_mcp.core.selfhost.authz.models import GrantRecord

logger = logging.getLogger("canvas_mcp.selfhost.account_api")

API_PREFIX = "/account/api"

#: Every error code the API can answer with, and its HTTP status. The frontend's
#: ``CODE_SET`` is checked against this table by a test.
ERROR_STATUS: Mapping[str, int] = {
    # session and transport
    "not_authenticated": 401,
    "csrf_invalid": 403,
    "origin_not_allowed": 403,
    "reauth_required": 403,
    "forbidden": 403,
    "pending_approval": 403,
    "access_disabled": 403,
    "method_not_allowed": 405,
    "unsupported_media_type": 415,
    "payload_too_large": 413,
    "malformed_request": 400,
    "validation_failed": 422,
    "not_found": 404,
    "rate_limited": 429,
    "token_store_unavailable": 503,
    "internal_error": 500,
    # Canvas token
    "token_invalid_format": 422,
    "token_rejected": 422,
    "token_unreadable": 422,
    "canvas_unavailable": 503,
    "identity_change_required": 409,
    "recheck_not_allowed": 409,
    # schools
    "school_required": 422,
    "school_invalid": 422,
    "school_not_offered": 422,
    "school_not_in_directory": 422,
    "school_unresolvable": 422,
    "school_address_blocked": 422,
    "school_selection_unverified": 422,
    "directory_unavailable": 503,
    # write tools
    "write_tool_not_allowed": 422,
    "write_tools_unavailable": 503,
    # admin
    "last_owner": 409,
    "cannot_disable_self": 409,
    # an app's authorization request (SELFHOST_AUTH_MODE=local)
    "authorization_invalid": 400,
    "client_unavailable": 409,
}
API_ERROR_CODES = frozenset(ERROR_STATUS)

MAX_BODY_BYTES = web._MAX_BODY_BYTES
FRESH_WINDOW_SECONDS = web._FRESH_SIGN_IN_SECONDS
HISTORY_LIMIT = web._SIGN_IN_HISTORY
AUDIT_PAGE = web._AUDIT_PAGE
CSRF_HEADER = "x-csrf-token"
MAX_ENABLED_TOOLS = 120
MAX_DETAIL_TEXT = 200

_JSON_HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
}

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_AUDIT_ACTION_RE = re.compile(r"^[a-z_]{1,64}$")
_LOCALES = ("en", "zh")
_HISTORY_REASONS = frozenset(
    {"account_created", "activated", "access_disabled", "signups_paused", "pending_approval"}
)
_DISABLED_REASONS = frozenset({DISABLE_REASON_ADMIN, DISABLE_REASON_OPERATOR, DISABLE_REASON_DENIED})
_ADMIN_STATUSES = ("active", "pending", "disabled")
_TXN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_DECISIONS = ("approve", "deny")

Scalar = str | int


# -- errors --------------------------------------------------------------------


class _Fail(Exception):
    """An answer with a closed error code. Parameters are scalars, never upstream text."""

    def __init__(
        self,
        code: str,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code if code in ERROR_STATUS else "internal_error"
        self.params: dict[str, Scalar] = {
            str(key): value
            for key, value in (params or {}).items()
            if isinstance(value, str | int) and not isinstance(value, bool)
        }
        self.headers = dict(headers or {})
        if self.code == "rate_limited" and "retry_after_s" in self.params:
            self.headers["Retry-After"] = str(self.params["retry_after_s"])


def _invalid(field: str, **extra: Scalar) -> _Fail:
    return _Fail("validation_failed", {"field": field, **extra})


def _refusal_to_fail(refusal: Refusal) -> _Fail:
    params: dict[str, Any] = dict(refusal.params)
    for key in ("enrolled_user_name", "new_user_name"):
        if key in params:
            params[key] = _clean(params[key])
    return _Fail(refusal.code, params)


# -- small helpers ---------------------------------------------------------------


def _clean(value: object, limit: int = MAX_DETAIL_TEXT) -> str:
    """Display text without control characters, at most ``limit`` characters."""
    text = value if isinstance(value, str) else str(value)
    text = "".join(" " if (ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F) else ch for ch in text)
    return " ".join(text.split())[:limit]


def _ts(value: int | None) -> str | None:
    """An epoch second as ``2026-10-09T17:03:00Z``, or None."""
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _account_id(key: str) -> str | None:
    return key[len("acct:") :] if valid_account_key(key) else None


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _refuse_constant(_name: str) -> Any:
    raise ValueError("not a JSON number")


def _parse_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("not finite")
    return value


def _parse_object(raw: bytes) -> dict[str, Any]:
    """Strict JSON: UTF-8, one object, no duplicate keys, no NaN or Infinity."""
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_pairs,
            parse_constant=_refuse_constant,
            parse_float=_parse_float,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _Fail("malformed_request") from None
    if not isinstance(value, dict):
        raise _Fail("malformed_request")
    return value


def _closed(body: Mapping[str, Any], *, required: Sequence[str], optional: Sequence[str] = ()) -> None:
    """Refuse an unknown field, and a missing required one, with ``validation_failed``."""
    for key in body:
        if key not in required and key not in optional:
            raise _invalid(key if _FIELD_NAME_RE.fullmatch(key) else "body")
    for key in required:
        if key not in body:
            raise _invalid(key)


def _text(body: Mapping[str, Any], key: str, *, max_chars: int, nullable: bool = False) -> str:
    """A string field ('' for an absent or null optional one)."""
    value = body.get(key)
    if value is None and nullable:
        return ""
    if not isinstance(value, str) or len(value) > max_chars:
        raise _invalid(key)
    return value


# -- the API -----------------------------------------------------------------------


@dataclass
class _Ctx:
    request: Request
    session: web._Session | None
    body: dict[str, Any] | None
    params: Mapping[str, str]


Access = Literal["public", "session", "active", "owner"]
BodyKind = Literal["none", "json", "empty"]


@dataclass(frozen=True)
class _Endpoint:
    handler: Callable[[_Ctx], Awaitable[Response]]
    access: Access = "active"
    mutating: bool = False
    #: A GET that still needs the CSRF header (the school search).
    csrf: bool = False
    body: BodyKind = "none"
    #: Served only with the local authorization server; ``not_found`` otherwise, before any other check.
    local_authz: bool = False


class ApiApp:
    """The JSON API, over one :class:`~.account_web._AccountApp`."""

    def __init__(self, app: web._AccountApp) -> None:
        self.app = app

    # -- routing ------------------------------------------------------------

    def route_table(self) -> list[tuple[str, dict[str, _Endpoint]]]:
        """Every (path, {method: endpoint}) of the API."""
        e = _Endpoint
        return [
            (f"{API_PREFIX}/providers", {"GET": e(self.providers, access="public")}),
            (f"{API_PREFIX}/me", {"GET": e(self.me, access="session")}),
            (
                f"{API_PREFIX}/me/canvas-token",
                {
                    "GET": e(self.get_canvas_token),
                    "PUT": e(self.put_canvas_token, mutating=True, body="json"),
                    "DELETE": e(self.delete_canvas_token, mutating=True, body="empty"),
                },
            ),
            (
                f"{API_PREFIX}/me/canvas-token/recheck",
                {"POST": e(self.recheck_canvas_token, mutating=True, body="empty")},
            ),
            (f"{API_PREFIX}/me/schools", {"GET": e(self.get_schools)}),
            (f"{API_PREFIX}/me/schools/search", {"GET": e(self.search_schools, csrf=True)}),
            (
                f"{API_PREFIX}/me/write-tools",
                {
                    "GET": e(self.get_write_tools),
                    "PUT": e(self.put_write_tools, mutating=True, body="json"),
                    "DELETE": e(self.delete_write_tools, mutating=True, body="empty"),
                },
            ),
            (f"{API_PREFIX}/me/login-history", {"GET": e(self.login_history, access="session")}),
            (
                f"{API_PREFIX}/me/ui-locale",
                {"PUT": e(self.put_ui_locale, access="session", mutating=True, body="json")},
            ),
            (
                f"{API_PREFIX}/session/logout",
                {"POST": e(self.logout, access="session", mutating=True, body="empty")},
            ),
            (f"{API_PREFIX}/admin/accounts", {"GET": e(self.admin_accounts, access="owner")}),
            (f"{API_PREFIX}/admin/enrollments", {"GET": e(self.admin_enrollments, access="owner")}),
            *(
                (
                    f"{API_PREFIX}/admin/accounts/{{id}}/{action}",
                    {
                        "POST": e(
                            self._admin_access(action),
                            access="owner",
                            mutating=True,
                            body="empty",
                        )
                    },
                )
                for action in ("approve", "deny", "disable", "enable")
            ),
            (
                f"{API_PREFIX}/admin/enrollments/{{id}}/mark-invalid",
                {"POST": e(self.admin_mark_invalid, access="owner", mutating=True, body="empty")},
            ),
            (
                f"{API_PREFIX}/admin/enrollments/{{id}}",
                {"DELETE": e(self.admin_remove_enrollment, access="owner", mutating=True, body="empty")},
            ),
            (f"{API_PREFIX}/admin/audit", {"GET": e(self.admin_audit, access="owner")}),
            # SELFHOST_AUTH_MODE=local only (not_found otherwise).
            (
                f"{API_PREFIX}/consent",
                {
                    "GET": e(self.get_consent, access="session", local_authz=True),
                    "POST": e(
                        self.post_consent,
                        access="session",
                        mutating=True,
                        body="json",
                        local_authz=True,
                    ),
                },
            ),
            (f"{API_PREFIX}/me/grants", {"GET": e(self.my_grants, local_authz=True)}),
            (
                f"{API_PREFIX}/me/grants/{{id}}",
                {
                    "DELETE": e(
                        self.delete_my_grant, mutating=True, body="empty", local_authz=True
                    )
                },
            ),
            (
                f"{API_PREFIX}/admin/accounts/{{id}}/grants",
                {"GET": e(self.admin_account_grants, access="owner", local_authz=True)},
            ),
            (
                f"{API_PREFIX}/admin/grants/{{id}}",
                {
                    "DELETE": e(
                        self.admin_revoke_grant,
                        access="owner",
                        mutating=True,
                        body="empty",
                        local_authz=True,
                    )
                },
            ),
        ]

    def route_keys(self) -> set[tuple[str, str]]:
        """``(method, path)`` of every API route (the paths keep their ``{id}`` placeholder)."""
        return {
            (method, path) for path, endpoints in self.route_table() for method in endpoints
        }

    def routes(self) -> list[Route]:
        routes = [
            web.any_method_route(path, self._endpoint(endpoints))
            for path, endpoints in self.route_table()
        ]
        # Registered after the real routes and before the single-page fallback, so an
        # unknown path below /account/api is a JSON 404, never the app's index page.
        routes.append(web.any_method_route(API_PREFIX, self._unknown))
        routes.append(web.any_method_route(API_PREFIX + "/{rest:path}", self._unknown))
        return routes

    async def _unknown(self, request: Request) -> Response:
        return self._error(_Fail("not_found"))

    def _endpoint(self, endpoints: dict[str, _Endpoint]) -> Callable[[Request], Awaitable[Response]]:
        async def endpoint(request: Request) -> Response:
            try:
                return await self._handle(request, endpoints)
            except _Fail as fail:
                return self._error(fail)
            except web._StoreUnavailable:
                return self._error(_Fail("token_store_unavailable"))
            except TokenStoreError as exc:
                logger.error("account api store failure: %s", type(exc).__name__)
                return self._error(_Fail("token_store_unavailable"))
            except Exception as exc:  # noqa: BLE001 - never leak details
                logger.error("account api request failed: %s", type(exc).__name__)
                return self._error(_Fail("internal_error"))

        return endpoint

    # -- the request pipeline -------------------------------------------------------

    async def _handle(self, request: Request, endpoints: dict[str, _Endpoint]) -> Response:
        """method, session, active, owner, origin, csrf, body, then the action."""
        if self.app.authz is None and any(e.local_authz for e in endpoints.values()):
            # Not served in this mode: as if the path did not exist, for any method.
            raise _Fail("not_found")
        endpoint = endpoints.get(request.method)
        if endpoint is None:
            raise _Fail("method_not_allowed", headers={"Allow": ", ".join(sorted(endpoints))})
        session: web._Session | None = None
        if endpoint.access != "public":
            session = await self._session(request)
            if endpoint.access in ("active", "owner") and session.pending:
                raise _Fail("pending_approval")
            if endpoint.access == "owner":
                self._require_owner(session)
            self._check_origin(request, mutating=endpoint.mutating)
            if endpoint.mutating or endpoint.csrf:
                supplied = request.headers.get(CSRF_HEADER)
                if not self.app._csrf_ok(session, supplied):
                    raise _Fail("csrf_invalid")
        body: dict[str, Any] | None = None
        if endpoint.body == "json":
            body = await self._json_body(request)
        elif endpoint.body == "empty":
            if await self._read_body(request):
                raise _Fail("malformed_request")
        ctx = _Ctx(request, session, body, request.path_params)
        return await endpoint.handler(ctx)

    async def _session(self, request: Request) -> web._Session:
        try:
            session = await self.app._resolve_session(request)
        except Exception as exc:  # noqa: BLE001 - fail closed, never leak details
            logger.error("account api session check failed: %s", type(exc).__name__)
            raise _Fail("token_store_unavailable") from None
        if session is None:
            raise _Fail("not_authenticated")
        return session

    def _require_owner(self, session: web._Session) -> None:
        if not session.owner:
            raise _Fail("forbidden")
        if not self.app._signed_in_recently(session):
            raise _Fail("reauth_required", {"max_age_s": FRESH_WINDOW_SECONDS})

    def _check_origin(self, request: Request, *, mutating: bool) -> None:
        fetch_site = request.headers.get("sec-fetch-site")
        if mutating:
            if request.headers.get("origin") != self.app.base:
                raise _Fail("origin_not_allowed")
            if fetch_site is not None and fetch_site != "same-origin":
                raise _Fail("origin_not_allowed")
        elif fetch_site is not None and fetch_site not in ("same-origin", "none"):
            raise _Fail("origin_not_allowed")

    async def _read_body(self, request: Request) -> bytes:
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                raise _Fail("malformed_request") from None
            if length < 0:
                raise _Fail("malformed_request")
            if length > MAX_BODY_BYTES:
                raise _Fail("payload_too_large")
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > MAX_BODY_BYTES:
                raise _Fail("payload_too_large")
            chunks.append(chunk)
        return b"".join(chunks)

    async def _json_body(self, request: Request) -> dict[str, Any]:
        header = request.headers.get("content-type", "")
        media, _, params = header.partition(";")
        if media.strip().lower() != "application/json":
            raise _Fail("unsupported_media_type")
        charset = re.search(r"charset\s*=\s*\"?([^\";\s]+)", params, re.IGNORECASE)
        if charset is not None and charset.group(1).lower() not in ("utf-8", "utf8"):
            raise _Fail("unsupported_media_type")
        return _parse_object(await self._read_body(request))

    # -- responses ------------------------------------------------------------------

    @staticmethod
    def _response(
        status: int, payload: object | None, headers: Mapping[str, str] | None = None
    ) -> Response:
        merged = {**_JSON_HEADERS, **(headers or {})}
        if payload is None:
            return Response(b"", status_code=status, headers=merged)
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        return Response(body, status_code=status, headers=merged)

    def _error(self, fail: _Fail) -> Response:
        error: dict[str, Any] = {"code": fail.code}
        if fail.params:
            error["params"] = fail.params
        return self._response(ERROR_STATUS[fail.code], {"error": error}, fail.headers)

    def _ok(self, payload: object, status: int = 200) -> Response:
        return self._response(status, payload)

    def _no_content(self) -> Response:
        return self._response(204, None)

    # -- shared views ---------------------------------------------------------------------

    def _school_of(self, host: str | None) -> dict[str, Any] | None:
        resolved = self.app.schools.resolve_stored(host)
        if resolved is not None:
            return {"host": resolved.host, "name": _clean(resolved.name), "offered": True}
        if host:
            return {"host": host, "name": _clean(host), "offered": False}
        return None

    def _canvas_status(self, info: EnrollmentInfo | None) -> dict[str, Any]:
        if info is None:
            return {
                "state": "none",
                "canvas_user_id": None,
                "canvas_user_name": None,
                "school": None,
                "invalid_reason": None,
                "invalid_since": None,
                "recheck_allowed": False,
                "expires_on": None,
                "expiry_notice": "none",
                "settings_url": None,
                "enrolled_at": None,
                "updated_at": None,
                "last_used_at": None,
                "last_verified_at": None,
            }
        invalid = info.status == STATUS_INVALID
        reason = info.invalid_reason if info.invalid_reason in INVALID_REASONS else None
        hint = info.expires_hint_at
        notice = "none"
        if not invalid and hint is not None:
            now = self.app.clock()
            if hint - now <= web._EXPIRY_REMINDER_DAYS * 86400:
                notice = "soon" if now < hint + 86400 else "passed"
        return {
            "state": "invalid" if invalid else "active",
            "canvas_user_id": str(info.canvas_user_id),
            "canvas_user_name": _clean(info.canvas_user_name),
            "school": self._school_of(info.canvas_host),
            "invalid_reason": reason if invalid else None,
            "invalid_since": _ts(info.invalid_since) if invalid else None,
            "recheck_allowed": invalid and info.invalid_reason != REASON_REVOKED_BY_ADMIN,
            "expires_on": web._fmt_utc_date(hint) if hint is not None else None,
            "expiry_notice": notice,
            "settings_url": self.app.settings_url(info),
            "enrolled_at": _ts(info.created_at),
            "updated_at": _ts(info.updated_at),
            "last_used_at": _ts(info.last_used_at),
            "last_verified_at": _ts(info.last_verified_at),
        }

    async def _canvas_now(self, session: web._Session) -> dict[str, Any]:
        info = await anyio.to_thread.run_sync(self.app.store.info, session.acct)
        return self._canvas_status(info)

    def _write_tools_view(self, snapshot: WriteToolsSnapshot) -> dict[str, Any]:
        offered, current = snapshot.offered, snapshot.current
        prefs = snapshot.prefs

        def tool(name: str) -> dict[str, Any]:
            stamp = prefs.enabled_at.get(name) if prefs is not None and name in current else None
            return {
                "name": name,
                "offered": name in offered,
                "enabled": name in current,
                "enabled_at": _ts(stamp),
                "effect": "local_write"
                if TOOL_EFFECTS.get(name) is Effect.LOCAL_WRITE
                else "canvas_write",
            }

        groups: list[dict[str, Any]] = []
        known: set[str] = set()
        for group, names in WRITE_TOOL_GROUPS:
            groups.append({"id": group, "tools": [tool(name) for name in names]})
            known.update(names)
        others = sorted(name for name in offered if name not in known)
        if others:
            groups.append({"id": OTHER_GROUP, "tools": [tool(name) for name in others]})
        return {
            "groups": groups,
            "kept_not_offered": sorted(
                name for name in current if name not in offered and name not in known
            ),
            "offered_any": bool(offered),
            "editable": bool(offered or current),
        }

    async def _write_snapshot(self, session: web._Session) -> WriteToolsSnapshot:
        if self.app.write_tools is None:
            raise _Fail("not_found")
        try:
            return await self.app.read_write_tools(session)
        except Exception as exc:  # noqa: BLE001
            logger.error("account api write tools read failed: %s", type(exc).__name__)
            raise _Fail("write_tools_unavailable") from None

    # -- public ------------------------------------------------------------------------------

    async def providers(self, ctx: _Ctx) -> Response:
        return self._ok(
            {
                "providers": [
                    {
                        "id": PROVIDER_ENTRA,
                        "kind": "oidc",
                        "name": "Microsoft",
                        "icon": "microsoft",
                        "start_url": web._LOGIN_PATH,
                    }
                ],
                "mcp_url": self.app.base + "/mcp",
            }
        )

    # -- self --------------------------------------------------------------------------------------

    async def me(self, ctx: _Ctx) -> Response:
        session = ctx.session
        assert session is not None
        app = self.app
        pending = session.pending
        canvas = None
        write_tools = None
        if not pending:
            canvas = await self._canvas_now(session)
            if app.write_tools is not None:
                try:
                    snapshot = await app.read_write_tools(session)
                    write_tools = {
                        "offered": len(snapshot.offered),
                        "enabled": len(snapshot.current & snapshot.offered),
                    }
                except Exception as exc:  # noqa: BLE001 - the count is a convenience
                    logger.error("account api write tools read failed: %s", type(exc).__name__)
        fresh = app._signed_in_recently(session)
        locale = ctx.request.cookies.get(web.LANG_COOKIE)
        zone = getattr(web._display_tz(), "key", None)
        key = session.acct
        return self._ok(
            {
                "account": {
                    "id": _account_id(key),
                    "key": key,
                    "display_name": _clean(session.name),
                    "username": _clean(session.upn, 254),
                    "provider_id": session.pid,
                    "role": "owner" if session.owner else "user",
                    "status": "pending" if pending else "active",
                },
                "csrf_token": session.csrf,
                "session": {
                    "issued_at": _ts(session.iat) if session.iat > 0 else None,
                    "expires_at": _ts(session.exp),
                    "fresh_until": _ts(session.iat + FRESH_WINDOW_SECONDS) if fresh else None,
                    "fresh": fresh,
                    "fresh_window_s": FRESH_WINDOW_SECONDS,
                },
                "canvas": canvas,
                "write_tools": write_tools,
                "features": {
                    "school_picker": (not pending) and app.schools.picker_enabled,
                    "school_search": (not pending) and app.schools.search_enabled,
                    "write_tools": (not pending) and app.write_tools is not None,
                    "admin": session.owner,
                    "identities": False,
                    # Local authorization server only (see the module docstring). A waiting
                    # account is still told so; its own screens and the API refuse it.
                    "connected_apps": app.authz is not None,
                    "consent": app.authz is not None,
                    "logout_everywhere": False,
                    "role_management": False,
                },
                "ui_locale": locale if locale in _LOCALES else None,
                "server": {
                    "mcp_url": app.base + "/mcp",
                    "display_timezone": zone if isinstance(zone, str) and zone else "UTC",
                },
            }
        )

    async def get_canvas_token(self, ctx: _Ctx) -> Response:
        assert ctx.session is not None
        return self._ok(await self._canvas_now(ctx.session))

    async def put_canvas_token(self, ctx: _Ctx) -> Response:
        session, body = ctx.session, ctx.body
        assert session is not None and body is not None
        _closed(
            body,
            required=("canvas_token",),
            optional=("school", "school_sig", "expires_on", "confirm_identity_change"),
        )
        token = _text(body, "canvas_token", max_chars=1024)
        school = _text(body, "school", max_chars=253, nullable=True)
        signature = _text(body, "school_sig", max_chars=128, nullable=True)
        expires = _text(body, "expires_on", max_chars=32, nullable=True)
        confirmation = _text(body, "confirm_identity_change", max_chars=128, nullable=True)
        outcome = await self.app.enroll_token(
            session,
            token_raw=token,
            expires_raw=expires,
            school_raw=school,
            confirm_raw=confirmation,
            pick_signature=signature or None,
            require_pick_signature=True,
        )
        if isinstance(outcome, Refusal):
            raise _refusal_to_fail(outcome)
        return self._ok(await self._canvas_now(session))

    async def delete_canvas_token(self, ctx: _Ctx) -> Response:
        assert ctx.session is not None
        await self.app.delete_own_token(ctx.session)
        return self._no_content()

    async def recheck_canvas_token(self, ctx: _Ctx) -> Response:
        assert ctx.session is not None
        outcome = await self.app.recheck_own_token(ctx.session)
        if isinstance(outcome, Refusal):
            raise _refusal_to_fail(outcome)
        return self._ok({"result": outcome.result, "canvas": await self._canvas_now(ctx.session)})

    async def get_schools(self, ctx: _Ctx) -> Response:
        session = ctx.session
        assert session is not None
        schools = self.app.schools
        info = await anyio.to_thread.run_sync(self.app.store.info, session.acct)
        choices: list[dict[str, str]] = []
        selected: str | None = None
        sole: dict[str, str] | None = None
        mode: Literal["picker", "sole", "fixed"]
        if schools.picker_enabled:
            mode = "picker"
            choices = [
                {"host": s.host, "name": _clean(s.name), "source": "featured"}
                for s in schools.featured
            ]
            listed = {choice["host"] for choice in choices}
            enrolled = info.canvas_host if info is not None else None
            if (
                enrolled is not None
                and enrolled not in listed
                and schools.resolve_stored(enrolled) is not None
            ):
                choices.append({"host": enrolled, "name": _clean(enrolled), "source": "enrolled"})
                listed.add(enrolled)
            if enrolled is not None and enrolled in listed:
                selected = enrolled
            elif schools.default is not None:
                selected = schools.default.host
            elif choices:
                selected = choices[0]["host"]
        else:
            only = schools.sole_school
            if only is not None and schools.default is None:
                mode = "sole"
            else:
                mode = "fixed"
            shown = only or schools.default
            if shown is not None:
                sole = {"host": shown.host, "name": _clean(shown.name)}
        return self._ok(
            {
                "mode": mode,
                "choices": choices,
                "selected": selected,
                "sole": sole,
                "search_enabled": schools.search_enabled,
            }
        )

    async def search_schools(self, ctx: _Ctx) -> Response:
        session = ctx.session
        assert session is not None
        app = self.app
        if not app.schools.search_enabled:
            raise _Fail("not_found")
        query = ctx.request.query_params.get("q", "").strip()
        if (
            len(query) < MIN_QUERY_CHARS
            or len(query) > MAX_QUERY_CHARS
            or web._has_control(query)
        ):
            raise _invalid("q", min=MIN_QUERY_CHARS, max=MAX_QUERY_CHARS)
        if not app.search_limiter.allow((session.acct,)):
            raise _Fail("rate_limited", {"retry_after_s": web._SEARCH_LIMIT_WINDOW_SECONDS})
        try:
            entries = await app._directory.search(query)
        except DirectoryError:
            logger.warning("account api school search failed")
            raise _Fail("directory_unavailable") from None
        results = [
            {
                "host": entry.domain,
                "name": _clean(entry.name),
                "sig": app._pick_signature(session, entry.domain),
            }
            for entry in entries
            if not is_blocked_hostname(entry.domain)
        ]
        logger.info("account api school search account=%s results=%d", session.acct, len(results))
        return self._ok({"results": results})

    async def get_write_tools(self, ctx: _Ctx) -> Response:
        assert ctx.session is not None
        snapshot = await self._write_snapshot(ctx.session)
        return self._ok(self._write_tools_view(snapshot))

    async def put_write_tools(self, ctx: _Ctx) -> Response:
        session, body = ctx.session, ctx.body
        assert session is not None and body is not None
        _closed(body, required=("enabled",))
        raw = body["enabled"]
        if (
            not isinstance(raw, list)
            or len(raw) > MAX_ENABLED_TOOLS
            or not all(isinstance(name, str) and _TOOL_NAME_RE.fullmatch(name) for name in raw)
            or len(set(raw)) != len(raw)
        ):
            raise _invalid("enabled")
        snapshot = await self._write_snapshot(session)
        allowed = snapshot.offered | (snapshot.current - snapshot.offered)
        for name in raw:
            if name not in allowed:
                raise _Fail("write_tool_not_allowed", {"tool": name})
        ticked = frozenset(name for name in raw if name in snapshot.offered and user_can_enable(name))
        return await self._save_write_tools(session, snapshot, ticked=ticked, disable_all=False)

    async def delete_write_tools(self, ctx: _Ctx) -> Response:
        assert ctx.session is not None
        snapshot = await self._write_snapshot(ctx.session)
        return await self._save_write_tools(
            ctx.session, snapshot, ticked=frozenset(), disable_all=True
        )

    async def _save_write_tools(
        self,
        session: web._Session,
        snapshot: WriteToolsSnapshot,
        *,
        ticked: frozenset[str],
        disable_all: bool,
    ) -> Response:
        outcome = await self.app.apply_write_tools(
            session, snapshot, ticked=ticked, disable_all=disable_all
        )
        if isinstance(outcome, Refusal):
            raise _refusal_to_fail(outcome)
        fresh = await self._write_snapshot(session)
        return self._ok({"result": outcome.result, **self._write_tools_view(fresh)})

    async def login_history(self, ctx: _Ctx) -> Response:
        session = ctx.session
        assert session is not None
        events = await anyio.to_thread.run_sync(
            self.app.store.list_auth_events, session.acct, HISTORY_LIMIT
        )
        return self._ok(
            {
                "events": [
                    {
                        "at": _ts(event.at),
                        "provider_id": event.provider_id,
                        "outcome": event.outcome
                        if event.outcome in ("success", "pending")
                        else "refused",
                        "reason": event.reason if event.reason in _HISTORY_REASONS else None,
                    }
                    for event in events
                ]
            }
        )

    async def put_ui_locale(self, ctx: _Ctx) -> Response:
        body = ctx.body
        assert body is not None
        _closed(body, required=("locale",))
        locale = body["locale"]
        if locale not in _LOCALES:
            raise _invalid("locale")
        response = self._no_content()
        web._AccountApp._remember_lang(response, str(locale))
        return response

    async def logout(self, ctx: _Ctx) -> Response:
        if ctx.request.url.query:
            raise _invalid("query")
        response = self._no_content()
        self.app.clear_cookie(response, web.SESSION_COOKIE)
        return response

    # -- owner ----------------------------------------------------------------------------------------

    def _enrollment_view(self, row: EnrollmentInfo) -> dict[str, Any]:
        schools = self.app.schools
        default = schools.default
        host = row.canvas_host
        school: dict[str, Any] | None
        if host is None:
            school = (
                {"host": default.host, "name": _clean(default.name), "offered": True, "is_default": True}
                if default is not None
                else None
            )
        else:
            resolved = schools.resolve_stored(host)
            school = {
                "host": host,
                "name": _clean(resolved.name if resolved is not None else host),
                "offered": resolved is not None,
                "is_default": default is not None and host == default.host,
            }
        invalid = row.status == STATUS_INVALID
        return {
            "canvas_user_name": _clean(row.canvas_user_name),
            "canvas_user_id": str(row.canvas_user_id),
            "school": school,
            "state": "invalid" if invalid else "active",
            "invalid_reason": row.invalid_reason if invalid and row.invalid_reason in INVALID_REASONS else None,
            "invalid_since": _ts(row.invalid_since) if invalid else None,
            "last_verified_at": _ts(row.last_verified_at),
            "last_used_at": _ts(row.last_used_at),
            "created_at": _ts(row.created_at),
            "updated_at": _ts(row.updated_at),
        }

    @staticmethod
    def _actions(
        key: str, caller: str, row: EnrollmentInfo | None, status: PrincipalStatus
    ) -> list[str]:
        """What the caller may do to this account, as the HTML admin table offers it."""
        if status.pending:
            return ["approve", "deny"]
        actions: list[str] = []
        if row is not None and row.status != STATUS_INVALID and status.active:
            actions.append("mark_invalid")
        if status.disabled:
            actions.append("enable")
        elif status.missing:
            pass  # an enrollment without an account can only be removed
        elif key != caller:
            actions.append("disable")
        if row is not None:
            actions.append("remove_enrollment")
        return actions

    def _admin_account(
        self,
        session: web._Session,
        status: PrincipalStatus,
        identities: Sequence[Any],
        row: EnrollmentInfo | None,
    ) -> dict[str, Any] | None:
        key = status.principal_key
        account_id = _account_id(key)
        if account_id is None:
            return None
        identity = identities[0] if identities else None
        return {
            "id": account_id,
            "key": key,
            "display_name": _clean(status.display_name),
            "username": _clean(identity.username if identity is not None else "", 254),
            "role": "owner" if status.is_owner else "user",
            "status": status.status,
            "disabled_reason": status.disabled_reason
            if status.disabled and status.disabled_reason in _DISABLED_REASONS
            else None,
            "disabled_at": _ts(status.disabled_at) if status.disabled else None,
            "created_at": _ts(status.created_at) if status.created_at else None,
            "approved_at": _ts(status.approved_at),
            "last_login_at": _ts(status.last_login_at),
            "is_self": key == session.acct,
            "identity": {
                "provider_id": identity.provider_id,
                "tenant_id": identity.tenant_id,
                "subject": identity.subject,
            }
            if identity is not None
            else None,
            "enrollment": self._enrollment_view(row) if row is not None else None,
            "actions": self._actions(key, session.acct, row, status),
        }

    async def admin_accounts(self, ctx: _Ctx) -> Response:
        session = ctx.session
        assert session is not None
        wanted = ctx.request.query_params.get("status")
        if wanted is not None and wanted not in _ADMIN_STATUSES:
            raise _invalid("status")
        accounts = await anyio.to_thread.run_sync(self.app.store.list_accounts)
        enrollments = await anyio.to_thread.run_sync(self.app.store.list_enrollments)
        rows = {row.principal_key: row for row in enrollments}
        shown = [a for a in accounts if wanted is None or a.status.status == wanted]
        shown.sort(key=lambda a: 0 if a.status.pending else 1)
        views = [
            view
            for a in shown
            if (view := self._admin_account(session, a.status, a.identities, rows.get(a.principal_key)))
            is not None
        ]
        return self._ok(
            {
                "accounts": views,
                "counts": {
                    "total": len(accounts),
                    "active": sum(1 for a in accounts if a.status.active),
                    "pending": sum(1 for a in accounts if a.status.pending),
                    "disabled": sum(1 for a in accounts if a.status.disabled),
                    "owners": sum(1 for a in accounts if a.status.active and a.status.is_owner),
                },
            }
        )

    async def admin_enrollments(self, ctx: _Ctx) -> Response:
        session = ctx.session
        assert session is not None
        wanted = ctx.request.query_params.get("filter", "all")
        if wanted not in ("all", web._FILTER_NEEDS_REENROLL):
            raise _invalid("filter")
        only_needing = wanted == web._FILTER_NEEDS_REENROLL
        all_rows = await anyio.to_thread.run_sync(self.app.store.list_enrollments)
        accounts = await anyio.to_thread.run_sync(self.app.store.list_accounts)
        by_key = {a.principal_key: a for a in accounts}
        needing = [row for row in all_rows if row.status == STATUS_INVALID]
        entries: list[tuple[PrincipalStatus, Sequence[Any], EnrollmentInfo | None]] = []
        seen: set[str] = set()
        for row in needing if only_needing else all_rows:
            seen.add(row.principal_key)
            account = by_key.get(row.principal_key)
            if account is not None:
                entries.append((account.status, account.identities, row))
            else:
                entries.append((PrincipalStatus(row.principal_key, status="missing"), (), row))
        if not only_needing:
            # A pending or disabled user without an enrollment must still be listed, or
            # nobody could approve or enable them.
            entries.extend(
                (a.status, a.identities, None)
                for a in accounts
                if (a.status.pending or a.status.disabled) and a.principal_key not in seen
            )
        entries.sort(key=lambda entry: 0 if entry[0].pending else 1)
        views = [
            view
            for status, identities, row in entries
            if (view := self._admin_account(session, status, identities, row)) is not None
        ]
        return self._ok(
            {
                "rows": views,
                "counts": {
                    "needing": len(needing),
                    "total_enrollments": len(all_rows),
                    "disabled": sum(1 for a in accounts if a.status.disabled),
                    "pending": sum(1 for a in accounts if a.status.pending),
                },
            }
        )

    @staticmethod
    def _target(ctx: _Ctx) -> str:
        raw = ctx.params.get("id", "")
        if not _UUID_RE.fullmatch(raw):
            raise _invalid("id")
        return "acct:" + raw

    async def _admin_result(self, ctx: _Ctx, target: str, changed: bool) -> Response:
        """The account as it is now, or 404 when nothing changed because it does not exist."""
        session = ctx.session
        assert session is not None
        store = self.app.store
        status = await anyio.to_thread.run_sync(store.get_principal_status, target)
        if not changed and status.missing:
            raise _Fail("not_found")
        identities = await anyio.to_thread.run_sync(store.account_identities, target)
        row = await anyio.to_thread.run_sync(store.info, target)
        account = self._admin_account(session, status, identities, row)
        return self._ok({"changed": changed, "account": account})

    def _admin_access(
        self, action: Literal["approve", "deny", "disable", "enable"]
    ) -> Callable[[_Ctx], Awaitable[Response]]:
        async def handler(ctx: _Ctx) -> Response:
            assert ctx.session is not None
            target = self._target(ctx)
            outcome = await self.app.change_access(ctx.session, target, action)
            if isinstance(outcome, Refusal):
                raise _refusal_to_fail(outcome)
            return await self._admin_result(ctx, target, outcome)

        return handler

    async def admin_mark_invalid(self, ctx: _Ctx) -> Response:
        assert ctx.session is not None
        target = self._target(ctx)
        if await anyio.to_thread.run_sync(self.app.store.info, target) is None:
            raise _Fail("not_found")
        outcome = await self.app.invalidate_enrollment(ctx.session, target)
        if isinstance(outcome, Refusal):
            raise _refusal_to_fail(outcome)
        return await self._admin_result(ctx, target, outcome)

    async def admin_remove_enrollment(self, ctx: _Ctx) -> Response:
        assert ctx.session is not None
        target = self._target(ctx)
        outcome = await self.app.remove_enrollment(ctx.session, target)
        if isinstance(outcome, Refusal):
            raise _refusal_to_fail(outcome)
        return await self._admin_result(ctx, target, outcome)

    @staticmethod
    def _audit_detail(detail: Mapping[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name, value in detail.items():
            if not isinstance(name, str) or not _FIELD_NAME_RE.fullmatch(name):
                continue
            if isinstance(value, bool) or isinstance(value, int):
                out[name] = value
            elif isinstance(value, str):
                out[name] = _clean(value)
            elif isinstance(value, list):
                out[name] = [_clean(item) for item in value[:100] if isinstance(item, str)]
        return out

    def _audit_entry(self, entry: AuditEntry, names: Mapping[str, str]) -> dict[str, Any]:
        actor_kind = "account"
        if entry.actor == OPERATOR_ACTOR:
            actor_kind = "operator"
        elif entry.actor == SYSTEM_ACTOR:
            actor_kind = "system"
        is_account = actor_kind == "account"
        return {
            "id": entry.id,
            "at": _ts(entry.at),
            "action": entry.action if _AUDIT_ACTION_RE.fullmatch(entry.action) else "unknown",
            "actor": {
                "kind": actor_kind,
                "key": _clean(entry.actor, 128) if is_account else None,
                "name": _clean(names[entry.actor]) if is_account and entry.actor in names else None,
            },
            "target": {
                "key": _clean(entry.target, 128),
                "name": _clean(names[entry.target]) if entry.target in names else None,
            }
            if entry.target
            else None,
            "reason": _clean(entry.reason) if entry.reason else None,
            "detail": self._audit_detail(entry.detail),
        }

    async def admin_audit(self, ctx: _Ctx) -> Response:
        raw = ctx.request.query_params.get("before")
        before: int | None = None
        if raw is not None:
            if not (raw.isascii() and raw.isdigit() and len(raw) < 15):
                raise _invalid("before")
            before = int(raw)
        store = self.app.store
        entries = await anyio.to_thread.run_sync(store.list_audit, AUDIT_PAGE, before)
        accounts = await anyio.to_thread.run_sync(store.list_accounts)
        names = {a.principal_key: a.status.display_name for a in accounts if a.status.display_name}
        return self._ok(
            {
                "entries": [self._audit_entry(entry, names) for entry in entries],
                "next_cursor": str(entries[-1].id) if len(entries) >= AUDIT_PAGE else None,
            }
        )


    # -- connected apps and consent (SELFHOST_AUTH_MODE=local) ------------------------------------

    @staticmethod
    def _grant_view(grant: GrantRecord) -> dict[str, Any]:
        """A connection as the pages show it: who, where it returns to, when. No ids of clients."""
        verified = grant.client_host is not None
        name = _clean(grant.client_name, 100)
        return {
            "id": grant.id,
            "client": {
                "kind": grant.client_kind if grant.client_kind in ("dcr", "cimd") else "dcr",
                "label": _clean(grant.client_host, 253) if grant.client_host else name,
                "name": name,
                "host": _clean(grant.client_host, 253) if grant.client_host else None,
                "verified": verified,
            },
            "redirect_host": _clean(grant.redirect_host, 253),
            "created_at": _ts(grant.created_at),
            "last_used_at": _ts(grant.last_used_at),
            "expires_at": _ts(grant.expires_at),
        }

    @staticmethod
    def _txn(raw: object) -> str:
        """The request id; a malformed one is as good as an unknown one.

        It travels in the query of the read and in the body of the decision, never in the
        path: proxies log paths (nginx ``$uri``), and the query is what their filters blank.
        """
        if not isinstance(raw, str) or not _TXN_ID_RE.fullmatch(raw):
            raise _Fail("authorization_invalid")
        return raw

    def _binding(self, ctx: _Ctx) -> str | None:
        assert self.app.authz is not None
        return ctx.request.cookies.get(self.app.authz.binding_cookie)

    async def get_consent(self, ctx: _Ctx) -> Response:
        from canvas_mcp.core.selfhost.authz.consent import ConsentRefusal

        session = ctx.session
        assert session is not None and self.app.authz is not None
        if set(ctx.request.query_params.keys()) - {"txn"}:
            raise _invalid("query")
        txn = self._txn(ctx.request.query_params.get("txn"))
        try:
            shown = await self.app.authz.consent.describe(
                txn, self._binding(ctx), account_pending=session.pending
            )
        except Exception as exc:  # noqa: BLE001 - never leak details
            logger.error("account api consent read failed: %s", type(exc).__name__)
            raise _Fail("token_store_unavailable") from None
        if isinstance(shown, ConsentRefusal):
            raise _Fail(shown.code)
        verified = shown.verified
        return self._ok(
            {
                "client": {
                    "kind": shown.client_kind if shown.client_kind in ("dcr", "cimd") else "dcr",
                    "label": _clean(shown.label, 253),
                    "name": _clean(shown.client_name, 100),
                    "host": _clean(shown.label, 253) if verified else None,
                    "verified": verified,
                },
                "redirect": {
                    "host": _clean(shown.redirect_host, 253),
                    "loopback": shown.redirect_is_loopback,
                },
                "scopes": [{"name": _clean(name, 128)} for name in shown.scopes],
                "account": {
                    "display_name": _clean(session.name),
                    "username": _clean(session.upn, 254),
                },
                "can_approve": shown.can_approve,
                "expires_at": _ts(shown.expires_at),
            }
        )

    async def post_consent(self, ctx: _Ctx) -> Response:
        from canvas_mcp.core.selfhost.authz.consent import ConsentRefusal

        session, body = ctx.session, ctx.body
        assert session is not None and body is not None and self.app.authz is not None
        if ctx.request.url.query:
            raise _invalid("query")
        _closed(body, required=("txn", "decision"))
        txn = self._txn(body["txn"])
        decision = body["decision"]
        if decision not in _DECISIONS:
            raise _invalid("decision")
        try:
            outcome = await self.app.authz.consent.decide(
                txn,
                self._binding(ctx),
                account_key=session.acct,
                session_iat=session.iat,
                session_epoch=session.ep,
                account_pending=session.pending,
                decision="approve" if decision == "approve" else "deny",
            )
        except Exception as exc:  # noqa: BLE001 - never leak details
            logger.error("account api consent decision failed: %s", type(exc).__name__)
            raise _Fail("token_store_unavailable") from None
        if isinstance(outcome, ConsentRefusal):
            raise _Fail(outcome.code)
        return self._ok({"redirect_to": outcome.url})

    async def my_grants(self, ctx: _Ctx) -> Response:
        assert ctx.session is not None
        grants = await self.app.list_own_grants(ctx.session)
        if isinstance(grants, Refusal):
            raise _refusal_to_fail(grants)
        return self._ok({"grants": [self._grant_view(grant) for grant in grants]})

    @staticmethod
    def _grant_id(ctx: _Ctx) -> str:
        raw = ctx.params.get("id", "")
        if not _UUID_RE.fullmatch(raw):
            raise _invalid("id")
        return raw

    async def delete_my_grant(self, ctx: _Ctx) -> Response:
        assert ctx.session is not None
        outcome = await self.app.revoke_own_grant(ctx.session, self._grant_id(ctx))
        if isinstance(outcome, Refusal):
            raise _refusal_to_fail(outcome)
        if not outcome:
            # Not this account's, unknown, or already over: all the same to the caller.
            raise _Fail("not_found")
        return self._no_content()

    async def admin_account_grants(self, ctx: _Ctx) -> Response:
        assert ctx.session is not None
        grants = await self.app.list_account_grants(ctx.session, self._target(ctx))
        if isinstance(grants, Refusal):
            raise _refusal_to_fail(grants)
        return self._ok({"grants": [self._grant_view(grant) for grant in grants]})

    async def admin_revoke_grant(self, ctx: _Ctx) -> Response:
        assert ctx.session is not None
        outcome = await self.app.owner_revoke_grant(ctx.session, self._grant_id(ctx))
        if isinstance(outcome, Refusal):
            raise _refusal_to_fail(outcome)
        return self._ok({"changed": outcome})


def build_api_routes(app: web._AccountApp) -> list[Route]:
    """The ``/account/api`` routes over an existing account application."""
    return ApiApp(app).routes()

