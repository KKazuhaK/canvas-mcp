"""The browser extension's endpoints, ``/api/v1/extension/*``.

These are not part of the signed-in account API: the extension has no session. It
pairs once with a single-use code and then holds an upload token that works only
here. Origin is a CORS boundary, not authentication; every call except the
capability check still needs a code or the token.

* Only an extension origin (``chrome-extension://<32 letters a-p>`` or
  ``moz-extension://<uuid>``) is answered; CORS replies to those and nobody else.
* A request that carries a ``Cookie`` header is refused: the extension must send
  none, so a cookie means a page in a browser reached this endpoint by accident or
  on purpose with the student's session.
* Rate limited per client address and per binding; request bodies stop at 4 MiB.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from . import account_core as web
from .account_api import _object_pairs, _parse_float, _refuse_constant
from .browser_plan import (
    ALLOWED_PATH,
    MAX_COURSE_LIST_LENGTH,
    MAX_COURSES_PER_BINDING,
    MAX_RESOURCES_PER_UPLOAD,
    PLAN_VERSION,
    SCHEMA_VERSION,
    build_plan,
    expected_resources,
    normalize_upload_query,
    resource_key,
    valid_window,
)
from .browser_store import (
    Binding,
    BindingGone,
    BrowserSyncStore,
    PinConflict,
    QuotaExceeded,
    SnapshotItem,
    rejection_reason,
)
from .config_snapshot import CURRENT_CONFIG
from .db.errors import StoreUnavailable
from .db.workers import run_store
from .limits import build_rate_limiters
from .routes import API_PREFIX
from .schools import is_blocked_hostname, parse_hostname

logger = logging.getLogger("canvas_mcp.selfhost.browser_extension")

EXTENSION_PREFIX = f"{API_PREFIX}/extension"
MAX_BODY_BYTES = 4 * 1024 * 1024
BROWSER_SYNC_VERSION = 1
#: Per binding, after the token is checked.
REQUESTS_PER_MINUTE = 120
#: A process-wide ceiling for requests that carry a valid token.
AUTHENTICATED_REQUESTS_PER_MINUTE = 3000
#: Failures (an unknown token, a wrong code) are counted apart from everything else:
#: the Portal cannot tell clients apart by address (it sees the proxy), so a shared
#: bucket that failures could fill would let one anonymous loop lock every user out.
#: A full failure bucket only turns further failures into 429; a valid token or a
#: valid pairing code never meets it. Codes carry about 60 bits and live five
#: minutes, so a valid code needs no limit of its own.
FAILED_REQUESTS_PER_MINUTE = 600
FAILED_CLAIMS_PER_WINDOW = 600
CLAIM_WINDOW_SECONDS = 600

_CHROME_ORIGIN = re.compile(r"^chrome-extension://[a-p]{32}$")
_FIREFOX_ORIGIN = re.compile(
    r"^moz-extension://[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_BEARER = re.compile(r"^Bearer ([A-Za-z0-9_-]{20,100})$")
_ALLOWED_METHODS = "GET, POST, DELETE"
_FUTURE_SLACK_SECONDS = 300
_EARLIEST = int(dt.datetime(2020, 1, 1, tzinfo=dt.UTC).timestamp())


def is_extension_origin(origin: str | None) -> bool:
    """True for the origin of an installed Chrome or Firefox extension."""
    return bool(origin) and bool(
        _CHROME_ORIGIN.fullmatch(origin or "") or _FIREFOX_ORIGIN.fullmatch(origin or "")
    )


class _Reply(Exception):
    def __init__(
        self, status: int, error: str, headers: Mapping[str, str] | None = None
    ) -> None:
        super().__init__(error)
        self.status = status
        self.error = error
        self.headers = dict(headers or {})


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_pairs,
            parse_constant=_refuse_constant,
            parse_float=_parse_float,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _Reply(400, "invalid_request") from None
    if not isinstance(value, dict):
        raise _Reply(400, "invalid_request")
    return value


def _canvas_host(origin: object) -> str | None:
    """The host of a plain ``https://host`` Canvas origin, or None for anything else."""
    if not isinstance(origin, str) or len(origin) > 300:
        return None
    try:
        parts = urlsplit(origin)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if (
        parts.scheme != "https"
        or host is None
        or parts.username is not None
        or parts.password is not None
        or port not in (None, 443)
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        return None
    normalized = parse_hostname(host)
    if normalized is None or is_blocked_hostname(normalized):
        return None
    return normalized


def _when(value: object) -> int | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return int(parsed.timestamp())


class ExtensionApi:
    """The extension's routes over one account application and one snapshot store."""

    def __init__(self, app: web.AccountCore, store: BrowserSyncStore) -> None:
        self.app = app
        self.store = store
        window = build_rate_limiters("memory").sliding_window
        clock = app.clock
        self.authenticated_limiter = window(AUTHENTICATED_REQUESTS_PER_MINUTE, 60, 1, clock)
        self.binding_limiter = window(REQUESTS_PER_MINUTE, 60, 4096, clock)
        self.failed_token_limiter = window(FAILED_REQUESTS_PER_MINUTE, 60, 1, clock)
        self.failed_claim_limiter = window(
            FAILED_CLAIMS_PER_WINDOW, CLAIM_WINDOW_SECONDS, 1, clock
        )

    # -- routing ------------------------------------------------------------------

    def routes(self) -> list[Route]:
        table = {
            f"{EXTENSION_PREFIX}/capabilities": {"GET": self.capabilities},
            f"{EXTENSION_PREFIX}/claim": {"POST": self.claim},
            f"{EXTENSION_PREFIX}/plan": {"GET": self.plan},
            f"{EXTENSION_PREFIX}/snapshots": {"POST": self.snapshots},
            f"{EXTENSION_PREFIX}/binding": {"DELETE": self.binding},
        }
        return [web.any_method_route(path, self._endpoint(methods)) for path, methods in table.items()]

    def _endpoint(self, methods: dict[str, Any]) -> Any:
        async def endpoint(request: Request) -> Response:
            origin = request.headers.get("origin")
            cors = is_extension_origin(origin)
            marker = CURRENT_CONFIG.set(None)
            try:
                try:
                    return await self._handle(request, methods, origin if cors else None)
                except _Reply as reply:
                    return self._reply(reply.status, {"error": reply.error}, origin if cors else None, reply.headers)
                except StoreUnavailable:
                    return self._reply(503, {"error": "unavailable"}, origin if cors else None)
                except web._StoreUnavailable:
                    return self._reply(503, {"error": "unavailable"}, origin if cors else None)
                except Exception as exc:  # noqa: BLE001 - never leak details
                    logger.error("extension request failed: %s", type(exc).__name__)
                    return self._reply(500, {"error": "internal_error"}, origin if cors else None)
            finally:
                CURRENT_CONFIG.reset(marker)

        return endpoint

    async def _handle(
        self, request: Request, methods: dict[str, Any], origin: str | None
    ) -> Response:
        if "cookie" in request.headers:
            raise _Reply(400, "cookies_not_allowed")
        # A page in a browser always sends Origin on a cross-origin fetch, so a
        # present Origin that is not an extension's is refused. Chrome omits it on
        # GETs from an extension service worker, so an absent one is allowed (with
        # no CORS headers); the bearer token or pairing code still authenticates.
        if origin is None and request.headers.get("origin") is not None:
            raise _Reply(403, "origin_not_allowed")
        if request.method == "OPTIONS":
            if origin is None:
                raise _Reply(403, "origin_not_allowed")
            return Response(
                b"",
                status_code=204,
                headers={
                    **self._cors(origin),
                    "Access-Control-Allow-Methods": _ALLOWED_METHODS,
                    "Access-Control-Allow-Headers": "Authorization, Content-Type",
                    "Access-Control-Max-Age": "600",
                    "Cache-Control": "no-store",
                },
            )
        handler = methods.get(request.method)
        if handler is None:
            raise _Reply(405, "method_not_allowed", {"Allow": ", ".join(sorted(methods))})
        response: Response = await handler(request, origin)
        return response

    # -- responses ------------------------------------------------------------------

    @staticmethod
    def _cors(origin: str) -> dict[str, str]:
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Expose-Headers": "Retry-After",
            "Vary": "Origin",
        }

    def _reply(
        self,
        status: int,
        payload: object | None,
        origin: str | None,
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        merged: dict[str, str] = {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            **(self._cors(origin) if origin else {}),
            **(headers or {}),
        }
        if payload is None:
            return Response(b"", status_code=status, headers=merged)
        merged["Content-Type"] = "application/json; charset=utf-8"
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        return Response(body, status_code=status, headers=merged)

    # -- request helpers --------------------------------------------------------------

    async def _read_json(self, request: Request) -> dict[str, Any]:
        media = request.headers.get("content-type", "").partition(";")[0].strip().lower()
        if media != "application/json":
            raise _Reply(415, "unsupported_media_type")
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                raise _Reply(400, "invalid_request") from None
            if length < 0:
                raise _Reply(400, "invalid_request")
            if length > MAX_BODY_BYTES:
                raise _Reply(413, "payload_too_large")
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > MAX_BODY_BYTES:
                raise _Reply(413, "payload_too_large")
            chunks.append(chunk)
        return _json_object(b"".join(chunks))

    async def _authenticate(self, request: Request) -> Binding:
        """The live binding for the bearer token; failures are counted apart from valid use."""
        match = _BEARER.fullmatch(request.headers.get("authorization", ""))
        binding = None
        if match is not None:
            binding = await run_store(self.store.authenticate, match.group(1))
        if binding is None:
            if not self.failed_token_limiter.allow(("failed",)):
                raise _Reply(429, "rate_limited", {"Retry-After": "60"})
            raise _Reply(401, "invalid_token")
        if not self.binding_limiter.allow((binding.id,)) or not (
            self.authenticated_limiter.allow(("all",))
        ):
            raise _Reply(429, "rate_limited", {"Retry-After": "60"})
        return binding

    # -- endpoints --------------------------------------------------------------------

    async def capabilities(self, request: Request, origin: str | None) -> Response:
        return self._reply(
            200,
            {"browserSync": BROWSER_SYNC_VERSION, "maxBodyBytes": MAX_BODY_BYTES},
            origin,
        )

    async def claim(self, request: Request, origin: str | None) -> Response:
        body = await self._read_json(request)
        if set(body) != {"code"}:
            raise _Reply(400, "invalid_request")
        claimed = await run_store(self.store.claim, body["code"])
        if claimed is None:
            # Only failed claims count; a valid unexpired code is never limited.
            if not self.failed_claim_limiter.allow(("failed",)):
                raise _Reply(429, "rate_limited", {"Retry-After": str(CLAIM_WINDOW_SECONDS)})
            raise _Reply(400, "invalid_code")
        token, binding_id = claimed
        return self._reply(200, {"uploadToken": token, "bindingId": binding_id}, origin)

    async def plan(self, request: Request, origin: str | None) -> Response:
        binding = await self._authenticate(request)
        plan = build_plan(
            canvas_host=binding.canvas_host,
            canvas_user_id=binding.canvas_user_id,
            now=self.app.clock(),
        )
        return self._reply(200, plan, origin)

    async def binding(self, request: Request, origin: str | None) -> Response:
        binding = await self._authenticate(request)
        await run_store(self.store.revoke_account, binding.account_id)
        return self._reply(204, None, origin)

    async def snapshots(self, request: Request, origin: str | None) -> Response:
        binding = await self._authenticate(request)
        body = await self._read_json(request)
        await self.app.refresh_public_config()
        host, user_id, captured_at, raw_resources = self._upload_header(body)
        if host != binding.canvas_host and binding.canvas_host is not None:
            raise _Reply(409, "canvas_mismatch")
        if binding.canvas_user_id not in (None, user_id):
            raise _Reply(409, "canvas_mismatch")
        if self.app.schools.resolve_stored(host) is None:
            raise _Reply(409, "canvas_mismatch")

        uploaded = self._parsed_resources(raw_resources)
        # Expanding the plan and checking every resource is CPU work: off the event loop.
        items, rejected = await run_store(
            self._checked_items, binding.id, user_id, captured_at, uploaded
        )
        try:
            accepted, stale = await run_store(
                lambda: self.store.save(
                    binding.id,
                    canvas_host=host,
                    canvas_user_id=user_id,
                    items=items,
                )
            )
        except PinConflict:
            raise _Reply(409, "canvas_mismatch") from None
        except QuotaExceeded:
            raise _Reply(413, "quota_exceeded") from None
        except BindingGone:
            raise _Reply(401, "invalid_token") from None
        paths = {item.key: item.path for item in items}
        rejected.extend({"path": paths.get(key, key), "reason": reason} for key, reason in stale)
        return self._reply(200, {"accepted": accepted, "rejected": rejected}, origin)

    def _course_decisions(
        self,
        binding_id: str,
        user_id: str,
        captured_at: int,
        uploaded: list[tuple[Any, dict[str, list[str]] | None, Any, Any]],
    ) -> tuple[dict[int, str], set[str]]:
        """Which course lists are refused, and the course ids the binding will then name.

        Each ``/courses`` entry is decided once, the way the store will decide it: the
        first valid entry of a key is the only one written, and only if it would replace
        the stored row (``rejection_reason``). A list an upload really replaces stops
        counting its old ids, so a new term can roll over; one that replaces nothing
        (older, a transient failure, refused, a repeat) leaves its stored ids counting.
        """
        base = expected_resources((), user_id)
        first: list[tuple[int, str, int, Any]] = []
        seen: set[str] = set()
        for index, (path, query, status, content) in enumerate(uploaded):
            if path != "/courses" or query is None:
                continue
            if self._reject_reason(path, query, status, content, base, seen) is not None:
                continue
            key = resource_key(path, query)
            seen.add(key)
            first.append((index, key, status, content))
        stored = self.store.stored_state(binding_id, [key for _, key, _, _ in first])
        refused: dict[int, str] = {}
        writing = []
        for index, key, status, content in first:
            if rejection_reason(stored.get(key), captured_at, status) is not None:
                continue
            if status == 200 and len(content) > MAX_COURSE_LIST_LENGTH:
                refused[index] = "too_many_courses"
                continue
            writing.append((index, key, status, content))
        replacing = {key for _, key, _, _ in writing}
        while True:
            known = self.store.course_ids(binding_id, excluding=replacing)
            over: set[int] = set()
            for index, _key, status, content in writing:
                if status != 200 or index in over:
                    continue
                ids = {
                    str(c["id"])
                    for c in content
                    if isinstance(c, dict)
                    and isinstance(c.get("id"), int)
                    and not isinstance(c.get("id"), bool)
                }
                if len(known | ids) > MAX_COURSES_PER_BINDING:
                    over.add(index)
                else:
                    known |= ids
            if not over:
                return refused, known
            for index in over:
                refused[index] = "too_many_courses"
            writing = [entry for entry in writing if entry[0] not in over]
            replacing = {key for _, key, _, _ in writing}

    def _checked_items(
        self,
        binding_id: str,
        user_id: str,
        captured_at: int,
        uploaded: list[tuple[Any, dict[str, list[str]] | None, Any, Any]],
    ) -> tuple[list[SnapshotItem], list[dict[str, str]]]:
        """Validate an upload against the plan: the items to store, and the rejections."""
        refused, known = self._course_decisions(binding_id, user_id, captured_at, uploaded)
        expected = expected_resources(known, user_id)

        items: list[SnapshotItem] = []
        rejected: list[dict[str, str]] = []
        seen: set[str] = set()
        for index, (path, query, status, content) in enumerate(uploaded):
            reason = refused.get(index) or self._reject_reason(
                path, query, status, content, expected, seen
            )
            if index in refused and isinstance(path, str) and query is not None:
                # A refused first copy still is "the first": a repeat must not slip in.
                seen.add(resource_key(path, query))
            if reason is not None or query is None:
                rejected.append(
                    {
                        "path": path if isinstance(path, str) else "",
                        "reason": reason or "invalid_resource",
                    }
                )
                continue
            key = resource_key(path, query)
            seen.add(key)
            items.append(
                SnapshotItem(
                    key=key,
                    path=path,
                    query=query,
                    captured_at=captured_at,
                    status=status,
                    body=content if status == 200 else None,
                )
            )
        return items, rejected

    # -- upload validation ---------------------------------------------------------------

    def _upload_header(self, body: dict[str, Any]) -> tuple[str, str, int, list[Any]]:
        if body.get("schemaVersion") != SCHEMA_VERSION or isinstance(body.get("schemaVersion"), bool):
            raise _Reply(400, "unsupported_schema")
        if body.get("planVersion") != PLAN_VERSION or isinstance(body.get("planVersion"), bool):
            raise _Reply(409, "plan_outdated")
        host = _canvas_host(body.get("canvasOrigin"))
        if host is None:
            raise _Reply(409, "canvas_mismatch")
        raw_user = body.get("canvasUserId")
        if isinstance(raw_user, bool) or not isinstance(raw_user, (int, str)):
            raise _Reply(400, "invalid_request")
        user_id = str(raw_user)
        if not re.fullmatch(r"[1-9][0-9]{0,19}", user_id):
            raise _Reply(400, "invalid_request")
        captured_at = _when(body.get("capturedAt"))
        if (
            captured_at is None
            or captured_at < _EARLIEST
            or captured_at > self.app.clock() + _FUTURE_SLACK_SECONDS
        ):
            raise _Reply(400, "invalid_request")
        resources = body.get("resources")
        if not isinstance(resources, list) or len(resources) > MAX_RESOURCES_PER_UPLOAD:
            raise _Reply(400, "invalid_request")
        return host, user_id, captured_at, resources

    @staticmethod
    def _parsed_resources(
        raw: list[Any],
    ) -> list[tuple[Any, dict[str, list[str]] | None, Any, Any]]:
        parsed: list[tuple[Any, dict[str, list[str]] | None, Any, Any]] = []
        for entry in raw:
            if not isinstance(entry, dict):
                parsed.append((None, None, None, None))
                continue
            parsed.append(
                (
                    entry.get("path"),
                    normalize_upload_query(entry.get("query", {})),
                    entry.get("status"),
                    entry.get("body"),
                )
            )
        return parsed

    @staticmethod
    def _reject_reason(
        path: Any,
        query: dict[str, list[str]] | None,
        status: Any,
        content: Any,
        expected: Mapping[str, bool],
        seen: set[str],
    ) -> str | None:
        if (
            not isinstance(path, str)
            or query is None
            or isinstance(status, bool)
            or not isinstance(status, int)
            or not 100 <= status <= 599
            or not ALLOWED_PATH.fullmatch(path)
        ):
            return "invalid_resource"
        if status == 200 and not isinstance(content, (list, dict)):
            return "invalid_resource"
        key = resource_key(path, query)
        if key not in expected:
            return "not_in_plan"
        has_window = "start_date" in query or "end_date" in query
        if expected[key]:
            if not valid_window(query):
                return "invalid_resource"
        elif has_window:
            return "invalid_resource"
        if key in seen:
            return "duplicate_in_upload"
        return None


def build_extension_routes(app: web.AccountCore, store: BrowserSyncStore) -> list[Route]:
    """The ``/api/v1/extension`` routes over an existing account application."""
    return ExtensionApi(app, store).routes()
