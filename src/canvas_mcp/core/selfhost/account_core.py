"""Shared account sessions and operations behind the v1 JSON API and sign-in flows."""

from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
import urllib.parse
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta, tzinfo
from typing import TYPE_CHECKING, Any, Literal

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route, request_response
from starlette.types import Receive, Scope, Send

from canvas_mcp.core import audit
from canvas_mcp.core.dates import output_timezone
from canvas_mcp.core.selfhost.account_ops import (
    LINK_ERROR_CODES,
    IdentityView,
    Linked,
    LinkStarted,
    Rechecked,
    Refusal,
    Unlinked,
    WriteSaved,
    WriteToolsSnapshot,
)
from canvas_mcp.core.selfhost.accounts import (
    DENY_ACCESS_DENIED,
    DENY_ACCESS_DISABLED,
    DENY_BAD_ROLES,
    DENY_BAD_SUBJECT,
    DENY_SIGNUPS_PAUSED,
    DENY_UNAVAILABLE,
    DENY_WRONG_TENANT,
    PROVIDER_ENTRA,
    REASON_MEMBERSHIP_UNAVAILABLE,
    Denied,
    valid_account_key,
)
from canvas_mcp.core.selfhost.identity import IdentityService, SignIn
from canvas_mcp.core.selfhost.limits import (
    RateLimiters,
    build_rate_limiters,
)
from canvas_mcp.core.selfhost.schools import (
    DirectoryError,
    HostResolver,
    School,
    SchoolDirectory,
    SchoolDirectoryLike,
    SchoolPolicy,
    check_public_host,
    is_blocked_hostname,
    parse_hostname,
    system_resolve,
)
from canvas_mcp.core.selfhost.token_health import TokenHealth
from canvas_mcp.core.selfhost.token_store import (
    DISABLE_REASON_ADMIN,
    REASON_REVOKED_BY_ADMIN,
    STATUS_INVALID,
    AccessActionRefused,
    EnrollmentInfo,
    PrincipalDisabledError,
    PrincipalMissingError,
    PrincipalPendingError,
    TokenDecryptionError,
    TokenStore,
)
from canvas_mcp.core.selfhost.tool_prefs import (
    ToolPrefsCache,
    WriteToolCatalog,
)

from .config_snapshot import CURRENT_CONFIG, ConfigSnapshots
from .custody import CustodyAcknowledgement
from .db.workers import run_store
from .pagination import DEFAULT_LIMIT, Page
from .routes import ACCOUNT_PREFIX as ACCOUNT_PATH
from .routes import AUTH_LOGIN as _LOGIN_PATH  # noqa: F401 - shared API contract
from .routes import SIGN_IN_PAGE as SIGN_IN_PATH

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from canvas_mcp.core.selfhost.account_spa import SpaBundle
    from canvas_mcp.core.selfhost.authz.models import GrantRecord
    from canvas_mcp.core.selfhost.authz.runtime import AuthzRuntime
    from canvas_mcp.core.selfhost.login.flows import ExternalSignIn
    from canvas_mcp.core.selfhost.login.registry import LoginRuntime

logger = logging.getLogger("canvas_mcp.selfhost.account")


SIGN_IN_METHODS_PATH = "/account/sign-in-methods"
CONSENT_PATH = "/account/consent"

SESSION_COOKIE = "__Host-cmcp_session"
LANG_COOKIE = "canvas_mcp_lang"
_IAT_SKEW_SECONDS = 600
_MAX_BODY_BYTES = 8192
_RATE_LIMIT_ATTEMPTS = 10
_RATE_LIMIT_WINDOW_SECONDS = 600
_RATE_LIMIT_MAX_KEYS = 1024
_RECHECK_LIMIT_ATTEMPTS = 1
_RECHECK_LIMIT_WINDOW_SECONDS = 60
_FRESH_SIGN_IN_SECONDS = 600
_SESSION_VERSION = 3
_SIGN_IN_HISTORY = 20
_AUDIT_PAGE = 100
_SESSION_SCOPE_KEY = "canvas_mcp.session"
_EXPIRY_REMINDER_DAYS = 7
_EXPIRY_MAX_YEARS = 10
_FILTER_NEEDS_REENROLL = "needs_reenroll"
_SEARCH_LIMIT_ATTEMPTS = 30
_SEARCH_LIMIT_WINDOW_SECONDS = 600


class _AnyMethodApp:
    """An ASGI app that hands a request of *any* HTTP method to ``handler``.

    A ``Route`` with a method list answers every other verb (``PROPFIND``, ``TRACE``,
    anything custom) with Starlette's own plain-text 405, which carries none of the
    response headers the handler adds. A route without a method list lets the handler
    produce the refusal itself, headers included.
    """

    def __init__(self, handler: Callable[[Request], Awaitable[Response]]) -> None:
        self.handler = handler
        self._app = request_response(handler)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._app(scope, receive, send)


def any_method_route(
    path: str, handler: Callable[[Request], Awaitable[Response]]
) -> Route:
    """A route for ``path`` that dispatches every HTTP method to ``handler``."""
    return Route(path, _AnyMethodApp(handler), methods=None)


_RETURN_TO_MAX_CHARS = 512
_RETURN_TO_FORBIDDEN_PREFIXES = ("/api", "/auth")
SIGN_IN_ERROR_CODES = frozenset(
    {
        "state_invalid",
        "provider_error",
        "sign_in_incomplete",
        "sign_in_unverified",
        DENY_WRONG_TENANT,
        DENY_BAD_SUBJECT,
        DENY_BAD_ROLES,
        DENY_ACCESS_DENIED,
        DENY_ACCESS_DISABLED,
        DENY_SIGNUPS_PAUSED,
        "token_store_unavailable",
        "authorization_invalid",
        "rate_limited",
    }
)

_TOKEN_RE = re.compile(r"^[A-Za-z0-9~._-]{20,512}$")

_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)
_TXN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Content-Security-Policy": _CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@dataclass(frozen=True)
class CanvasIdentity:
    user_id: str
    name: str


class CanvasCheckError(Exception):
    """Canvas token verification failed: ``invalid`` or ``unavailable``."""

    def __init__(self, kind: Literal["invalid", "unavailable"]) -> None:
        super().__init__(kind)
        self.kind: Literal["invalid", "unavailable"] = kind


CanvasWhoAmI = Callable[[str, str], Awaitable[CanvasIdentity]]


@dataclass(frozen=True)
class AccountConfig:
    public_base_url: str
    session_secret: bytes = field(repr=False)
    session_ttl_seconds: int = 900


def sanitize_return_to(value: str | None) -> str | None:
    """A same-site path below ``/account`` to return to after sign-in, else None.

    Used only by the react UI, and the same rules as the page's own check: at most
    512 ASCII characters; starts with ``/account``; not the API, the login or the
    callback; no ``//``, backslash, control character, ``.`` or ``..`` segment; and
    all of that again after percent-decoding (repeatedly, so a double-encoded trick
    fails too). Anything else is dropped and the user lands on ``/account/``.
    """
    if not isinstance(value, str) or not value or len(value) > _RETURN_TO_MAX_CHARS:
        return None
    candidate = value
    for _ in range(4):
        if not _return_to_clean(candidate):
            return None
        decoded = urllib.parse.unquote(candidate)
        if decoded == candidate:
            return value
        candidate = decoded
    return None


def _return_to_clean(text: str) -> bool:
    if not text.isascii() or _has_control(text) or "\\" in text or "//" in text:
        return False
    path = re.split(r"[?#]", text, maxsplit=1)[0]
    if not path.startswith(ACCOUNT_PATH + "/"):
        return False
    if any(segment in (".", "..") for segment in path.split("/")):
        return False
    lowered = path.lower()
    return not any(
        lowered == prefix or lowered.startswith(prefix + "/")
        for prefix in _RETURN_TO_FORBIDDEN_PREFIXES
    )


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class _CookieCodec:
    """AES-256-GCM sealed JSON cookies; the cookie name is the associated data."""

    _PREFIX = "v1."

    def __init__(self, secret: bytes) -> None:
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"canvas-mcp-account",
            info=b"cookie-aead-v1",
        ).derive(secret)
        self._aead = AESGCM(key)

    def seal(self, name: str, payload: Mapping[str, Any]) -> str:
        nonce = secrets.token_bytes(12)
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        sealed = self._aead.encrypt(nonce, data, name.encode("ascii"))
        return self._PREFIX + _b64url(nonce + sealed)

    def unseal(self, name: str, value: str | None) -> dict[str, Any] | None:
        """Return the payload, or None for anything missing or invalid."""
        if not value or not value.startswith(self._PREFIX):
            return None
        try:
            raw = _b64url_decode(value[len(self._PREFIX) :])
            if len(raw) < 12 + 16:
                return None
            data = self._aead.decrypt(raw[:12], raw[12:], name.encode("ascii"))
            payload = json.loads(data.decode("utf-8"))
        except Exception:  # noqa: BLE001 - any decode failure means "absent"
            return None
        return payload if isinstance(payload, dict) else None


@dataclass(frozen=True)
class _Session:
    acct: str
    name: str
    upn: str
    owner: bool
    csrf: str
    exp: int
    iat: int = 0
    ep: int = 0
    pid: str = PROVIDER_ENTRA
    pending: bool = False


class _StoreUnavailable(Exception):
    """The access status could not be read, so no session can be trusted (fail closed)."""


_UNAVAILABLE = object()


def _has_control(text: str) -> bool:
    return any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in text)


def _display_tz() -> tzinfo:
    try:
        return output_timezone()
    except Exception:  # noqa: BLE001 - never fail a page over a timezone
        return UTC


def _fmt_utc_date(value: int) -> str:
    """The calendar date a user typed for a token expiry (stored as midnight UTC)."""
    try:
        return datetime.fromtimestamp(value, tz=UTC).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return "-"


def _parse_expiry(raw: str, now: float) -> int | None | Literal["invalid"]:
    """The expiry date from the optional form field as epoch seconds (midnight UTC).

    ``None`` for an empty field; ``"invalid"`` for anything that is not a real
    calendar date between today and ``_EXPIRY_MAX_YEARS`` years ahead.
    """
    text = raw.strip()
    if not text:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return "invalid"
    try:
        day = date.fromisoformat(text)
    except ValueError:
        return "invalid"
    today = datetime.fromtimestamp(now, tz=UTC).date()
    if day < today or day > today + timedelta(days=365 * _EXPIRY_MAX_YEARS):
        return "invalid"
    return int(datetime(day.year, day.month, day.day, tzinfo=UTC).timestamp())


Handler = Callable[[Request], Awaitable[Response]]


class AccountCore:
    authz: AuthzRuntime
    logins: LoginRuntime
    external: ExternalSignIn

    def __init__(
        self,
        cfg: AccountConfig,
        store: TokenStore,
        identity: IdentityService,
        canvas_whoami: CanvasWhoAmI | None,
        http_client_factory: Callable[[], httpx.AsyncClient] | None,
        clock: Callable[[], float],
        *,
        directory: SchoolDirectoryLike | None = None,
        resolve_host: HostResolver | None = None,
        health: TokenHealth | None = None,
        write_tools: WriteToolCatalog | None = None,
        tool_prefs: ToolPrefsCache | None = None,
        rate_limiters: RateLimiters | None = None,
        authz: AuthzRuntime,
        logins: LoginRuntime,
        snapshots: ConfigSnapshots,
    ) -> None:
        window = (rate_limiters or build_rate_limiters("memory")).sliding_window
        self.authz = authz
        self.logins = logins
        self.session_pids: frozenset[str] = logins.accepted_pids
        self.snapshots = snapshots
        from canvas_mcp.core.selfhost.login.flows import ExternalSignIn

        self.external = ExternalSignIn(self, logins)
        self.cfg = cfg
        self.write_tools = write_tools
        self.tool_prefs = tool_prefs
        self.base = cfg.public_base_url.rstrip("/")
        self.store = store
        self.identity = identity
        self.clock = clock
        self.codec = _CookieCodec(cfg.session_secret)
        self._ua_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"canvas-mcp-account",
            info=b"auth-event-ua-v1",
        ).derive(cfg.session_secret)
        self.limiter = window(
            _RATE_LIMIT_ATTEMPTS,
            _RATE_LIMIT_WINDOW_SECONDS,
            _RATE_LIMIT_MAX_KEYS,
            clock,
        )
        self.recheck_limiter = window(
            _RECHECK_LIMIT_ATTEMPTS,
            _RECHECK_LIMIT_WINDOW_SECONDS,
            _RATE_LIMIT_MAX_KEYS,
            clock,
        )
        self.health = health or TokenHealth(store, account_url=self.base + ACCOUNT_PATH)
        self.search_limiter = window(
            _SEARCH_LIMIT_ATTEMPTS,
            _SEARCH_LIMIT_WINDOW_SECONDS,
            _RATE_LIMIT_MAX_KEYS,
            clock,
        )
        self.link_limiter = window(5, 600, _RATE_LIMIT_MAX_KEYS, clock)
        self.unlink_limiter = window(10, 600, _RATE_LIMIT_MAX_KEYS, clock)
        self._client_factory = http_client_factory or (
            lambda: httpx.AsyncClient(timeout=10, follow_redirects=False)
        )
        self._directory: SchoolDirectoryLike = directory or SchoolDirectory(
            client_factory=self._client_factory
        )
        self._resolve_host: HostResolver = resolve_host or system_resolve
        self._canvas_whoami = canvas_whoami or self._default_whoami

    @property
    def schools(self) -> SchoolPolicy:
        return (CURRENT_CONFIG.get() or self.snapshots.current).schools

    async def refresh_public_config(self) -> None:
        revision = await run_store(self.snapshots.revision)
        CURRENT_CONFIG.set(await run_store(self.snapshots.get, revision))

    @staticmethod
    def _remember_lang(response: Response, lang: str) -> None:
        response.set_cookie(
            LANG_COOKIE,
            lang,
            max_age=365 * 86400,
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
        )

    def finish(self, response: Response) -> Response:
        for name, value in _SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    def redirect(
        self, location: str, status: int = 303, *, csp: str | None = None
    ) -> Response:
        response = self.finish(
            Response(b"", status_code=status, headers={"Location": location})
        )
        if csp is not None:
            response.headers["Content-Security-Policy"] = csp
        return response

    def _cookie_kwargs(self) -> dict[str, Any]:
        return {"path": "/", "secure": True, "httponly": True, "samesite": "lax"}

    def clear_cookie(self, response: Response, name: str) -> None:
        response.delete_cookie(name, **self._cookie_kwargs())

    def session_from(self, request: Request) -> _Session | None:
        payload = self.codec.unseal(SESSION_COOKIE, request.cookies.get(SESSION_COOKIE))
        if payload is None or payload.get("v") != _SESSION_VERSION:
            return None
        try:
            acct, pid = payload["acct"], payload["pid"]
            name, upn, csrf = payload["name"], payload["upn"], payload["csrf"]
            owner, exp, epoch = payload["owner"], payload["exp"], payload["ep"]
        except KeyError:
            return None
        if not (
            isinstance(acct, str)
            and isinstance(pid, str)
            and isinstance(name, str)
            and isinstance(upn, str)
            and isinstance(csrf, str)
            and isinstance(owner, bool)
            and isinstance(exp, int)
            and not isinstance(exp, bool)
            and isinstance(epoch, int)
            and not isinstance(epoch, bool)
            and epoch >= 0
        ):
            return None
        if (
            exp <= self.clock()
            or not valid_account_key(acct)
            or pid not in self.session_pids
            or not csrf
        ):
            return None
        raw_iat = payload.get("iat")
        iat = (
            raw_iat if isinstance(raw_iat, int) and not isinstance(raw_iat, bool) else 0
        )
        return _Session(acct, name, upn, owner, csrf, exp, iat, epoch, pid)

    async def _resolve_session(self, request: Request) -> _Session | None:
        """The session in the cookie, accepted only if the stored decision still allows it.

        Read from the database on every request (no cache): the session must be
        refused as soon as the account is disabled, denied or gone, or the epoch moved
        on. A pending account keeps its session (the page tells it to wait) but is
        marked ``pending``. The owner role in the cookie is a snapshot, so it is kept
        only while the stored role agrees and the account is active. A database error
        raises, and the caller fails closed.
        """
        cookie = self.session_from(request)
        if cookie is None:
            return None
        stored = await run_store(self.store.read_session_snapshot, cookie.acct)
        if (
            stored is None
            or stored.status not in ("active", "pending")
            or stored.session_epoch != cookie.ep
        ):
            return None
        CURRENT_CONFIG.set(
            await run_store(self.snapshots.get, stored.settings_revision)
        )
        return replace(
            cookie,
            owner=cookie.owner and stored.role == "owner" and stored.status == "active",
            pending=stored.status == "pending",
        )

    @staticmethod
    def _session_of(request: Request) -> _Session | None:
        """The verified session of this request (see :meth:`_resolve_session`)."""
        value = request.scope.get(_SESSION_SCOPE_KEY)
        if value is _UNAVAILABLE:
            raise _StoreUnavailable
        return value if isinstance(value, _Session) else None

    def _signed_in_recently(self, session: _Session) -> bool:
        """True when this session was issued within the last ``_FRESH_SIGN_IN_SECONDS``."""
        age = self.clock() - session.iat
        return session.iat > 0 and -_IAT_SKEW_SECONDS <= age <= _FRESH_SIGN_IN_SECONDS

    def _csrf_ok(self, session: _Session, supplied: str | None) -> bool:
        if not supplied:
            return False
        return hmac.compare_digest(
            supplied.encode("utf-8"), session.csrf.encode("utf-8")
        )

    def _pick_signature(self, session: _Session, host: str) -> str:
        """Proof that ``host`` came from this session's own school search results."""
        message = (
            b"school-pick|" + session.csrf.encode("utf-8") + b"|" + host.encode("ascii")
        )
        return _b64url(
            hmac.new(self.cfg.session_secret, message, hashlib.sha256).digest()
        )

    def _identity_confirmation(
        self, session: _Session, host: str, enrolled_user_id: str, new_user_id: str
    ) -> str:
        """Proof that this session was warned about switching to exactly this Canvas user.

        Bound to the session, the school, the user enrolled now and the user the
        pasted token belongs to, so a confirmation cannot be sent ahead of the
        warning and does not carry over to a token for a third user.
        """
        message = "|".join(
            ("identity-change", session.csrf, host, enrolled_user_id, new_user_id)
        ).encode("utf-8")
        return _b64url(
            hmac.new(self.cfg.session_secret, message, hashlib.sha256).digest()
        )

    def settings_url(self, info: EnrollmentInfo) -> str | None:
        """The school's own Canvas settings page, where tokens are made (https only)."""
        school = self.schools.resolve_stored(info.canvas_host)
        if school is None or not school.api_url.startswith("https://"):
            return None
        base = re.sub(r"/api/v\d+/?$", "", school.api_url.rstrip("/"))
        return f"{base}/profile/settings"

    def _ua_hash(self, request: Request) -> str | None:
        """16 hex characters of a keyed hash of the user agent (never the user agent itself)."""
        agent = request.headers.get("user-agent", "")[:512]
        if not agent:
            return None
        return hmac.new(
            self._ua_key, agent.encode("utf-8", "replace"), hashlib.sha256
        ).hexdigest()[:16]

    async def _login_txn(self, request: Request) -> tuple[str | None, Response | None]:
        """The authorization transaction waiting for this sign-in, and an early answer if there is one.

        With the local authorization server an app can be waiting (``?txn=``): the request must
        exist and belong to this browser before anything else happens; a person who is already
        signed in goes straight to the consent page unless they asked for another account
        (``reauth=1``).
        """
        if "txn" not in request.query_params:
            return None, None
        txn_id = request.query_params.get("txn", "")
        binding = request.cookies.get(self.authz.binding_cookie)
        if not await self.authz.consent.txn_open(txn_id, binding):
            return None, self._authorization_invalid()
        session = self._session_of(request)
        reauth = request.query_params.get("reauth") == "1"
        if session is not None and not reauth and (session.pending or session.iat > 0):
            return txn_id, self.redirect(
                f"{CONSENT_PATH}?{urllib.parse.urlencode({'txn': txn_id})}", 303
            )
        return txn_id, None

    @staticmethod
    def _carry(
        txn_id: str | None, reauth: bool, return_to: str | None
    ) -> dict[str, str]:
        """The validated values a provider start needs to know about (nothing else is passed on)."""
        carried: dict[str, str] = {}
        if txn_id is not None:
            carried["txn"] = txn_id
        if reauth:
            carried["reauth"] = "1"
        if return_to is not None:
            carried["return_to"] = return_to
        return carried

    async def _choose_provider(self, request: Request) -> Response:
        assert self.logins is not None
        txn_id, early = await self._login_txn(request)
        if early is not None:
            return early
        reauth = request.query_params.get("reauth") == "1"
        return_to = None
        if txn_id is None:
            return_to = sanitize_return_to(request.query_params.get("return_to"))
        carried = self._carry(txn_id, reauth, return_to)
        entries = self.logins.entries()
        if len(entries) == 1:
            suffix = "?" + urllib.parse.urlencode(carried) if carried else ""
            return self.redirect(entries[0].start_path + suffix, 303)
        suffix = "?" + urllib.parse.urlencode(carried) if carried else ""
        return self.redirect(SIGN_IN_PATH + suffix, 303)

    def _provider_failure(self, code: str, status: int, provider: Any) -> Response:
        """Return only a closed failure code to the sign-in screen."""
        return self._sign_in_failure(code)

    def _link_redirect(self, outcome: Linked | Refusal) -> Response:
        """Back to the sign-in methods screen after a link ceremony: ``?linked=1`` or ``?error=<code>``."""
        if isinstance(outcome, Linked):
            query = {"linked": "1"}
        else:
            query = {
                "error": outcome.code
                if outcome.code in LINK_ERROR_CODES
                else "provider_error"
            }
        return self.redirect(
            f"{SIGN_IN_METHODS_PATH}?{urllib.parse.urlencode(query)}", 303
        )

    def _session_payload(
        self,
        *,
        acct: str,
        pid: str,
        name: str,
        upn: str,
        owner: bool,
        iat: int,
        exp: int,
        csrf: str,
        epoch: int,
    ) -> str:
        """The sealed session cookie (version 3) for an account."""
        return self.codec.seal(
            SESSION_COOKIE,
            {
                "v": _SESSION_VERSION,
                "acct": acct,
                "pid": pid,
                "name": name[:200],
                "upn": upn[:254],
                "owner": owner,
                "iat": iat,
                "exp": exp,
                "csrf": csrf,
                "ep": epoch,
            },
        )

    def _reissue_session(self, session: _Session, epoch: int) -> str:
        """The same session under a new session epoch (an unlink kept the caller signed in)."""
        return self._session_payload(
            acct=session.acct,
            pid=session.pid,
            name=session.name,
            upn=session.upn,
            owner=session.owner,
            iat=session.iat,
            exp=session.exp,
            csrf=session.csrf,
            epoch=epoch,
        )

    def _complete_sign_in(
        self, outcome: SignIn, *, now: float, waiting: Any, return_to: Any
    ) -> Response:
        """The session cookie and the landing page of a successful sign-in (every provider)."""
        standing = outcome.status
        sign_in_key = standing.principal_key
        if standing.owner_change is not None:
            audit.log_principal_event(
                standing.owner_change, sign_in_key, reason="sign_in"
            )

        issued = int(now)
        sealed = self._session_payload(
            acct=sign_in_key,
            pid=outcome.ext.provider_id,
            name=outcome.ext.display_name,
            upn=outcome.ext.username,
            owner=bool(outcome.owner),
            iat=issued,
            exp=issued + self.cfg.session_ttl_seconds,
            csrf=secrets.token_urlsafe(32),
            epoch=standing.session_epoch,
        )
        logger.info(
            "account sign-in ok account=%s pending=%s", sign_in_key, outcome.pending
        )
        landing = ACCOUNT_PATH
        landing = ACCOUNT_PATH + "/"
        if isinstance(return_to, str) and sanitize_return_to(return_to) is not None:
            landing = return_to
        if isinstance(waiting, str) and _TXN_ID_RE.fullmatch(waiting):
            landing = f"{CONSENT_PATH}?{urllib.parse.urlencode({'txn': waiting})}"
        response = self.redirect(landing, 303)
        response.set_cookie(
            SESSION_COOKIE,
            sealed,
            max_age=self.cfg.session_ttl_seconds,
            **self._cookie_kwargs(),
        )
        return response

    async def _admission_lost(self, denied: Denied) -> None:
        """A person who is no longer admitted signed in again: end the apps they had connected.

        This is where a removal at the identity provider reaches existing connections
        (their access tokens do not carry roles). Best effort: the sign-in is refused
        either way.
        """
        key = getattr(denied, "account_key", None)
        if denied.code != DENY_ACCESS_DENIED or not key:
            return
        if getattr(denied, "reason", None) == REASON_MEMBERSHIP_UNAVAILABLE:
            return
        count = await self.authz.admission_lost(key)
        if count:
            logger.info(
                "account admission lost: %d connected app(s) ended account=%s",
                count,
                key,
            )

    def _authorization_invalid(self) -> Response:
        return self._sign_in_failure("authorization_invalid")

    def _sign_in_refused(self, denied: Denied) -> Response:
        key = getattr(denied, "account_key", None)
        if denied.code == DENY_ACCESS_DISABLED and key:
            audit.log_principal_event("sign_in_refused", key, reason="access_disabled")
        logger.info("account sign-in refused reason=%s account=%s", denied.code, key)
        return self._sign_in_failure(self._sign_in_error_code(denied))

    @staticmethod
    def _sign_in_error_code(denied: Denied) -> str:
        """The identity layer's code for the react sign-in page (a closed set)."""
        if denied.code == DENY_UNAVAILABLE:
            return "token_store_unavailable"
        return denied.code if denied.code in SIGN_IN_ERROR_CODES else DENY_ACCESS_DENIED

    def _sign_in_failure(self, code: str) -> Response:
        if code not in SIGN_IN_ERROR_CODES:
            code = "provider_error"
        return self.redirect(
            f"{SIGN_IN_PATH}?{urllib.parse.urlencode({'error': code})}", 303
        )

    async def list_own_grants(
        self,
        session: _Session,
        *,
        cursor: str | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> Page[GrantRecord] | Refusal:
        """The apps connected to the signed-in account, newest first."""
        try:
            return await self.authz.grants_page(
                session.acct, cursor=cursor, limit=limit
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("account list grants failed: %s", type(exc).__name__)
            return Refusal("token_store_unavailable")

    async def revoke_own_grant(
        self, session: _Session, grant_id: str
    ) -> bool | Refusal:
        """End one of the signed-in account's connections; True if it was live."""
        try:
            return await self.authz.revoke_own_grant(grant_id, session.acct)
        except Exception as exc:  # noqa: BLE001
            logger.error("account revoke grant failed: %s", type(exc).__name__)
            return Refusal("token_store_unavailable")

    async def list_account_grants(
        self,
        session: _Session,
        target: str,
        *,
        cursor: str | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> Page[GrantRecord] | Refusal:
        """An owner reads another account's connections (owner, signed in within ten minutes)."""
        refusal = self._owner_op_refusal(session)
        if refusal is not None:
            return refusal
        try:
            return await self.authz.grants_page(target, cursor=cursor, limit=limit)
        except Exception as exc:  # noqa: BLE001
            logger.error("account list grants failed: %s", type(exc).__name__)
            return Refusal("token_store_unavailable")

    async def owner_revoke_grant(
        self, session: _Session, grant_id: str
    ) -> bool | Refusal:
        """An owner ends any connection. The store re-checks the owner inside its transaction."""
        refusal = self._owner_op_refusal(session)
        if refusal is not None:
            return refusal
        try:
            return await self.authz.owner_revoke_grant(grant_id, session.acct)
        except AccessActionRefused:
            return Refusal("forbidden")
        except Exception as exc:  # noqa: BLE001
            logger.error("account owner revoke grant failed: %s", type(exc).__name__)
            return Refusal("token_store_unavailable")

    def _owner_op_refusal(self, session: _Session) -> Refusal | None:
        if not session.owner:
            return Refusal("forbidden")
        if not self._signed_in_recently(session):
            return Refusal("reauth_required")
        return None

    async def _default_whoami(self, token: str, api_url: str) -> CanvasIdentity:
        url = api_url.rstrip("/") + "/users/self"
        try:
            async with self._client_factory() as client:
                resp = await client.get(
                    url,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                    },
                    timeout=10.0,
                    follow_redirects=False,
                )
            if resp.status_code in (401, 403):
                raise CanvasCheckError("invalid")
            if resp.status_code != 200:
                raise CanvasCheckError("unavailable")
            data = resp.json()
        except CanvasCheckError:
            raise
        except (httpx.HTTPError, ValueError):
            raise CanvasCheckError("unavailable") from None
        if not isinstance(data, dict) or data.get("id") is None:
            raise CanvasCheckError("unavailable")
        name = data.get("name") or data.get("short_name") or ""
        return CanvasIdentity(str(data["id"]), str(name)[:200])

    async def enroll_token(
        self,
        session: _Session,
        *,
        token_raw: str,
        expires_raw: str,
        school_raw: str,
        confirm_raw: str,
        custody: CustodyAcknowledgement,
        pick_signature: str | None = None,
        require_pick_signature: bool = False,
    ) -> School | Refusal:
        """Verify a pasted Canvas token with Canvas and store it; the school, or why not.

        The one sequence behind both ``POST /account/token`` and the JSON API, in
        this order: rate limit, token shape, expiry date, the school (operator
        list or directory, then DNS), Canvas itself, the identity-change
        confirmation, and the store's own check that the account is still active.
        Nothing is sent to a school before the school checks have passed.

        ``require_pick_signature`` (the JSON API) additionally demands that a school
        taken from the directory carries the signature of this session's own search
        results (``pick_signature``); the HTML form has no such proof and keeps the
        directory's confirmation as its only check.
        """
        custody.validate(now=int(self.clock()))
        if not self.limiter.allow((session.acct,)):
            return Refusal(
                "rate_limited", {"retry_after_s": _RATE_LIMIT_WINDOW_SECONDS}
            )
        token = token_raw.strip()
        if not _TOKEN_RE.fullmatch(token):
            return Refusal("token_invalid_format")
        expiry = _parse_expiry(expires_raw, self.clock())
        if isinstance(expiry, str):
            return Refusal("validation_failed", {"field": "expires_on"})
        if require_pick_signature:
            enrolled = await run_store(self._safe_info, session)
            needs_proof = self._directory_pick(school_raw, enrolled)
            if needs_proof is not None and not (
                pick_signature
                and hmac.compare_digest(
                    pick_signature.encode("utf-8"),
                    self._pick_signature(session, needs_proof).encode("utf-8"),
                )
            ):
                return Refusal("school_selection_unverified")
        chosen = await self._choose_school(school_raw)
        if not isinstance(chosen, School):
            return Refusal(chosen)
        school = chosen
        try:
            identity = await self._canvas_whoami(token, school.api_url)
        except CanvasCheckError as exc:
            return Refusal(
                "token_rejected" if exc.kind == "invalid" else "canvas_unavailable"
            )
        existing = await run_store(self._safe_info, session)
        if existing is not None and self._identity_changed(existing, school, identity):
            principal_key = self._principal_key(session)
            confirmation = self._identity_confirmation(
                session, school.host, existing.canvas_user_id, identity.user_id
            )
            if not hmac.compare_digest(
                confirm_raw.encode("utf-8"),
                confirmation.encode("utf-8"),
            ):
                logger.warning(
                    "account token identity change needs confirmation account=%s",
                    session.acct,
                )
                audit.log_token_event(
                    "identity_change_detected",
                    principal_key,
                    outcome="confirmation_required",
                )
                return Refusal(
                    "identity_change_required",
                    {
                        "enrolled_user_name": existing.canvas_user_name,
                        "new_user_name": identity.name,
                        "confirmation": confirmation,
                    },
                )
            logger.warning(
                "account token identity change confirmed account=%s", session.acct
            )
            audit.log_token_event(
                "identity_change_confirmed", principal_key, outcome="confirmed"
            )
        try:
            await run_store(
                functools.partial(
                    self.store.put,
                    principal_key=session.acct,
                    api_token=token,
                    canvas_user_id=identity.user_id,
                    canvas_user_name=identity.name,
                    canvas_host=school.host,
                    expires_hint_at=expiry,
                    custody=custody,
                )
            )
        except PrincipalDisabledError:
            audit.log_principal_event("enroll_refused", self._principal_key(session))
            return Refusal("access_disabled")
        except PrincipalPendingError:
            audit.log_principal_event(
                "enroll_refused", self._principal_key(session), reason="pending"
            )
            return Refusal("pending_approval")
        except PrincipalMissingError:
            audit.log_principal_event(
                "enroll_refused", self._principal_key(session), reason="missing"
            )
            return Refusal("forbidden")
        except Exception as exc:  # noqa: BLE001
            logger.error("account token save failed: %s", type(exc).__name__)
            return Refusal("token_store_unavailable")
        self.health.forget(self._principal_key(session))
        logger.info(
            "account token enrolled account=%s host=%s", session.acct, school.host
        )
        return school

    def _directory_pick(self, raw: str, enrolled: EnrollmentInfo | None) -> str | None:
        """The host that must carry a search signature, or None when no proof is needed.

        Only a well-formed public host that would be confirmed by the directory
        needs one: the operator's default, a featured school and the school the
        account is enrolled at already are trusted, and anything malformed or
        unoffered is refused by the school checks with its own code.
        """
        policy = self.schools
        value = raw.strip().lower()
        if not value or not policy.search_enabled:
            return None
        host = parse_hostname(value)
        if host is None or is_blocked_hostname(host):
            return None
        if policy.featured_school(host) is not None:
            return None
        if (
            enrolled is not None
            and enrolled.canvas_host == host
            and policy.resolve_stored(enrolled.canvas_host) is not None
        ):
            return None
        return host

    @staticmethod
    def _principal_key(session: _Session) -> str:
        return session.acct

    def _identity_changed(
        self, existing: EnrollmentInfo, school: School, identity: CanvasIdentity
    ) -> bool:
        """True when the token is for another Canvas user than the one enrolled, same school.

        Canvas user ids are per school, so a different id at a different school
        means nothing and is not a change.
        """
        enrolled_host = existing.canvas_host
        if enrolled_host is None or enrolled_host != school.host:
            return False
        return existing.canvas_user_id != identity.user_id

    async def _choose_school(self, raw: str) -> School | str:
        """The school to enroll at, or the code of the refusal.

        Nothing is sent to the school (or anywhere else) before every check has
        passed: syntax, the operator's list or the directory's confirmation, and
        the public-address check on what the name resolves to.
        """
        policy = self.schools
        value = raw.strip().lower()
        if not value:
            sole = policy.sole_school
            if sole is None:
                return (
                    "school_required" if policy.picker_enabled else "school_not_offered"
                )
            return await self._public_school_or_refusal(sole)
        host = parse_hostname(value)
        if host is None:
            return "school_invalid"
        school = policy.featured_school(host) or next(
            (s for s in policy.private if s.host == host), None
        )
        if is_blocked_hostname(host) and (school is None or not school.allow_private):
            return "school_invalid"
        if school is None:
            if not policy.search_enabled:
                return "school_not_offered"
            try:
                entry = await self._directory.confirm(host)
            except DirectoryError:
                return "directory_unavailable"
            if entry is None:
                return "school_not_in_directory"
            school = School(host, f"https://{host}/api/v1", entry.name)
        return await self._public_school_or_refusal(school)

    async def _public_school_or_refusal(self, school: School) -> School | str:
        """Refuse a school whose name does not resolve, or resolves to a non-public address.

        Only explicitly allowed private schools skip the public-address check.
        """
        if school.allow_private:
            return school
        verdict = await check_public_host(school.host, self._resolve_host)
        if verdict == "unresolvable":
            return "school_unresolvable"
        if verdict == "blocked":
            return "school_address_blocked"
        return school

    def _safe_info(self, session: _Session) -> EnrollmentInfo | None:
        try:
            return self.store.info(session.acct)
        except Exception:  # noqa: BLE001
            return None

    async def delete_own_token(self, session: _Session) -> bool:
        """A self-disconnect: remove the user's own token and nothing else; True if one existed.

        It is not an authorization decision, so it does not touch the access status.
        """
        removed = bool(await run_store(self.store.delete, session.acct))
        logger.info("account token deleted account=%s", session.acct)
        if removed:
            audit.log_principal_event("self_disconnected", self._principal_key(session))
        return removed

    async def recheck_own_token(self, session: _Session) -> Rechecked | Refusal:
        """Probe Canvas once with the stored token; restore it if Canvas accepts it.

        Once a minute per account. ``not_found`` (nothing stored) and
        ``recheck_not_allowed`` (an administrator's decision) end the attempt
        without asking Canvas; a token that is not invalid, or that was replaced
        while Canvas was asked, is ``unchanged``.
        """
        if not self.recheck_limiter.allow((session.acct,)):
            return Refusal(
                "rate_limited", {"retry_after_s": _RECHECK_LIMIT_WINDOW_SECONDS}
            )
        info = await run_store(self._safe_info, session)
        if info is None:
            return Refusal("not_found")
        if info.status != STATUS_INVALID:
            return Rechecked("unchanged")
        if info.invalid_reason == REASON_REVOKED_BY_ADMIN:
            return Refusal("recheck_not_allowed")
        principal_key = self._principal_key(session)
        school = self.schools.resolve_stored(info.canvas_host)
        if school is None:
            return Refusal("school_not_offered")
        try:
            stored = await run_store(self.store.get, session.acct)
        except TokenDecryptionError:
            audit.log_token_event("recheck", principal_key, outcome="unreadable")
            return Refusal("token_unreadable")
        if stored is None:
            return Refusal("not_found")
        try:
            await self._canvas_whoami(stored.api_token, school.api_url)
        except CanvasCheckError as exc:
            if exc.kind == "invalid":
                logger.info("account recheck still rejected account=%s", session.acct)
                audit.log_token_event(
                    "recheck", principal_key, outcome="still_rejected"
                )
                return Refusal("token_rejected")
            audit.log_token_event("recheck", principal_key, outcome="unavailable")
            return Refusal("canvas_unavailable")
        restored = await run_store(
            functools.partial(
                self.store.restore_active,
                principal_key,
                expected_updated_at=info.updated_at,
                expected_generation=stored.credential_generation,
            )
        )
        if not restored:
            return Rechecked("unchanged")
        self.health.forget(principal_key)
        logger.info("account recheck restored account=%s", session.acct)
        audit.log_token_event("recheck", principal_key, outcome="restored")
        return Rechecked("restored")

    async def read_write_tools(self, session: _Session) -> WriteToolsSnapshot:
        """What the server offers and what this account has on. Raises when unreadable."""
        assert self.write_tools is not None
        offered = await self.write_tools.offered()
        prefs = await run_store(self.store.get_tool_prefs, self._principal_key(session))
        return WriteToolsSnapshot(offered, prefs)

    async def apply_write_tools(
        self,
        session: _Session,
        snapshot: WriteToolsSnapshot,
        *,
        ticked: frozenset[str],
        disable_all: bool,
    ) -> WriteSaved | Refusal:
        """Store the new switches for the account; turning one on needs a recent sign-in.

        ``ticked`` are the tools the user wants on (names the server does not offer are
        dropped); names kept from an earlier choice that the server no longer offers
        stay as they are, unless ``disable_all``. Behind both the HTML form and the JSON
        API, this is the only place that writes the switches.
        """
        key = self._principal_key(session)
        offered = snapshot.offered
        current = snapshot.current
        if disable_all:
            desired: frozenset[str] = frozenset()
        else:
            desired = frozenset(name for name in ticked if name in offered) | (
                current - offered
            )
        turned_on = desired - current
        turned_off = current - desired

        if turned_on and not self._signed_in_recently(session):
            audit.log_write_tools_event(
                "refused",
                key,
                enabled=turned_on,
                disabled=(),
                outcome="sign_in_too_old",
            )
            return Refusal("reauth_required", {"max_age_s": _FRESH_SIGN_IN_SECONDS})
        if not turned_on and not turned_off:
            return WriteSaved("unchanged")

        try:
            await run_store(functools.partial(self.store.set_tool_prefs, key, desired))
        except Exception as exc:  # noqa: BLE001
            logger.error("account write tools save failed: %s", type(exc).__name__)
            return Refusal("write_tools_unavailable")
        if self.tool_prefs is not None:
            self.tool_prefs.invalidate(key)
        audit.log_write_tools_event(
            "cleared" if not desired else "changed",
            key,
            enabled=turned_on,
            disabled=turned_off,
        )
        logger.info(
            "account write tools changed account=%s on=%d off=%d",
            session.acct,
            len(turned_on),
            len(turned_off),
        )
        return WriteSaved("saved")

    async def list_own_identities(
        self, session: _Session
    ) -> list[IdentityView] | Refusal:
        """The caller's linked identities (see ``login.linking``)."""
        return await self.external.linking.list_own(session)

    async def start_link(
        self, session: _Session, provider_id: str
    ) -> LinkStarted | Refusal:
        """Prepare a link ceremony for the caller; nothing changes until the callback completes it."""
        return await self.external.linking.start(session, provider_id)

    async def unlink_own_identity(
        self, session: _Session, identity_id: str
    ) -> Unlinked | Refusal:
        """Remove one of the caller's identities (they keep at least one)."""
        return await self.external.linking.unlink_own(session, identity_id)

    async def owner_unlink_identity(
        self, session: _Session, target: str, identity_id: str
    ) -> Unlinked | Refusal:
        """An owner removes an identity from any account."""
        return await self.external.linking.owner_unlink(session, target, identity_id)

    async def invalidate_enrollment(
        self, session: _Session, target: str
    ) -> bool | Refusal:
        """Owner action: mark an enrollment invalid (``revoked_by_admin``); True if it changed.

        The store re-checks inside the transaction that the acting account is still an
        active owner.
        """
        actor = self._principal_key(session)
        try:
            changed = await self.health.mark_invalid(
                target, REASON_REVOKED_BY_ADMIN, actor=actor
            )
        except AccessActionRefused as exc:
            audit.log_principal_event("refused", target, actor=actor, outcome=exc.code)
            return Refusal(self._access_refusal_code(exc.code))
        logger.info(
            "account admin mark invalid by account=%s target=%s changed=%s",
            session.acct,
            target,
            changed,
        )
        return changed

    async def remove_enrollment(self, session: _Session, target: str) -> bool | Refusal:
        """Owner action: delete a user's stored token (nothing else); True if one existed.

        The store re-checks inside the transaction that the acting account is still an
        active owner.
        """
        actor = self._principal_key(session)
        try:
            removed = bool(
                await run_store(
                    functools.partial(self.store.delete, target, actor=actor)
                )
            )
        except AccessActionRefused as exc:
            audit.log_principal_event("refused", target, actor=actor, outcome=exc.code)
            return Refusal(self._access_refusal_code(exc.code))
        if removed:
            audit.log_principal_event("enrollment_removed", target, actor=actor)
        logger.info(
            "account admin remove enrollment by account=%s target=%s",
            session.acct,
            target,
        )
        return removed

    @staticmethod
    def _access_refusal_code(code: str) -> str:
        """The closed code for an access change the store refused."""
        if code == AccessActionRefused.LAST_OWNER:
            return "last_owner"
        if code == AccessActionRefused.SELF:
            return "cannot_disable_self"
        return "forbidden"

    async def change_access(
        self,
        session: _Session,
        target: str,
        action: Literal["disable", "enable", "approve", "deny"],
    ) -> bool | Refusal:
        """Owner action on an account's access; True if it changed anything.

        The store re-checks inside the transaction that the acting account is still an
        active owner, and refuses to disable the actor or the last usable owner. The
        MCP side's access cache is dropped for the target afterwards.
        """
        actor = self._principal_key(session)
        try:
            if action == "disable":
                changed = await run_store(
                    functools.partial(
                        self.store.disable_principal,
                        target,
                        actor=actor,
                        reason=DISABLE_REASON_ADMIN,
                        listed_providers=self.identity.login_providers,
                    )
                )
            else:
                method = {
                    "enable": self.store.enable_principal,
                    "approve": self.store.approve_account,
                    "deny": self.store.deny_account,
                }[action]
                changed = await run_store(
                    functools.partial(method, target, actor=actor)
                )
        except AccessActionRefused as exc:
            audit.log_principal_event("refused", target, actor=actor, outcome=exc.code)
            return Refusal(self._access_refusal_code(exc.code))
        except Exception as exc:  # noqa: BLE001
            logger.error("account admin %s failed: %s", action, type(exc).__name__)
            return Refusal("token_store_unavailable")
        if changed:
            if action == "disable":
                audit.log_principal_event(
                    "disabled", target, actor=actor, reason=DISABLE_REASON_ADMIN
                )
            else:
                audit.log_principal_event(
                    {"enable": "enabled", "approve": "approved", "deny": "denied"}[
                        action
                    ],
                    target,
                    actor=actor,
                )
        logger.info(
            "account admin %s by account=%s target=%s changed=%s",
            action,
            session.acct,
            target,
            changed,
        )
        return bool(changed)


def build_account_app(
    cfg: AccountConfig,
    store: TokenStore,
    identity: IdentityService,
    *,
    authz: AuthzRuntime,
    logins: LoginRuntime,
    canvas_whoami: CanvasWhoAmI | None = None,
    http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
    clock: Callable[[], float] = time.time,
    **options: Any,
) -> AccountCore:
    """Build the shared operations; no page rendering or alternative UI exists."""
    return AccountCore(
        cfg,
        store,
        identity,
        canvas_whoami,
        http_client_factory,
        clock,
        authz=authz,
        logins=logins,
        **options,
    )


def build_account_routes(
    cfg: AccountConfig,
    store: TokenStore,
    identity: IdentityService,
    *,
    spa: SpaBundle,
    authz: AuthzRuntime,
    logins: LoginRuntime,
    **options: Any,
) -> list[Route]:
    from .account_api import build_api_routes
    from .account_spa import build_spa_routes
    from .login.routes import build_login_routes

    app = build_account_app(cfg, store, identity, authz=authz, logins=logins, **options)
    return build_login_routes(app) + build_api_routes(app) + build_spa_routes(spa)


def register_account_routes(
    mcp: FastMCP,
    cfg: AccountConfig,
    store: TokenStore,
    identity: IdentityService,
    **options: Any,
) -> None:
    for route in build_account_routes(cfg, store, identity, **options):
        if route.methods is None:
            mcp._additional_http_routes.append(route)
        else:
            mcp.custom_route(route.path, methods=sorted(route.methods))(route.endpoint)
