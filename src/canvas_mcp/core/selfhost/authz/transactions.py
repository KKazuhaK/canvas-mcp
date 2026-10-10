"""A pending ``/authorize`` request, and the database-backed login-state store it lives in.

``/authorize`` cannot answer with a code: the user has to sign in at ``/account`` and
approve the app first. The request therefore becomes a *transaction* (a
:class:`PendingAuthorization`) stored for ten minutes under an unguessable id, and the
browser is sent to ``/account/login?txn=<id>``.

The transaction is **bound to the browser that made the ``/authorize`` request**: that
browser gets a ``__Host-cmcp_bind`` cookie (random, HttpOnly, Secure, SameSite=Lax) and the
store keeps only its SHA-256. Every later step (the login page, the consent page, the
decision) needs the cookie. A link to ``/account/login?txn=...`` that reaches another
browser (a phishing message, a leaked log line) is therefore refused: that browser has no
cookie whose hash matches. SameSite=Lax is deliberate: the chain passes through
``claude.ai``, this server, Microsoft and back, and a Strict cookie would not be sent on
the cross-site navigation that returns from Microsoft.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256

import anyio.to_thread

from ..db.engine import Database
from ..db.repos import Repositories

TXN_KIND = "mcp_txn"
TXN_TTL_S = 600
BINDING_COOKIE = "__Host-cmcp_bind"
BINDING_COOKIE_MAX_AGE = TXN_TTL_S
MAX_PAYLOAD_BYTES = 4096
MAX_TTL_SECONDS = 3600

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")

MAX_CLIENT_ID_CHARS = 512
MAX_REDIRECT_URI_CHARS = 2048
MAX_STATE_CHARS = 1024
MAX_SCOPES = 8
MAX_SCOPE_CHARS = 64
MAX_RESOURCE_CHARS = 512


def token_ok(value: object) -> bool:
    """True for a 43-character base64url value (what ``secrets.token_urlsafe(32)`` makes)."""
    return isinstance(value, str) and _TOKEN_RE.fullmatch(value) is not None


def binding_ok(value: object) -> bool:
    """Whether a ``__Host-cmcp_bind`` cookie value has the shape this server issues."""
    return token_ok(value)


def txn_id_ok(value: object) -> bool:
    return token_ok(value)


def new_binding() -> str:
    return secrets.token_urlsafe(32)


def binding_hash(value: str) -> str:
    """SHA-256 hex of a binding cookie value (the only form that is stored)."""
    return sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PendingAuthorization:
    """An ``/authorize`` request that passed every check and waits for sign-in and consent."""

    client_id: str
    client_kind: str
    redirect_uri: str
    redirect_uri_explicit: bool
    code_challenge: str
    scopes: tuple[str, ...]
    state: str | None
    resource: str
    created_at: int
    v: int = 1

    def to_json(self) -> bytes:
        if (
            not 0 < len(self.client_id) <= MAX_CLIENT_ID_CHARS
            or not 0 < len(self.redirect_uri) <= MAX_REDIRECT_URI_CHARS
            or (self.state is not None and len(self.state) > MAX_STATE_CHARS)
            or not 0 < len(self.scopes) <= MAX_SCOPES
            or any(not 0 < len(s) <= MAX_SCOPE_CHARS for s in self.scopes)
            or not 0 < len(self.resource) <= MAX_RESOURCE_CHARS
        ):
            raise ValueError("pending authorization out of bounds")
        raw = json.dumps(
            {
                "v": self.v,
                "client_id": self.client_id,
                "client_kind": self.client_kind,
                "redirect_uri": self.redirect_uri,
                "explicit": self.redirect_uri_explicit,
                "code_challenge": self.code_challenge,
                "scopes": list(self.scopes),
                "state": self.state,
                "resource": self.resource,
                "created_at": self.created_at,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        if len(raw) > MAX_PAYLOAD_BYTES:
            raise ValueError("pending authorization too large")
        return raw

    @classmethod
    def from_json(cls, raw: bytes | str) -> PendingAuthorization:
        """Parse a stored transaction; raises ``ValueError`` for anything unexpected."""
        try:
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get("v") != 1:
                raise ValueError("unsupported")
            scopes = data["scopes"]
            state = data["state"]
            if (
                not isinstance(scopes, list)
                or not all(isinstance(s, str) for s in scopes)
                or not (state is None or isinstance(state, str))
                or not isinstance(data["explicit"], bool)
                or isinstance(data["created_at"], bool)
                or not isinstance(data["created_at"], int)
            ):
                raise ValueError("shape")
            pending = cls(
                client_id=_text(data["client_id"]),
                client_kind=_text(data["client_kind"]),
                redirect_uri=_text(data["redirect_uri"]),
                redirect_uri_explicit=data["explicit"],
                code_challenge=_text(data["code_challenge"]),
                scopes=tuple(scopes),
                state=state,
                resource=_text(data["resource"]),
                created_at=data["created_at"],
            )
        except (KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("invalid pending authorization") from None
        pending.to_json()  # the same bounds as on the way in
        return pending


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("shape")
    return value


class SqlLoginStateStore:
    """The :class:`~canvas_mcp.core.selfhost.login_state.LoginStateStore` over ``login_states``.

    Rows hold the SHA-256 of the id (a database dump does not yield usable ids), the
    SHA-256 of the binding, a UTF-8 text payload and the expiry. ``pop`` is one conditional
    ``DELETE`` whose ``rowcount`` decides who gets the payload, so two concurrent callers
    (even from two processes) can never both receive it. Storage errors are not caught:
    they fail closed.
    """

    def __init__(
        self,
        db: Database,
        *,
        clock: Callable[[], float] = time.time,
        pause_hook: Callable[[str], None] | None = None,
    ) -> None:
        self._db = db
        self._repos = Repositories(db.kind)
        self._clock = clock
        self.pause_hook = pause_hook

    def _now(self) -> int:
        return int(self._clock())

    # -- synchronous core (used by the async protocol methods and by the race tests) -------

    def put_sync(
        self, kind: str, payload: bytes, ttl_s: float, *, binding_hash: str | None = None
    ) -> str:
        if not kind or not 0 < ttl_s <= MAX_TTL_SECONDS or len(payload) > MAX_PAYLOAD_BYTES:
            raise ValueError("invalid login state")
        text = payload.decode("utf-8")  # raises ValueError for non-text payloads
        state_id = secrets.token_urlsafe(32)
        now = self._now()
        with self._db.row_write() as conn:
            self._repos.login_states.insert(
                conn,
                kind=kind,
                id_hash=sha256(state_id.encode("utf-8")).hexdigest(),
                binding_hash=binding_hash,
                payload=text,
                now=now,
                expires_at=now + int(ttl_s),
            )
        return state_id

    def peek_sync(self, kind: str, state_id: str, *, binding_hash: str | None = None) -> bytes | None:
        if not token_ok(state_id):
            return None
        with self._db.read() as conn:
            value = self._repos.login_states.peek(
                conn,
                kind=kind,
                id_hash=sha256(state_id.encode("utf-8")).hexdigest(),
                binding_hash=binding_hash,
                now=self._now(),
            )
        return None if value is None else value.encode("utf-8")

    def pop_sync(self, kind: str, state_id: str, *, binding_hash: str | None = None) -> bytes | None:
        if not token_ok(state_id):
            return None
        id_hash = sha256(state_id.encode("utf-8")).hexdigest()
        now = self._now()
        with self._db.row_write() as conn:
            value = self._repos.login_states.peek(
                conn, kind=kind, id_hash=id_hash, binding_hash=binding_hash, now=now
            )
            if self.pause_hook is not None:
                self.pause_hook("after_txn_select")
            if value is None:
                return None
            won = self._repos.login_states.delete_matching(
                conn, kind=kind, id_hash=id_hash, binding_hash=binding_hash, now=now
            )
        return value.encode("utf-8") if won else None

    # -- the LoginStateStore protocol ------------------------------------------------------

    async def put(
        self, kind: str, payload: bytes, ttl_s: float, *, binding_hash: str | None = None
    ) -> str:
        return await anyio.to_thread.run_sync(
            lambda: self.put_sync(kind, payload, ttl_s, binding_hash=binding_hash)
        )

    async def pop(
        self, kind: str, state_id: str, *, binding_hash: str | None = None
    ) -> bytes | None:
        return await anyio.to_thread.run_sync(
            lambda: self.pop_sync(kind, state_id, binding_hash=binding_hash)
        )

    async def peek(
        self, kind: str, state_id: str, *, binding_hash: str | None = None
    ) -> bytes | None:
        return await anyio.to_thread.run_sync(
            lambda: self.peek_sync(kind, state_id, binding_hash=binding_hash)
        )


__all__ = [
    "BINDING_COOKIE",
    "TXN_KIND",
    "TXN_TTL_S",
    "PendingAuthorization",
    "SqlLoginStateStore",
    "binding_hash",
    "binding_ok",
    "new_binding",
    "txn_id_ok",
]
