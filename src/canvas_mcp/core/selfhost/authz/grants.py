"""Grants: minting tokens, the replay rules, and the per-process status cache.

:class:`GrantService` is the async face of :class:`~.store.AuthzStore` for the token
endpoint and the request path. It turns the store's outcomes into either an
``OAuthToken`` or a ``TokenError`` (never an ``assert``), mints the access JWT only
*after* the transaction committed, and keeps the status cache honest.

**The status cache.** Every MCP request carries an access token that is valid for up to
an hour by its signature alone, so each request also asks "is this grant still live and is
its account still active?". That answer is cached in this process for
``GRANT_STATUS_CACHE_S`` seconds, keyed by grant. A revocation or a disabling made in this
process invalidates the entry at once; one made by another process (a second worker, the
operator CLI) is noticed within the cache time. A read that started before an invalidation
cannot store its (possibly old) answer afterwards, and errors are never cached.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from typing import Any

import anyio.to_thread
from mcp.server.auth.provider import TokenError
from mcp.shared.auth import OAuthToken

from ...logging import log_info, log_warning
from ..settings import AuthzSettings
from .models import (
    REVOKE_ACCOUNT_DISABLED,
    REVOKE_ADMISSION_LOST,
    ExchangeOutcome,
    GrantRecord,
    GrantStatus,
    RotateOutcome,
)
from .store import LAST_USED_GRANULARITY_SECONDS, AuthzStore
from .tokens import AccessTokenCodec, hash_secret, new_refresh_token

_MAX_CACHED_GRANTS = 8192


class GrantStatusCache:
    """``grant id -> GrantStatus`` for a few seconds. Thread-safe; ``ttl <= 0`` caches nothing."""

    def __init__(
        self,
        ttl: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = _MAX_CACHED_GRANTS,
    ) -> None:
        self._ttl = ttl
        self._clock = clock
        self._max = max_entries
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, tuple[float, GrantStatus]] = OrderedDict()
        self._epoch = 0

    @property
    def epoch(self) -> int:
        with self._lock:
            return self._epoch

    def get(self, grant_id: str) -> GrantStatus | None:
        if self._ttl <= 0:
            return None
        with self._lock:
            entry = self._entries.get(grant_id)
            if entry is None:
                return None
            if entry[0] <= self._clock():
                del self._entries[grant_id]
                return None
            return entry[1]

    def put(self, grant_id: str, status: GrantStatus, epoch: int) -> None:
        """Remember an answer read after ``epoch`` was taken, unless something was invalidated since."""
        if self._ttl <= 0:
            return
        with self._lock:
            if epoch != self._epoch:
                return
            self._entries[grant_id] = (self._clock() + self._ttl, status)
            self._entries.move_to_end(grant_id)
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)

    def invalidate(self, grant_id: str) -> None:
        with self._lock:
            self._epoch += 1
            self._entries.pop(grant_id, None)

    def invalidate_account(self, account_id: str) -> None:
        """Forget every grant of an account (``account_id`` is the bare uuid)."""
        with self._lock:
            self._epoch += 1
            for key in [k for k, (_, s) in self._entries.items() if s.account_id == account_id]:
                del self._entries[key]

    def clear(self) -> None:
        with self._lock:
            self._epoch += 1
            self._entries.clear()


# -- fixed token error texts (never a detail from the database or the request) -------------

_CODE_INVALID = "The authorization code is not valid."
_REFRESH_INVALID = "The refresh token is not valid."
_REAUTH = "The sign-in has expired. Sign in again."


def _refusal(description: str, reason: str) -> TokenError:
    log_warning("oauth_token_refused", reason=reason)
    return TokenError(error="invalid_grant", error_description=description)


class GrantService:
    """Issue and rotate tokens, answer "is this grant live", and revoke."""

    def __init__(
        self,
        store: AuthzStore,
        codec: AccessTokenCodec,
        cache: GrantStatusCache,
        settings: AuthzSettings,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.codec = codec
        self.cache = cache
        self.settings = settings
        self._clock = clock

    # -- minting ---------------------------------------------------------------------------

    def _mint(self, grant: GrantRecord, scopes: Sequence[str], refresh: str | None) -> OAuthToken:
        """The access token (and refresh token) for a committed grant. Synchronous: may read the epoch."""
        now = int(self._clock())
        expires_at = min(
            now + self.settings.access_token_ttl,
            grant.expires_at,
            grant.upstream_auth_at + self.settings.max_upstream_auth_age,
        )
        if expires_at <= now:
            raise _refusal(_REFRESH_INVALID, "grant_expired")
        issued = self.codec.encode(
            account_key=grant.account_key,
            client_id=grant.client_id,
            grant_id=grant.id,
            scopes=scopes,
            expires_at=expires_at,
        )
        return OAuthToken(
            access_token=issued.token,
            token_type="Bearer",
            expires_in=expires_at - now,
            scope=" ".join(scopes),
            refresh_token=refresh,
        )

    # -- the token endpoint ----------------------------------------------------------------

    async def issue_from_code(self, client: Any, code: Any) -> OAuthToken:
        """Exchange an authorization code for tokens (see ``AuthzStore.exchange_code``)."""
        refresh_raw = new_refresh_token() if "refresh_token" in client.grant_types else None
        result = await anyio.to_thread.run_sync(
            lambda: self.store.exchange_code(
                code_hash=code.code_hash,
                client_id=client.client_id,
                grant_id=str(uuid.uuid4()),
                refresh_hash=None if refresh_raw is None else hash_secret(refresh_raw),
            )
        )
        outcome = result.outcome
        grant = result.grant
        if outcome in (ExchangeOutcome.WON, ExchangeOutcome.GRACE) and grant is not None:
            if outcome is ExchangeOutcome.GRACE:
                log_info("oauth_token_refused", reason="code_replay_grace")
            refresh = refresh_raw if result.refresh_issued else None
            return await anyio.to_thread.run_sync(lambda: self._mint(grant, grant.scopes, refresh))
        if outcome is ExchangeOutcome.REPLAY_REVOKED and grant is not None:
            self.cache.invalidate(grant.id)
            raise _refusal(_CODE_INVALID, "code_replay")
        if outcome is ExchangeOutcome.REAUTH:
            raise _refusal(_REAUTH, "reauth_required")
        raise _refusal(_CODE_INVALID, f"code_{outcome.value}")

    async def rotate(self, client: Any, refresh: Any, scopes: Sequence[str]) -> OAuthToken:
        """Exchange a refresh token for a new pair (see ``AuthzStore.rotate_refresh``)."""
        new_raw = new_refresh_token()
        result = await anyio.to_thread.run_sync(
            lambda: self.store.rotate_refresh(token_hash=refresh.token_hash, new_hash=hash_secret(new_raw))
        )
        outcome = result.outcome
        grant = result.grant
        if outcome in (RotateOutcome.ROTATED, RotateOutcome.GRACE) and grant is not None:
            if outcome is RotateOutcome.GRACE:
                log_info("oauth_token_refused", reason="grace_reissued")
            granted = list(scopes) or list(grant.scopes)
            return await anyio.to_thread.run_sync(lambda: self._mint(grant, granted, new_raw))
        if grant is not None and outcome in (RotateOutcome.REUSE_REVOKED, RotateOutcome.REAUTH):
            self.cache.invalidate(grant.id)
        if outcome is RotateOutcome.REUSE_REVOKED:
            raise _refusal(_REFRESH_INVALID, "reuse_revoked")
        if outcome is RotateOutcome.REAUTH:
            raise _refusal(_REAUTH, "reauth_required")
        raise _refusal(_REFRESH_INVALID, f"refresh_{outcome.value}")

    # -- the request path ------------------------------------------------------------------

    async def check_access(self, claims: Mapping[str, Any]) -> bool:
        """Whether a verified token's grant is live and its account active. Raises if unreadable."""
        grant_id = str(claims["grant"])
        account_id = str(claims["acct"]).removeprefix("acct:")
        status = self.cache.get(grant_id)
        if status is None:
            epoch = self.cache.epoch
            status = await anyio.to_thread.run_sync(self.store.grant_status, grant_id)
            self.cache.put(grant_id, status, epoch)
            now = int(self._clock())
            if (
                status.found
                and not status.revoked
                and (status.last_used_at is None or now - status.last_used_at >= LAST_USED_GRANULARITY_SECONDS)
            ):
                await anyio.to_thread.run_sync(self.store.touch_grant, grant_id)
        return (
            status.usable(int(self._clock()))
            and status.account_id == account_id
            and status.client_id == claims["client_id"]
        )

    # -- revocation ------------------------------------------------------------------------

    async def revoke_by_client(self, grant_id: str) -> bool:
        """A client's own ``/revoke``: end the whole connection."""
        changed = await anyio.to_thread.run_sync(self.store.revoke_client_grant, grant_id)
        self.cache.invalidate(grant_id)
        return changed

    async def revoke_own(self, grant_id: str, account_key: str) -> bool:
        changed = await anyio.to_thread.run_sync(self.store.revoke_own_grant, grant_id, account_key)
        self.cache.invalidate(grant_id)
        return changed

    async def owner_revoke(self, grant_id: str, actor_key: str) -> bool:
        changed = await anyio.to_thread.run_sync(self.store.owner_revoke_grant, grant_id, actor_key)
        self.cache.invalidate(grant_id)
        return changed

    async def revoke_all_for_account(self, account_key: str, reason: str = REVOKE_ADMISSION_LOST) -> int:
        assert reason in (REVOKE_ADMISSION_LOST, REVOKE_ACCOUNT_DISABLED)
        count = await anyio.to_thread.run_sync(
            lambda: self.store.revoke_all_for_account(account_key, reason=reason)
        )
        self.cache.invalidate_account(account_key.removeprefix("acct:"))
        return count

    async def list_grants(self, account_key: str) -> list[GrantRecord]:
        return await anyio.to_thread.run_sync(self.store.list_grants, account_key)

    def invalidate_account(self, account_key: str) -> None:
        """This process learned that an account changed (disabled, enabled, approved)."""
        self.cache.invalidate_account(account_key.removeprefix("acct:"))
