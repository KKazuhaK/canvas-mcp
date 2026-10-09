"""Health of the stored Canvas tokens: confirm a dead token, record it, never guess.

A Canvas 401 is only a suspicion (see :mod:`canvas_mcp.core.token_health`). This
service turns a suspicion into a verdict with one probe, ``GET <school>/users/self``
made with the very token that was rejected:

* the probe answers 401: Canvas really rejects the token, so the row is marked
  ``invalid`` (reason ``canvas_token_rejected``) and the caller gets the re-enroll
  message;
* the probe succeeds: the token is fine and the 401 was a permission problem, so
  the caller keeps the original error;
* the probe answers anything else (403, 5xx), times out or cannot connect: nothing
  is known, so nothing changes. Only a 401 from the probe ever invalidates.

Probes are single-flight per stored token: at most one is in flight for a token
(concurrent callers wait for it and share its verdict), and for 60 seconds after
a probe finishes its verdict is reused instead of probing again. A "token" here is
one credential generation of one principal: replacing the token starts a new
generation, so a verdict (rejected or ok) about the old token is never served for
the new one, and a probe of the old token that finishes late cannot mark the new
row invalid or verified (the store refuses the write for a generation that is no
longer current). The state is
process-local, so with several server processes each may probe once.

The verdict lives in the token store (shared by every process); this class keeps
only the single-flight table and a rate limit on the "last verified" writes.
"""

from __future__ import annotations

import asyncio
import functools
import time
from collections.abc import Callable
from dataclasses import dataclass

import anyio.to_thread
import httpx

from .. import audit
from ..credentials import RequestCredentials
from ..logging import log_warning
from .request_context import token_rejected_message
from .token_store import (
    REASON_CANVAS_TOKEN_REJECTED,
    STATUS_INVALID,
    TokenStore,
)

PROBE_COOLDOWN_SECONDS = 60.0
VERIFIED_WRITE_INTERVAL_SECONDS = 600.0
PROBE_TIMEOUT_SECONDS = 10.0
_MAX_TRACKED = 1024

REJECTED = "rejected"
OK = "ok"
UNKNOWN = "unknown"


@dataclass
class _Flight:
    """One probe of one stored token: in flight (``future`` pending) or finished."""

    future: asyncio.Future[str]
    finished_at: float | None = None
    verdict: str | None = None


class TokenHealth:
    """Confirms suspected dead tokens and records token health in the store."""

    def __init__(
        self,
        store: TokenStore,
        *,
        account_url: str,
        clock: Callable[[], float] = time.monotonic,
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
        probe_timeout: float = PROBE_TIMEOUT_SECONDS,
        cooldown_seconds: float = PROBE_COOLDOWN_SECONDS,
        verified_interval_seconds: float = VERIFIED_WRITE_INTERVAL_SECONDS,
    ) -> None:
        self._store = store
        self._account_url = account_url
        self._clock = clock
        self._probe_timeout = probe_timeout
        self._client_factory = client_factory or (
            lambda: httpx.AsyncClient(timeout=probe_timeout, follow_redirects=False)
        )
        self._cooldown = cooldown_seconds
        self._verified_interval = verified_interval_seconds
        # Keyed by (principal, credential generation); a request that carries no
        # generation (outside the self-hosted server) falls back to the token's
        # ``updated_at``.
        self._flights: dict[tuple[str, int | None], _Flight] = {}
        self._verified_at: dict[str, float] = {}
        self.probe_count = 0

    # -- the Canvas client's side -------------------------------------------

    async def confirm_dead_token(
        self,
        principal_key: str,
        credentials: RequestCredentials,
        token_version: int | None,
        credential_generation: int | None = None,
    ) -> str | None:
        """The re-enroll message if the rejected token is confirmed dead, else None."""
        verdict = await self._single_flight(
            principal_key, credentials, token_version, credential_generation
        )
        if verdict != REJECTED:
            return None
        return token_rejected_message(self._account_url)

    async def note_success(
        self, principal_key: str, credential_generation: int | None = None
    ) -> None:
        """Record "last verified" for a successful call, at most once per interval.

        With ``credential_generation`` the store records it only while that is still
        the principal's current generation.
        """
        now = self._clock()
        last = self._verified_at.get(principal_key)
        if last is not None and now - last < self._verified_interval:
            return
        if len(self._verified_at) >= _MAX_TRACKED:
            cutoff = now - self._verified_interval
            self._verified_at = {k: v for k, v in self._verified_at.items() if v > cutoff}
            if len(self._verified_at) >= _MAX_TRACKED:
                self._verified_at.clear()
        self._verified_at[principal_key] = now
        await anyio.to_thread.run_sync(
            functools.partial(
                self._store.mark_verified,
                principal_key,
                min_interval_seconds=int(self._verified_interval),
                expected_generation=credential_generation,
            )
        )

    def forget(self, principal_key: str) -> None:
        """Drop the finished probe verdicts of a principal.

        Called when the user brings the stored token back to life (a successful
        re-check, or a newly saved token): a REJECTED verdict cached for the same
        token version must not keep calling a working token dead for the rest of
        the cooldown. A probe still in flight is left alone.
        """
        self._flights = {
            k: f
            for k, f in self._flights.items()
            if k[0] != principal_key or f.finished_at is None
        }

    # -- recording -----------------------------------------------------------

    async def mark_invalid(
        self,
        principal_key: str,
        reason: str,
        *,
        expected_updated_at: int | None = None,
        expected_generation: int | None = None,
        actor: str | None = None,
    ) -> bool:
        """Mark a row invalid and audit it; False if it was not active (or was replaced)."""
        changed = await anyio.to_thread.run_sync(
            functools.partial(
                self._store.mark_invalid,
                principal_key,
                reason=reason,
                expected_updated_at=expected_updated_at,
                expected_generation=expected_generation,
                actor=actor,
            )
        )
        if changed:
            log_warning("Canvas token marked invalid", principal=principal_key, reason=reason)
            audit.log_token_event(
                "admin_marked_invalid" if actor else "invalidated",
                principal_key,
                reason=reason,
                actor=actor,
            )
        return changed

    # -- single flight -------------------------------------------------------

    async def _single_flight(
        self,
        principal_key: str,
        credentials: RequestCredentials,
        token_version: int | None,
        credential_generation: int | None = None,
    ) -> str:
        key = (
            principal_key,
            credential_generation if credential_generation is not None else token_version,
        )
        now = self._clock()
        flight = self._flights.get(key)
        if flight is not None:
            if flight.finished_at is None:
                # Join the probe that is already running. shield(): cancelling
                # this waiter must not cancel the shared future.
                return await asyncio.shield(flight.future)
            if flight.verdict is not None and now - flight.finished_at < self._cooldown:
                return flight.verdict
        return await self._lead(key, credentials, token_version, credential_generation)

    async def _lead(
        self,
        key: tuple[str, int | None],
        credentials: RequestCredentials,
        token_version: int | None = None,
        credential_generation: int | None = None,
    ) -> str:
        self._prune()
        flight = _Flight(future=asyncio.get_running_loop().create_future())
        self._flights[key] = flight
        verdict = UNKNOWN
        try:
            verdict = await self._probe(credentials)
            if verdict == REJECTED:
                verdict = await self._record_rejected(key, token_version, credential_generation)
            elif verdict == OK:
                await self.note_success(key[0], credential_generation)
        except asyncio.CancelledError:
            verdict = UNKNOWN
            raise
        except Exception:  # noqa: BLE001 - a failing probe or write changes nothing
            verdict = UNKNOWN
        finally:
            flight.verdict = verdict
            flight.finished_at = self._clock()
            if not flight.future.done():
                flight.future.set_result(verdict)
        return verdict

    async def _record_rejected(
        self,
        key: tuple[str, int | None],
        token_version: int | None,
        credential_generation: int | None,
    ) -> str:
        """Invalidate after a 401 probe; REJECTED only if that row is (now) invalid."""
        principal_key = key[0]
        version = token_version if token_version is not None else key[1]
        changed = await self.mark_invalid(
            principal_key,
            REASON_CANVAS_TOKEN_REJECTED,
            expected_updated_at=version,
            expected_generation=credential_generation,
        )
        if changed:
            return REJECTED
        # Not changed: already invalid (fine, same verdict), replaced by a newer
        # token or deleted (the rejected token is no longer the stored one).
        info = await anyio.to_thread.run_sync(self._store.info, principal_key)
        if (
            info is not None
            and info.status == STATUS_INVALID
            and (version is None or info.updated_at == version)
            and (
                credential_generation is None
                # The invalidation itself raised the generation by one.
                or info.credential_generation in (credential_generation, credential_generation + 1)
            )
        ):
            return REJECTED
        return UNKNOWN

    async def _probe(self, credentials: RequestCredentials) -> str:
        """``GET /users/self`` with the rejected token; the verdict of that one answer."""
        from ..client import _canvas_auth_headers

        self.probe_count += 1
        url = credentials.api_url.rstrip("/") + "/users/self"
        headers = _canvas_auth_headers(credentials.api_token)
        headers["Accept"] = "application/json"
        try:
            async with self._client_factory() as client:
                response = await client.get(
                    url,
                    headers=headers,
                    timeout=self._probe_timeout,
                    follow_redirects=False,
                )
        except (httpx.HTTPError, ValueError):
            return UNKNOWN
        if response.status_code == 401:
            return REJECTED
        if response.status_code == 200:
            return OK
        return UNKNOWN

    def _prune(self) -> None:
        if len(self._flights) < _MAX_TRACKED:
            return
        cutoff = self._clock() - self._cooldown
        self._flights = {
            k: f
            for k, f in self._flights.items()
            if f.finished_at is None or f.finished_at > cutoff
        }
        if len(self._flights) >= _MAX_TRACKED:
            self._flights = {k: f for k, f in self._flights.items() if f.finished_at is None}
