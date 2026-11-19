"""Accept an external issuer's token on /mcp: choose the issuer, verify, find or make the account."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass

from ...logging import log_info, log_warning
from ..accounts import AccessPolicy, Denied
from ..db.workers import run_store
from ..login.http import SafeHttp
from .config import TrustedIssuer
from .store import FederationStore, Resolved
from .verifier import TokenRejected, TokenVerifier, VerifiedToken, peek_issuer

#: How long a read of the issuer list is reused. The CLI runs in another process, so a change
#: takes effect on a running server within this time.
ISSUER_LIST_TTL_S = 10.0


@dataclass(frozen=True)
class Accepted:
    verified: VerifiedToken
    resolved: Resolved
    issuer: TrustedIssuer


@dataclass(frozen=True)
class Refused:
    """A verified person the server does not admit (pending, disabled, not admitted)."""

    message: str


class FederationService:
    def __init__(
        self,
        store: FederationStore,
        *,
        audience: str,
        policy: AccessPolicy,
        http: SafeHttp | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.policy = policy
        self.http = http or SafeHttp()
        self.verifier = TokenVerifier(self.http, default_audience=audience, clock=clock)
        self._clock = clock
        self._issuers: list[TrustedIssuer] = []
        self._read_at = float("-inf")
        self._lock = asyncio.Lock()

    async def issuers(self) -> list[TrustedIssuer]:
        if self._clock() - self._read_at < ISSUER_LIST_TTL_S:
            return self._issuers
        async with self._lock:
            if self._clock() - self._read_at >= ISSUER_LIST_TTL_S:
                self._issuers = await run_store(self.store.list_issuers)
                self._read_at = self._clock()
                self.verifier.forget_except({i.issuer for i in self._issuers})
        return self._issuers

    def reload(self) -> None:
        """Read the issuer list again at the next request (after a change in this process)."""
        self._read_at = float("-inf")

    async def authenticate(self, token: str) -> Accepted | Refused | None:
        """None: not a token of any trusted issuer, or not valid. Refused: valid, but not admitted."""
        named = peek_issuer(token)
        if named is None:
            return None
        issuer = next((i for i in await self.issuers() if i.issuer == named), None)
        if issuer is None:
            return None
        try:
            verified = await self.verifier.verify(token, issuer)
        except TokenRejected as exc:
            log_warning("federated token refused", reason=exc.reason)
            return None
        resolved = await run_store(
            self.store.resolve, issuer, verified.subject, self.policy
        )
        if isinstance(resolved, Denied):
            log_info("federated sign-in refused", reason=resolved.code)
            return Refused(resolved.message)
        return Accepted(verified, resolved, issuer)
