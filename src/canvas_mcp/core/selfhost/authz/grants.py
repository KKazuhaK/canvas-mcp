"""Mint and revoke OAuth grants using committed transaction results."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Any

from mcp.server.auth.provider import TokenError
from mcp.shared.auth import OAuthToken

from ...logging import log_info, log_warning
from ..db.types import new_id
from ..db.workers import run_store
from ..settings import AuthzSettings
from .models import (
    REVOKE_ACCOUNT_DISABLED,
    REVOKE_ADMISSION_LOST,
    ExchangeOutcome,
    GrantRecord,
    RotateOutcome,
)
from .store import AuthzStore
from .tokens import AccessTokenCodec, hash_secret, new_refresh_token

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
        settings: AuthzSettings,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.codec = codec
        self.settings = settings
        self._clock = clock

    # -- minting ---------------------------------------------------------------------------

    def _mint(
        self, grant: GrantRecord, scopes: Sequence[str], refresh: str | None, epoch: int
    ) -> OAuthToken:
        """Sign with the epoch read inside the committed exchange transaction."""
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
            epoch=epoch,
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
        refresh_raw = (
            new_refresh_token() if "refresh_token" in client.grant_types else None
        )
        result = await run_store(
            lambda: self.store.exchange_code(
                code_hash=code.code_hash,
                client_id=client.client_id,
                grant_id=new_id(),
                refresh_hash=None if refresh_raw is None else hash_secret(refresh_raw),
            )
        )
        outcome = result.outcome
        grant = result.grant
        if (
            outcome in (ExchangeOutcome.WON, ExchangeOutcome.GRACE)
            and grant is not None
        ):
            if result.jwt_epoch is None:
                raise _refusal(_CODE_INVALID, "missing_signing_epoch")
            if outcome is ExchangeOutcome.GRACE:
                log_info("oauth_token_refused", reason="code_replay_grace")
            refresh = refresh_raw if result.refresh_issued else None
            return self._mint(grant, grant.scopes, refresh, result.jwt_epoch)
        if outcome is ExchangeOutcome.REPLAY_REVOKED and grant is not None:
            raise _refusal(_CODE_INVALID, "code_replay")
        if outcome is ExchangeOutcome.REAUTH:
            raise _refusal(_REAUTH, "reauth_required")
        raise _refusal(_CODE_INVALID, f"code_{outcome.value}")

    async def rotate(
        self, client: Any, refresh: Any, scopes: Sequence[str]
    ) -> OAuthToken:
        """Exchange a refresh token for a new pair (see ``AuthzStore.rotate_refresh``)."""
        new_raw = new_refresh_token()
        result = await run_store(
            lambda: self.store.rotate_refresh(
                token_hash=refresh.token_hash, new_hash=hash_secret(new_raw)
            )
        )
        outcome = result.outcome
        grant = result.grant
        if (
            outcome in (RotateOutcome.ROTATED, RotateOutcome.GRACE)
            and grant is not None
        ):
            if result.jwt_epoch is None:
                raise _refusal(_REFRESH_INVALID, "missing_signing_epoch")
            if outcome is RotateOutcome.GRACE:
                log_info("oauth_token_refused", reason="grace_reissued")
            granted = list(scopes) or list(grant.scopes)
            return self._mint(grant, granted, new_raw, result.jwt_epoch)
        if outcome is RotateOutcome.REUSE_REVOKED:
            raise _refusal(_REFRESH_INVALID, "reuse_revoked")
        if outcome is RotateOutcome.REAUTH:
            raise _refusal(_REAUTH, "reauth_required")
        raise _refusal(_REFRESH_INVALID, f"refresh_{outcome.value}")

    # -- revocation ------------------------------------------------------------------------

    async def revoke_by_client(self, grant_id: str) -> bool:
        """A client's own ``/revoke``: end the whole connection."""
        changed = await run_store(self.store.revoke_client_grant, grant_id)
        return changed

    async def revoke_own(self, grant_id: str, account_key: str) -> bool:
        changed = await run_store(self.store.revoke_own_grant, grant_id, account_key)
        return changed

    async def owner_revoke(self, grant_id: str, actor_key: str) -> bool:
        changed = await run_store(self.store.owner_revoke_grant, grant_id, actor_key)
        return changed

    async def revoke_all_for_account(
        self, account_key: str, reason: str = REVOKE_ADMISSION_LOST
    ) -> int:
        assert reason in (REVOKE_ADMISSION_LOST, REVOKE_ACCOUNT_DISABLED)
        count = await run_store(
            lambda: self.store.revoke_all_for_account(account_key, reason=reason)
        )
        return count
