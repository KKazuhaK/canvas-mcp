"""Linking more sign-in methods to an account, and taking them away again.

Linking is explicit and never automatic: a signed-in, active person whose sign-in is fresh
(ten minutes) asks to add a provider; a ceremony bound to that very session proves they control
the new identity; the store then attaches it in one transaction (see
``TokenStore.link_identity``) unless it belongs to another account (``identity_in_use``: there is
no silent merge), the account already has one from that provider, the admission rules would refuse
it, or the session ended in the meantime. An e-mail address is never a reason to link.

Every method returns a :mod:`..account_ops` outcome and never renders anything, so the legacy pages
and the JSON API cannot disagree.
"""

from __future__ import annotations

import functools
import logging
import secrets
from typing import TYPE_CHECKING

from ..account_ops import IdentityView, Linked, LinkStarted, Refusal, Unlinked
from ..accounts import ExternalClaims
from ..db.errors import LoginConfigurationChanged
from ..db.workers import run_store
from ..token_store import AccessActionRefused, LinkedIdentity
from .ceremony import (
    FLOW_COOKIE,
    FLOW_KIND,
    FLOW_TTL_S,
    FlowRecord,
    binding_digest,
    new_cookie_payload,
)
from .metadata import ProviderUnavailable

if TYPE_CHECKING:
    from starlette.requests import Request

    from ..account_core import AccountCore, _Session
    from .registry import LoginRuntime

logger = logging.getLogger("canvas_mcp.selfhost.account")

#: Per account: link starts and unlinks in ten minutes.
LINK_START_LIMIT = 5
UNLINK_LIMIT = 10
LIMIT_WINDOW_S = 600


def _b64url_sha256(verifier: str) -> str:
    import base64
    import hashlib

    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )


class LinkingService:
    """The linking operations of one running server."""

    def __init__(self, app: AccountCore, runtime: LoginRuntime) -> None:
        self.app = app
        self.rt = runtime

    # -- reading -------------------------------------------------------------------------------

    async def list_own(self, session: _Session) -> list[IdentityView] | Refusal:
        """The caller's linked identities, oldest first."""
        if not self.rt.linking_enabled:
            return Refusal("not_found")
        try:
            rows = await run_store(self.app.store.list_identities, session.acct)
        except Exception as exc:  # noqa: BLE001
            logger.error("account identities read failed: %s", type(exc).__name__)
            return Refusal("token_store_unavailable")
        return views_of(rows, session.pid)

    # -- starting a link -----------------------------------------------------------------------

    async def start(self, session: _Session, provider_id: str) -> LinkStarted | Refusal:
        """Prepare a link ceremony for the caller. Nothing changes until the callback completes it."""
        app, rt = self.app, self.rt
        if not rt.linking_enabled:
            return Refusal("not_found")
        if session.pending:
            return Refusal("pending_approval")
        if not app._signed_in_recently(session):
            return Refusal("reauth_required", {"max_age_s": 600})
        if provider_id == "local" or rt.entry(provider_id) is None:
            return Refusal("validation_failed", {"field": "provider"})
        if not app.link_limiter.allow((session.acct,)):
            return Refusal("rate_limited", {"retry_after_s": LIMIT_WINDOW_S})
        try:
            rows = await run_store(app.store.list_identities, session.acct)
        except Exception as exc:  # noqa: BLE001
            logger.error("account link start failed: %s", type(exc).__name__)
            return Refusal("token_store_unavailable")
        if any(row.provider_id == provider_id for row in rows):
            return Refusal("provider_already_linked")
        try:
            return await self._start_provider(session, provider_id)
        except ProviderUnavailable:
            return Refusal("provider_unavailable")
        except Exception as exc:  # noqa: BLE001
            logger.error("account link start failed: %s", type(exc).__name__)
            return Refusal("token_store_unavailable")

    async def _start_provider(self, session: _Session, provider_id: str) -> LinkStarted:
        app, rt = self.app, self.rt
        provider = rt.providers[provider_id]
        await provider.prepare()
        now = int(app.clock())
        verifier = secrets.token_urlsafe(48)
        nonce = secrets.token_urlsafe(32)
        binding = secrets.token_urlsafe(32)
        record = FlowRecord(
            p=provider.id,
            cv=verifier,
            n=nonce,
            pp="link",
            txn=None,
            rt=None,
            rz=True,
            ru=provider.redirect_uri,
            la=session.acct,
            le=session.ep,
            li=session.iat,
            iat=now,
            revision=app.login_bundle.revision,
        )
        state = await rt.flow_store.put(
            FLOW_KIND,
            record.to_json(),
            FLOW_TTL_S,
            binding_hash=binding_digest(binding),
        )
        url = provider.authorize_url(
            state=state,
            nonce=nonce,
            code_challenge=_b64url_sha256(verifier),
            reauth=True,
        )
        cookie = app.codec.seal(
            FLOW_COOKIE, new_cookie_payload(state, binding, provider.id, now, "link")
        )
        return LinkStarted(url, provider.id, FLOW_COOKIE, cookie, FLOW_TTL_S)

    # -- completing a link (the callbacks call this) ----------------------------------------------

    async def complete(
        self, request: Request, record: FlowRecord, ext: ExternalClaims
    ) -> Linked | Refusal:
        """Attach the verified identity to the account the ceremony was started for.

        The request's own session (re-checked against the database as for every request) must
        be that account, in the same session epoch, from the same sign-in, and not pending.
        """
        app = self.app
        session = app._session_of(request)
        if (
            session is None
            or session.pending
            or record.la is None
            or session.acct != record.la
            or session.ep != record.le
            or session.iat != record.li
            or record.p != ext.provider_id
        ):
            return Refusal("link_session_ended")
        assert record.le is not None
        try:
            result = await run_store(
                functools.partial(
                    app.identity.link,
                    record.la,
                    ext,
                    expected_epoch=record.le,
                    ua_hash=app._ua_hash(request),
                )
            )
        except LoginConfigurationChanged:
            return Refusal("state_invalid")
        except Exception as exc:  # noqa: BLE001
            logger.error("account link failed: %s", type(exc).__name__)
            return Refusal("token_store_unavailable")
        if not result.ok:
            logger.info(
                "account link refused account=%s provider=%s code=%s",
                session.acct,
                ext.provider_id,
                result.code,
            )
            return Refusal(result.code)
        logger.info(
            "account identity linked account=%s provider=%s",
            session.acct,
            ext.provider_id,
        )
        return Linked(ext.provider_id)

    # -- unlinking --------------------------------------------------------------------------------

    async def unlink_own(
        self, session: _Session, identity_id: str
    ) -> Unlinked | Refusal:
        """Remove one of the caller's identities (they keep at least one)."""
        app = self.app
        if not self.rt.linking_enabled:
            return Refusal("not_found")
        if session.pending:
            return Refusal("pending_approval")
        if not app._signed_in_recently(session):
            return Refusal("reauth_required", {"max_age_s": 600})
        if not app.unlink_limiter.allow((session.acct,)):
            return Refusal("rate_limited", {"retry_after_s": LIMIT_WINDOW_S})
        try:
            result = await run_store(
                functools.partial(
                    app.identity.unlink,
                    session.acct,
                    identity_id,
                    actor=session.acct,
                    expected_epoch=session.ep,
                )
            )
        except AccessActionRefused:
            return Refusal("forbidden")
        except Exception as exc:  # noqa: BLE001
            logger.error("account unlink failed: %s", type(exc).__name__)
            return Refusal("token_store_unavailable")
        if not result.ok:
            return Refusal(result.code)
        logger.info(
            "account identity unlinked account=%s provider=%s by=self",
            session.acct,
            result.provider_id,
        )
        return self._after_unlink(session, result.provider_id, result.session_epoch)

    async def owner_unlink(
        self, session: _Session, target: str, identity_id: str
    ) -> Unlinked | Refusal:
        """An owner removes an identity from any account (fresh sign-in; owner re-checked in the transaction)."""
        app = self.app
        if not self.rt.linking_enabled:
            return Refusal("not_found")
        if not session.owner:
            return Refusal("forbidden")
        if not app._signed_in_recently(session):
            return Refusal("reauth_required", {"max_age_s": 600})
        if not app.unlink_limiter.allow((session.acct,)):
            return Refusal("rate_limited", {"retry_after_s": LIMIT_WINDOW_S})
        try:
            result = await run_store(
                functools.partial(
                    app.identity.unlink, target, identity_id, actor=session.acct
                )
            )
        except AccessActionRefused:
            return Refusal("forbidden")
        except Exception as exc:  # noqa: BLE001
            logger.error("account unlink failed: %s", type(exc).__name__)
            return Refusal("token_store_unavailable")
        if not result.ok:
            return Refusal(result.code)
        logger.info(
            "account identity unlinked account=%s provider=%s by=owner owner=%s",
            target,
            result.provider_id,
            session.acct,
        )
        if target == session.acct:
            return self._after_unlink(session, result.provider_id, result.session_epoch)
        return Unlinked(result.provider_id, signed_out=False, session_cookie=None)

    def _after_unlink(
        self, session: _Session, provider_id: str, epoch: int
    ) -> Unlinked:
        """The caller keeps their session (re-issued under the new epoch) unless they used the identity just removed."""
        if provider_id == session.pid:
            return Unlinked(provider_id, signed_out=True, session_cookie=None)
        return Unlinked(
            provider_id,
            signed_out=False,
            session_cookie=self.app._reissue_session(session, epoch),
        )


def views_of(rows: list[LinkedIdentity], current_pid: str) -> list[IdentityView]:
    """The sign-in methods screen's rows for an account's identities."""
    many = len(rows) > 1
    return [
        IdentityView(
            id=row.id,
            provider_id=row.provider_id,
            username=row.username,
            email=row.email,
            email_verified=row.email_verified,
            linked_at=row.linked_at,
            last_login_at=row.last_login_at,
            current=row.provider_id == current_pid,
            can_unlink=many,
        )
        for row in rows
    ]
