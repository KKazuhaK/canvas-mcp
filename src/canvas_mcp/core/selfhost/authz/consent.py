"""The consent step: what the user is shown, and what a decision does.

This module decides; the pages (``account_web`` for the server-rendered UI, the JSON API
for the single-page one) only render its results, so both UIs share every check.

``describe`` answers "what is this request?" for the page: it looks the stored transaction
up (it must be bound to this browser), loads the client **from the database only** (no
outbound fetch while a person is looking at a page), checks the redirect URI against the
client and the operator's allowlist once more, and returns what to show.

``decide`` is the one place an authorization code is created: it consumes the transaction
(single use, same binding), reloads and rechecks the client and the redirect URI, and
either creates the code (``approve``) or builds the ``access_denied`` redirect (``deny``).
Both redirects go through :func:`fastmcp_compat.client_redirect`, which sets exactly one
RFC 9207 ``iss``. An account that is not active can never approve; a pending account
sees the request but can only cancel (its transaction is not consumed by the refusal).

Results are plain data with closed codes (:data:`CONSENT_CODES`); no text for people lives
here.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

import anyio.to_thread
from pydantic import AnyUrl

from ...logging import log_info, log_warning
from . import fastmcp_compat as compat
from . import tokens as tk
from .clients import ClientDirectory, PublicClient, clean_label
from .store import AuthzStore
from .transactions import (
    TXN_KIND,
    TXN_TTL_S,
    PendingAuthorization,
    SqlLoginStateStore,
    binding_hash,
    binding_ok,
    txn_id_ok,
)
from .urls import host_of, is_loopback_host

CODE_AUTHORIZATION_INVALID = "authorization_invalid"
CODE_CLIENT_UNAVAILABLE = "client_unavailable"
CODE_PENDING_APPROVAL = "pending_approval"
CODE_ACCESS_DISABLED = "access_disabled"
CONSENT_CODES = frozenset(
    {
        CODE_AUTHORIZATION_INVALID,
        CODE_CLIENT_UNAVAILABLE,
        CODE_PENDING_APPROVAL,
        CODE_ACCESS_DISABLED,
    }
)

Decision = Literal["approve", "deny"]


@dataclass(frozen=True)
class ConsentRefusal:
    """The request cannot be shown or decided; ``code`` is one of :data:`CONSENT_CODES`."""

    code: str


@dataclass(frozen=True)
class ConsentView:
    """What the consent page shows for one pending request."""

    client_kind: str
    #: The primary name: the CIMD host (verified) or the cleaned self-asserted name.
    label: str
    #: The name the app gives itself (shown muted next to a verified host).
    client_name: str
    #: True when ``label`` is a domain the app was fetched from (CIMD), not a claim.
    verified: bool
    redirect_host: str
    redirect_is_loopback: bool
    scopes: tuple[str, ...]
    expires_at: int
    #: False for an account that waits for approval: it can only cancel.
    can_approve: bool


@dataclass(frozen=True)
class ConsentRedirect:
    """Send the browser here (the app's redirect URI, with the code or the error)."""

    url: str
    approved: bool


class ConsentService:
    def __init__(
        self,
        store: AuthzStore,
        txns: SqlLoginStateStore,
        directory: ClientDirectory,
        *,
        issuer: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._txns = txns
        self._directory = directory
        self._issuer = issuer
        self._clock = clock

    # -- shared checks ---------------------------------------------------------------------

    def _bound(self, txn_id: str, binding: str | None) -> str | None:
        """The binding hash if both values have the shape this server issues, else None."""
        if not txn_id_ok(txn_id) or not binding_ok(binding):
            return None
        assert binding is not None
        return binding_hash(binding)

    @staticmethod
    def _parse(raw: bytes | None) -> PendingAuthorization | None:
        if raw is None:
            return None
        try:
            return PendingAuthorization.from_json(raw)
        except ValueError:
            return None

    async def _client_for(self, pending: PendingAuthorization) -> PublicClient | None:
        client = await self._directory.get_for_consent(pending.client_id, pending.created_at)
        if client is None:
            return None
        try:
            client.validate_redirect_uri(AnyUrl(pending.redirect_uri))
        except Exception:  # noqa: BLE001 - InvalidRedirectUriError, or a URL that no longer parses
            return None
        return client

    async def txn_open(self, txn_id: str, binding: str | None) -> bool:
        """Whether this browser holds a live, unused authorization request with this id."""
        digest = self._bound(txn_id, binding)
        if digest is None:
            return False
        return await self._txns.peek(TXN_KIND, txn_id, binding_hash=digest) is not None

    # -- the page --------------------------------------------------------------------------

    async def describe(
        self, txn_id: str, binding: str | None, *, account_pending: bool
    ) -> ConsentView | ConsentRefusal:
        digest = self._bound(txn_id, binding)
        if digest is None:
            return ConsentRefusal(CODE_AUTHORIZATION_INVALID)
        pending = self._parse(await self._txns.peek(TXN_KIND, txn_id, binding_hash=digest))
        if pending is None:
            return ConsentRefusal(CODE_AUTHORIZATION_INVALID)
        client = await self._client_for(pending)
        if client is None:
            return ConsentRefusal(CODE_CLIENT_UNAVAILABLE)
        host = host_of(pending.redirect_uri)
        return ConsentView(
            client_kind=client.kind,
            label=client.display_name or "",
            client_name=clean_label(client.client_name),
            verified=client.client_host is not None,
            redirect_host=host,
            redirect_is_loopback=is_loopback_host(host),
            scopes=pending.scopes,
            expires_at=pending.created_at + TXN_TTL_S,
            can_approve=not account_pending,
        )

    # -- the decision ----------------------------------------------------------------------

    async def decide(
        self,
        txn_id: str,
        binding: str | None,
        *,
        account_key: str,
        session_iat: int,
        account_pending: bool,
        decision: Decision,
    ) -> ConsentRedirect | ConsentRefusal:
        digest = self._bound(txn_id, binding)
        if digest is None:
            return ConsentRefusal(CODE_AUTHORIZATION_INVALID)
        if decision == "approve" and account_pending:
            # Refused without consuming the transaction: the person can still cancel.
            return ConsentRefusal(CODE_PENDING_APPROVAL)
        pending = self._parse(await self._txns.pop(TXN_KIND, txn_id, binding_hash=digest))
        if pending is None:
            return ConsentRefusal(CODE_AUTHORIZATION_INVALID)
        client = await self._client_for(pending)
        if client is None:
            log_warning("oauth_consent", reason="client_unavailable")
            return ConsentRefusal(CODE_CLIENT_UNAVAILABLE)

        params: dict[str, str] = {}
        if pending.state is not None:
            params["state"] = pending.state
        if decision == "deny":
            params["error"] = "access_denied"
            params["error_description"] = "The user denied the request."
            await anyio.to_thread.run_sync(
                self._store.record_consent_denied, account_key.removeprefix("acct:")
            )
            log_info("oauth_consent", decision="deny")
            return ConsentRedirect(
                compat.client_redirect(pending.redirect_uri, params, iss=self._issuer), approved=False
            )

        raw_code = tk.new_auth_code()
        host = host_of(pending.redirect_uri)
        created = await anyio.to_thread.run_sync(
            lambda: self._store.create_code(
                code_hash=tk.hash_secret(raw_code),
                client_id=pending.client_id,
                client_kind=client.kind,
                client_name=clean_label(client.client_name),
                client_host=client.client_host,
                account_id=account_key.removeprefix("acct:"),
                redirect_uri=pending.redirect_uri,
                redirect_uri_explicit=pending.redirect_uri_explicit,
                redirect_host=host,
                code_challenge=pending.code_challenge,
                scopes=pending.scopes,
                resource=pending.resource,
                upstream_auth_at=session_iat,
            )
        )
        if not created:
            return ConsentRefusal(CODE_ACCESS_DISABLED)
        params["code"] = raw_code
        log_info("oauth_consent", decision="approve", client_kind=client.kind)
        return ConsentRedirect(
            compat.client_redirect(pending.redirect_uri, params, iss=self._issuer), approved=True
        )
