"""The sign-in ceremony of Google, GitHub and generic OpenID Connect providers.

``ExternalSignIn`` holds the two route handlers of each provider, built over the same
``_AccountApp`` as the Entra sign-in (so the session, the cookies, the security headers, the rate
limiters and the P6 authorization-server continuation are the very same objects).

The callback checks, in this order (the A.11 list of the design):

1. the response always deletes the ceremony cookie, whatever else happens;
2. a ``?error=`` from the provider ends it: nothing is consumed and no request is made;
3. the ``state`` of the request must equal, in constant time, the one sealed in the cookie, and the
   cookie must be this provider's, fresh and well-formed;
4. the stored ceremony is popped: one conditional ``DELETE`` bound to the cookie's secret, so a
   replay, another browser, an expired or an unknown ``state`` are indistinguishable and a storage
   error fails closed;
5. the ``iss`` parameter (RFC 9207), when the provider sends or must send one, is compared exactly;
6. only now is the code exchanged.

Entra keeps its older order (state before error) and its stateless sign-in cookie; only a link
adds a server-side record there. Every failure is a closed code, never provider text.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import logging
import re
import secrets
from typing import TYPE_CHECKING

import anyio.to_thread
from starlette.requests import Request
from starlette.responses import Response

from .. import account_web as web
from ..account_ops import Refusal
from ..accounts import Denied
from ..identity import SignIn
from .ceremony import (
    FLOW_COOKIE,
    FLOW_KIND,
    FLOW_TTL_S,
    FlowCookie,
    FlowRecord,
    binding_digest,
    new_cookie_payload,
)
from .linking import LinkingService
from .metadata import ProviderUnavailable
from .protocol import LoginProvider, SignInRejected

if TYPE_CHECKING:
    from .registry import LoginRuntime

logger = logging.getLogger("canvas_mcp.selfhost.account")

_ERROR_CODE_RE = re.compile(r"^[a-z_]{1,64}$")
_CLOCK_SKEW_S = 60
_MAX_CODE_CHARS = 4096


def _b64url_sha256(verifier: str) -> str:
    return web._b64url(hashlib.sha256(verifier.encode("ascii")).digest())


class ExternalSignIn:
    """Start and callback handlers for every non-Entra provider."""

    def __init__(self, app: web._AccountApp, runtime: LoginRuntime) -> None:
        self.app = app
        self.rt = runtime
        self.linking = LinkingService(app, runtime)

    def route_table(self) -> list[tuple[str, dict[str, web.Handler]]]:
        table: list[tuple[str, dict[str, web.Handler]]] = []
        for provider in self.rt.providers.values():
            table.append((provider.start_path, {"GET": functools.partial(self._start, provider=provider)}))
            table.append(
                (provider.callback_path, {"GET": functools.partial(self._callback, provider=provider)})
            )
        return table

    # -- start ---------------------------------------------------------------------------------

    async def _start(self, request: Request, *, provider: LoginProvider) -> Response:
        app = self.app
        if self.rt.start_buckets[provider.id].take() > 0:
            return app._provider_failure("rate_limited", 429, provider)
        txn_id, early = await app._login_txn(request)
        if early is not None:
            return early
        return_to = None
        if app.react and txn_id is None:
            return_to = web.sanitize_return_to(request.query_params.get("return_to"))
        reauth = request.query_params.get("reauth") == "1"
        try:
            await provider.prepare()
        except ProviderUnavailable:
            logger.warning("provider sign-in unavailable provider=%s step=start", provider.id)
            return app._provider_failure("provider_error", 502, provider)
        now = int(app.clock())
        verifier = secrets.token_urlsafe(48)
        nonce = secrets.token_urlsafe(32)
        binding = secrets.token_urlsafe(32)
        record = FlowRecord(
            p=provider.id, cv=verifier, n=nonce, pp="sign_in", txn=txn_id, rt=return_to, rz=reauth,
            ru=provider.redirect_uri, la=None, le=None, li=None, iat=now,
        )
        try:
            state = await self.rt.flow_store.put(
                FLOW_KIND, record.to_json(), FLOW_TTL_S, binding_hash=binding_digest(binding)
            )
            url = provider.authorize_url(
                state=state, nonce=nonce, code_challenge=_b64url_sha256(verifier), reauth=reauth
            )
        except ProviderUnavailable:
            return app._provider_failure("provider_error", 502, provider)
        except Exception as exc:  # noqa: BLE001 - fail closed, never leak details
            logger.error("provider sign-in start failed: %s", type(exc).__name__)
            return app._provider_failure("token_store_unavailable", 503, provider)
        response = app.redirect(url, status=302)
        response.set_cookie(
            FLOW_COOKIE,
            app.codec.seal(FLOW_COOKIE, new_cookie_payload(state, binding, provider.id, now)),
            max_age=FLOW_TTL_S,
            **app._cookie_kwargs(),
        )
        return response

    # -- callback ------------------------------------------------------------------------------

    async def _callback(self, request: Request, *, provider: LoginProvider) -> Response:
        response = await self._callback_checked(request, provider)
        self.app.clear_cookie(response, FLOW_COOKIE)
        return response

    async def _callback_checked(self, request: Request, provider: LoginProvider) -> Response:
        app = self.app
        cookie = FlowCookie.from_payload(
            app.codec.unseal(FLOW_COOKIE, request.cookies.get(FLOW_COOKIE))
        )
        # The sealed cookie says what the ceremony is for before the stored record can be popped:
        # a cancelled or expired link still belongs on the Sign-in methods screen, a failed
        # re-sign-in or app consent does not.
        link = cookie is not None and cookie.provider_id == provider.id and cookie.purpose == "link"
        error = request.query_params.get("error")
        if error is not None:
            code = error if _ERROR_CODE_RE.fullmatch(error) else None
            logger.info("provider sign-in refused provider=%s error=%s", provider.id, code or "unknown")
            return self._failure(link, "provider_error", 403, provider)

        state = request.query_params.get("state", "")
        now = app.clock()
        if (
            cookie is None
            or cookie.provider_id != provider.id
            or cookie.iat > now + _CLOCK_SKEW_S
            or now - cookie.iat > FLOW_TTL_S
            or not hmac.compare_digest(state.encode("utf-8"), cookie.state.encode("utf-8"))
        ):
            return self._failure(link, "state_invalid", 400, provider)

        try:
            raw = await self.rt.flow_store.pop(
                FLOW_KIND, state, binding_hash=binding_digest(cookie.binding)
            )
        except Exception as exc:  # noqa: BLE001 - fail closed
            logger.error("provider sign-in state read failed: %s", type(exc).__name__)
            return self._failure(link, "token_store_unavailable", 503, provider)
        record: FlowRecord | None = None
        if raw is not None:
            try:
                record = FlowRecord.from_json(raw)
            except ValueError:
                record = None
        if record is None or record.p != provider.id or record.ru != provider.redirect_uri:
            return self._failure(link, "state_invalid", 400, provider)
        link = record.pp == "link"

        issuer = request.query_params.get("iss")
        if issuer is not None:
            # A provider without a known issuer (GitHub) has nothing to compare it with.
            if provider.response_issuer is not None and issuer != provider.response_issuer:
                logger.warning("provider sign-in refused provider=%s reason=iss_mismatch", provider.id)
                return self._failure(link, "state_invalid", 400, provider)
        else:
            # Whether the provider promises an ``iss`` is known from its metadata, which a restart
            # between the start and the callback leaves unloaded: load it first, and fail closed.
            try:
                await provider.prepare()
            except ProviderUnavailable:
                logger.warning("provider sign-in unavailable provider=%s step=callback", provider.id)
                return self._failure(link, "provider_error", 502, provider)
        if issuer is None and provider.requires_iss():
            logger.warning("provider sign-in refused provider=%s reason=iss_missing", provider.id)
            return self._failure(link, "state_invalid", 400, provider)

        code_param = request.query_params.get("code", "")
        if not code_param or len(code_param) > _MAX_CODE_CHARS:
            return self._failure(link, "sign_in_incomplete", 400, provider)

        try:
            ext = await provider.finish(code=code_param, code_verifier=record.cv, nonce=record.n)
        except SignInRejected as exc:
            status = 400 if exc.code != "provider_error" else 502
            return self._failure(link, exc.code, status, provider)
        except Exception as exc:  # noqa: BLE001 - never let a provider bug become a 500 page with details
            logger.error("provider sign-in failed provider=%s: %s", provider.id, type(exc).__name__)
            return self._failure(link, "provider_error", 502, provider)

        if link:
            outcome = await self.linking.complete(request, record, ext)
            return app._link_redirect(outcome)

        try:
            signed = await anyio.to_thread.run_sync(
                functools.partial(
                    app.identity.sign_in_external, ext, ip="unknown", ua_hash=app._ua_hash(request)
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("account sign-in status check failed: %s", type(exc).__name__)
            return self._failure(link, "token_store_unavailable", 503, provider)
        if isinstance(signed, Denied):
            await app._admission_lost(signed)
            return app._sign_in_refused(signed)
        assert isinstance(signed, SignIn)
        return app._complete_sign_in(signed, now=now, waiting=record.txn, return_to=record.rt)

    def _failure(
        self, link: bool, code: str, status: int, provider: LoginProvider
    ) -> Response:
        """A failed ceremony: a link goes back to the sign-in methods screen, a sign-in to its page."""
        if link:
            return self.app._link_redirect(Refusal(code))
        return self.app._provider_failure(code, status, provider)
