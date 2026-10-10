"""The authorization server: a FastMCP ``OAuthProvider`` that issues its own tokens.

``LocalAuthorizationServer`` implements all nine methods of the provider protocol (a guard
test checks that each one is defined on this class, because the base methods are not
abstract and quietly return ``None``), and replaces the routes the stock provider builds
where the stock ones do not fit a public-client, JWT-issuing server:

``GET  /.well-known/oauth-authorization-server``  our metadata (S256 only, public clients only, RFC 9207, CIMD)
``GET  /authorize``    FastMCP's handler, with the browser-binding cookie set on the redirect to the sign-in
``POST /token``        FastMCP's handler behind a wrapper that refuses a foreign ``resource`` and maps an outage to 503
``POST /register``     the SDK's handler, with ``register_client`` doing the validation the SDK does not
``POST /revoke``       ours: the SDK's insists on a ``client_secret`` that a public client does not have

``/.well-known/oauth-protected-resource/mcp`` is FastMCP's, unchanged (``authorization_servers``
is the issuer). After the surgery the route table is compared with the one expected
(:data:`EXPECTED_ROUTES`) and the server refuses to start on any difference.

**One issuer string** (``https://host/``, the trailing slash included) is the metadata
``issuer``, the protected-resource ``authorization_servers[0]``, the ``iss`` claim of every
access token and the RFC 9207 ``iss`` of every redirect. **The audience** of an access token
is the MCP endpoint URL, which must equal the resource URL FastMCP derives (checked at
start-up and again when the MCP path is set).

The sign-in is not here: ``/authorize`` stores the request and sends the browser to
``/account/login?txn=...``; the user signs in at ``/account``, approves on the consent
page, and the code is created by :class:`~.consent.ConsentService`.
"""

from __future__ import annotations

import re
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any

import anyio.to_thread
from fastmcp.server.auth import AccessToken, OAuthProvider
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthMetadata, OAuthToken
from pydantic import AnyHttpUrl, AnyUrl
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route, request_response
from starlette.types import ASGIApp, Receive, Scope, Send

from ...logging import log_info, log_warning
from ..db.errors import StoreUnavailable
from ..settings import SelfhostConfigError, SelfhostSettings
from . import fastmcp_compat as compat
from .clients import (
    DCR_TTL_SECONDS,
    LOOKUP_OUTAGE,
    LOOKUP_PURPOSE,
    MAX_REGISTRATION_JSON_BYTES,
    PURPOSE_AUTHORIZE,
    PURPOSE_TOKEN,
    PublicClient,
    clean_label,
    make_public,
    validate_dcr_metadata,
)
from .tokens import CODE_RE, REFRESH_RE, AccessTokenInvalid, hash_secret
from .transactions import (
    BINDING_COOKIE,
    BINDING_COOKIE_MAX_AGE,
    TXN_KIND,
    TXN_TTL_S,
    PendingAuthorization,
    binding_hash,
    binding_ok,
    new_binding,
)
from .urls import audience_of, is_canonical_base, issuer_of, normalize_resource

if TYPE_CHECKING:  # runtime.py imports this module
    from .runtime import AuthzRuntime

_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
MAX_ACCESS_TOKEN_CHARS = 4096

#: The binding value (the browser's secret) for the ``/authorize`` request being handled.
_BINDING: ContextVar[str | None] = ContextVar("canvas_mcp_authz_binding", default=None)

#: Every route of the local authorization server: ``(path, methods)``. Starlette adds HEAD to GET.
EXPECTED_ROUTES: frozenset[tuple[str, frozenset[str]]] = frozenset(
    {
        ("/.well-known/oauth-authorization-server", frozenset({"GET", "HEAD", "OPTIONS"})),
        ("/.well-known/oauth-protected-resource/mcp", frozenset({"GET", "HEAD", "OPTIONS"})),
        ("/authorize", frozenset({"GET", "HEAD", "POST"})),
        ("/token", frozenset({"POST", "OPTIONS"})),
        ("/register", frozenset({"POST", "OPTIONS"})),
        ("/revoke", frozenset({"POST", "OPTIONS"})),
    }
)
METADATA_CACHE_CONTROL = "public, max-age=300"
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def assert_route_table(routes: list[Any]) -> None:
    """Refuse to start when the provider's routes are not exactly :data:`EXPECTED_ROUTES`."""
    actual = {
        (route.path, frozenset(route.methods or ()))
        for route in routes
        if isinstance(route, Route)
    }
    if len(actual) != len(routes) or actual != EXPECTED_ROUTES:
        raise RuntimeError("the authorization server routes are not the expected ones")


class LocalAuthorizationCode(AuthorizationCode):
    """An authorization code as loaded from the database (possibly already used)."""

    account_id: str
    code_hash: str
    consumed_at: int | None = None
    grant_id: str | None = None


class LocalRefreshToken(RefreshToken):
    """A refresh token as loaded from the database (possibly already used)."""

    # mcp 2.2.0 adds this field to RefreshToken; declaring it keeps 2.1.1 compatible.
    resource: str | None = None
    grant_id: str
    token_hash: str
    account_id: str


class _StoreGuard:
    """ASGI wrapper: an unreachable database is a 503, not an unhandled error."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        started = False

        async def tracking_send(message: Any) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except StoreUnavailable:
            if started:
                raise
            await _unavailable()(scope, receive, send)


def _unavailable() -> Response:
    return JSONResponse(
        {"error": "temporarily_unavailable", "error_description": "Try again in a moment."},
        status_code=503,
        headers={**_NO_STORE, "Retry-After": "5"},
    )


def _json_error(status: int, error: str, description: str | None = None) -> Response:
    body = {"error": error}
    if description:
        body["error_description"] = description
    return JSONResponse(body, status_code=status, headers=dict(_NO_STORE))


def _cors(app: ASGIApp, methods: list[str]) -> ASGIApp:
    return CORSMiddleware(app=app, allow_origins="*", allow_methods=methods, allow_headers=["mcp-protocol-version"])


class LocalAuthorizationServer(OAuthProvider):
    """Our own authorization server, over the database."""

    def __init__(self, settings: SelfhostSettings, authz: AuthzRuntime) -> None:
        base = settings.public_base_url
        if not is_canonical_base(base):
            raise SelfhostConfigError(
                ["PUBLIC_BASE_URL must be a canonical origin (lower case, no default port, no trailing slash)"]
            )
        scope = settings.api_scope
        super().__init__(
            base_url=base,
            issuer_url=base,
            required_scopes=[scope],
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[scope], default_scopes=[scope]
            ),
            revocation_options=RevocationOptions(enabled=True),
        )
        self.settings = settings
        self.authz = authz
        self.scope = scope
        self.base = base
        self.cimd_enabled = settings.authz.cimd_enabled
        self.allowlist = tuple(settings.allowed_client_redirect_uris)
        #: The one issuer string (with its trailing slash) used everywhere.
        self.issuer = str(self.issuer_url)
        if self.issuer != issuer_of(base) or self.issuer != base + "/":
            raise SelfhostConfigError(["the issuer is not PUBLIC_BASE_URL with a trailing slash"])
        self.audience = audience_of(base, settings.mcp_path)
        self._clock = authz.clock

    # -- start-up assertions ----------------------------------------------------------------

    def set_mcp_path(self, mcp_path: str | None) -> None:
        super().set_mcp_path(mcp_path)
        resource = compat.resource_url_of(self, mcp_path or "")
        if not (resource == self.audience == self.authz.audience == self.settings.mcp_url):
            raise SelfhostConfigError(
                ["the audience of access tokens is not the MCP resource URL FastMCP advertises"]
            )

    # -- 1. clients ---------------------------------------------------------------------------

    async def get_client(self, client_id: str) -> PublicClient | None:
        return await self.authz.clients.get(client_id)

    # -- 2. registration -----------------------------------------------------------------------

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        error = validate_dcr_metadata(client_info, self.allowlist, [self.scope])
        if error is not None:
            raise error
        make_public(client_info, self.scope)
        info_json = client_info.model_dump_json(exclude_none=True)
        if len(info_json.encode("utf-8")) > MAX_REGISTRATION_JSON_BYTES:
            raise RegistrationError(
                error="invalid_client_metadata", error_description="The registration is too large."
            )
        expires_at = int(self._clock()) + DCR_TTL_SECONDS
        await anyio.to_thread.run_sync(
            self.authz.store.put_client,
            client_info.client_id,
            info_json,
            clean_label(client_info.client_name, 200),
            expires_at,
        )
        log_info("dcr_registered")  # a counter line: nothing from the request reaches the log

    # -- 3. authorize --------------------------------------------------------------------------

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        binding = _BINDING.get()
        if not isinstance(client, PublicClient) or binding is None:
            raise AuthorizeError(error="server_error", error_description="Authorization could not be started.")
        if params.resource is None:
            resource = self.audience  # a client that sends no resource is served for ours
        else:
            wanted = normalize_resource(params.resource)
            if wanted is None or wanted != normalize_resource(self.audience):
                raise AuthorizeError(error="invalid_target", error_description="Unknown resource.")
            resource = self.audience
        scopes = list(params.scopes) if params.scopes else (client.scope or self.scope).split()
        if not scopes or not set(scopes) <= {self.scope}:
            raise AuthorizeError(error="invalid_scope", error_description="Unknown scope.")
        if not _CHALLENGE_RE.fullmatch(params.code_challenge):
            raise AuthorizeError(error="invalid_request", error_description="Invalid code_challenge.")
        pending = PendingAuthorization(
            client_id=client.client_id,
            client_kind=client.kind,
            redirect_uri=str(params.redirect_uri),
            redirect_uri_explicit=params.redirect_uri_provided_explicitly,
            code_challenge=params.code_challenge,
            scopes=tuple(scopes),
            state=params.state,
            resource=resource,
            created_at=int(self._clock()),
        )
        try:
            payload = pending.to_json()
        except ValueError:
            raise AuthorizeError(error="invalid_request", error_description="The request is too large.") from None
        try:
            txn_id = await self.authz.txns.put(
                TXN_KIND, payload, TXN_TTL_S, binding_hash=binding_hash(binding)
            )
        except Exception:  # noqa: BLE001 - the driver text is not for the client
            log_warning("oauth_authorize", reason="store_unavailable")
            raise AuthorizeError(
                error="temporarily_unavailable", error_description="Try again in a moment."
            ) from None
        return f"{self.base}/account/login?txn={txn_id}"

    # -- 4./5. authorization codes ------------------------------------------------------------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> LocalAuthorizationCode | None:
        """Look a code up without changing anything.

        A code that was already used is returned too (with its original expiry): the SDK
        then checks the PKCE verifier and the redirect URI **before** the exchange, so a
        replay that cannot prove it holds the verifier never reaches the replay rules.
        """
        if not CODE_RE.fullmatch(authorization_code):
            return None
        record = await anyio.to_thread.run_sync(self.authz.store.load_code, hash_secret(authorization_code))
        if record is None or record.client_id != client.client_id:
            return None
        return LocalAuthorizationCode(
            code=authorization_code,
            scopes=list(record.scopes),
            expires_at=float(record.expires_at),
            client_id=record.client_id,
            code_challenge=record.code_challenge,
            redirect_uri=AnyUrl(record.redirect_uri),
            redirect_uri_provided_explicitly=record.redirect_uri_explicit,
            resource=record.resource,
            subject=f"acct:{record.account_id}",
            account_id=record.account_id,
            code_hash=record.code_hash,
            consumed_at=record.consumed_at,
            grant_id=record.grant_id,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        if not isinstance(authorization_code, LocalAuthorizationCode):
            raise TokenError(error="invalid_grant", error_description="The authorization code is not valid.")
        return await self.authz.grants.issue_from_code(client, authorization_code)

    # -- 6./7. refresh tokens -----------------------------------------------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> LocalRefreshToken | None:
        """Look a refresh token up without changing anything (a used one is returned: see ``rotate``)."""
        if not REFRESH_RE.fullmatch(refresh_token):
            return None
        view = await anyio.to_thread.run_sync(self.authz.store.load_refresh, hash_secret(refresh_token))
        if (
            view is None
            or view.client_id != client.client_id
            or view.grant_revoked_at is not None
            or view.account_id is None
        ):
            return None
        return LocalRefreshToken(
            token=refresh_token,
            client_id=view.client_id,
            scopes=list(view.scopes),
            expires_at=view.expires_at,
            subject=f"acct:{view.account_id}",
            resource=view.resource,
            grant_id=view.grant_id,
            token_hash=view.token_hash,
            account_id=view.account_id,
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        if not isinstance(refresh_token, LocalRefreshToken):
            raise TokenError(error="invalid_grant", error_description="The refresh token is not valid.")
        if not set(scopes) <= set(refresh_token.scopes):
            # Before anything is written: a rejected request must not consume the token.
            raise TokenError(error="invalid_scope", error_description="The scope is not permitted.")
        return await self.authz.grants.rotate(client, refresh_token, scopes)

    # -- 8. access tokens ---------------------------------------------------------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Verify a bearer token. Returns None for anything wrong, and never raises.

        It is called with arbitrary strings (the ``Authorization`` header of any request,
        the ``token`` of ``/revoke``). A failure to read the database counts as "not valid"
        (fail closed); a client that is refused keeps trying with a refresh token.
        """
        try:
            if not isinstance(token, str) or len(token) > MAX_ACCESS_TOKEN_CHARS:
                return None
            claims = await anyio.to_thread.run_sync(self.authz.codec.decode, token)
            if not await self.authz.grants.check_access(claims):
                return None
            return AccessToken(
                token=token,
                client_id=claims["client_id"],
                scopes=claims["scope"].split(" "),
                expires_at=int(claims["exp"]),
                resource=claims["aud"],
                subject=claims["acct"],
                claims=claims,
            )
        except AccessTokenInvalid:
            return None
        except Exception:  # noqa: BLE001 - fail closed on anything, including a database error
            return None

    # -- 9. revocation ------------------------------------------------------------------------

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, LocalRefreshToken):
            await self.authz.grants.revoke_by_client(token.grant_id)
            return
        grant = (getattr(token, "claims", None) or {}).get("grant")
        if isinstance(grant, str):
            await self.authz.grants.revoke_by_client(grant)

    # -- routes -------------------------------------------------------------------------------

    def metadata_document(self) -> dict[str, Any]:
        """The authorization server metadata (RFC 8414), built here so the JSON is pinned by a test."""
        def url(path: str) -> AnyHttpUrl:
            return AnyHttpUrl(self.base + path)

        metadata = OAuthMetadata(
            issuer=AnyHttpUrl(self.issuer),
            authorization_endpoint=url("/authorize"),
            token_endpoint=url("/token"),
            registration_endpoint=url("/register"),
            revocation_endpoint=url("/revoke"),
            scopes_supported=[self.scope],
            response_types_supported=["code"],
            grant_types_supported=["authorization_code", "refresh_token"],
            token_endpoint_auth_methods_supported=["none"],
            revocation_endpoint_auth_methods_supported=["none"],
            code_challenge_methods_supported=["S256"],
            authorization_response_iss_parameter_supported=True,
            client_id_metadata_document_supported=True if self.cimd_enabled else None,
        )
        return metadata.model_dump(mode="json", exclude_none=True)

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = super().get_routes(mcp_path)
        out: list[Route] = []
        for route in routes:
            path = getattr(route, "path", None)
            methods = set(getattr(route, "methods", None) or ())
            if path == "/.well-known/oauth-authorization-server":
                out.append(self._metadata_route())
            elif path == "/authorize":
                out.append(self._authorize_route())
            elif path == "/token" and "POST" in methods:
                out.append(self._token_route())
            elif path == "/revoke":
                out.append(self._revoke_route())
            elif path == "/register":
                out.append(Route(path, endpoint=_StoreGuard(route.endpoint), methods=sorted(methods)))
            else:
                out.append(route)
        assert_route_table(out)
        return out

    def _metadata_route(self) -> Route:
        async def metadata(request: Request) -> Response:
            return JSONResponse(self.metadata_document(), headers={"Cache-Control": METADATA_CACHE_CONTROL})

        return Route(
            "/.well-known/oauth-authorization-server",
            endpoint=_cors(request_response(metadata), ["GET", "OPTIONS"]),
            methods=["GET", "OPTIONS"],
        )

    def _authorize_route(self) -> Route:
        inner = compat.authorization_endpoint(self, base_url=self.base, issuer_url=self.issuer)
        login_prefix = f"{self.base}/account/login?txn="

        async def authorize(request: Request) -> Response:
            cookie = request.cookies.get(BINDING_COOKIE)
            binding = cookie if binding_ok(cookie) and cookie is not None else new_binding()
            purpose = LOOKUP_PURPOSE.set(PURPOSE_AUTHORIZE)
            bound = _BINDING.set(binding)
            outage: list[bool] = []
            flag = LOOKUP_OUTAGE.set(outage)
            try:
                response = await inner(request)
            finally:
                LOOKUP_OUTAGE.reset(flag)
                _BINDING.reset(bound)
                LOOKUP_PURPOSE.reset(purpose)
            if outage and response.status_code == 400:
                return _unavailable()
            location = response.headers.get("location", "")
            if response.status_code == 302 and location.startswith(login_prefix):
                response.set_cookie(
                    BINDING_COOKIE,
                    binding,
                    max_age=BINDING_COOKIE_MAX_AGE,
                    path="/",
                    secure=True,
                    httponly=True,
                    samesite="lax",
                )
            return response

        return Route("/authorize", endpoint=_StoreGuard(request_response(authorize)), methods=["GET", "POST"])

    def _token_route(self) -> Route:
        inner = compat.token_endpoint(self)
        audience = normalize_resource(self.audience)

        async def token(request: Request) -> Response:
            purpose = LOOKUP_PURPOSE.set(PURPOSE_TOKEN)
            outage: list[bool] = []
            flag = LOOKUP_OUTAGE.set(outage)
            try:
                form = await request.form()
                resource = form.get("resource")
                if isinstance(resource, str) and resource != "" and normalize_resource(resource) != audience:
                    # The SDK handler never looks at this field; this server refuses a token for
                    # any resource but its own, as RFC 8707 asks.
                    return _json_error(400, "invalid_target", "Unknown resource.")
                response = await inner(request)
            except StoreUnavailable:
                return _unavailable()
            finally:
                LOOKUP_OUTAGE.reset(flag)
                LOOKUP_PURPOSE.reset(purpose)
            if outage and response.status_code in (400, 401):
                return _unavailable()
            return response

        return Route("/token", endpoint=_cors(request_response(token), ["POST", "OPTIONS"]), methods=["POST", "OPTIONS"])

    def _revoke_route(self) -> Route:
        async def revoke(request: Request) -> Response:
            purpose = LOOKUP_PURPOSE.set(PURPOSE_TOKEN)
            outage: list[bool] = []
            flag = LOOKUP_OUTAGE.set(outage)
            try:
                form = await request.form()
                client_id, token = form.get("client_id"), form.get("token")
                client = await self.get_client(client_id) if isinstance(client_id, str) and client_id else None
                if outage:
                    return _unavailable()
                if client is None or client.token_endpoint_auth_method != "none":
                    return _json_error(401, "invalid_client")
                if not isinstance(token, str) or not token:
                    return _json_error(400, "invalid_request")
                await self._revoke_presented(client, token)
            except StoreUnavailable:
                return _unavailable()
            finally:
                LOOKUP_OUTAGE.reset(flag)
                LOOKUP_PURPOSE.reset(purpose)
            return Response(status_code=200, headers=dict(_NO_STORE))

        return Route("/revoke", endpoint=_cors(request_response(revoke), ["POST", "OPTIONS"]), methods=["POST", "OPTIONS"])

    async def _revoke_presented(self, client: PublicClient, token: str) -> None:
        """Revoke the grant a presented token belongs to, if it belongs to ``client``.

        The same answer (200) whatever the token is: unknown, expired, already revoked or
        another client's. An access token is read without the live-grant check, so a
        token whose grant is already over is simply a no-op.
        """
        if len(token) > MAX_ACCESS_TOKEN_CHARS:
            return
        if token.count(".") == 2:
            try:
                claims = await anyio.to_thread.run_sync(self.authz.codec.decode, token)
            except AccessTokenInvalid:
                return
            if claims.get("client_id") == client.client_id:
                await self.authz.grants.revoke_by_client(str(claims["grant"]))
            return
        refresh = await self.load_refresh_token(client, token)
        if refresh is not None:
            await self.authz.grants.revoke_by_client(refresh.grant_id)

