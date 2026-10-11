"""A generic OpenID Connect relying party (authorization code flow with PKCE).

:class:`OidcLoginProvider` serves any OpenID Connect provider (``oidc:<slug>``) and, with
a :class:`OidcProfile`, Google. The checks, in order, at the callback:

1. the code is exchanged at the token endpoint (client authentication as configured or as the
   discovery document lists it; PKCE verifier; the redirect URI that was registered);
2. an error body, a missing ``id_token`` or an unusable response is ``provider_error``;
3. the ID token is verified (:mod:`.idtoken`): signature against the provider's own keys,
   ``iss``, ``aud``/``azp``, ``exp``/``iat``, a required ``nonce``, ``sub``;
4. optionally the userinfo endpoint is read; its ``sub`` must equal the ID token's (OIDC Core
   5.3.2) and it can never replace ``iss``, ``sub``, ``aud``, ``nonce``, ``exp`` or ``iat``;
5. the claims are reduced to neutral :class:`~..accounts.ExternalClaims`.

The access token the provider returns is used for the userinfo call and then dropped.
Nothing the provider says is shown, stored or logged except a closed error code.
"""

from __future__ import annotations

import logging
import time
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ..accounts import ExternalClaims
from ..routes import auth_callback, auth_login
from .config import TOKEN_AUTH_METHODS, OidcConfig
from .http import CAP_TOKEN, CAP_USERINFO, SafeHttp, UpstreamError
from .idtoken import IdTokenRejected, peek_header, verify_id_token
from .jwks import JwksCache
from .metadata import DiscoveryCache, ProviderMetadata, ProviderUnavailable
from .protocol import ProviderDisplay, SignInRejected

logger = logging.getLogger("canvas_mcp.selfhost.login")

_MAX_CLAIM_NAMES = 32
_MAX_CLAIM_VALUES = 64
_MAX_CLAIM_VALUE_CHARS = 256
_MAX_EMAIL = 254
_MAX_NAME = 200


def clean_text(value: Any, limit: int) -> str:
    """Display text from a provider: control characters become spaces, whitespace is collapsed."""
    if not isinstance(value, str):
        return ""
    text = "".join(
        " " if (ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F) else ch for ch in value
    )
    return " ".join(text.split())[:limit]


@dataclass(frozen=True)
class OidcProfile:
    """What differs between OpenID Connect providers beyond their metadata."""

    #: Every ``iss`` spelling an ID token may carry (Google also uses ``accounts.google.com``).
    accepted_issuers: frozenset[str]
    #: The issuer stored in the identity key.
    stored_issuer: str
    #: The ``iss`` an authorization response must carry, or None.
    response_issuer: str | None
    #: Refuse a response without ``iss`` even if the metadata does not announce the parameter.
    iss_required: bool = False
    #: A ``prompt`` sent on every request (Google: ``select_account``).
    always_prompt: str | None = None
    #: The ``prompt`` that forces the provider to ask again (reauth and link).
    reauth_prompt: str | None = "login"
    #: Extra static authorization parameters (``hd`` for Google).
    extra_params: Mapping[str, str] = field(default_factory=dict)
    #: Provider-specific reduction applied after the generic one.
    reduce: Callable[[ExternalClaims, Mapping[str, Any]], ExternalClaims] | None = None


class OidcLoginProvider:
    """An OpenID Connect provider reached with the authorization code flow."""

    kind = "oidc"

    def __init__(
        self,
        *,
        provider_id: str,
        display: ProviderDisplay,
        start_path: str,
        callback_path: str,
        public_base_url: str,
        issuer: str,
        client_id: str,
        client_secret: str,
        scopes: tuple[str, ...],
        http: SafeHttp,
        profile: OidcProfile,
        token_auth_method: str | None = None,
        userinfo: bool = False,
        claim_names: frozenset[str] = frozenset(),
        clock: Callable[[], float] = time.time,
        discovery: DiscoveryCache | None = None,
        jwks: JwksCache | None = None,
    ) -> None:
        self.id = provider_id
        self.display = display
        self.start_path = start_path
        self.callback_path = callback_path
        self.redirect_uri = public_base_url.rstrip("/") + callback_path
        self.response_issuer = profile.response_issuer
        self._issuer = issuer
        self._client_id = client_id
        self._client_secret = client_secret
        self._scopes = scopes
        self._http = http
        self._profile = profile
        self._token_auth_method = token_auth_method
        self._userinfo = userinfo
        self._claim_names = claim_names
        self._clock = clock
        self.discovery = discovery or DiscoveryCache(issuer, http, clock=clock)
        self.jwks = jwks or JwksCache(http, clock=clock)

    def __repr__(self) -> str:
        return f"OidcLoginProvider({self.id})"

    # -- the start --------------------------------------------------------------------------

    async def prepare(self) -> None:
        await self.discovery.get()

    def requires_iss(self) -> bool:
        if self._profile.iss_required:
            return True
        meta = self.discovery.current()
        return meta is not None and meta.iss_param_supported

    def authorize_url(
        self, *, state: str, nonce: str, code_challenge: str, reauth: bool
    ) -> str:
        meta = self.discovery.current()
        if meta is None:
            raise ProviderUnavailable
        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self._scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        prompt = self._profile.always_prompt or (
            self._profile.reauth_prompt if reauth else None
        )
        if prompt:
            params["prompt"] = prompt
        params.update(self._profile.extra_params)
        separator = "&" if "?" in meta.authorization_endpoint else "?"
        return meta.authorization_endpoint + separator + urllib.parse.urlencode(params)

    # -- the callback -------------------------------------------------------------------------

    async def finish(
        self, *, code: str, code_verifier: str, nonce: str
    ) -> ExternalClaims:
        try:
            meta = await self.discovery.get()
        except ProviderUnavailable:
            raise SignInRejected("provider_error") from None
        body = await self._exchange(meta, code, code_verifier)
        raw_id_token = body.get("id_token")
        if not isinstance(raw_id_token, str) or not raw_id_token:
            logger.warning(
                "provider sign-in failed provider=%s step=token reason=no_id_token",
                self.id,
            )
            raise SignInRejected("provider_error")
        claims = await self._verify(meta, raw_id_token, nonce)
        extra: Mapping[str, Any] = {}
        if self._userinfo:
            extra = await self._fetch_userinfo(
                meta, body.get("access_token"), claims["sub"]
            )
        return self._reduce(claims, extra)

    async def _exchange(
        self, meta: ProviderMetadata, code: str, verifier: str
    ) -> Mapping[str, Any]:
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": verifier,
        }
        basic: tuple[str, str] | None = None
        if self._auth_method(meta) == "client_secret_basic":
            basic = (
                urllib.parse.quote_plus(self._client_id, safe=""),
                urllib.parse.quote_plus(self._client_secret, safe=""),
            )
        else:
            form["client_id"] = self._client_id
            form["client_secret"] = self._client_secret
        try:
            result = await self._http.post_form(
                meta.token_endpoint, form, max_bytes=CAP_TOKEN, basic_auth=basic
            )
        except UpstreamError as exc:
            logger.warning(
                "provider sign-in failed provider=%s step=token code=%s status=%s error=%s",
                self.id,
                exc.code,
                exc.status,
                exc.oauth_error or "-",
            )
            raise SignInRejected("provider_error") from None
        body: Mapping[str, Any] = result.body
        if "error" in body:
            logger.warning(
                "provider sign-in failed provider=%s step=token reason=error_body",
                self.id,
            )
            raise SignInRejected("provider_error")
        return body

    def _auth_method(self, meta: ProviderMetadata) -> str:
        """The configured method, else basic when the provider lists it (or lists nothing), else post."""
        if self._token_auth_method in TOKEN_AUTH_METHODS:
            assert self._token_auth_method is not None
            return self._token_auth_method
        listed = meta.token_auth_methods
        if not listed or "client_secret_basic" in listed:
            return "client_secret_basic"
        return "client_secret_post"

    async def _verify(
        self, meta: ProviderMetadata, raw_id_token: str, nonce: str
    ) -> dict[str, Any]:
        try:
            kid = peek_header(raw_id_token).get("kid")
            await self.jwks.ensure(meta.jwks_uri, kid if isinstance(kid, str) else None)
            return verify_id_token(
                raw_id_token,
                key_lookup=self.jwks.lookup,
                client_id=self._client_id,
                accepted_issuers=self._profile.accepted_issuers,
                nonce=nonce,
                allowed_algs=meta.algs,
                now=self._clock(),
            )
        except IdTokenRejected as exc:
            logger.warning(
                "provider sign-in refused provider=%s step=id_token reason=%s",
                self.id,
                exc.reason,
            )
            raise SignInRejected("sign_in_unverified") from None

    async def _fetch_userinfo(
        self, meta: ProviderMetadata, access_token: Any, subject: str
    ) -> Mapping[str, Any]:
        if (
            meta.userinfo_endpoint is None
            or not isinstance(access_token, str)
            or not access_token
        ):
            raise SignInRejected("provider_error")
        try:
            result = await self._http.get_json(
                meta.userinfo_endpoint,
                max_bytes=CAP_USERINFO,
                headers={"Authorization": f"Bearer {access_token}"},
            )
        except UpstreamError as exc:
            logger.warning(
                "provider sign-in failed provider=%s step=userinfo code=%s status=%s",
                self.id,
                exc.code,
                exc.status,
            )
            raise SignInRejected("provider_error") from None
        info: Mapping[str, Any] = result.body
        if info.get("sub") != subject:
            logger.warning(
                "provider sign-in refused provider=%s step=userinfo reason=sub", self.id
            )
            raise SignInRejected("sign_in_unverified")
        return info

    # -- reduction ----------------------------------------------------------------------------------

    def _reduce(
        self, claims: Mapping[str, Any], userinfo: Mapping[str, Any]
    ) -> ExternalClaims:
        def pick(name: str) -> tuple[Any, Mapping[str, Any]]:
            """The claim's value and the document it came from (the ID token wins)."""
            if name in claims:
                return claims[name], claims
            return userinfo.get(name), userinfo

        email_value, email_source = pick("email")
        email = (
            email_value.strip()
            if isinstance(email_value, str)
            and 0 < len(email_value.strip()) <= _MAX_EMAIL
            else None
        )
        verified = email is not None and email_source.get("email_verified") is True
        name_value, _ = pick("name")
        preferred, _ = pick("preferred_username")
        username = clean_text(preferred, _MAX_EMAIL) or (email or "")
        ext = ExternalClaims(
            provider_id=self.id,
            issuer=self._profile.stored_issuer,
            subject=claims["sub"],
            email=email,
            email_verified=verified,
            display_name=clean_text(name_value, _MAX_NAME)
            or clean_text(preferred, _MAX_NAME),
            username=username,
            claims=self._wanted_claims(claims, userinfo),
        )
        if self._profile.reduce is not None:
            ext = self._profile.reduce(ext, claims)
        return ext

    def _wanted_claims(
        self, claims: Mapping[str, Any], userinfo: Mapping[str, Any]
    ) -> tuple[tuple[str, tuple[str, ...]], ...]:
        """Only the claims the admission rules look at: strings and lists of strings, bounded."""
        out: list[tuple[str, tuple[str, ...]]] = []
        for name in sorted(self._claim_names)[:_MAX_CLAIM_NAMES]:
            value = claims[name] if name in claims else userinfo.get(name)
            if isinstance(value, str):
                values = [value]
            elif isinstance(value, list) and all(isinstance(v, str) for v in value):
                values = list(value)
            else:
                continue
            kept = tuple(
                v
                for v in values[:_MAX_CLAIM_VALUES]
                if len(v) <= _MAX_CLAIM_VALUE_CHARS
            )
            if kept:
                out.append((name, kept))
        return tuple(out)


def build_oidc_provider(
    config: OidcConfig,
    *,
    public_base_url: str,
    http: SafeHttp,
    claim_names: frozenset[str] = frozenset(),
    clock: Callable[[], float] = time.time,
) -> OidcLoginProvider:
    """A generic OpenID Connect provider (``oidc:<slug>``) from its configuration.

    ``claim_names`` are the claims ``ACCESS_RULES`` look at for this provider; only those are
    kept from the tokens.
    """
    return OidcLoginProvider(
        provider_id=config.provider_id,
        display=ProviderDisplay(config.label, "key"),
        start_path=auth_login(config.provider_id),
        callback_path=auth_callback(config.provider_id),
        public_base_url=public_base_url,
        issuer=config.issuer,
        client_id=config.client_id,
        client_secret=config.client_secret,
        scopes=config.scopes,
        http=http,
        profile=OidcProfile(
            accepted_issuers=frozenset({config.issuer}),
            stored_issuer=config.issuer,
            response_issuer=config.issuer,
        ),
        token_auth_method=config.token_auth_method,
        userinfo=config.userinfo,
        claim_names=claim_names,
        clock=clock,
    )
