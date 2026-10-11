"""Offline fakes of the identity providers, as ``httpx.MockTransport`` handlers.

Nothing here touches the network: the server under test is given :attr:`FakeNetwork.transport`
(its ``login_transport``), and every https request it makes lands in a handler below.

* :class:`FakeOidcIdp`: discovery, a JWKS with RSA and EC keys that can rotate, an authorization
  endpoint the test "visits" with :meth:`FakeOidcIdp.authorize`, a token endpoint that checks the
  client authentication, the code (single use), the redirect URI and the PKCE verifier, and a
  userinfo endpoint. :func:`google_idp` configures it like Google.
* :class:`FakeGitHub`: ``github.com/login/oauth`` and ``api.github.com`` as far as the sign-in uses
  them.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from joserfc import jwt
from joserfc.jwk import ECKey, OctKey, RSAKey

_RSA_CACHE: dict[str, Any] = {}


def rsa_key(name: str) -> RSAKey:
    """A 2048-bit RSA key, generated once per name for the whole test run (generation is slow)."""
    if name not in _RSA_CACHE:
        _RSA_CACHE[name] = RSAKey.generate_key(2048, parameters={"kid": name, "use": "sig"})
    key: RSAKey = _RSA_CACHE[name]
    return key


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def s256(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


class FakeNetwork:
    """Routes every outbound https request of the server to the handler registered for its host."""

    def __init__(self) -> None:
        self.handlers: dict[str, Callable[[httpx.Request], httpx.Response]] = {}
        self.log: list[tuple[str, str, str]] = []
        self.blocked: set[str] = set()
        self.transport = httpx.MockTransport(self._handle)

    def add(self, host: str, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.handlers[host] = handler

    def requests_to(self, host: str, path_prefix: str = "") -> list[tuple[str, str, str]]:
        return [r for r in self.log if r[1] == host and r[2].startswith(path_prefix)]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        self.log.append((request.method, host, request.url.path))
        if host in self.blocked or host not in self.handlers:
            raise httpx.ConnectError("no route", request=request)
        return self.handlers[host](request)


def json_response(status: int, body: Any, **headers: str) -> httpx.Response:
    return httpx.Response(status, json=body, headers=headers)


@dataclass
class IdpUser:
    sub: str = "user-1"
    email: str | None = "ada@example.edu"
    email_verified: Any = True
    name: str = "Ada Lovelace"
    preferred_username: str = "ada"
    extra: dict[str, Any] = field(default_factory=dict)


class FakeOidcIdp:
    """An OpenID Connect provider."""

    def __init__(
        self,
        net: FakeNetwork,
        issuer: str = "https://idp.example.edu/realms/school",
        *,
        client_id: str = "canvas-mcp",
        client_secret: str = "oidc-secret-value-0123456789abcdef",
        algs: tuple[str, ...] = ("RS256", "ES256"),
        iss_param: bool = False,
        pkce_methods: tuple[str, ...] | None = ("S256",),
        token_auth: tuple[str, ...] | None = ("client_secret_basic", "client_secret_post"),
        endpoints: Mapping[str, str] | None = None,
        id_token_issuer: str | None = None,
        cache_control: str | None = None,
    ) -> None:
        self.net = net
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.algs = algs
        self.iss_param = iss_param
        self.pkce_methods = pkce_methods
        self.token_auth = token_auth
        self.id_token_issuer = id_token_issuer or issuer
        self.cache_control = cache_control
        base = issuer.rstrip("/")
        self.endpoints = {
            "authorization": f"{base}/protocol/openid-connect/auth",
            "token": f"{base}/protocol/openid-connect/token",
            "jwks": f"{base}/protocol/openid-connect/certs",
            "userinfo": f"{base}/protocol/openid-connect/userinfo",
            **dict(endpoints or {}),
        }
        self.discovery_overrides: dict[str, Any] = {}
        self.rsa = rsa_key("rsa-1")
        self.ec = ECKey.generate_key("P-256", parameters={"kid": "ec-1", "use": "sig"})
        self.published: list[Any] = [self.rsa, self.ec]
        self.extra_jwks: list[dict[str, Any]] = []
        self.user = IdpUser()
        self.userinfo_sub: str | None = None
        self.userinfo_extra: dict[str, Any] = {}
        self.codes: dict[str, dict[str, Any]] = {}
        self.counts = {"discovery": 0, "jwks": 0, "token": 0, "userinfo": 0}
        self.token_requests: list[dict[str, Any]] = []
        self.token_error: tuple[int, dict[str, Any]] | None = None
        self.token_extra: dict[str, Any] = {}
        self.id_token_override: dict[str, Any] | None = None
        self.drop_id_token = False
        self.now: Callable[[], float] = time.time
        hosts = {urlsplit(u).hostname or "" for u in (issuer, *self.endpoints.values())}
        for host in hosts:
            net.add(host, self.handle)

    # -- documents ---------------------------------------------------------------------------

    def discovery_document(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "issuer": self.issuer,
            "authorization_endpoint": self.endpoints["authorization"],
            "token_endpoint": self.endpoints["token"],
            "jwks_uri": self.endpoints["jwks"],
            "userinfo_endpoint": self.endpoints["userinfo"],
            "response_types_supported": ["code", "id_token", "code id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": list(self.algs),
            "scopes_supported": ["openid", "email", "profile"],
        }
        if self.pkce_methods is not None:
            doc["code_challenge_methods_supported"] = list(self.pkce_methods)
        if self.token_auth is not None:
            doc["token_endpoint_auth_methods_supported"] = list(self.token_auth)
        if self.iss_param:
            doc["authorization_response_iss_parameter_supported"] = True
        doc.update(self.discovery_overrides)
        return {k: v for k, v in doc.items() if v is not None}

    def jwks_document(self) -> dict[str, Any]:
        keys = [k.as_dict(private=False) for k in self.published]
        return {"keys": [*keys, *self.extra_jwks]}

    def rotate(self, *, drop_old: bool = True, name: str = "rsa-2") -> RSAKey:
        """Publish a new signing key; optionally stop publishing the old ones."""
        new = rsa_key(name)
        self.published = [new] if drop_old else [*self.published, new]
        self.rsa = new
        return new

    # -- the handler ------------------------------------------------------------------------

    def handle(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url).split("?", 1)[0]
        if url == self.issuer.rstrip("/") + "/.well-known/openid-configuration":
            self.counts["discovery"] += 1
            headers = {"cache-control": self.cache_control} if self.cache_control else {}
            return json_response(200, self.discovery_document(), **headers)
        if url == self.endpoints["jwks"]:
            self.counts["jwks"] += 1
            return json_response(200, self.jwks_document())
        if url == self.endpoints["token"]:
            return self._token(request)
        if url == self.endpoints["userinfo"]:
            return self._userinfo(request)
        return httpx.Response(404, json={"error": "not_found"})

    def _client_auth(self, request: httpx.Request, form: Mapping[str, str]) -> str | None:
        """The method the client authenticated with, or None when it failed."""
        header = request.headers.get("authorization", "")
        if header.lower().startswith("basic "):
            if self.token_auth is not None and "client_secret_basic" not in self.token_auth:
                return None
            try:
                decoded = base64.b64decode(header[6:]).decode("utf-8")
            except ValueError:
                return None
            user, _, password = decoded.partition(":")
            from urllib.parse import unquote_plus

            if unquote_plus(user) == self.client_id and unquote_plus(password) == self.client_secret:
                return "client_secret_basic"
            return None
        if "client_secret" in form:
            if self.token_auth is not None and "client_secret_post" not in self.token_auth:
                return None
            if form.get("client_id") == self.client_id and form["client_secret"] == self.client_secret:
                return "client_secret_post"
        return None

    def _token(self, request: httpx.Request) -> httpx.Response:
        self.counts["token"] += 1
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        method = self._client_auth(request, form)
        record = {"form": form, "auth": method, "headers": dict(request.headers)}
        self.token_requests.append(record)
        if self.token_error is not None:
            return json_response(*self.token_error)
        if method is None:
            return json_response(401, {"error": "invalid_client"})
        if form.get("grant_type") != "authorization_code":
            return json_response(400, {"error": "unsupported_grant_type"})
        grant = self.codes.pop(form.get("code", ""), None)
        if grant is None:
            return json_response(400, {"error": "invalid_grant"})
        if form.get("redirect_uri") != grant["redirect_uri"]:
            return json_response(400, {"error": "invalid_grant"})
        if grant["code_challenge"] and s256(form.get("code_verifier", "")) != grant["code_challenge"]:
            return json_response(400, {"error": "invalid_grant"})
        body: dict[str, Any] = {
            "access_token": "idp-access-token-" + secrets.token_urlsafe(8),
            "token_type": "Bearer",
            "expires_in": 3600,
            **self.token_extra,
        }
        if not self.drop_id_token:
            body["id_token"] = self.mint_id_token(nonce=grant["nonce"])
        return json_response(200, body)

    def _userinfo(self, request: httpx.Request) -> httpx.Response:
        self.counts["userinfo"] += 1
        if not request.headers.get("authorization", "").startswith("Bearer idp-access-token-"):
            return json_response(401, {"error": "invalid_token"})
        doc = {"sub": self.userinfo_sub or self.user.sub, **self.userinfo_extra}
        return json_response(200, doc)

    # -- the browser's part ---------------------------------------------------------------

    def authorize(
        self,
        url: str,
        *,
        iss: str | None = "auto",
        error: str | None = None,
        user: IdpUser | None = None,
    ) -> str:
        """"Visit" the server's authorization URL and return the callback URL the IdP redirects to."""
        parts = urlsplit(url)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == self.endpoints["authorization"], url
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        assert q["response_type"] == "code" and q["client_id"] == self.client_id, q
        assert q["code_challenge_method"] == "S256" and len(q["code_challenge"]) == 43, q
        assert "openid" in q["scope"].split() and q["state"] and q["nonce"], q
        assert q.get("response_mode", "query") == "query" and "id_token" not in q.get("response_type", ""), q
        callback = q["redirect_uri"]
        params: dict[str, str] = {"state": q["state"]}
        if error is not None:
            params["error"] = error
            params["error_description"] = "<script>alert(1)</script> secret idp text"
        else:
            code = "code-" + secrets.token_urlsafe(12)
            self.codes[code] = {
                "redirect_uri": callback,
                "code_challenge": q["code_challenge"],
                "nonce": q["nonce"],
                "user": user or self.user,
            }
            params["code"] = code
        if iss == "auto":
            iss = self.issuer if self.iss_param else None
        if iss is not None:
            params["iss"] = iss
        self.last_authorize = q
        return callback + "?" + urlencode(params)

    last_authorize: dict[str, str] = {}

    # -- tokens -----------------------------------------------------------------------------

    def claims_for(self, nonce: str | None, user: IdpUser | None = None) -> dict[str, Any]:
        user = user or self.user
        now = int(self.now())
        claims: dict[str, Any] = {
            "iss": self.id_token_issuer,
            "aud": self.client_id,
            "sub": user.sub,
            "iat": now,
            "exp": now + 3600,
            "name": user.name,
            "preferred_username": user.preferred_username,
        }
        if nonce is not None:
            claims["nonce"] = nonce
        if user.email is not None:
            claims["email"] = user.email
            claims["email_verified"] = user.email_verified
        claims.update(user.extra)
        if self.id_token_override:
            claims.update(self.id_token_override)
        return {k: v for k, v in claims.items() if v is not _DELETE}

    def mint_id_token(
        self,
        *,
        nonce: str | None,
        claims: Mapping[str, Any] | None = None,
        header: Mapping[str, Any] | None = None,
        key: Any = None,
        alg: str | None = None,
        user: IdpUser | None = None,
    ) -> str:
        """A signed ID token. ``claims`` override (use ``DELETE`` to remove one); ``key``/``alg``/``header`` too."""
        body = self.claims_for(nonce, user)
        body.update(claims or {})
        body = {k: v for k, v in body.items() if v is not _DELETE}
        signer = key if key is not None else self.rsa
        algorithm = alg or ("ES256" if isinstance(signer, ECKey) else "RS256")
        head = {"alg": algorithm, "kid": signer.kid, "typ": "JWT", **dict(header or {})}
        head = {k: v for k, v in head.items() if v is not _DELETE}
        return jwt.encode(head, body, signer, algorithms=[algorithm])

    def hs256_token(self, secret: str, *, nonce: str) -> str:
        """The key-confusion attack: an HMAC token keyed with the client secret."""
        body = self.claims_for(nonce)
        return jwt.encode(
            {"alg": "HS256", "typ": "JWT"}, body, OctKey.import_key(secret), algorithms=["HS256"]
        )

    def unsigned_token(self, *, nonce: str, alg: str = "none") -> str:
        head = b64url(json.dumps({"alg": alg, "typ": "JWT"}).encode())
        body = b64url(json.dumps(self.claims_for(nonce)).encode())
        return f"{head}.{body}."


class _Delete:
    def __repr__(self) -> str:
        return "DELETE"


#: Pass as a claim or header value to remove it.
DELETE = _Delete()
_DELETE = DELETE


def google_idp(net: FakeNetwork, **kw: Any) -> FakeOidcIdp:
    """A fake Google: its real endpoints, RFC 9207 on, RS256 only."""
    options: dict[str, Any] = {
        "client_id": "1234567890-abcdefghij.apps.googleusercontent.com",
        "client_secret": "GOCSPX-google-secret-value-0123",
        "algs": ("RS256",),
        "iss_param": True,
        "pkce_methods": ("plain", "S256"),
        "token_auth": ("client_secret_post", "client_secret_basic"),
        "endpoints": {
            "authorization": "https://accounts.google.com/o/oauth2/v2/auth",
            "token": "https://oauth2.googleapis.com/token",
            "jwks": "https://www.googleapis.com/oauth2/v3/certs",
            "userinfo": "https://openidconnect.googleapis.com/v1/userinfo",
        },
        **kw,
    }
    idp = FakeOidcIdp(net, "https://accounts.google.com", **options)
    idp.user = IdpUser(sub="110169484474386276334", email="ada@example.edu", extra={"hd": "example.edu"})
    idp.published = [idp.rsa]
    return idp


# -- GitHub ---------------------------------------------------------------------------------------


@dataclass
class GitHubUser:
    id: Any = 583231
    login: str = "octocat"
    name: str | None = "The Octocat"
    email: str | None = None
    emails: list[dict[str, Any]] | None = field(
        default_factory=lambda: [
            {"email": "octocat@example.test", "primary": True, "verified": True, "visibility": "private"}
        ]
    )
    #: org -> membership answer: ("active"|"pending", status 200) / 404 / 403
    orgs: dict[str, Any] = field(default_factory=dict)
    #: "org/team" -> same
    teams: dict[str, Any] = field(default_factory=dict)


class FakeGitHub:
    """github.com (authorize and token) and api.github.com (/user, /user/emails, memberships)."""

    def __init__(self, net: FakeNetwork, *, client_id: str = "Iv1.0123456789abcdef",
                 client_secret: str = "github-secret-value-0123456789abcdef") -> None:
        self.net = net
        self.client_id = client_id
        self.client_secret = client_secret
        self.user = GitHubUser()
        self.granted_scope: str | None = None  # None: grant what was requested
        self.codes: dict[str, dict[str, Any]] = {}
        self.issued_tokens: list[str] = []
        self.token_error: dict[str, Any] | None = None
        self.token_extra: dict[str, Any] = {"refresh_token": "ghr_refresh_value", "expires_in": 28800}
        self.api_requests: list[tuple[str, str, dict[str, str]]] = []
        self.token_requests: list[dict[str, str]] = []
        self.emails_status = 200
        #: (status, headers) the membership endpoints answer with instead of the user's data
        self.membership_override: tuple[int, dict[str, str]] | None = None
        net.add("github.com", self._web)
        net.add("api.github.com", self._api)
        self.last_authorize: dict[str, str] = {}

    def authorize(self, url: str, *, error: str | None = None) -> str:
        parts = urlsplit(url)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == "https://github.com/login/oauth/authorize", url
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        assert q["client_id"] == self.client_id and q["code_challenge_method"] == "S256", q
        assert len(q["code_challenge"]) == 43 and q["state"], q
        assert "nonce" not in q and "response_type" not in q, q
        self.last_authorize = q
        params: dict[str, str] = {"state": q["state"]}
        if error is not None:
            params["error"] = error
            params["error_description"] = "idp supplied text that must never be shown"
        else:
            code = "ghcode-" + secrets.token_urlsafe(10)
            scope = self.granted_scope if self.granted_scope is not None else q.get("scope", "")
            self.codes[code] = {
                "redirect_uri": q["redirect_uri"],
                "challenge": q["code_challenge"],
                "scope": scope,
            }
            params["code"] = code
        return q["redirect_uri"] + "?" + urlencode(params)

    def _web(self, request: httpx.Request) -> httpx.Response:
        if request.url.path != "/login/oauth/access_token":
            return httpx.Response(404)
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        self.token_requests.append(form)
        if request.headers.get("accept") != "application/json":
            return httpx.Response(200, text="access_token=form-encoded&token_type=bearer")
        if self.token_error is not None:
            return json_response(200, self.token_error)
        grant = self.codes.pop(form.get("code", ""), None)
        if (
            grant is None
            or form.get("client_id") != self.client_id
            or form.get("client_secret") != self.client_secret
        ):
            return json_response(200, {"error": "bad_verification_code", "error_description": "x"})
        if form.get("redirect_uri") != grant["redirect_uri"]:
            return json_response(200, {"error": "redirect_uri_mismatch"})
        if s256(form.get("code_verifier", "")) != grant["challenge"]:
            return json_response(200, {"error": "bad_verification_code"})
        token = "gho_" + secrets.token_urlsafe(24)
        self.issued_tokens.append(token)
        return json_response(
            200, {"access_token": token, "scope": grant["scope"].replace(" ", ","),
                  "token_type": "bearer", **self.token_extra},
        )

    def _api(self, request: httpx.Request) -> httpx.Response:
        headers = {k.lower(): v for k, v in request.headers.items()}
        self.api_requests.append((request.method, request.url.path, headers))
        assert headers.get("accept") == "application/vnd.github+json", headers
        assert headers.get("x-github-api-version") == "2026-03-10", headers
        assert headers.get("user-agent"), headers
        token = headers.get("authorization", "")
        if not token.startswith("Bearer ") or token[7:] not in self.issued_tokens:
            return json_response(401, {"message": "Bad credentials"})
        path = request.url.path
        user = self.user
        if path == "/user":
            return json_response(
                200, {"id": user.id, "login": user.login, "name": user.name, "email": user.email}
            )
        if path == "/user/emails":
            if self.emails_status != 200:
                return json_response(self.emails_status, {"message": "x"})
            return json_response(200, user.emails if user.emails is not None else [])
        if self.membership_override is not None and (
            path.startswith("/user/memberships/orgs/") or "/memberships/" in path
        ):
            status, extra = self.membership_override
            return json_response(status, {"message": "x"}, **extra)
        if path.startswith("/user/memberships/orgs/"):
            return self._membership(user.orgs.get(path.rsplit("/", 1)[1].lower()))
        if path.startswith("/orgs/") and "/teams/" in path and "/memberships/" in path:
            org = path.split("/")[2].lower()
            team = path.split("/")[4].lower()
            return self._membership(user.teams.get(f"{org}/{team}"))
        return json_response(404, {"message": "Not Found"})

    @staticmethod
    def _membership(value: Any) -> httpx.Response:
        if value is None or value == 404:
            return json_response(404, {"message": "Not Found"})
        if value == 403:
            return json_response(403, {"message": "OAuth App access restrictions"})
        return json_response(200, {"state": value, "role": "member"})
