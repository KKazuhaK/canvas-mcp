"""What the authorization server relies on in FastMCP and the MCP SDK, pinned.

``authz/fastmcp_compat.py`` is the only module that imports non-exported pieces of
FastMCP and the SDK. Each test here pins one fact about them that the design depends on,
so a release that changes it fails *here*, with the reason in the test name, instead of
somewhere in the flow. The suite runs against the locked versions (what CI installs) and
the newest installed ones; where the two differ the test says which is which.

Facts pinned (letters follow the design):

a. the ``/authorize`` handler: constructor keywords; an ``AuthorizeError`` becomes a 302
   with ``error``, ``state`` and exactly one ``iss``; an unknown client is a 400 page.
b. the ``/token`` handler: fields; ``invalid_grant`` is HTTP 401; an unknown client is 401
   ``invalid_client``; a public client needs no secret; the form ``resource`` is ignored.
c. the registration handler: echoes the mutated record; defaults to ``client_secret_post``
   with a minted secret; refuses jwt-bearer and ``private_key_jwt``; applies default scopes;
   accepts ``javascript:`` and plain-http redirect URIs (so ``register_client`` must not).
d. the stock ``/revoke`` answers 400 to a public client (so ours replaces it).
e. the route table of a bare provider.
f. ``_get_resource_url``.
g. the SSRF-pinned fetcher: keywords, and offline refusals.
h. the CIMD document model.
i. the redirect helpers.
j. public types: provider protocol fields, error literals, metadata fields.
k. an AST guard: nobody but ``fastmcp_compat`` imports non-exported internals.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import pathlib
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastmcp.server.auth import AccessToken, OAuthProvider
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthMetadata,
    OAuthToken,
    ProtectedResourceMetadata,
)
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from canvas_mcp.core.selfhost.authz import fastmcp_compat as compat

BASE = "https://canvas.example.test"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"
SRC = pathlib.Path(__file__).resolve().parents[3] / "src" / "canvas_mcp"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"  # its S256 challenge is CHALLENGE


class Stock(OAuthProvider):
    """A minimal provider on the stock base class, to observe what the stock handlers do."""

    def __init__(self) -> None:
        super().__init__(
            base_url=BASE,
            issuer_url=BASE,
            required_scopes=["s"],
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=["s"], default_scopes=["s"]
            ),
            revocation_options=RevocationOptions(enabled=True),
        )
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.authorize_error: str | None = None
        self.exchange_error: str | None = None
        self.exchanged = 0

    async def get_client(self, client_id: str):  # type: ignore[no-untyped-def]
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: Any, params: AuthorizationParams) -> str:
        if self.authorize_error:
            raise AuthorizeError(error=self.authorize_error)  # type: ignore[arg-type]
        return f"{BASE}/login?x=1"

    async def load_authorization_code(self, client: Any, authorization_code: str):  # type: ignore[no-untyped-def]
        if authorization_code != "code-1":
            return None
        return AuthorizationCode(
            code="code-1", scopes=["s"], expires_at=4_000_000_000, client_id=client.client_id,
            code_challenge=CHALLENGE, redirect_uri=AnyUrl(REDIRECT),
            redirect_uri_provided_explicitly=True,
        )

    async def exchange_authorization_code(self, client: Any, authorization_code: Any) -> OAuthToken:
        if self.exchange_error:
            raise TokenError(error=self.exchange_error)  # type: ignore[arg-type]
        self.exchanged += 1
        return OAuthToken(access_token="at", token_type="Bearer")


def _public(client_id: str = "c1", **kw: Any) -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id=client_id, redirect_uris=[AnyUrl(REDIRECT)], token_endpoint_auth_method="none",
        scope="s", **kw,
    )


@pytest.fixture
def stock() -> Stock:
    provider = Stock()
    provider.clients["c1"] = _public()
    return provider


@pytest.fixture
def stock_client(stock: Stock) -> TestClient:
    return TestClient(Starlette(routes=stock.get_routes("/mcp")), base_url=BASE, follow_redirects=False)


# -- a. /authorize ------------------------------------------------------------------------


class TestAuthorizeHandler:
    def _params(self, **extra: str) -> dict[str, str]:
        return {
            "response_type": "code", "client_id": "c1", "redirect_uri": REDIRECT, "state": "st",
            "code_challenge": CHALLENGE, "code_challenge_method": "S256", "scope": "s", **extra,
        }

    def test_the_constructor_takes_provider_and_both_urls_as_keywords(self) -> None:
        params = inspect.signature(compat.AuthorizationHandler.__init__).parameters
        assert {"provider", "base_url", "issuer_url"} <= set(params)
        assert all(params[n].kind is inspect.Parameter.KEYWORD_ONLY for n in ("provider", "base_url", "issuer_url"))

    def test_an_authorize_error_redirects_with_error_state_and_exactly_one_iss(self, stock: Stock) -> None:
        stock.authorize_error = "invalid_target"
        handler = compat.authorization_endpoint(stock, base_url=BASE, issuer_url=BASE + "/")
        client = TestClient(
            Starlette(routes=[Route("/authorize", handler, methods=["GET"])]), base_url=BASE, follow_redirects=False
        )
        response = client.get("/authorize", params=self._params())
        assert response.status_code == 302
        location = response.headers["location"]
        assert location.startswith(REDIRECT + "?")
        query = parse_qs(urlsplit(location).query)
        assert query["error"] == ["invalid_target"] and query["state"] == ["st"]
        assert query["iss"] == [BASE + "/"]  # exactly one, byte for byte the issuer given

    def test_an_iss_in_the_registered_redirect_is_replaced_not_duplicated(self) -> None:
        url = compat.client_redirect(REDIRECT + "?iss=evil&keep=1", {"code": "c"}, iss=BASE + "/")
        query = parse_qs(urlsplit(url).query)
        assert query["iss"] == [BASE + "/"] and query["keep"] == ["1"] and query["code"] == ["c"]
        assert url.count("iss=") == 1

    def test_a_success_redirect_without_code_or_error_is_untouched(self, stock: Stock) -> None:
        handler = compat.authorization_endpoint(stock, base_url=BASE, issuer_url=BASE + "/")
        client = TestClient(
            Starlette(routes=[Route("/authorize", handler, methods=["GET"])]), base_url=BASE, follow_redirects=False
        )
        response = client.get("/authorize", params=self._params())
        assert response.status_code == 302 and response.headers["location"] == f"{BASE}/login?x=1"
        assert response.headers["cache-control"] == "no-store"

    def test_an_unknown_client_is_a_400_with_no_redirect(self, stock: Stock) -> None:
        handler = compat.authorization_endpoint(stock, base_url=BASE, issuer_url=BASE + "/")
        client = TestClient(
            Starlette(routes=[Route("/authorize", handler, methods=["GET"])]), base_url=BASE, follow_redirects=False
        )
        response = client.get("/authorize", params=self._params(client_id="nobody"))
        assert response.status_code == 400 and "location" not in response.headers

    def test_an_unregistered_redirect_uri_is_a_400_with_no_redirect(self, stock: Stock) -> None:
        handler = compat.authorization_endpoint(stock, base_url=BASE, issuer_url=BASE + "/")
        client = TestClient(
            Starlette(routes=[Route("/authorize", handler, methods=["GET"])]), base_url=BASE, follow_redirects=False
        )
        response = client.get("/authorize", params=self._params(redirect_uri="https://evil.example/cb"))
        assert response.status_code == 400 and "location" not in response.headers

    def test_the_stock_handler_checks_challenge_method_and_response_type(self, stock_client: TestClient) -> None:
        for bad in ({"code_challenge_method": "plain"}, {"response_type": "token"}):
            response = stock_client.get("/authorize", params=self._params(**bad))
            assert response.status_code == 302 and "error=" in response.headers["location"]


# -- b. /token ------------------------------------------------------------------------------


class TestTokenHandler:
    def _form(self, **extra: str) -> dict[str, str]:
        return {
            "grant_type": "authorization_code", "code": "code-1", "client_id": "c1",
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER, **extra,
        }

    def _client(self, stock: Stock) -> TestClient:
        handler = compat.token_endpoint(stock)
        return TestClient(Starlette(routes=[Route("/token", handler, methods=["POST"])]), base_url=BASE)

    def test_the_handler_is_a_dataclass_of_provider_authenticator_and_the_assertion_flag(self) -> None:
        names = [f.name for f in dataclasses.fields(compat.TokenHandler)]
        assert names[:2] == ["provider", "client_authenticator"] and "identity_assertion_enabled" in names
        default = next(f for f in dataclasses.fields(compat.TokenHandler) if f.name == "identity_assertion_enabled")
        assert default.default is False

    def test_a_public_client_exchanges_a_code_without_any_secret(self, stock: Stock) -> None:
        response = self._client(stock).post("/token", data=self._form())
        assert response.status_code == 200 and response.json()["access_token"] == "at"

    def test_invalid_grant_is_http_401(self, stock: Stock) -> None:
        stock.exchange_error = "invalid_grant"
        response = self._client(stock).post("/token", data=self._form())
        assert response.status_code == 401 and response.json()["error"] == "invalid_grant"
        assert response.headers["cache-control"] == "no-store"

    def test_an_unknown_client_is_401_invalid_client(self, stock: Stock) -> None:
        response = self._client(stock).post("/token", data=self._form(client_id="nobody"))
        assert response.status_code == 401 and response.json()["error"] == "invalid_client"

    def test_a_wrong_verifier_is_invalid_grant_before_the_provider_is_asked_to_exchange(self, stock: Stock) -> None:
        response = self._client(stock).post("/token", data=self._form(code_verifier="x" * 50))
        assert response.status_code == 401 and response.json()["error"] == "invalid_grant"
        assert stock.exchanged == 0

    def test_the_form_resource_is_not_looked_at(self, stock: Stock) -> None:
        # Documents why our /token wrapper exists: the stock handler accepts any resource.
        response = self._client(stock).post("/token", data=self._form(resource="https://evil.example/mcp"))
        assert response.status_code == 200

    def test_a_grant_type_the_client_did_not_register_is_refused(self, stock: Stock) -> None:
        stock.clients["c1"] = _public(grant_types=["authorization_code"])
        response = self._client(stock).post(
            "/token", data={"grant_type": "refresh_token", "refresh_token": "r", "client_id": "c1"}
        )
        assert response.status_code == 400 and response.json()["error"] == "unsupported_grant_type"


# -- c. registration --------------------------------------------------------------------------


class TestRegistrationHandler:
    def _register(self, client: TestClient, **body: Any):
        payload = {"redirect_uris": [REDIRECT], "client_name": "App", **body}
        return client.post("/register", json=payload)

    def test_the_record_is_echoed_after_register_client_so_changes_in_place_reach_the_client(
        self, stock: Stock
    ) -> None:
        async def register(info: OAuthClientInformationFull) -> None:
            info.token_endpoint_auth_method = "none"
            info.client_secret = None
            info.client_secret_expires_at = None
            info.client_name = "changed in place"

        stock.register_client = register  # type: ignore[method-assign]
        client = TestClient(Starlette(routes=stock.get_routes("/mcp")), base_url=BASE)
        body = self._register(client, token_endpoint_auth_method="client_secret_post").json()
        assert body["token_endpoint_auth_method"] == "none" and body.get("client_secret") is None
        assert body["client_name"] == "changed in place"

    def test_without_a_method_it_registers_a_confidential_client_with_a_minted_secret(
        self, stock_client: TestClient, stock: Stock
    ) -> None:
        body = self._register(stock_client).json()
        assert body["token_endpoint_auth_method"] == "client_secret_post" and len(body["client_secret"]) == 64
        assert body["scope"] == "s"  # the default scope is applied

    @pytest.mark.parametrize(
        "extra",
        [
            {"grant_types": ["authorization_code", "urn:ietf:params:oauth:grant-type:jwt-bearer"]},
            {"token_endpoint_auth_method": "private_key_jwt"},
            {"grant_types": ["refresh_token"]},
            {"response_types": ["token"]},
            {"scope": "not-a-valid-scope"},
        ],
    )
    def test_these_registrations_are_refused_by_the_stock_handler(self, stock_client, extra) -> None:
        assert self._register(stock_client, **extra).status_code == 400

    @pytest.mark.parametrize("uri", ["javascript:alert(1)", "http://evil.example/cb", "ftp://x/cb", "data:text/html,x"])
    def test_the_stock_handler_does_not_validate_redirect_uris(self, stock_client, uri) -> None:
        # So LocalAuthorizationServer.register_client has to.
        assert self._register(stock_client, redirect_uris=[uri]).status_code == 201


# -- d. /revoke ---------------------------------------------------------------------------------


def test_the_stock_revoke_endpoint_rejects_a_public_client_that_sends_no_secret(stock_client: TestClient) -> None:
    """If this ever returns 200 the replacement endpoint can be dropped."""
    response = stock_client.post("/revoke", data={"token": "t", "client_id": "c1"})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


# -- e. the route table of a bare provider --------------------------------------------------


def test_the_stock_route_table_is_the_one_the_surgery_expects(stock: Stock) -> None:
    table = {(r.path, frozenset(r.methods or ())) for r in stock.get_routes("/mcp") if isinstance(r, Route)}
    assert table == {
        ("/.well-known/oauth-authorization-server", frozenset({"GET", "HEAD", "OPTIONS"})),
        ("/authorize", frozenset({"GET", "HEAD", "POST"})),
        ("/token", frozenset({"POST", "OPTIONS"})),
        ("/register", frozenset({"POST", "OPTIONS"})),
        ("/revoke", frozenset({"POST", "OPTIONS"})),
        ("/.well-known/oauth-protected-resource/mcp", frozenset({"GET", "HEAD", "OPTIONS"})),
    }


def test_the_protected_resource_metadata_names_the_issuer_as_the_authorization_server(stock: Stock) -> None:
    client = TestClient(Starlette(routes=stock.get_routes("/mcp")), base_url=BASE)
    body = client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert body["resource"] == BASE + "/mcp"
    assert body["authorization_servers"] == [BASE + "/"] and body["scopes_supported"] == ["s"]


# -- f. the resource url -------------------------------------------------------------------------


def test_the_resource_url_is_the_base_plus_the_mcp_path(stock: Stock) -> None:
    assert compat.resource_url_of(stock, "/mcp") == BASE + "/mcp"
    assert compat.resource_url_of(stock, "/other") == BASE + "/other"


# -- g. the SSRF-pinned fetcher -------------------------------------------------------------------


class TestFetcher:
    def test_the_keywords_we_pass_exist(self) -> None:
        from fastmcp.server.auth.ssrf import ssrf_safe_fetch_response

        params = inspect.signature(ssrf_safe_fetch_response).parameters
        assert {"require_path", "max_size", "timeout", "overall_timeout", "request_headers", "allowed_status_codes"} <= set(params)

    @pytest.mark.parametrize(
        "url",
        [
            "https://127.0.0.1/x",
            "https://localhost/x",
            "https://169.254.169.254/x",
            "https://[::1]/x",
            "https://10.0.0.1/x",
            "http://example.com/x",
            "https://example.com/",
            "https://example.com",
        ],
    )
    async def test_internal_and_unsafe_urls_are_refused_before_any_connection(self, url: str) -> None:
        with pytest.raises(compat.MetadataFetchError) as raised:
            await compat.fetch_client_metadata(url, 1.0)
        assert raised.value.code == compat.FETCH_SSRF_BLOCKED


# -- h. the CIMD document model ----------------------------------------------------------------------


class TestDocumentModel:
    def test_the_fields_we_read(self) -> None:
        fields = set(compat.CIMDDocument.model_fields)
        assert {
            "client_id", "client_name", "redirect_uris", "grant_types", "response_types", "scope",
            "token_endpoint_auth_method",
        } <= fields

    def test_the_default_grant_types_and_the_shared_secret_methods(self) -> None:
        doc = compat.CIMDDocument.model_validate({"client_id": f"{BASE}/c.json", "redirect_uris": [REDIRECT]})
        assert doc.grant_types == ["authorization_code"] and doc.token_endpoint_auth_method == "none"
        for method in ("client_secret_post", "client_secret_basic", "client_secret_jwt"):
            with pytest.raises(ValueError):
                compat.CIMDDocument.model_validate(
                    {"client_id": f"{BASE}/c.json", "redirect_uris": [REDIRECT], "token_endpoint_auth_method": method}
                )

    def test_validate_client_document(self) -> None:
        url = "https://client.example/doc.json"
        raw = {"client_id": url, "client_name": "C", "redirect_uris": [REDIRECT]}
        doc = compat.validate_client_document(raw, url)
        assert doc.client_id == url and doc.redirect_uris == (REDIRECT,) and doc.scope is None
        for bad, code in (
            ({**raw, "client_id": url + "/"}, compat.DOC_CLIENT_ID_MISMATCH),
            ({**raw, "client_id": "https://other.example/doc.json"}, compat.DOC_CLIENT_ID_MISMATCH),
            ({**raw, "token_endpoint_auth_method": "private_key_jwt"}, compat.DOC_UNSUPPORTED_AUTH_METHOD),
            ({**raw, "token_endpoint_auth_method": "client_secret_post"}, compat.DOC_UNSUPPORTED_AUTH_METHOD),
            ({**raw, "redirect_uris": []}, compat.DOC_INVALID),
            ({k: v for k, v in raw.items() if k != "redirect_uris"}, compat.DOC_INVALID),
        ):
            with pytest.raises(compat.DocumentRejected) as rejected:
                compat.validate_client_document(bad, url)
            assert rejected.value.code == code


# -- i. redirect helpers ----------------------------------------------------------------------------------


class TestRedirectHelpers:
    @pytest.mark.parametrize(
        ("uri", "application_type", "allowed"),
        [
            ("https://claude.ai/cb", "web", True),
            ("http://localhost:5000/cb", "web", False),
            ("https://localhost/cb", "web", False),
            ("http://localhost:5000/cb", "native", True),
            ("http://127.0.0.1:5000/cb", None, True),
            ("http://evil.example/cb", "native", False),
            ("javascript:alert(1)", "native", False),
        ],
    )
    def test_application_type_rules(self, uri: str, application_type: str | None, allowed: bool) -> None:
        assert compat.redirect_allowed_for_application_type(uri, application_type) is allowed


# -- j. public types we rely on -----------------------------------------------------------------------------


class TestPublicTypes:
    def test_a_bare_subclass_instantiates_and_its_methods_silently_return_none(self) -> None:
        class Bare(OAuthProvider):
            pass

        provider = Bare(base_url=BASE, issuer_url=BASE)
        import asyncio

        assert asyncio.run(provider.get_client("x")) is None  # why the guard test exists
        assert asyncio.run(provider.load_access_token("x")) is None

    def test_access_token_carries_claims(self) -> None:
        token = AccessToken(token="t", client_id="c", scopes=["s"], claims={"a": 1})
        assert token.claims == {"a": 1}

    def test_authorization_params_and_code_fields(self) -> None:
        assert {"state", "scopes", "code_challenge", "redirect_uri", "redirect_uri_provided_explicitly", "resource"} <= set(
            AuthorizationParams.model_fields
        )
        assert {"resource", "subject", "redirect_uri_provided_explicitly", "expires_at"} <= set(AuthorizationCode.model_fields)

    def test_our_refresh_token_may_declare_resource_on_either_sdk(self) -> None:
        from canvas_mcp.core.selfhost.authz.server import LocalRefreshToken

        token = LocalRefreshToken(
            token="t", client_id="c", scopes=["s"], expires_at=1, subject="acct:x", resource="r",
            grant_id="g", token_hash="h", account_id="a",
        )
        assert token.resource == "r"
        assert {"token", "client_id", "scopes", "expires_at", "subject"} <= set(RefreshToken.model_fields)

    def test_the_error_literals_include_invalid_target(self) -> None:
        from typing import get_args

        from mcp.server.auth.provider import AuthorizationErrorCode, TokenErrorCode

        assert "invalid_target" in get_args(AuthorizationErrorCode) and "invalid_target" in get_args(TokenErrorCode)
        assert {"temporarily_unavailable", "server_error", "invalid_scope"} <= set(get_args(AuthorizationErrorCode))

    def test_the_metadata_models_have_the_fields_we_fill(self) -> None:
        assert {
            "client_id_metadata_document_supported", "authorization_response_iss_parameter_supported",
            "revocation_endpoint_auth_methods_supported", "code_challenge_methods_supported",
        } <= set(OAuthMetadata.model_fields)
        assert {"resource", "authorization_servers", "scopes_supported"} <= set(ProtectedResourceMetadata.model_fields)
        assert ClientRegistrationOptions(enabled=True).enabled and RevocationOptions(enabled=True).enabled

    def test_the_issuer_serialises_with_a_trailing_slash(self) -> None:
        from pydantic import AnyHttpUrl

        metadata = OAuthMetadata(
            issuer=AnyHttpUrl(BASE),
            authorization_endpoint=AnyHttpUrl(BASE + "/authorize"),
            token_endpoint=AnyHttpUrl(BASE + "/token"),
        )
        assert metadata.model_dump(mode="json")["issuer"] == BASE + "/"

    async def test_fastmcp_accepts_a_bearer_whose_resource_differs_so_the_audience_is_ours_to_check(self) -> None:
        from fastmcp.server.auth.middleware import (
            RequireAuthMiddleware,  # noqa: F401 - the public chain
        )
        from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
        from starlette.requests import HTTPConnection

        class Verifier:
            async def verify_token(self, token: str):  # type: ignore[no-untyped-def]
                return AccessToken(token=token, client_id="c", scopes=["s"], resource="https://elsewhere.example/mcp")

        backend = BearerAuthBackend(Verifier())  # type: ignore[arg-type]
        scope = {"type": "http", "headers": [(b"authorization", b"Bearer abc")], "method": "GET", "path": "/"}
        assert await backend.authenticate(HTTPConnection(scope)) is not None


# -- k. only fastmcp_compat imports the internals ----------------------------------------------------------------

_FORBIDDEN_PREFIXES = (
    "fastmcp.server.auth.handlers",
    "fastmcp.server.auth.auth",
    "fastmcp.server.auth.cimd",
    "fastmcp.server.auth.ssrf",
    "fastmcp.server.auth.redirect_validation",
    "fastmcp.server.auth.jwt_issuer",
    "fastmcp.server.auth.oauth_proxy",
    "fastmcp.server.auth.providers",
    "mcp.server.auth.routes",
    "mcp.server.auth.handlers",
    "mcp.server.auth.middleware",
    "mcp.server.auth.json_response",
)


def _imports(path: pathlib.Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
            found.update(f"{node.module}.{alias.name}" for alias in node.names)
    return found


def _guarded_files() -> list[pathlib.Path]:
    selfhost = SRC / "core" / "selfhost"
    files = sorted((selfhost / "authz").glob("*.py"))
    files += [selfhost / name for name in ("request_context.py", "tool_gate.py", "app.py", "edge_guard.py")]
    return [f for f in files if f.name != "fastmcp_compat.py"]


@pytest.mark.parametrize("path", _guarded_files(), ids=lambda p: p.name)
def test_nothing_but_fastmcp_compat_imports_non_exported_internals(path: pathlib.Path) -> None:
    offending = sorted(
        name
        for name in _imports(path)
        if any(name == prefix or name.startswith(prefix + ".") for prefix in _FORBIDDEN_PREFIXES)
    )
    assert not offending, f"{path.name} imports {offending}: go through fastmcp_compat"


def test_the_compat_module_is_the_one_that_does_import_them() -> None:
    imported = _imports(SRC / "core" / "selfhost" / "authz" / "fastmcp_compat.py")
    assert "fastmcp.server.auth.ssrf" in imported and "fastmcp.server.auth.cimd" in imported
    assert "fastmcp.server.auth.handlers.authorize" in imported


def test_the_public_modules_the_rest_of_the_package_may_use_exist() -> None:
    import fastmcp.server.auth
    import mcp.server.auth.provider
    import mcp.server.auth.settings
    import mcp.shared.auth

    assert OAuthProvider is fastmcp.server.auth.OAuthProvider
    assert hasattr(mcp.server.auth.provider, "AuthorizeError") and hasattr(mcp.shared.auth, "OAuthMetadata")
    assert hasattr(mcp.server.auth.settings, "RevocationOptions")

