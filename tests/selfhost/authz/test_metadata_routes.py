"""Discovery documents, the route table and the 401 challenge, in both authorization modes."""

from __future__ import annotations

import pathlib
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from canvas_mcp.core.selfhost.authz.server import EXPECTED_ROUTES

from .stack import (
    ALICE,
    AUDIENCE,
    BASE,
    CLAUDE_REDIRECT,
    ISSUER,
    SCOPE,
    Browser,
    local_stack,
    pkce,
)

AS_METADATA = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{BASE}/authorize",
    "token_endpoint": f"{BASE}/token",
    "registration_endpoint": f"{BASE}/register",
    "revocation_endpoint": f"{BASE}/revoke",
    "scopes_supported": [SCOPE],
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_methods_supported": ["none"],
    "revocation_endpoint_auth_methods_supported": ["none"],
    "code_challenge_methods_supported": ["S256"],
    "authorization_response_iss_parameter_supported": True,
    "client_id_metadata_document_supported": True,
}
PRM = {
    "resource": AUDIENCE,
    "authorization_servers": [ISSUER],
    "scopes_supported": [SCOPE],
    "bearer_methods_supported": ["header"],
}
ALL_ACCOUNT_METHODS = ("DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT")


def route_table(stack: Any) -> dict[str, tuple[str, ...]]:
    app = stack.client.app
    while not hasattr(app, "routes") and hasattr(app, "app"):
        app = app.app
    return {r.path: tuple(sorted(r.methods or ())) for r in app.routes if hasattr(r, "path")}


class TestAuthorizationServerMetadata:
    def test_the_document_is_exactly_this(self, stack) -> None:
        response = stack.client.get("/.well-known/oauth-authorization-server")
        assert response.status_code == 200
        assert response.json() == AS_METADATA

    def test_cimd_off_drops_the_flag_and_nothing_else(self, tmp_path: pathlib.Path, monkeypatch) -> None:
        with local_stack(tmp_path, monkeypatch, env={"CIMD_ENABLED": "false"}) as stack:
            body = stack.client.get("/.well-known/oauth-authorization-server").json()
        expected = dict(AS_METADATA)
        del expected["client_id_metadata_document_supported"]
        assert body == expected

    def test_the_cache_time_is_five_minutes_and_cors_is_open(self, stack) -> None:
        response = stack.client.get("/.well-known/oauth-authorization-server", headers={"Origin": BASE})
        assert response.headers["cache-control"] == "public, max-age=300"
        assert response.headers["access-control-allow-origin"] == "*"
        preflight = stack.client.options(
            "/.well-known/oauth-authorization-server",
            headers={"Origin": BASE, "Access-Control-Request-Method": "GET"},
        )
        assert preflight.status_code == 200 and preflight.headers["access-control-allow-origin"] == "*"

    def test_no_offline_access_and_no_jwt_bearer_anywhere(self, stack) -> None:
        text = stack.client.get("/.well-known/oauth-authorization-server").text
        text += stack.client.get("/.well-known/oauth-protected-resource/mcp").text
        assert "offline_access" not in text and "jwt-bearer" not in text
        assert "client_secret" not in text and "private_key_jwt" not in text

    def test_the_stock_oauth_server_metadata_advertised_secrets_and_ours_does_not(self, stack, proxy_stack) -> None:
        local = stack.client.get("/.well-known/oauth-authorization-server").json()
        proxy = proxy_stack.client.get("/.well-known/oauth-authorization-server").json()
        assert local["token_endpoint_auth_methods_supported"] == ["none"]
        assert "revocation_endpoint" not in proxy  # the proxy has no /revoke at all


class TestProtectedResourceMetadata:
    def test_the_document_is_exactly_this(self, stack) -> None:
        assert stack.client.get("/.well-known/oauth-protected-resource/mcp").json() == PRM

    def test_it_is_identical_in_both_modes(self, stack, proxy_stack) -> None:
        local = stack.client.get("/.well-known/oauth-protected-resource/mcp").json()
        proxy = proxy_stack.client.get("/.well-known/oauth-protected-resource/mcp").json()
        assert local == proxy == PRM


class TestOneIssuerString:
    def test_it_is_byte_identical_everywhere(self, stack) -> None:
        stack.enroll(ALICE)
        issuer_metadata = stack.client.get("/.well-known/oauth-authorization-server").json()["issuer"]
        issuer_prm = stack.client.get("/.well-known/oauth-protected-resource/mcp").json()["authorization_servers"][0]
        client_id = stack.register(CLAUDE_REDIRECT)
        _, challenge = pkce()
        browser = Browser(stack)
        # success, and a decline
        landed = browser.connect(stack.authorize_params(client_id, challenge), ALICE)
        denied = browser.connect(stack.authorize_params(client_id, challenge), ALICE, decision="deny")
        assert "code" in landed.query and denied.query["error"] == "access_denied"
        # an error redirect for an unknown resource, and one for a malformed challenge
        errors = [
            browser.start(stack.authorize_params(client_id, challenge, resource="https://other.example/mcp")),
            browser.start(stack.authorize_params(client_id, "short")),
        ]
        redirected = [landed.query["iss"], denied.query["iss"]]
        for response in errors:
            assert response.status_code == 302
            query = parse_qs(urlsplit(response.headers["location"]).query)
            assert len(query["iss"]) == 1 and "error" in query
            redirected.append(query["iss"][0])
        _, tokens = stack.tokens_for(ALICE)
        claims = stack.authz.codec.decode(tokens["access_token"])
        assert [issuer_metadata, issuer_prm, claims["iss"], *redirected] == [ISSUER] * (3 + len(redirected))

    def test_the_audience_is_the_mcp_url_that_fastmcp_advertises(self, stack) -> None:
        _, tokens = stack.tokens_for(ALICE)
        assert stack.authz.codec.decode(tokens["access_token"])["aud"] == AUDIENCE
        assert stack.client.get("/.well-known/oauth-protected-resource/mcp").json()["resource"] == AUDIENCE


class TestRouteTables:
    def test_the_local_route_table(self, stack) -> None:
        table = route_table(stack)
        assert table == {
            "/.well-known/oauth-authorization-server": ("GET", "HEAD", "OPTIONS"),
            "/.well-known/oauth-protected-resource/mcp": ("GET", "HEAD", "OPTIONS"),
            "/account": ALL_ACCOUNT_METHODS,
            "/account/admin": ALL_ACCOUNT_METHODS,
            "/account/admin/approve": ALL_ACCOUNT_METHODS,
            "/account/admin/audit": ALL_ACCOUNT_METHODS,
            "/account/admin/deny": ALL_ACCOUNT_METHODS,
            "/account/admin/disable": ALL_ACCOUNT_METHODS,
            "/account/admin/enable": ALL_ACCOUNT_METHODS,
            "/account/admin/invalidate": ALL_ACCOUNT_METHODS,
            "/account/admin/remove": ALL_ACCOUNT_METHODS,
            "/account/callback": ALL_ACCOUNT_METHODS,
            "/account/consent": ALL_ACCOUNT_METHODS,
            "/account/login": ALL_ACCOUNT_METHODS,
            "/account/logout": ALL_ACCOUNT_METHODS,
            "/account/schools": ALL_ACCOUNT_METHODS,
            "/account/token": ALL_ACCOUNT_METHODS,
            "/account/token/delete": ALL_ACCOUNT_METHODS,
            "/account/token/recheck": ALL_ACCOUNT_METHODS,
            "/account/write-tools": ALL_ACCOUNT_METHODS,
            "/authorize": ("GET", "HEAD", "POST"),
            "/healthz": ("GET", "HEAD"),
            "/mcp": ("DELETE", "POST"),
            "/register": ("OPTIONS", "POST"),
            "/revoke": ("OPTIONS", "POST"),
            "/token": ("OPTIONS", "POST"),
        }

    def test_the_proxy_route_table_is_the_one_it_always_was(self, proxy_stack) -> None:
        table = route_table(proxy_stack)
        assert table == {
            "/.well-known/oauth-authorization-server": ("GET", "HEAD", "OPTIONS"),
            "/.well-known/oauth-protected-resource/mcp": ("GET", "HEAD", "OPTIONS"),
            "/account": ALL_ACCOUNT_METHODS,
            "/account/admin": ALL_ACCOUNT_METHODS,
            "/account/admin/approve": ALL_ACCOUNT_METHODS,
            "/account/admin/audit": ALL_ACCOUNT_METHODS,
            "/account/admin/deny": ALL_ACCOUNT_METHODS,
            "/account/admin/disable": ALL_ACCOUNT_METHODS,
            "/account/admin/enable": ALL_ACCOUNT_METHODS,
            "/account/admin/invalidate": ALL_ACCOUNT_METHODS,
            "/account/admin/remove": ALL_ACCOUNT_METHODS,
            "/account/callback": ALL_ACCOUNT_METHODS,
            "/account/login": ALL_ACCOUNT_METHODS,
            "/account/logout": ALL_ACCOUNT_METHODS,
            "/account/schools": ALL_ACCOUNT_METHODS,
            "/account/token": ALL_ACCOUNT_METHODS,
            "/account/token/delete": ALL_ACCOUNT_METHODS,
            "/account/token/recheck": ALL_ACCOUNT_METHODS,
            "/account/write-tools": ALL_ACCOUNT_METHODS,
            "/auth/callback": ("GET", "HEAD"),
            "/authorize": ("GET", "HEAD", "POST"),
            "/consent": ("GET", "HEAD", "POST"),
            "/healthz": ("GET", "HEAD"),
            "/mcp": ("DELETE", "POST"),
            "/register": ("OPTIONS", "POST"),
            "/token": ("OPTIONS", "POST"),
        }

    def test_the_provider_route_set_is_the_expected_one(self, stack) -> None:
        provider = stack.mcp.auth
        routes = provider.get_routes("/mcp")
        assert {(r.path, frozenset(r.methods)) for r in routes} == set(EXPECTED_ROUTES)

    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("GET", "/consent"),
            ("POST", "/consent"),
            ("GET", "/auth/callback"),
            ("GET", "/.well-known/openid-configuration"),
            ("GET", "/.well-known/oauth-protected-resource"),
        ],
    )
    def test_the_proxy_only_and_oidc_paths_do_not_exist_in_local_mode(self, stack, method, path) -> None:
        assert stack.client.request(method, path).status_code == 404


class TestChallenge:
    def test_without_a_token_the_challenge_has_the_metadata_url_and_no_error(self, stack) -> None:
        response = stack.rpc(None, "tools/list")
        assert response.status_code == 401
        challenge = response.headers["www-authenticate"]
        assert f'resource_metadata="{BASE}/.well-known/oauth-protected-resource/mcp"' in challenge
        assert f'scope="{SCOPE}"' in challenge
        assert "error=" not in challenge.replace("error_description", "")

    def test_a_junk_token_says_invalid_token(self, stack) -> None:
        response = stack.rpc("not-a-token", "tools/list")
        assert response.status_code == 401
        assert 'error="invalid_token"' in response.headers["www-authenticate"]

    def test_the_stock_wiring_is_not_a_sign_in_page(self, stack) -> None:
        assert stack.client.get("/mcp").status_code in (401, 405)
