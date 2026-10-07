"""The real AzureProvider wired through build_selfhost_asgi_app (no network)."""

import base64
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import fastmcp
import pytest
from fastmcp import FastMCP
from starlette.testclient import TestClient

pytest.importorskip("canvas_mcp.core.selfhost.token_store")
pytest.importorskip("canvas_mcp.core.selfhost.account_web")

from canvas_mcp.core.selfhost.app import (  # noqa: E402
    build_selfhost_asgi_app,
    install_selfhost,
    prepare_selfhost,
)
from canvas_mcp.core.selfhost.oauth import build_entra_auth_provider  # noqa: E402
from canvas_mcp.core.selfhost.settings import (  # noqa: E402
    SelfhostSettings,
    load_selfhost_settings,
)

from .conftest import CLIENT, TENANT  # noqa: E402

BASE = "https://canvas.example.test"
CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"


def _settings(tmp_path: Path, **overrides: str) -> SelfhostSettings:
    env = {
        "PUBLIC_BASE_URL": BASE,
        "ENTRA_TENANT_ID": TENANT,
        "ENTRA_CLIENT_ID": CLIENT,
        "ENTRA_CLIENT_SECRET": "entra-client-secret-0123456789",
        "OAUTH_JWT_SIGNING_KEY": "jwt-signing-key-" + "z" * 40,
        "ACCOUNT_SESSION_SECRET": base64.b64encode(bytes(range(32))).decode(),
        "CANVAS_TOKEN_KEYS": "k1:" + base64.b64encode(bytes(32)).decode(),
        "FASTMCP_HOME": str(tmp_path / "fastmcp"),
        "SELFHOST_DATA_DIR": str(tmp_path / "data"),
    }
    env.update(overrides)
    return load_selfhost_settings(env)


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SelfhostSettings:
    monkeypatch.setattr(fastmcp.settings, "test_mode", True)  # cheap key stretching
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path / "fastmcp")
    return _settings(tmp_path)


@pytest.fixture
def client(settings: SelfhostSettings) -> Iterator[TestClient]:
    config: Any = SimpleNamespace(canvas_api_url="https://canvas.example.edu/api/v1")
    runtime = prepare_selfhost(settings)
    mcp = FastMCP("wiring", auth=build_entra_auth_provider(settings))

    @mcp.tool()
    def ping() -> str:
        """Dummy tool."""
        return "pong"

    install_selfhost(mcp, runtime, config)
    app = build_selfhost_asgi_app(mcp, runtime, config)
    with TestClient(app, base_url=BASE) as test_client:
        yield test_client


class TestDiscovery:
    def test_protected_resource_metadata(self, client):
        response = client.get("/.well-known/oauth-protected-resource/mcp")
        assert response.status_code == 200
        body = response.json()
        assert body["resource"] == "https://canvas.example.test/mcp"
        assert [s.rstrip("/") for s in body["authorization_servers"]] == [BASE]
        assert body["scopes_supported"] == ["Canvas.Access"]

    def test_authorization_server_metadata(self, client):
        response = client.get("/.well-known/oauth-authorization-server")
        assert response.status_code == 200
        body = response.json()
        assert str(body["issuer"]).rstrip("/") == BASE
        assert "S256" in body["code_challenge_methods_supported"]
        assert body["registration_endpoint"] == f"{BASE}/register"
        assert body["authorization_endpoint"] == f"{BASE}/authorize"
        assert body["token_endpoint"] == f"{BASE}/token"
        assert body["client_id_metadata_document_supported"] is True


class TestMcpEndpointRequiresOAuth:
    def test_no_bearer_gets_401_with_resource_metadata(self, client):
        response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert response.status_code == 401
        challenge = response.headers["www-authenticate"]
        assert challenge.startswith("Bearer")
        assert 'resource_metadata="https://canvas.example.test/.well-known/oauth-protected-resource/mcp"' in challenge

    def test_a_bearer_that_fastmcp_did_not_issue_is_rejected(self, client):
        response = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": "Bearer not.a.fastmcp-issued-token"},
        )
        assert response.status_code == 401

    def test_get_is_not_an_open_stream(self, client):
        assert client.get("/mcp").status_code in (401, 405)


class TestClientRegistration:
    def _register(self, client: TestClient, *redirect_uris: str):
        return client.post("/register", json={
            "client_name": "test client",
            "redirect_uris": list(redirect_uris),
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        })

    def test_claude_ai_callback_is_accepted(self, client):
        response = self._register(client, CLAUDE_CALLBACK)
        assert response.status_code == 201, response.text
        assert response.json()["redirect_uris"] == [CLAUDE_CALLBACK]

    @pytest.mark.parametrize("uri", [
        "http://localhost:53682/callback",
        "http://127.0.0.1:39211/callback",
        "http://localhost/callback",
    ])
    def test_loopback_callback_is_accepted_on_any_port(self, client, uri):
        assert self._register(client, uri).status_code == 201

    @pytest.mark.parametrize("uri", [
        "https://evil.example/cb",
        "https://claude.ai.evil.example/api/mcp/auth_callback",
        "https://claude.ai/other",
        "http://localhost:8080/elsewhere",
        "http://evil.example/callback",
    ])
    def test_other_redirect_uris_are_rejected(self, client, uri):
        response = self._register(client, uri)
        assert response.status_code == 400, response.text

    def test_one_bad_uri_spoils_the_registration(self, client):
        assert self._register(client, CLAUDE_CALLBACK, "https://evil.example/cb").status_code == 400


class TestHostAndOriginProtection:
    def test_other_hosts_get_421(self, client):
        response = client.get("/healthz", headers={"Host": "evil.example"})
        assert response.status_code == 421

    def test_other_hosts_cannot_reach_the_mcp_endpoint_either(self, client):
        response = client.post("/mcp", json={}, headers={"Host": "evil.example"})
        assert response.status_code == 421

    def test_a_foreign_origin_is_refused(self, client):
        response = client.post("/mcp", json={}, headers={"Origin": "https://evil.example"})
        assert response.status_code == 403

    def test_the_public_origin_is_allowed_through_to_auth(self, client):
        response = client.post("/mcp", json={}, headers={"Origin": BASE})
        assert response.status_code == 401


class TestHealth:
    def test_healthz(self, client):
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.text == "ok"
        assert response.headers["cache-control"] == "no-store"

    def test_account_page_is_served_without_mcp_auth(self, client):
        response = client.get("/account")
        assert response.status_code == 200
        assert response.headers["cache-control"].startswith("no-store")


class TestProviderConstruction:
    def test_provider_is_configured_from_settings(self, settings):
        provider = build_entra_auth_provider(settings)
        assert provider.required_scopes == ["Canvas.Access"]
        assert str(provider.base_url).rstrip("/") == BASE

    def test_oauth_state_lives_under_fastmcp_home(self, settings, tmp_path):
        build_entra_auth_provider(settings)
        # The default file store creates its tree below FASTMCP_HOME.
        assert (tmp_path / "fastmcp" / "oauth-proxy").is_dir()
