"""End to end over real HTTP: the official MCP SDK OAuth client against the whole app.

uvicorn serves the real ``build_selfhost_asgi_app`` in ``SELFHOST_AUTH_MODE=local``; the SDK's
``OAuthClientProvider`` discovers, registers (DCR) or identifies itself (CIMD), sends the user's
browser (a script) through /authorize, the /account sign-in and the consent page, exchanges the
code, calls a tool, and refreshes. Clients reach the server as ``https://canvas.example.test``
through a transport that forwards to the local socket and keeps the Host header, so cookies,
the Host/Origin guard and the issuer are exactly as in production. Only Entra and the CIMD
host are faked.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import anyio
import anyio.to_thread
import httpx2
import pytest
from dbbackend import raw_sql
from mcp.client import Client
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import (
    AuthorizationCodeResult,
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthToken,
)
from pydantic import AnyUrl

from canvas_mcp.core.selfhost.authz import tokens as tk

from .stack import (
    ALICE,
    AUDIENCE,
    CLAUDE_REDIRECT,
    ISSUER,
    SCOPE,
    Browser,
    Served,
    User,
    cimd_document,
    local_stack,
    pkce,
    served_stack,
)
from .test_cimd_documents import CLAUDE_AI_URL, CLAUDE_CODE_URL, fixture

CIMD_URL = "https://client.example/cimd.json"
SDK_REDIRECT = "http://127.0.0.1:9/callback"  # nothing listens: the scripted browser never connects


class MemoryStorage:
    def __init__(self) -> None:
        self.tokens: OAuthToken | None = None
        self.client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self.tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self.client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self.client_info = client_info


def make_oauth(
    served: Served, user: User = ALICE, *, client_metadata_url: str | None = None,
    storage: MemoryStorage | None = None, results: list[dict[str, str]] | None = None,
    decision: str = "approve",
) -> tuple[OAuthClientProvider, MemoryStorage, list[dict[str, str]]]:
    storage = storage or MemoryStorage()
    results = results if results is not None else []
    browser = Browser(served.stack)

    async def redirect_handler(url: str) -> None:
        params = dict(parse_qsl(urlsplit(url).query))
        landed = await anyio.to_thread.run_sync(lambda: browser.connect(params, user, decision=decision))
        results.append(landed.query)

    async def callback_handler() -> AuthorizationCodeResult:
        result = results[-1]
        if "code" not in result:
            raise RuntimeError(f"authorization failed: {result}")
        return AuthorizationCodeResult(code=result["code"], state=result.get("state"), iss=result.get("iss"))

    oauth = OAuthClientProvider(
        server_url=AUDIENCE,
        client_metadata=OAuthClientMetadata(
            redirect_uris=[AnyUrl(SDK_REDIRECT)],
            client_name="sdk test client",
            grant_types=["authorization_code", "refresh_token"],
            token_endpoint_auth_method="none",
            scope=None,
        ),
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
        client_metadata_url=client_metadata_url,
    )
    return oauth, storage, results


def sdk_client(served: Served, oauth: OAuthClientProvider) -> Client:
    http = httpx2.AsyncClient(auth=oauth, timeout=30, transport=served.async_transport())
    return Client(streamable_http_client(AUDIENCE, http_client=http))


async def whoami(client: Client) -> str:
    result = await client.call_tool("list_courses", {})
    return str(result.content[0].text)  # type: ignore[union-attr]


@pytest.fixture
def served(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    with served_stack(tmp_path, monkeypatch) as running:
        running.stack.enroll(ALICE)
        yield running


def grants(served: Served) -> list[tuple]:
    return raw_sql(served.stack.store, "SELECT id, client_kind, client_id, revoked_reason, expires_at FROM oauth_grants")


class TestOfficialSdkClient:
    async def test_dcr_flow_and_a_tool_call_as_the_account(self, served: Served) -> None:
        stack = served.stack
        oauth, storage, results = make_oauth(served)
        async with sdk_client(served, oauth) as client:
            assert await whoami(client) == stack.account_of(ALICE)
        # registered as a public client; the secret in the echo is gone
        assert storage.client_info is not None and storage.client_info.client_secret is None
        assert storage.client_info.token_endpoint_auth_method == "none"
        # RFC 9207: the SDK validated iss; it is the one issuer string
        assert results[0]["iss"] == ISSUER
        assert storage.tokens is not None and storage.tokens.refresh_token
        claims = stack.authz.codec.decode(storage.tokens.access_token)
        assert claims["aud"] == AUDIENCE and claims["iss"] == ISSUER and claims["acct"] == stack.account_of(ALICE)
        assert claims["client_id"] == storage.client_info.client_id and claims["scope"] == SCOPE
        # the refresh token is opaque and only its hash is stored
        assert tk.REFRESH_RE.fullmatch(storage.tokens.refresh_token)
        stored = [r[0] for r in raw_sql(stack.store, "SELECT token_hash FROM oauth_refresh_tokens")]
        assert stored == [tk.hash_secret(storage.tokens.refresh_token)]
        assert grants(served)[0][1] == "dcr"

    async def test_cimd_flow_uses_the_url_as_the_client_id_and_creates_no_registration(self, served: Served) -> None:
        stack = served.stack
        stack.cimd.serve(CIMD_URL, cimd_document(CIMD_URL, redirect_uris=["http://127.0.0.1/callback"]))
        oauth, storage, results = make_oauth(served, client_metadata_url=CIMD_URL)
        async with sdk_client(served, oauth) as client:
            assert await whoami(client) == stack.account_of(ALICE)
        assert storage.client_info is not None and storage.client_info.client_id == CIMD_URL
        assert raw_sql(stack.store, "SELECT COUNT(*) FROM oauth_clients")[0][0] == 0
        assert results[0]["iss"] == ISSUER
        assert stack.authz.codec.decode(storage.tokens.access_token)["client_id"] == CIMD_URL  # type: ignore[union-attr]
        assert grants(served)[0][1] == "cimd"
        # a refresh works for a CIMD client too
        first = storage.tokens
        async with sdk_client(served, oauth) as client:
            oauth.context.token_expiry_time = time.time() - 10
            assert await whoami(client) == stack.account_of(ALICE)
        assert storage.tokens.refresh_token != first.refresh_token  # type: ignore[union-attr]

    async def test_the_sdk_refreshes_proactively_and_the_family_keeps_its_cap(self, served: Served) -> None:
        stack = served.stack
        oauth, storage, _ = make_oauth(served)
        async with sdk_client(served, oauth) as client:
            assert await whoami(client) == stack.account_of(ALICE)
            first = storage.tokens
            oauth.context.token_expiry_time = time.time() - 10  # the SDK refreshes on the next request
            assert await whoami(client) == stack.account_of(ALICE)
        second = storage.tokens
        assert first is not None and second is not None
        assert second.refresh_token != first.refresh_token and second.access_token != first.access_token
        old = raw_sql(
            stack.store,
            "SELECT used_at, replaced_by, expires_at FROM oauth_refresh_tokens WHERE token_hash = :h",
            {"h": tk.hash_secret(first.refresh_token or "")},
        )[0]
        new = raw_sql(
            stack.store, "SELECT used_at, expires_at FROM oauth_refresh_tokens WHERE token_hash = :h",
            {"h": tk.hash_secret(second.refresh_token or "")},
        )[0]
        assert old[0] is not None and old[1] == tk.hash_secret(second.refresh_token or "")
        assert new[0] is None and new[1] == old[2] == grants(served)[0][4]

    async def test_a_declined_request_reaches_the_sdk_as_access_denied(self, served: Served) -> None:
        oauth, storage, results = make_oauth(served, decision="deny")
        with pytest.raises(Exception):  # noqa: B017 - the SDK raises its own error type
            async with sdk_client(served, oauth) as client:
                await whoami(client)
        assert results and results[0]["error"] == "access_denied" and results[0]["iss"] == ISSUER
        assert storage.tokens is None and grants(served) == []

    async def test_the_sdk_survives_a_revoked_connection_by_connecting_again(self, served: Served) -> None:
        stack = served.stack
        oauth, storage, results = make_oauth(served)
        async with sdk_client(served, oauth) as client:
            assert await whoami(client) == stack.account_of(ALICE)
            assert await stack.authz.grants.revoke_by_client(grants(served)[0][0])
            assert await whoami(client) == stack.account_of(ALICE)  # a 401, then a fresh authorization
        assert len(results) == 2 and len(grants(served)) == 2


class TestRecordedClients:
    def authorize_and_exchange(self, stack: Any, client_id: str, redirect_uri: str) -> tuple[dict[str, Any], str]:
        verifier, challenge = pkce()
        landed = Browser(stack).connect(
            stack.authorize_params(client_id, challenge, redirect_uri=redirect_uri), ALICE
        )
        assert landed.url.startswith(redirect_uri + "?") and landed.query["iss"] == ISSUER, landed
        response = stack.token(
            grant_type="authorization_code", code=landed.query["code"], client_id=client_id,
            redirect_uri=redirect_uri, code_verifier=verifier, resource=AUDIENCE,
        )
        assert response.status_code == 200, response.text
        return response.json(), landed.query["state"]

    def test_claude_ai_by_its_published_identity(self, served: Served) -> None:
        stack = served.stack
        stack.cimd.serve(CLAUDE_AI_URL, fixture("claude-ai.json"))
        tokens, state = self.authorize_and_exchange(stack, CLAUDE_AI_URL, CLAUDE_REDIRECT)
        assert state == "state-1"
        key = stack.account_of(ALICE)
        assert stack.whoami(tokens["access_token"]) == key
        refreshed = stack.refresh(CLAUDE_AI_URL, tokens["refresh_token"])
        assert refreshed.status_code == 200 and stack.whoami(refreshed.json()["access_token"]) == key
        assert grants(served)[0][1] == "cimd"

    @pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
    def test_claude_code_on_a_random_loopback_port(self, served: Served, host: str) -> None:
        stack = served.stack
        stack.cimd.serve(CLAUDE_CODE_URL, fixture("claude-code.json"))
        port = 20000 + int(time.time() * 1000) % 30000
        redirect = f"http://{host}:{port}/callback"
        tokens, _ = self.authorize_and_exchange(stack, CLAUDE_CODE_URL, redirect)
        assert stack.whoami(tokens["access_token"]) == stack.account_of(ALICE)
        assert stack.refresh(CLAUDE_CODE_URL, tokens["refresh_token"]).status_code == 200

    def test_a_different_loopback_host_or_path_is_not_this_clients(self, served: Served) -> None:
        stack = served.stack
        stack.cimd.serve(CLAUDE_CODE_URL, fixture("claude-code.json"))
        _, challenge = pkce()
        for uri in ("http://[::1]:5000/callback", "http://localhost:5000/other", "https://localhost:5000/callback"):
            response = stack.client.get(
                "/authorize", params=stack.authorize_params(CLAUDE_CODE_URL, challenge, redirect_uri=uri)
            )
            assert response.status_code == 400, uri

    def test_when_the_document_cannot_be_fetched_an_authorization_cannot_start_but_refresh_still_works(
        self, served: Served
    ) -> None:
        from canvas_mcp.core.selfhost.authz import fastmcp_compat as compat

        stack = served.stack
        stack.cimd.serve(CLAUDE_AI_URL, fixture("claude-ai.json"), cache_control="max-age=60")
        tokens, _ = self.authorize_and_exchange(stack, CLAUDE_AI_URL, CLAUDE_REDIRECT)
        stack.cimd.fail(CLAUDE_AI_URL, compat.MetadataFetchError(compat.FETCH_TIMEOUT))
        stack.clock.advance(120)  # the copy is stale now
        _, challenge = pkce()
        denied = stack.client.get("/authorize", params=stack.authorize_params(CLAUDE_AI_URL, challenge))
        assert denied.status_code == 400 and "location" not in denied.headers
        assert stack.refresh(CLAUDE_AI_URL, tokens["refresh_token"]).status_code == 200


class TestTwoBrowsers:
    def test_a_link_opened_in_another_browser_is_refused_and_the_rightful_one_completes(self, served: Served) -> None:
        stack = served.stack
        client_id = stack.register(CLAUDE_REDIRECT)
        _, challenge = pkce()
        owner = Browser(stack)
        started = owner.start(stack.authorize_params(client_id, challenge))
        assert started.status_code == 302
        stranger = Browser(stack)
        refused = stranger.get(started.headers["location"])
        assert refused.status_code == 400 and "location" not in refused.headers
        landed = owner.connect(stack.authorize_params(client_id, challenge), ALICE)
        assert "code" in landed.query


class TestModeSwitch:
    def test_a_token_of_the_local_server_is_nothing_to_the_proxy_and_the_reverse(self, tmp_path, monkeypatch) -> None:
        with local_stack(tmp_path / "local", monkeypatch) as local:
            local.enroll(ALICE)
            _, tokens = local.tokens_for(ALICE)
            assert local.mcp_status(tokens["access_token"]) == 200
        with local_stack(tmp_path / "proxy", monkeypatch, env={"SELFHOST_AUTH_MODE": "entra_proxy"}) as proxy:
            assert proxy.mcp_status(tokens["access_token"]) == 401

    def test_in_local_mode_no_proxy_storage_exists_and_the_provider_is_ours(self, tmp_path, monkeypatch) -> None:
        from canvas_mcp.core.selfhost.authz.server import LocalAuthorizationServer
        from canvas_mcp.core.selfhost.oauth import oauth_storage_of

        with local_stack(tmp_path, monkeypatch) as stack:
            stack.enroll(ALICE)
            assert isinstance(stack.mcp.auth, LocalAuthorizationServer)
            assert oauth_storage_of(stack.mcp.auth) is None
            assert not (tmp_path / "fastmcp" / "oauth-proxy").exists()

    def test_in_proxy_mode_nothing_of_the_local_server_is_loaded_or_written(self, tmp_path) -> None:
        import subprocess
        import sys
        import textwrap

        script = textwrap.dedent(
            """
            import sys
            from canvas_mcp.core.selfhost import app, oauth, request_context, tool_gate, edge_guard, account_web  # noqa
            from canvas_mcp.core.selfhost.settings import load_selfhost_settings
            loaded = sorted(m for m in sys.modules if m.startswith("canvas_mcp.core.selfhost.authz"))
            print(",".join(loaded))
            """
        )
        import os

        env = {**os.environ, "PYTHONPATH": app_src(), "PYTHONUTF8": "1", "PYTHON_DOTENV_DISABLED": "1"}
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env, timeout=120)
        assert result.returncode == 0, result.stderr
        loaded = set(result.stdout.strip().split(","))
        assert loaded <= {"canvas_mcp.core.selfhost.authz", "canvas_mcp.core.selfhost.authz.fastmcp_compat"}

    def test_the_default_mode_never_writes_grants(self, tmp_path, monkeypatch) -> None:
        with local_stack(tmp_path, monkeypatch, env={"SELFHOST_AUTH_MODE": "entra_proxy"}) as stack:
            stack.enroll(ALICE)
            assert stack.runtime.authz is None
            for table in ("oauth_clients", "oauth_grants", "oauth_codes", "oauth_refresh_tokens", "login_states", "cimd_clients"):
                assert raw_sql(stack.store, f"SELECT COUNT(*) FROM {table}")[0][0] == 0
            assert stack.client.get("/account/consent").status_code == 404
            assert stack.client.post("/revoke", data={"token": "x", "client_id": "y"}).status_code in (404, 405)


def app_src() -> str:
    import pathlib

    return str(pathlib.Path(__file__).resolve().parents[3] / "src")
