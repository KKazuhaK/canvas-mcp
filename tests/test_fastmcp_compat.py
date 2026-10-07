"""Characterization tests for the fastmcp APIs this codebase relies on.

These pin the exact upstream behaviors the migration (issue #142) assumes,
originally written against fastmcp 2.x and revalidated on 3.x and 4.x. If a fastmcp
upgrade breaks one of these, it breaks the server the same way.
"""

import pytest
from fastmcp import Client, FastMCP
from mcp.types import ToolAnnotations


def _make_server() -> FastMCP:
    mcp = FastMCP(name="compat-test")

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    async def sample_tool(course_identifier: str) -> str:
        """A sample tool."""
        return f"ok:{course_identifier}"

    @mcp.resource(
        name="sample-resource",
        description="A sample resource",
        uri="canvas://course/{course_identifier}/sample",
    )
    async def sample_resource(course_identifier: str) -> str:
        return f"resource:{course_identifier}"

    @mcp.prompt(name="sample-prompt", description="A sample prompt")
    async def sample_prompt(topic: str) -> str:
        return f"Summarize {topic}"

    return mcp


@pytest.mark.asyncio
async def test_tool_registration_and_annotations():
    mcp = _make_server()
    async with Client(mcp) as client:
        tools = await client.list_tools()
        tool = next(t for t in tools if t.name == "sample_tool")
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is True
        result = await client.call_tool(
            "sample_tool", {"course_identifier": "badm_350"}
        )
        assert "ok:badm_350" in str(result.content)


@pytest.mark.asyncio
async def test_resource_template_with_keyword_uri():
    mcp = _make_server()
    async with Client(mcp) as client:
        templates = await client.list_resource_templates()
        assert any("canvas://course/" in t.uri_template for t in templates)


@pytest.mark.asyncio
async def test_prompt_returning_str_renders_as_user_message():
    mcp = _make_server()
    async with Client(mcp) as client:
        result = await client.get_prompt("sample-prompt", {"topic": "grading"})
        assert result.messages[0].role == "user"
        assert "Summarize grading" in str(result.messages[0].content)


def test_http_app_exists_and_mounts_mcp_path():
    mcp = _make_server()
    app = mcp.http_app()
    paths = [getattr(r, "path", "") for r in app.routes]
    assert any(p.startswith("/mcp") for p in paths), f"expected /mcp mount, got {paths}"


_STALE_SESSION_REQUEST = {
    "headers": {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Mcp-Session-Id": "00000000000000000000000000000000",
    },
    "json": {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
}


def test_stateful_http_app_rejects_stale_session_id():
    """Default (stateful) mode 404s on an unknown Mcp-Session-Id — the
    response mcp-remote fails to recover from (issue #159)."""
    from starlette.testclient import TestClient

    mcp = _make_server()
    with TestClient(mcp.http_app()) as client:
        response = client.post("/mcp", **_STALE_SESSION_REQUEST)
    assert response.status_code == 404


def test_stateless_http_app_serves_request_with_stale_session_id():
    """stateless_http=True (what _run_http_server uses) must serve a request
    carrying a stale session id — no server-side session can go stale, which
    is the fix for issue #159."""
    from starlette.testclient import TestClient

    mcp = _make_server()
    with TestClient(mcp.http_app(stateless_http=True)) as client:
        response = client.post("/mcp", **_STALE_SESSION_REQUEST)
    assert response.status_code == 200
    assert "sample_tool" in response.text


def test_run_http_server_builds_stateless_app(monkeypatch):
    """_run_http_server must pass stateless_http=True — regression guard so a
    refactor can't silently reintroduce the stateful session table."""
    from unittest.mock import MagicMock

    from canvas_mcp import server as server_module

    mcp = MagicMock()
    # Stop before actually binding a port: make uvicorn.Server(...).serve a no-op
    # by intercepting anyio.run.
    monkeypatch.setattr(server_module, "CanvasCredentialMiddleware", MagicMock())
    import anyio

    monkeypatch.setattr(anyio, "run", lambda fn: None)
    server_module._run_http_server(mcp, host="127.0.0.1", port=0)
    mcp.http_app.assert_called_once_with(stateless_http=True)


@pytest.mark.asyncio
async def test_summarize_course_prompt_renders(monkeypatch):
    """The real summarize-course prompt must render through fastmcp
    (a 'system'-role dict, as v1 returned, is rejected at render time)."""
    from unittest.mock import AsyncMock, patch

    from canvas_mcp.resources.resources import register_resources_and_prompts

    mcp = FastMCP(name="prompt-test")
    register_resources_and_prompts(mcp)

    with (
        patch(
            "canvas_mcp.resources.resources.get_course_id",
            new=AsyncMock(return_value="12345"),
        ),
        patch(
            "canvas_mcp.resources.resources.make_canvas_request",
            new=AsyncMock(
                return_value={"name": "Test Course", "course_code": "TST_101"}
            ),
        ),
        patch(
            "canvas_mcp.resources.resources.fetch_all_paginated_results",
            new=AsyncMock(return_value=[]),
        ),
    ):
        async with Client(mcp) as client:
            result = await client.get_prompt(
                "summarize-course", {"course_identifier": "TST_101"}
            )

    assert result.messages[0].role == "user"
    assert "Test Course" in str(result.messages[0].content)


# --------------------------------------------------------------------------
# OAuthProxy.load_access_token: the contract the entra-oauth mode authorizes on
# --------------------------------------------------------------------------

_TID = "11111111-2222-3333-4444-555555555555"
_OID = "99999999-8888-7777-6666-555555555555"
_FORGED_OID = "00000000-0000-4000-8000-000000000bad"


class _MemoryStore:
    """The slice of PydanticAdapter that load_access_token reads."""

    def __init__(self, items: dict | None = None) -> None:
        self.items = items or {}

    async def get(self, key: str):
        return self.items.get(key)


class _FakeVerifier:
    """Stands in for the JWKS verification of the upstream Entra access token."""

    def __init__(self, claims: dict | None) -> None:
        self.claims = claims
        self.seen: list[str] = []

    async def verify_token(self, token: str):
        from fastmcp.server.auth import AccessToken

        self.seen.append(token)
        if self.claims is None:
            return None
        return AccessToken(token=token, client_id="client", scopes=["Canvas.Access"], claims=dict(self.claims))


def _entra_provider(tmp_path, monkeypatch):
    import time

    import fastmcp
    from fastmcp.server.auth.oauth_proxy.models import JTIMapping, UpstreamTokenSet

    from canvas_mcp.core.selfhost.oauth import build_entra_auth_provider
    from canvas_mcp.core.selfhost.settings import load_selfhost_settings

    monkeypatch.setattr(fastmcp.settings, "test_mode", True)
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path / "fastmcp")
    settings = load_selfhost_settings({
        "PUBLIC_BASE_URL": "https://canvas.example.test",
        "ENTRA_TENANT_ID": _TID,
        "ENTRA_CLIENT_ID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "ENTRA_CLIENT_SECRET": "entra-client-secret-0123456789",
        "OAUTH_JWT_SIGNING_KEY": "jwt-signing-key-" + "z" * 40,
        "ACCOUNT_SESSION_SECRET": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "CANVAS_TOKEN_KEYS": "k1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "FASTMCP_HOME": str(tmp_path / "fastmcp"),
        "SELFHOST_DATA_DIR": str(tmp_path / "data"),
    })
    provider = build_entra_auth_provider(settings)
    provider.set_mcp_path("/mcp")  # what get_routes() does: builds the real JWT issuer

    upstream = UpstreamTokenSet(
        upstream_token_id="up-1", access_token="upstream-entra-access-token", refresh_token=None,
        refresh_token_expires_at=None, expires_at=time.time() + 3600, token_type="Bearer",
        scope="api://x/Canvas.Access", client_id="client", created_at=time.time(),
    )
    provider._upstream_token_store = _MemoryStore({"up-1": upstream})
    provider._jti_mapping_store = _MemoryStore({
        "jti-1": JTIMapping(jti="jti-1", upstream_token_id="up-1", created_at=time.time()),
    })
    return provider


@pytest.mark.asyncio
async def test_oauth_proxy_returns_verified_upstream_claims_not_the_snapshot(tmp_path, monkeypatch):
    """Authorization must read tid/oid/roles from the verified upstream token.

    FastMCP also embeds a snapshot of the upstream claims in its own JWT
    ('upstream_claims', decoded without signature verification when the token
    was issued). Those must never be what the top-level claims come from. If a
    FastMCP upgrade changes this, the self-hosted mode must be re-reviewed.
    """
    provider = _entra_provider(tmp_path, monkeypatch)
    verified = {"tid": _TID, "oid": _OID, "roles": ["Canvas.User"], "azp": "app", "scp": "Canvas.Access"}
    verifier = _FakeVerifier(verified)
    provider._token_validator = verifier

    forged = {"tid": "ffffffff-ffff-ffff-ffff-ffffffffffff", "oid": _FORGED_OID, "roles": ["Canvas.Owner"]}
    fastmcp_jwt = provider.jwt_issuer.issue_access_token(
        client_id="client", scopes=["Canvas.Access"], jti="jti-1", upstream_claims=forged,
    )

    access = await provider.load_access_token(fastmcp_jwt)

    assert access is not None
    assert verifier.seen == ["upstream-entra-access-token"]  # the UPSTREAM token was verified
    assert access.claims["tid"] == _TID
    assert access.claims["oid"] == _OID
    assert access.claims["roles"] == ["Canvas.User"]
    assert access.claims["azp"] == "app"
    # The snapshot stays quarantined under its own key.
    assert access.claims["upstream_claims"] == forged
    assert access.claims["oid"] != forged["oid"]


@pytest.mark.asyncio
async def test_oauth_proxy_rejects_tokens_it_did_not_issue(tmp_path, monkeypatch):
    from fastmcp.server.auth.jwt_issuer import JWTIssuer

    provider = _entra_provider(tmp_path, monkeypatch)
    verifier = _FakeVerifier({"tid": _TID, "oid": _OID, "roles": ["Canvas.User"]})
    provider._token_validator = verifier

    # A token straight from Entra (or any other IdP) is not a FastMCP JWT.
    assert await provider.load_access_token("eyJhbGciOiJSUzI1NiJ9.e30.c2ln") is None
    # A FastMCP-shaped JWT signed with another key.
    stranger = JWTIssuer(
        issuer=provider.jwt_issuer.issuer, audience=provider.jwt_issuer.audience, signing_key=b"x" * 32
    ).issue_access_token(client_id="client", scopes=["Canvas.Access"], jti="jti-1")
    assert await provider.load_access_token(stranger) is None
    # A genuine FastMCP JWT for a different audience.
    elsewhere = JWTIssuer(
        issuer=provider.jwt_issuer.issuer, audience="https://other.example/mcp",
        signing_key=provider.jwt_issuer._signing_key,
    ).issue_access_token(client_id="client", scopes=["Canvas.Access"], jti="jti-1")
    assert await provider.load_access_token(elsewhere) is None
    assert verifier.seen == []


@pytest.mark.asyncio
async def test_oauth_proxy_denies_when_the_upstream_token_no_longer_verifies(tmp_path, monkeypatch):
    provider = _entra_provider(tmp_path, monkeypatch)
    provider._token_validator = _FakeVerifier(None)
    fastmcp_jwt = provider.jwt_issuer.issue_access_token(
        client_id="client", scopes=["Canvas.Access"], jti="jti-1",
        upstream_claims={"tid": _TID, "oid": _OID, "roles": ["Canvas.Owner"]},
    )
    assert await provider.load_access_token(fastmcp_jwt) is None
