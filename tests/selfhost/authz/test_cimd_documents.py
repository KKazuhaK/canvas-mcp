"""The two client metadata documents Anthropic hosts, and what this server makes of them.

The fixtures (see ``fixtures/cimd/README.md`` for their provenance) pin the behaviour that
the connection of claude.ai and Claude Code depends on:

* claude.ai: one https redirect URI, the jwt-bearer grant among its grant types, and **no
  scope** (so the server's own scope must be the default, or every ``scope`` request would
  be refused);
* Claude Code: ``http://localhost/callback`` and ``http://127.0.0.1/callback`` **without a
  port**; the app picks a free port at run time, so any port must match, and nothing else.

An opt-in test (``CANVAS_MCP_LIVE_CIMD=1``, needs network access) fetches the live documents
through the production fetcher and compares the fields the tests use with the fixtures.
"""

from __future__ import annotations

import json
import os
import pathlib

import pytest

from canvas_mcp.core.selfhost.authz import fastmcp_compat as compat
from canvas_mcp.core.selfhost.authz.clients import CimdResolver, ClientDirectory
from canvas_mcp.core.selfhost.settings import AuthzSettings

from .helpers import Env, make_env
from .stack import FakeCimd

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "cimd"
CLAUDE_AI_URL = "https://claude.ai/oauth/mcp-oauth-client-metadata"
CLAUDE_CODE_URL = "https://claude.ai/oauth/claude-code-client-metadata"
DEFAULT_ALLOWLIST = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "http://localhost/callback",
    "http://127.0.0.1/callback",
)
SCOPES = ("Canvas.Access",)


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def env(tmp_path, keyring, clock) -> Env:
    return make_env(tmp_path, keyring, clock)


def directory(env: Env, cimd: FakeCimd, allowlist=DEFAULT_ALLOWLIST) -> ClientDirectory:
    settings = AuthzSettings()
    resolver = CimdResolver(env.authz, settings, allowlist, SCOPES, fetch=cimd, clock=env.clock)
    return ClientDirectory(env.authz, resolver, allowlist, SCOPES, clock=env.clock)


class TestTheRecordedDocuments:
    def test_the_fixtures_say_what_the_design_assumes(self) -> None:
        ai, code = fixture("claude-ai.json"), fixture("claude-code.json")
        assert ai["client_id"] == CLAUDE_AI_URL and code["client_id"] == CLAUDE_CODE_URL
        assert ai["token_endpoint_auth_method"] == code["token_endpoint_auth_method"] == "none"
        assert "scope" not in ai and "scope" not in code
        assert ai["redirect_uris"] == ["https://claude.ai/api/mcp/auth_callback"]
        assert "urn:ietf:params:oauth:grant-type:jwt-bearer" in ai["grant_types"]
        assert code["redirect_uris"] == ["http://localhost/callback", "http://127.0.0.1/callback"]

    async def test_the_models_parse_both_documents(self) -> None:
        for name, url in (("claude-ai.json", CLAUDE_AI_URL), ("claude-code.json", CLAUDE_CODE_URL)):
            doc = compat.validate_client_document(fixture(name), url)
            assert doc.client_id == url and doc.scope is None

    async def test_claude_ai_is_accepted_with_the_server_scope_and_without_the_jwt_bearer_grant(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.serve(CLAUDE_AI_URL, fixture("claude-ai.json"))
        client = await directory(env, cimd).get(CLAUDE_AI_URL)
        assert client is not None and client.kind == "cimd" and client.client_host == "claude.ai"
        assert client.scope == "Canvas.Access"  # the document has none: ours is the default
        assert client.grant_types == ["authorization_code", "refresh_token"]
        assert client.token_endpoint_auth_method == "none" and client.client_secret is None
        assert client.validate_scope("Canvas.Access") == ["Canvas.Access"]
        assert client.display_name == "claude.ai"  # the verified host, not the self-asserted name

    async def test_claude_ai_may_only_use_its_callback(self, env: Env) -> None:
        from pydantic import AnyUrl

        from mcp.shared.auth import InvalidRedirectUriError

        cimd = FakeCimd()
        cimd.serve(CLAUDE_AI_URL, fixture("claude-ai.json"))
        client = await directory(env, cimd).get(CLAUDE_AI_URL)
        assert client is not None
        assert str(client.validate_redirect_uri(AnyUrl("https://claude.ai/api/mcp/auth_callback"))) == (
            "https://claude.ai/api/mcp/auth_callback"
        )
        for bad in (
            "https://claude.com/api/mcp/auth_callback",  # on the allowlist, but not in the document
            "https://claude.ai/api/mcp/other",
            "https://claude.ai/api/mcp/auth_callback/",
            "http://localhost:3000/callback",
            "https://evil.example/cb",
        ):
            with pytest.raises(InvalidRedirectUriError):
                client.validate_redirect_uri(AnyUrl(bad))
        # no redirect_uri parameter: the single registered https URI is used
        assert str(client.validate_redirect_uri(None)) == "https://claude.ai/api/mcp/auth_callback"

    @pytest.mark.parametrize(
        "uri",
        ["http://localhost:53682/callback", "http://127.0.0.1:39211/callback", "http://localhost/callback",
         "http://127.0.0.1:1/callback"],
    )
    async def test_claude_code_matches_loopback_callbacks_on_any_port(self, env: Env, uri: str) -> None:
        from pydantic import AnyUrl

        cimd = FakeCimd()
        cimd.serve(CLAUDE_CODE_URL, fixture("claude-code.json"))
        client = await directory(env, cimd).get(CLAUDE_CODE_URL)
        assert client is not None and client.client_name == "Claude Code"
        assert str(client.validate_redirect_uri(AnyUrl(uri))) == uri

    @pytest.mark.parametrize(
        "uri",
        [
            "http://localhost:53682/other",
            "http://127.0.0.1:39211/other",
            "https://localhost/callback",
            "https://localhost:53682/callback",
            "http://[::1]:53682/callback",  # not in the document
            "http://localhost.evil.example:5000/callback",
            "http://localhost:53682/callback?x=1",
        ],
    )
    async def test_claude_code_matches_nothing_else(self, env: Env, uri: str) -> None:
        from pydantic import AnyUrl

        from mcp.shared.auth import InvalidRedirectUriError

        cimd = FakeCimd()
        cimd.serve(CLAUDE_CODE_URL, fixture("claude-code.json"))
        client = await directory(env, cimd).get(CLAUDE_CODE_URL)
        assert client is not None
        with pytest.raises(InvalidRedirectUriError):
            client.validate_redirect_uri(AnyUrl(uri))
        # with two registered URIs a missing redirect_uri is ambiguous
        with pytest.raises(InvalidRedirectUriError):
            client.validate_redirect_uri(None)

    async def test_a_document_with_no_allowlisted_redirect_is_refused(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.serve(CLAUDE_AI_URL, fixture("claude-ai.json"))
        assert await directory(env, cimd, allowlist=("https://other.example/cb",)).get(CLAUDE_AI_URL) is None
        assert env.authz.cimd_snapshot(CLAUDE_AI_URL) is None  # and nothing was stored
        assert cimd.calls == [CLAUDE_AI_URL]

    async def test_only_the_allowlisted_part_of_a_document_survives(self, env: Env) -> None:
        cimd = FakeCimd()
        doc = fixture("claude-ai.json")
        doc["redirect_uris"] = ["https://claude.ai/api/mcp/auth_callback", "https://evil.example/cb"]
        cimd.serve(CLAUDE_AI_URL, doc)
        client = await directory(env, cimd).get(CLAUDE_AI_URL)
        assert client is not None and [str(u) for u in client.redirect_uris] == ["https://claude.ai/api/mcp/auth_callback"]

    async def test_the_stored_copy_is_the_reduced_document_not_the_raw_one(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.serve(CLAUDE_AI_URL, fixture("claude-ai.json"))
        await directory(env, cimd).get(CLAUDE_AI_URL)
        snapshot = env.authz.cimd_snapshot(CLAUDE_AI_URL)
        assert snapshot is not None
        stored = json.loads(snapshot.doc_json)
        assert stored["grant_types"] == ["authorization_code", "refresh_token"] and stored["scope"] == "Canvas.Access"
        assert "client_uri" not in stored and "jwt-bearer" not in snapshot.doc_json


@pytest.mark.skipif(os.environ.get("CANVAS_MCP_LIVE_CIMD") != "1", reason="set CANVAS_MCP_LIVE_CIMD=1 (needs network access)")
class TestLiveDrift:
    @pytest.mark.parametrize(("name", "url"), [("claude-ai.json", CLAUDE_AI_URL), ("claude-code.json", CLAUDE_CODE_URL)])
    async def test_the_live_document_still_has_the_fields_the_tests_rely_on(self, name: str, url: str) -> None:
        fetched = await compat.fetch_client_metadata(url, 5.0)
        live = json.loads(fetched.content)
        recorded = fixture(name)
        compat.validate_client_document(live, url)
        assert live["client_id"] == recorded["client_id"]
        assert set(live["redirect_uris"]) == set(recorded["redirect_uris"])
        assert set(live["grant_types"]) == set(recorded["grant_types"])
        assert live.get("token_endpoint_auth_method", "none") == recorded["token_endpoint_auth_method"]
        assert live.get("scope") == recorded.get("scope")
