"""Native claim resolution and per-call enforcement of the authorized snapshot."""

from dataclasses import replace

import pytest
from fastmcp import Client, FastMCP
from fastmcp.server.auth import AccessToken

from canvas_mcp.core.credentials import (
    RequestCredentials,
    set_request_credentials,
    set_request_principal,
)
from canvas_mcp.core.selfhost import tool_gate
from canvas_mcp.core.selfhost.accounts import Denied
from canvas_mcp.core.selfhost.mcp_state import MCP_READ, McpRead
from canvas_mcp.core.selfhost.request_context import LocalClaimsResolver
from canvas_mcp.core.selfhost.tool_gate import SelfhostCredentialGate

from ..conftest import OID_A, OID_B, acct_key, make_principal
from ..test_request_context import CANVAS_URL, GRANT, ISSUER, _claims, native_snapshot

ACCT = acct_key(OID_A)
OTHER = acct_key(OID_B)


@pytest.fixture
def read():
    marker = MCP_READ.set(McpRead(ACCT, GRANT, native_snapshot()))
    try:
        yield
    finally:
        MCP_READ.reset(marker)


class TestResolver:
    def test_active_account_becomes_a_native_principal(self, read):
        marker = MCP_READ.set(
            McpRead(ACCT, GRANT, native_snapshot(role="owner", display_name="Alice"))
        )
        try:
            principal = LocalClaimsResolver(ISSUER).resolve_request(_claims())
            assert not isinstance(principal, Denied)
            assert principal.key == principal.account_id == principal.subject == ACCT
            assert principal.provider_id == "local" and principal.issuer == ISSUER
            assert principal.is_owner and principal.display_name == "Alice"
            assert not hasattr(principal, "tenant_id") and not hasattr(
                principal, "object_id"
            )
        finally:
            MCP_READ.reset(marker)

    def test_unsigned_role_fields_do_not_promote_the_account(self, read):
        principal = LocalClaimsResolver(ISSUER).resolve_request(
            _claims(roles=["Canvas.Owner"], role="owner", name="Forged")
        )
        assert (
            not isinstance(principal, Denied)
            and not principal.is_owner
            and principal.display_name == "Ada"
        )

    @pytest.mark.parametrize(
        "state,code",
        [
            ("disabled", "access_disabled"),
            ("pending", "pending_approval"),
            ("missing", "access_denied"),
        ],
    )
    def test_nonactive_account_is_refused(self, read, state, code):
        marker = MCP_READ.set(McpRead(ACCT, GRANT, native_snapshot(status=state)))
        try:
            result = LocalClaimsResolver(ISSUER).resolve_request(_claims())
            assert isinstance(result, Denied) and result.code == code
        finally:
            MCP_READ.reset(marker)

    @pytest.mark.parametrize(
        "bad",
        [
            {"acct": "acct:" + ACCT, "sub": "acct:" + ACCT},
            {"acct": ...},
            {"acct": 5},
            {"sub": OTHER},
            {"sub": ...},
            {"iss": ISSUER.rstrip("/")},
            {"iss": "https://evil.example/"},
            {"iss": ...},
            {"token_use": "refresh"},
            {"token_use": ...},
            {"acct": "entra:tenant:oid", "sub": "entra:tenant:oid"},
            {"acct": ACCT.upper(), "sub": ACCT.upper()},
            {"grant": OTHER},
        ],
    )
    def test_foreign_claims_and_wrong_snapshot_binding_are_refused(self, read, bad):
        result = LocalClaimsResolver(ISSUER).resolve_request(_claims(**bad))
        assert isinstance(result, Denied) and result.code == "bad_subject"

    def test_valid_claims_without_authenticated_snapshot_are_refused(self):
        marker = MCP_READ.set(None)
        try:
            result = LocalClaimsResolver(ISSUER).resolve_request(_claims())
            assert isinstance(result, Denied) and result.code == "bad_subject"
        finally:
            MCP_READ.reset(marker)


class Body:
    runs = 0


@pytest.fixture
def server():
    Body.runs = 0
    mcp = FastMCP("gate-local")
    mcp.add_middleware(SelfhostCredentialGate())

    @mcp.tool()
    def get_my_profile() -> str:
        """Dummy tool."""
        Body.runs += 1
        return "ran"

    @mcp.resource("test://profile")
    def profile() -> str:
        """Dummy resource."""
        Body.runs += 1
        return "ran"

    return mcp


def enrol():
    set_request_principal(replace(make_principal(OID_A), issuer=ISSUER))
    set_request_credentials(
        RequestCredentials(
            api_token="canvas-token-1234567890abcdef", api_url=CANVAS_URL
        )
    )


def use_token(monkeypatch, claims):
    token = (
        None
        if claims is None
        else AccessToken(token="t", client_id="client", scopes=[], claims=claims)
    )
    monkeypatch.setattr(tool_gate, "get_access_token", lambda: token)


async def call_tool(server):
    async with Client(server) as client:
        return await client.call_tool("get_my_profile", {}, raise_on_error=False)


def text(result):
    return "".join(getattr(block, "text", "") for block in result.content)


class TestLocalGate:
    async def test_matching_identity_and_active_snapshot_pass(
        self, server, monkeypatch, read
    ):
        use_token(monkeypatch, _claims())
        enrol()
        result = await call_tool(server)
        assert not result.is_error and text(result) == "ran" and Body.runs == 1

    @pytest.mark.parametrize(
        "claims",
        [
            None,
            _claims(acct=OTHER, sub=OTHER),
            _claims(acct=...),
            _claims(iss="https://evil.example/"),
            _claims(token_use="refresh"),
            _claims(token_use=...),
        ],
    )
    async def test_identity_disagreement_refuses_the_tool(
        self, server, monkeypatch, read, claims
    ):
        use_token(monkeypatch, claims)
        enrol()
        result = await call_tool(server)
        assert (
            result.is_error
            and text(result) == "Identity check failed; reconnect the connector."
        )
        assert Body.runs == 0

    async def test_foreign_provider_principal_is_refused(
        self, server, monkeypatch, read
    ):
        use_token(monkeypatch, _claims())
        enrol()
        set_request_principal(
            replace(make_principal(OID_A), issuer=ISSUER, provider_id="entra")
        )
        assert (
            text(await call_tool(server))
            == "Identity check failed; reconnect the connector."
        )
        assert Body.runs == 0

    @pytest.mark.parametrize(
        "snapshot,reason",
        [
            (None, "could not be verified"),
            (McpRead(OTHER, GRANT, native_snapshot()), "could not be verified"),
            (McpRead(ACCT, GRANT, native_snapshot(status="disabled")), "disabled"),
            (McpRead(ACCT, GRANT, native_snapshot(status="pending")), "approval"),
            (McpRead(ACCT, GRANT, native_snapshot(status="missing")), "access"),
        ],
    )
    async def test_missing_mismatched_and_nonactive_reads_refuse(
        self, server, monkeypatch, snapshot, reason
    ):
        use_token(monkeypatch, _claims())
        enrol()
        marker = MCP_READ.set(snapshot)
        try:
            result = await call_tool(server)
            assert result.is_error and reason in text(result).lower() and Body.runs == 0
            async with Client(server) as client:
                with pytest.raises(Exception, match=reason):
                    await client.read_resource("test://profile")
            assert Body.runs == 0
        finally:
            MCP_READ.reset(marker)
