"""The request context and the credential gate with tokens issued by this server."""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from fastmcp import Client, FastMCP
from fastmcp.server.auth import AccessToken

from canvas_mcp.core.credentials import (
    RequestCredentials,
    clear_http_request_context,
    set_request_credentials,
    set_request_principal,
)
from canvas_mcp.core.selfhost import tool_gate
from canvas_mcp.core.selfhost.accounts import Denied
from canvas_mcp.core.selfhost.request_context import (
    LocalClaimsResolver,
    SelfhostRequestContextMiddleware,
)
from canvas_mcp.core.selfhost.schools import SchoolPolicy
from canvas_mcp.core.selfhost.token_store import PrincipalStatus
from canvas_mcp.core.selfhost.tool_gate import SelfhostCredentialGate

from ..conftest import make_principal
from ..test_request_context import Call, FakeStore, Probe, _user

ISSUER = "https://canvas.example.test/"
ACCT = "acct:aaaaaaaa-0000-4000-8000-00000000000a"
OTHER = "acct:bbbbbbbb-0000-4000-8000-00000000000b"
CANVAS_URL = "https://canvas.example.edu/api/v1"
SECRET = "canvas-token-that-must-never-be-logged-1234567890"


class Access:
    """The access cache: the status of each account, or an error."""

    def __init__(self, **statuses: PrincipalStatus) -> None:
        self.by_key = {k.replace("_", ":"): v for k, v in statuses.items()}
        self.fail: Exception | None = None
        self.asked: list[str] = []

    def status(self, key: str) -> PrincipalStatus:
        self.asked.append(key)
        if self.fail is not None:
            raise self.fail
        return self.by_key.get(key, PrincipalStatus(key, status="missing"))

    def invalidate(self, key: str | None = None) -> None:  # pragma: no cover - interface
        return None


def claims(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "iss": ISSUER, "aud": "https://canvas.example.test/mcp", "sub": ACCT, "acct": ACCT,
        "client_id": "client-1", "scope": "Canvas.Access", "grant": "11111111-1111-4111-8111-111111111111",
        "token_use": "access", "iat": 1, "exp": 4_000_000_000, "jti": "j",
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not ...}


def status(key: str = ACCT, **kw: Any) -> PrincipalStatus:
    kw.setdefault("stored", True)
    return PrincipalStatus(key, **kw)


def resolver(access: Access) -> LocalClaimsResolver:
    return LocalClaimsResolver(access, ISSUER)


class TestResolver:
    def test_an_active_account_becomes_a_principal(self) -> None:
        access = Access(**{ACCT.replace(":", "_"): status(display_name="Alice", role="owner")})
        principal = resolver(access).resolve_request(claims())
        assert not isinstance(principal, Denied)
        assert principal.key == ACCT and principal.account_id == ACCT.removeprefix("acct:")
        assert principal.provider_id == "local" and principal.issuer == ISSUER and principal.subject == ACCT
        assert principal.is_owner is True and principal.display_name == "Alice"
        assert principal.tenant_id == "" and principal.object_id == "" and principal.roles == frozenset()
        assert access.asked == [ACCT]

    def test_a_normal_user_is_not_an_owner(self) -> None:
        access = Access(**{ACCT.replace(":", "_"): status()})
        principal = resolver(access).resolve_request(claims())
        assert not isinstance(principal, Denied) and principal.is_owner is False

    @pytest.mark.parametrize(
        ("account_status", "code"),
        [("disabled", "access_disabled"), ("pending", "pending_approval"), ("missing", "access_denied")],
    )
    def test_an_account_that_is_not_active_is_refused(self, account_status: str, code: str) -> None:
        access = Access(**{ACCT.replace(":", "_"): status(status=account_status)})
        outcome = resolver(access).resolve_request(claims())
        assert isinstance(outcome, Denied) and outcome.code == code

    @pytest.mark.parametrize(
        "bad",
        [
            {"acct": "acct:NOT-A-UUID", "sub": "acct:NOT-A-UUID"},
            {"acct": ...},
            {"acct": 5},
            {"sub": OTHER},
            {"sub": ...},
            {"iss": "https://canvas.example.test"},
            {"iss": "https://evil.example/"},
            {"iss": ...},
            {"token_use": "refresh"},
            {"token_use": ...},
            {"acct": "entra:tenant:oid", "sub": "entra:tenant:oid"},
        ],
    )
    def test_a_claim_set_that_is_not_ours_is_refused_before_any_lookup(self, bad: dict[str, Any]) -> None:
        access = Access(**{ACCT.replace(":", "_"): status()})
        outcome = resolver(access).resolve_request(claims(**bad))
        assert isinstance(outcome, Denied) and outcome.code == "bad_subject"
        assert access.asked == []

    def test_a_database_error_propagates_so_the_caller_can_say_503(self) -> None:
        access = Access()
        access.fail = RuntimeError("database down")
        with pytest.raises(RuntimeError):
            resolver(access).resolve_request(claims())


def middleware(app: Probe, store: FakeStore, access: Access, **kw: Any) -> SelfhostRequestContextMiddleware:
    return SelfhostRequestContextMiddleware(
        app, mcp_path="/mcp", identity=resolver(access), store=store, schools=SchoolPolicy.pinned(CANVAS_URL),
        account_url="https://canvas.example.test/account", identity_mode="local", **kw,
    )


async def run(mw: SelfhostRequestContextMiddleware, user: Any, path: str = "/mcp") -> Call:
    call = Call()
    await mw({"type": "http", "path": path, "method": "POST", "headers": [], "user": user}, call.receive, call.send)
    return call


def local_user(**overrides: Any) -> Any:
    token = AccessToken(token="t", client_id="client-1", scopes=["Canvas.Access"], claims=claims(**overrides))
    from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser

    return AuthenticatedUser(token)


class TestMiddleware:
    async def test_an_active_account_gets_its_own_canvas_credentials(self) -> None:
        probe = Probe()
        store = FakeStore()
        store.rows[ACCT] = SECRET
        access = Access(**{ACCT.replace(":", "_"): status()})
        call = await run(middleware(probe, store, access), local_user())
        assert call.status == 200 and probe.calls == 1
        assert probe.seen["principal"].key == ACCT and probe.seen["principal"].provider_id == "local"
        assert probe.seen["creds"].api_token == SECRET and store.gets == [ACCT]

    @pytest.mark.parametrize("account_status", ["disabled", "pending", "missing"])
    async def test_an_account_that_is_not_active_is_a_403_whatever_token_it_holds(self, account_status: str) -> None:
        probe = Probe()
        store = FakeStore()
        store.rows[ACCT] = SECRET
        access = Access(**{ACCT.replace(":", "_"): status(status=account_status)})
        call = await run(middleware(probe, store, access), local_user())
        assert call.status == 403 and probe.calls == 0 and store.gets == []

    async def test_a_database_error_is_a_503_not_a_pass(self) -> None:
        probe = Probe()
        access = Access()
        access.fail = RuntimeError("database down")
        call = await run(middleware(probe, FakeStore(), access), local_user())
        assert call.status == 503 and probe.calls == 0
        assert "could not be verified" in json.loads(call.body)["error"]

    async def test_a_foreign_claim_set_is_a_403(self) -> None:
        probe = Probe()
        call = await run(middleware(probe, FakeStore(), Access()), _user({"tid": "t", "oid": "o", "roles": ["Canvas.User"]}))
        assert call.status == 403 and probe.calls == 0

    async def test_the_denial_log_names_the_account_only_when_it_is_well_formed(self, caplog) -> None:
        caplog.set_level(logging.WARNING)
        await run(middleware(Probe(), FakeStore(), Access()), local_user())
        assert ACCT in caplog.text and "access_denied" in caplog.text
        caplog.clear()
        await run(middleware(Probe(), FakeStore(), Access()), local_user(acct="<script>", sub="<script>"))
        assert "<script>" not in caplog.text and "bad_subject" in caplog.text

    async def test_an_owners_local_token_never_demotes_them(self) -> None:
        # Entra evidence of a lost owner role does not exist in our token; with no ledger the
        # request path never touches the owner role.
        probe = Probe()
        store = FakeStore()
        store.rows[ACCT] = SECRET
        access = Access(**{ACCT.replace(":", "_"): status(role="owner", role_source="rules")})
        call = await run(middleware(probe, store, access, owners=None), local_user())
        assert call.status == 200 and probe.seen["principal"].is_owner is True


# -- the credential gate ---------------------------------------------------------------------


class Body:
    runs = 0


@pytest.fixture
def server() -> FastMCP:
    Body.runs = 0
    mcp = FastMCP("gate-local")
    mcp.add_middleware(SelfhostCredentialGate(identity_mode="local"))

    @mcp.tool()
    def get_my_profile() -> str:
        """Dummy tool."""
        Body.runs += 1
        return "ran"

    return mcp


def principal(key: str = ACCT, **kw: Any):
    base = make_principal("aaaaaaaa-0000-4000-8000-00000000000a")
    from dataclasses import replace

    return replace(base, key=key, provider_id="local", issuer=ISSUER, subject=key, tenant_id="", object_id="", **kw)


def use_token(monkeypatch: pytest.MonkeyPatch, token_claims: dict[str, Any] | None) -> None:
    token = None if token_claims is None else AccessToken(token="t", client_id="c", scopes=[], claims=token_claims)
    monkeypatch.setattr(tool_gate, "get_access_token", lambda: token)


async def call_tool(server: FastMCP) -> Any:
    async with Client(server) as client:
        return await client.call_tool("get_my_profile", {}, raise_on_error=False)


def text(result: Any) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


def enrol(p: Any) -> None:
    set_request_principal(p)
    set_request_credentials(RequestCredentials(api_token="canvas-token-1234567890abcdef", api_url=CANVAS_URL))


class TestLocalGate:
    async def test_matching_account_issuer_and_token_use_pass(self, server, monkeypatch) -> None:
        use_token(monkeypatch, claims())
        enrol(principal())
        result = await call_tool(server)
        assert not result.is_error and text(result) == "ran" and Body.runs == 1

    @pytest.mark.parametrize(
        "token_claims",
        [claims(acct=OTHER, sub=OTHER), claims(acct=...), claims(iss="https://evil.example/"), claims(token_use="refresh"), claims(token_use=...)],
    )
    async def test_any_disagreement_is_refused_before_the_body_runs(self, server, monkeypatch, token_claims, caplog) -> None:
        caplog.set_level(logging.ERROR)
        use_token(monkeypatch, token_claims)
        enrol(principal())
        result = await call_tool(server)
        assert result.is_error and text(result) == "Identity check failed; reconnect the connector."
        assert Body.runs == 0 and "identity mismatch" in caplog.text

    async def test_no_token_and_no_principal_are_refused(self, server, monkeypatch) -> None:
        use_token(monkeypatch, None)
        enrol(principal())
        assert text(await call_tool(server)) == "Identity check failed; reconnect the connector."
        use_token(monkeypatch, claims())
        clear_http_request_context()
        set_request_credentials(RequestCredentials(api_token="x" * 30, api_url=CANVAS_URL))
        assert text(await call_tool(server)) == "Not signed in."

    async def test_a_principal_that_an_entra_token_produced_is_refused_in_local_mode(self, server, monkeypatch) -> None:
        use_token(monkeypatch, claims())
        enrol(make_principal("aaaaaaaa-0000-4000-8000-00000000000a"))  # provider_id 'entra'
        assert text(await call_tool(server)) == "Identity check failed; reconnect the connector."

    async def test_the_proxy_gate_still_wants_a_tenant_and_an_object_id(self, monkeypatch) -> None:
        mcp = FastMCP("gate-proxy")
        mcp.add_middleware(SelfhostCredentialGate())

        @mcp.tool()
        def get_my_profile() -> str:
            """Dummy tool."""
            return "ran"

        use_token(monkeypatch, claims())
        enrol(principal())
        result = await call_tool(mcp)
        assert result.is_error and text(result) == "Identity check failed; reconnect the connector."

    async def test_access_and_credential_checks_are_unchanged(self, monkeypatch) -> None:
        access = Access(**{ACCT.replace(":", "_"): status(status="disabled")})
        mcp = FastMCP("gate-local-access")
        mcp.add_middleware(SelfhostCredentialGate(identity_mode="local", access=access))

        @mcp.tool()
        def get_my_profile() -> str:
            """Dummy tool."""
            return "ran"

        use_token(monkeypatch, claims())
        enrol(principal())
        result = await call_tool(mcp)
        assert result.is_error and "disabled" in text(result)
