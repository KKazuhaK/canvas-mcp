"""The request context and the tool gate for tokens whose status is invalid."""

from __future__ import annotations

from typing import Any

import pytest
from fastmcp import Client, FastMCP
from fastmcp.server.auth import AccessToken

from canvas_mcp.core.credentials import (
    RequestCredentials,
    RequestTokenState,
    get_request_token_state,
    set_request_credentials,
    set_request_principal,
    set_request_token_state,
)
from canvas_mcp.core.selfhost import tool_gate
from canvas_mcp.core.selfhost.request_context import (
    invalid_token_message,
    not_enrolled_message,
    token_rejected_message,
    token_revoked_message,
    unreadable_token_message,
)
from canvas_mcp.core.selfhost.token_store import (
    REASON_CANVAS_TOKEN_REJECTED,
    REASON_DECRYPT_FAILED,
    REASON_REVOKED_BY_ADMIN,
    STATUS_ACTIVE,
    STATUS_INVALID,
    TokenDecryptionError,
)
from canvas_mcp.core.selfhost.tool_gate import SelfhostCredentialGate

from .conftest import OID_A, TENANT, make_principal
from .test_request_context import (
    ACCOUNT_URL,
    SECRET_TOKEN,
    FakeStore,
    Probe,
    _claims,
    _middleware,
    _Row,
    _run,
    _user,
)


class StatusRow(_Row):
    def __init__(
        self,
        status: str = STATUS_ACTIVE,
        reason: str | None = None,
        updated_at: int = 1234,
    ) -> None:
        super().__init__(SECRET_TOKEN, None)
        self.status = status
        self.invalid_reason = reason
        self.updated_at = updated_at


class RowStore(FakeStore):
    """A fake store whose row can carry a status."""

    def __init__(self, row: StatusRow | None, *, fail: Exception | None = None) -> None:
        super().__init__(fail=fail)
        self.row = row

    def get(self, tenant_id: str, object_id: str) -> Any:  # type: ignore[override]
        self.gets.append((tenant_id, object_id))
        if self.fail is not None:
            raise self.fail
        return self.row


class Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail = False

    async def mark_invalid(
        self, principal_key: str, reason: str, *, expected_updated_at: int | None = None
    ) -> bool:
        if self.fail:
            raise RuntimeError("store exploded")
        self.calls.append((principal_key, reason))
        return True


class StateProbe(Probe):
    """Also records the shared token-health object of the request."""

    state: RequestTokenState | None = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.state = get_request_token_state()
        await super().__call__(scope, receive, send)


async def serve(store: FakeStore, health: Recorder | None = None) -> StateProbe:
    probe = StateProbe()
    middleware = _middleware(probe, store)
    middleware.health = health
    await _run(middleware, user=_user(_claims()))
    return probe


class TestInvalidRows:
    @pytest.mark.parametrize(
        ("reason", "expected"),
        [
            (REASON_CANVAS_TOKEN_REJECTED, token_rejected_message(ACCOUNT_URL)),
            (REASON_REVOKED_BY_ADMIN, token_revoked_message(ACCOUNT_URL)),
            (REASON_DECRYPT_FAILED, unreadable_token_message(ACCOUNT_URL)),
            (None, token_rejected_message(ACCOUNT_URL)),
        ],
    )
    async def test_an_invalid_row_mounts_no_credentials_and_says_how_to_fix_it(
        self, reason: str | None, expected: str
    ) -> None:
        store = RowStore(StatusRow(STATUS_INVALID, reason))
        probe = await serve(store)

        assert probe.seen["creds"] is None
        assert probe.seen["principal"] is not None
        assert probe.seen["message"] == expected
        assert ACCOUNT_URL in expected
        assert probe.state is not None and probe.state.dead and probe.state.message == expected
        assert store.touches == []  # a dead token is not "used"

    async def test_the_messages_never_ask_for_the_token_in_chat(self) -> None:
        for message in (
            token_rejected_message(ACCOUNT_URL),
            token_revoked_message(ACCOUNT_URL),
            invalid_token_message(ACCOUNT_URL, REASON_REVOKED_BY_ADMIN),
        ):
            assert "never paste it into this chat" in message
            assert SECRET_TOKEN not in message
            assert message.isascii()

    async def test_an_active_row_starts_a_live_token_state_with_its_version(self) -> None:
        probe = await serve(RowStore(StatusRow(STATUS_ACTIVE, updated_at=777)))
        assert probe.seen["creds"] is not None
        assert probe.state is not None
        assert probe.state.dead is False and probe.state.token_version == 777

    async def test_rows_without_a_status_attribute_are_active(self) -> None:
        probe = await serve(FakeStore({(TENANT, OID_A): SECRET_TOKEN}))
        assert probe.seen["creds"] is not None
        assert probe.state is not None and probe.state.dead is False

    async def test_not_enrolled_users_are_unaffected(self) -> None:
        probe = await serve(RowStore(None))
        assert probe.seen["message"] == not_enrolled_message(ACCOUNT_URL)
        assert probe.state is not None and probe.state.dead is False

    async def test_the_state_does_not_outlive_the_request(self) -> None:
        await serve(RowStore(StatusRow(STATUS_INVALID, REASON_CANVAS_TOKEN_REJECTED)))
        assert get_request_token_state() is None


class TestDecryptFailure:
    async def test_a_failed_decryption_marks_the_row_invalid(self) -> None:
        health = Recorder()
        probe = await serve(RowStore(None, fail=TokenDecryptionError("nope")), health)
        assert health.calls == [(f"entra:{TENANT}:{OID_A}", REASON_DECRYPT_FAILED)]
        assert probe.seen["creds"] is None
        assert probe.seen["message"] == unreadable_token_message(ACCOUNT_URL)
        assert probe.state is not None and probe.state.dead

    @pytest.mark.parametrize("error", [RuntimeError("database is locked"), OSError("disk")])
    async def test_a_store_failure_that_is_not_a_decryption_error_changes_nothing(
        self, error: Exception
    ) -> None:
        health = Recorder()
        probe = await serve(RowStore(None, fail=error), health)
        assert health.calls == []
        assert probe.seen["message"] == unreadable_token_message(ACCOUNT_URL)

    async def test_a_failing_status_write_does_not_change_the_answer(self) -> None:
        health = Recorder()
        health.fail = True
        probe = await serve(RowStore(None, fail=TokenDecryptionError("nope")), health)
        assert probe.seen["message"] == unreadable_token_message(ACCOUNT_URL)

    async def test_without_a_health_service_the_message_is_still_given(self) -> None:
        probe = await serve(RowStore(None, fail=TokenDecryptionError("nope")), None)
        assert probe.seen["message"] == unreadable_token_message(ACCOUNT_URL)


class Body:
    runs = 0


@pytest.fixture
def server() -> FastMCP:
    Body.runs = 0
    mcp = FastMCP("gate-health-test")
    mcp.add_middleware(SelfhostCredentialGate())

    @mcp.tool()
    def whoami() -> str:
        """Dummy tool."""
        Body.runs += 1
        return "ran"

    return mcp


@pytest.fixture
def verified_oid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tool_gate,
        "get_access_token",
        lambda: AccessToken(token="t", client_id="c", scopes=[], claims={"oid": OID_A}),
    )


async def call(server: FastMCP) -> Any:
    async with Client(server) as client:
        return await client.call_tool("whoami", {}, raise_on_error=False)


def text_of(result: Any) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


class TestToolGate:
    async def test_an_invalid_token_gets_the_reenroll_message_and_the_tool_never_runs(
        self, server: FastMCP, verified_oid: None
    ) -> None:
        # What the middleware publishes for an invalid row: no credentials, a message.
        from canvas_mcp.core.credentials import set_missing_credentials_message

        message = token_rejected_message(ACCOUNT_URL)
        set_request_principal(make_principal(OID_A))
        set_missing_credentials_message(message)
        set_request_token_state(RequestTokenState(dead=True, message=message))

        result = await call(server)

        assert result.is_error
        assert text_of(result) == message
        assert Body.runs == 0

    async def test_a_token_found_dead_earlier_in_the_request_stops_later_calls(
        self, server: FastMCP, verified_oid: None
    ) -> None:
        message = token_rejected_message(ACCOUNT_URL)
        set_request_principal(make_principal(OID_A))
        set_request_credentials(
            RequestCredentials(api_token="canvas-token-1234567890abcdef", api_url="https://c.example.test/api/v1")
        )
        set_request_token_state(RequestTokenState(dead=True, message=message))

        result = await call(server)

        assert result.is_error and text_of(result) == message
        assert Body.runs == 0

    async def test_a_live_token_passes(self, server: FastMCP, verified_oid: None) -> None:
        set_request_principal(make_principal(OID_A))
        set_request_credentials(
            RequestCredentials(api_token="canvas-token-1234567890abcdef", api_url="https://c.example.test/api/v1")
        )
        set_request_token_state(RequestTokenState())
        result = await call(server)
        assert not result.is_error and text_of(result) == "ran"
