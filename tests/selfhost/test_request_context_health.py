"""The request context and the tool gate for tokens whose status is invalid."""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
from dbbackend import make_store, raw_connection
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
from canvas_mcp.core.selfhost.token_health import TokenHealth
from canvas_mcp.core.selfhost.token_store import (
    REASON_CANVAS_TOKEN_REJECTED,
    REASON_DECRYPT_FAILED,
    REASON_REVOKED_BY_ADMIN,
    STATUS_ACTIVE,
    STATUS_INVALID,
    TokenDecryptionError,
    TokenStore,
)
from canvas_mcp.core.selfhost.tool_gate import SelfhostCredentialGate

from .conftest import OID_A, TENANT, acct_key, make_account, make_principal
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
from .test_token_store import Clock as StoreClock
from .test_token_store import _ring


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

    def get(self, principal_key: str) -> Any:  # type: ignore[override]
        self.gets.append(principal_key)
        if self.fail is not None:
            raise self.fail
        return self.row


class Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.versions: list[int | None] = []
        self.fail = False

    async def mark_invalid(
        self,
        principal_key: str,
        reason: str,
        *,
        expected_updated_at: int | None = None,
        expected_generation: int | None = None,
    ) -> bool:
        if self.fail:
            raise RuntimeError("store exploded")
        self.calls.append((principal_key, reason))
        self.versions.append(expected_updated_at)
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


def _decrypt_error(version: int | None) -> TokenDecryptionError:
    error = TokenDecryptionError("nope")
    error.updated_at = version
    return error


class TestDecryptFailure:
    async def test_a_failed_decryption_marks_the_failing_row_invalid(self) -> None:
        health = Recorder()
        probe = await serve(RowStore(None, fail=_decrypt_error(4321)), health)
        assert health.calls == [(acct_key(OID_A), REASON_DECRYPT_FAILED)]
        # Only the row version that failed to decrypt may be marked.
        assert health.versions == [4321]
        assert probe.seen["creds"] is None
        assert probe.seen["message"] == unreadable_token_message(ACCOUNT_URL)
        assert probe.state is not None and probe.state.dead

    async def test_without_a_row_version_nothing_is_marked(self) -> None:
        health = Recorder()
        probe = await serve(RowStore(None, fail=_decrypt_error(None)), health)
        assert health.calls == []
        assert probe.seen["message"] == unreadable_token_message(ACCOUNT_URL)
        assert probe.state is not None and probe.state.dead

    async def test_a_token_saved_while_the_old_row_was_unreadable_stays_active(
        self, tmp_path: pathlib.Path
    ) -> None:
        store = make_store(tmp_path / "tokens.sqlite3", _ring(("k1", 1)), clock=StoreClock())
        store.initialize()
        put_args: dict[str, Any] = {
            "principal_key": make_account(store, OID_A, name="Ada", username="ada@example.test"),
            "canvas_user_id": "42",
            "canvas_user_name": "Ada",
        }
        store.put(api_token=SECRET_TOKEN, **put_args)
        with raw_connection(store) as conn:
            conn.execute("UPDATE canvas_tokens SET ciphertext = x'00'")
        key = acct_key(OID_A)

        class RacingStore(TokenStore):
            """The user saves a new token right after the read of the old row failed."""

            def get(self, principal_key: str) -> Any:
                try:
                    return super().get(principal_key)
                finally:
                    # The fresh row gets a newer updated_at than the failed read.
                    store_clock.now += 5
                    self.put(api_token="7~" + "R" * 62, **put_args)

        store_clock = StoreClock()
        racing = RacingStore(store.database, _ring(("k1", 1)), clock=store_clock)
        health = TokenHealth(racing, account_url=ACCOUNT_URL)
        probe = StateProbe()
        middleware = _middleware(probe, racing)  # type: ignore[arg-type]
        middleware.health = health
        await _run(middleware, user=_user(_claims()))

        row = racing.info(key)
        assert row is not None and row.status == STATUS_ACTIVE
        assert row.invalid_reason is None
        assert probe.state is not None and probe.state.dead  # this request still fails closed

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
    def get_my_profile() -> str:
        """Dummy tool."""
        Body.runs += 1
        return "ran"

    return mcp


@pytest.fixture
def verified_oid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tool_gate,
        "get_access_token",
        lambda: AccessToken(token="t", client_id="c", scopes=[], claims={"tid": TENANT, "oid": OID_A}),
    )


async def call(server: FastMCP) -> Any:
    async with Client(server) as client:
        return await client.call_tool("get_my_profile", {}, raise_on_error=False)


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
