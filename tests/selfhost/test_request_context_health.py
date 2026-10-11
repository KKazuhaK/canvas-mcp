"""Native credential health, compare-and-set invalidation and tool refusals."""

from typing import Any

import pytest
from dbbackend import make_store
from fastmcp import Client, FastMCP
from fastmcp.server.auth import AccessToken
from sqlalchemy import select

from canvas_mcp.core.credentials import (
    RequestCredentials,
    RequestTokenState,
    get_request_token_state,
    set_request_credentials,
    set_request_principal,
    set_request_token_state,
)
from canvas_mcp.core.selfhost import tool_gate
from canvas_mcp.core.selfhost.custody import (
    CUSTODY_NOTICE_VERSION,
    CustodyAcknowledgement,
)
from canvas_mcp.core.selfhost.db import schema
from canvas_mcp.core.selfhost.mcp_state import MCP_READ, McpRead
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

from .conftest import OID_A, acct_key, make_account, make_principal
from .test_request_context import (
    ACCOUNT_URL,
    CANVAS_HOST,
    GRANT,
    SECRET_TOKEN,
    FakeStore,
    Probe,
    _claims,
    _middleware,
    _run,
    _user,
    native_snapshot,
)
from .test_token_store import Clock, _ring

KEY = acct_key(OID_A)


class Recorder:
    def __init__(self):
        self.calls = []
        self.versions = []
        self.generations = []
        self.fail = False

    async def mark_invalid(
        self,
        principal_key,
        reason,
        *,
        expected_updated_at=None,
        expected_generation=None,
    ):
        self.calls.append((principal_key, reason))
        self.versions.append(expected_updated_at)
        self.generations.append(expected_generation)
        if self.fail:
            raise RuntimeError("status write failed")
        return True


class StateProbe(Probe):
    state: RequestTokenState | None = None

    async def __call__(self, scope, receive, send):
        self.state = get_request_token_state()
        await super().__call__(scope, receive, send)


async def serve(*, snapshot=None, fail=None, health=None):
    store = FakeStore({KEY: SECRET_TOKEN}, fail=fail)
    store.snapshots[KEY] = snapshot or native_snapshot()
    probe = StateProbe()
    response = await _run(
        _middleware(probe, store, health=health), user=_user(_claims())
    )
    return response, probe, store


class TestInvalidRows:
    @pytest.mark.parametrize(
        "reason,expected",
        [
            (REASON_CANVAS_TOKEN_REJECTED, token_rejected_message(ACCOUNT_URL)),
            (REASON_REVOKED_BY_ADMIN, token_revoked_message(ACCOUNT_URL)),
            (REASON_DECRYPT_FAILED, unreadable_token_message(ACCOUNT_URL)),
            (None, token_rejected_message(ACCOUNT_URL)),
        ],
    )
    async def test_invalid_snapshot_never_decrypts_or_touches(self, reason, expected):
        response, probe, store = await serve(
            snapshot=native_snapshot(
                credential_status=STATUS_INVALID, invalid_reason=reason
            )
        )
        assert response.status == 200 and probe.seen["creds"] is None
        assert probe.seen["principal"] is not None and probe.seen["message"] == expected
        assert probe.state.dead and probe.state.message == expected
        assert store.gets == store.touches == []

    async def test_messages_do_not_ask_for_a_token_in_chat(self):
        for message in (
            token_rejected_message(ACCOUNT_URL),
            token_revoked_message(ACCOUNT_URL),
            invalid_token_message(ACCOUNT_URL, REASON_REVOKED_BY_ADMIN),
        ):
            assert "never paste it into this chat" in message
            assert SECRET_TOKEN not in message and message.isascii()

    async def test_active_state_carries_the_snapshot_version_and_generation(self):
        _, probe, _ = await serve(
            snapshot=native_snapshot(
                credential_updated_at=777, generation=4, credential_generation=4
            )
        )
        assert probe.seen["creds"] is not None and not probe.state.dead
        assert (
            probe.state.token_version == 777 and probe.state.credential_generation == 4
        )

    async def test_unenrolled_user_can_connect_without_credentials(self):
        response, probe, store = await serve(
            snapshot=native_snapshot(credential_id=None)
        )
        assert response.status == 200 and not probe.state.dead
        assert (
            probe.seen["message"] == not_enrolled_message(ACCOUNT_URL)
            and store.gets == []
        )

    async def test_state_does_not_outlive_the_request(self):
        await serve(snapshot=native_snapshot(credential_status=STATUS_INVALID))
        assert get_request_token_state() is None


class TestDecryptFailure:
    async def test_failure_marks_only_the_snapshot_version_and_generation(self):
        health = Recorder()
        error = TokenDecryptionError("secret")
        error.updated_at = 9999  # Exception text/attributes are not authoritative.
        response, probe, _ = await serve(
            snapshot=native_snapshot(
                credential_updated_at=4321, credential_generation=7, generation=7
            ),
            fail=error,
            health=health,
        )
        assert response.status == 503 and probe.calls == 0
        assert health.calls == [(KEY, REASON_DECRYPT_FAILED)]
        assert health.versions == [4321] and health.generations == [7]
        assert b"could not be read" in response.body and b"secret" not in response.body

    async def test_no_snapshot_version_changes_nothing(self):
        health = Recorder()
        response, _, _ = await serve(
            snapshot=native_snapshot(credential_updated_at=None),
            fail=TokenDecryptionError("nope"),
            health=health,
        )
        assert response.status == 503 and health.calls == []

    @pytest.mark.parametrize("health", [None, Recorder()])
    async def test_status_write_failure_cannot_allow_the_request(self, health):
        if health:
            health.fail = True
        response, probe, _ = await serve(
            fail=TokenDecryptionError("nope"), health=health
        )
        assert response.status == 503 and probe.calls == 0

    async def test_a_replacement_saved_during_failed_decryption_stays_active(
        self, tmp_path
    ):
        clock = Clock()
        store = make_store(tmp_path / "tokens.sqlite3", _ring(("k1", 1)), clock=clock)
        store.initialize()
        put_args = {
            "principal_key": make_account(store, OID_A),
            "canvas_host": CANVAS_HOST,
            "canvas_user_id": "42",
            "canvas_user_name": "Ada",
            "custody": CustodyAcknowledgement(CUSTODY_NOTICE_VERSION, int(clock())),
        }
        store.put(api_token=SECRET_TOKEN, **put_args)
        with store.database.write() as conn:
            conn.execute(
                schema.canvas_credentials.update().values(ciphertext=b"x" * 32)
            )
        with store.database.read() as conn:
            row = conn.execute(select(schema.canvas_credentials)).mappings().one()
        held = native_snapshot(
            credential_id=row["id"],
            key_id=row["key_id"],
            ciphertext=row["ciphertext"],
            nonce=row["nonce"],
            canvas_host=row["canvas_host"],
            credential_updated_at=row["updated_at"],
            generation=row["generation"],
            credential_generation=row["generation"],
        )

        class RacingStore(TokenStore):
            def decrypt_snapshot(self, account_id, snapshot):
                try:
                    return super().decrypt_snapshot(account_id, snapshot)
                finally:
                    clock.now += 5
                    self.put(api_token="7~" + "R" * 62, **put_args)

        racing = RacingStore(store.database, _ring(("k1", 1)), clock=clock)
        health = TokenHealth(racing, account_url=ACCOUNT_URL)
        probe = StateProbe()
        read = McpRead(KEY, GRANT, held)
        response = await _run(
            _middleware(probe, racing, health=health), read=read, user=_user(_claims())
        )
        try:
            current = racing.info(KEY)
            assert current.status == STATUS_ACTIVE and current.invalid_reason is None
            assert current.credential_generation > held.generation
            assert response.status == 503 and probe.calls == 0
        finally:
            store.close()


class Body:
    runs = 0


@pytest.fixture
def server():
    Body.runs = 0
    mcp = FastMCP("gate-health")
    mcp.add_middleware(SelfhostCredentialGate())

    @mcp.tool()
    def get_my_profile() -> str:
        """Dummy tool."""
        Body.runs += 1
        return "ran"

    return mcp


@pytest.fixture
def verified_oid(monkeypatch):
    monkeypatch.setattr(
        tool_gate,
        "get_access_token",
        lambda: AccessToken(
            token="t",
            client_id="client",
            scopes=[],
            claims=_claims(iss="https://canvas.example.test"),
        ),
    )
    marker = MCP_READ.set(McpRead(KEY, GRANT, native_snapshot()))
    try:
        yield
    finally:
        MCP_READ.reset(marker)


async def call(server) -> Any:
    async with Client(server) as client:
        return await client.call_tool("get_my_profile", {}, raise_on_error=False)


def text_of(result):
    return "".join(getattr(block, "text", "") for block in result.content)


class TestToolGate:
    @pytest.mark.parametrize("mounted", [False, True])
    async def test_dead_token_stops_initial_and_later_calls(
        self, server, verified_oid, mounted
    ):
        from canvas_mcp.core.credentials import set_missing_credentials_message

        message = token_rejected_message(ACCOUNT_URL)
        set_request_principal(make_principal(OID_A))
        set_missing_credentials_message(message)
        if mounted:
            set_request_credentials(
                RequestCredentials(
                    api_token=SECRET_TOKEN, api_url="https://canvas.example.edu/api/v1"
                )
            )
        set_request_token_state(RequestTokenState(dead=True, message=message))
        result = await call(server)
        assert result.is_error and text_of(result) == message and Body.runs == 0

    async def test_live_token_passes(self, server, verified_oid):
        set_request_principal(make_principal(OID_A))
        set_request_credentials(
            RequestCredentials(
                api_token=SECRET_TOKEN, api_url="https://canvas.example.edu/api/v1"
            )
        )
        set_request_token_state(RequestTokenState())
        result = await call(server)
        assert not result.is_error and text_of(result) == "ran"
