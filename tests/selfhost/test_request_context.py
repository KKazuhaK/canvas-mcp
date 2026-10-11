"""Request isolation and fail-closed publication of the verified native snapshot."""

import asyncio
import json
import logging
from dataclasses import replace
from types import MappingProxyType
from typing import Any

import pytest
from fastmcp.server.auth import AccessToken
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from starlette.authentication import UnauthenticatedUser

from canvas_mcp.core.credentials import (
    current_principal_key,
    get_request_credentials,
    get_request_principal,
    is_http_request_active,
    missing_credentials_message,
    request_local_principal_state,
    uses_request_local_course_state,
)
from canvas_mcp.core.selfhost.config_snapshot import CURRENT_CONFIG, ConfigSnapshot
from canvas_mcp.core.selfhost.custody import CUSTODY_NOTICE_VERSION
from canvas_mcp.core.selfhost.db.settings_repo import TypedSettings
from canvas_mcp.core.selfhost.db.snapshots import McpSnapshot
from canvas_mcp.core.selfhost.mcp_state import MCP_READ, MCP_UNAVAILABLE, McpRead
from canvas_mcp.core.selfhost.request_context import (
    LocalClaimsResolver,
    SelfhostRequestContextMiddleware,
    not_enrolled_message,
    school_not_offered_message,
    unreadable_token_message,
)
from canvas_mcp.core.selfhost.schools import School, SchoolPolicy

from .conftest import OID_A, OID_B, TENANT, acct_key

ISSUER = "https://mcp.example.test/"
CANVAS_HOST = "canvas.example.edu"
CANVAS_URL = f"https://{CANVAS_HOST}/api/v1"
ACCOUNT_URL = "https://mcp.example.test/account"
GRANT = "019a1234-5678-7000-8000-000000000001"
SECRET_TOKEN = "canvas-token-that-must-never-be-logged-1234567890"


def native_snapshot(**changes: Any) -> McpSnapshot:
    return replace(
        McpSnapshot(
            client_id="client",
            display_name="Ada",
            status="active",
            role="user",
            session_epoch=1,
            credential_generation=1,
            write_tools_version=1,
            revoked_at=None,
            grant_expires_at=4_000_000_000,
            grant_used_at=None,
            credential_id="019a1234-5678-7000-8000-000000000002",
            canvas_host=CANVAS_HOST,
            kind="pat",
            generation=1,
            key_id="k1",
            nonce=b"n" * 12,
            ciphertext=b"c" * 32,
            credential_status="active",
            invalid_reason=None,
            credential_updated_at=1234,
            credential_used_at=None,
            last_verified_at=None,
            canvas_user_id="42",
            custody_notice_version=CUSTODY_NOTICE_VERSION,
            jwt_epoch=1,
            settings_revision=1,
        ),
        **changes,
    )


class FakeSnapshots:
    def __init__(self, schools: SchoolPolicy | None = None) -> None:
        self.schools = schools or SchoolPolicy(
            featured=(School(CANVAS_HOST, CANVAS_URL, "Example"),),
            search_enabled=False,
        )
        self.asked: list[int] = []
        self.fail: Exception | None = None

    def get(self, revision: int) -> ConfigSnapshot:
        self.asked.append(revision)
        if self.fail is not None:
            raise self.fail
        return ConfigSnapshot(
            revision, self.schools, (), TypedSettings(MappingProxyType({})), ()
        )


class FakeStore:
    """Only decrypts the supplied immutable row; it cannot fetch account standing."""

    def __init__(self, rows=None, *, fail: Exception | None = None) -> None:
        self.rows = {
            acct_key(key[1], tenant=key[0]) if isinstance(key, tuple) else key: value
            for key, value in (rows or {}).items()
        }
        self.fail = fail
        self.gets: list[str] = []
        self.touches: list[str] = []
        self.touch_fails = False
        self.snapshots: dict[str, McpSnapshot] = {}

    def snapshot(self, key: str) -> McpSnapshot:
        if key in self.snapshots:
            return self.snapshots[key]
        value = self.rows.get(key)
        if value is None:
            return native_snapshot(
                credential_id=None, canvas_host=None, generation=None
            )
        host = value[1] if isinstance(value, tuple) else CANVAS_HOST
        return native_snapshot(canvas_host=host)

    def decrypt_snapshot(self, account_id: str, snapshot: McpSnapshot) -> str:
        self.gets.append(account_id)
        if self.fail is not None:
            raise self.fail
        value = self.rows[account_id]
        return value[0] if isinstance(value, tuple) else value

    def touch(self, principal_key: str, *, min_interval_seconds: int = 300) -> None:
        self.touches.append(principal_key)
        if self.touch_fails:
            raise RuntimeError("touch exploded")


class Probe:
    def __init__(self, *, raises: Exception | None = None) -> None:
        self.calls = 0
        self.raises = raises
        self.seen: dict[str, Any] = {}

    async def __call__(self, scope, receive, send) -> None:
        self.calls += 1
        self.seen = {
            "active": is_http_request_active(),
            "creds": get_request_credentials(),
            "principal": get_request_principal(),
            "key": current_principal_key(),
            "message": missing_credentials_message(),
            "local": uses_request_local_course_state(),
            "bag": request_local_principal_state(),
            "config": CURRENT_CONFIG.get(),
        }
        if self.raises is not None:
            raise self.raises
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _claims(**overrides: Any) -> dict[str, Any]:
    key = acct_key(OID_A)
    values = {
        "iss": ISSUER,
        "sub": key,
        "acct": key,
        "grant": GRANT,
        "token_use": "access",
        "client_id": "client",
        "scope": "Canvas.Access",
    }
    values.update(overrides)
    return {k: v for k, v in values.items() if v is not ...}


def _user(
    claims: dict[str, Any] | None, *, claims_attr: bool = True
) -> AuthenticatedUser:
    if not claims_attr:

        class Bare:
            client_id = "client"
            scopes: list[str] = []

        return AuthenticatedUser(Bare())  # type: ignore[arg-type]
    return AuthenticatedUser(
        AccessToken(
            token="local",
            client_id="client",
            scopes=["Canvas.Access"],
            claims=claims or {},
        )
    )


class Call:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    async def send(self, message: dict[str, Any]) -> None:
        self.sent.append(message)

    async def receive(self) -> dict[str, Any]:
        return {"type": "http.request", "body": b""}

    @property
    def status(self) -> int:
        return next(
            m["status"] for m in self.sent if m["type"] == "http.response.start"
        )

    @property
    def headers(self) -> dict[bytes, bytes]:
        return dict(
            next(m for m in self.sent if m["type"] == "http.response.start")["headers"]
        )

    @property
    def body(self) -> bytes:
        return b"".join(
            m.get("body", b"") for m in self.sent if m["type"] == "http.response.body"
        )


def _middleware(
    app, store, schools=None, **options
) -> SelfhostRequestContextMiddleware:
    return SelfhostRequestContextMiddleware(
        app,
        mcp_path="/mcp",
        identity=LocalClaimsResolver(ISSUER),
        store=store,
        snapshots=FakeSnapshots(schools),
        account_url=ACCOUNT_URL,
        touch_grant=lambda grant: None,
        **options,
    )


_AUTO = object()


async def _run(
    mw, path="/mcp", *, read=_AUTO, unavailable=False, **scope_extra
) -> Call:
    user = scope_extra.get("user")
    if read is _AUTO:
        claims = getattr(getattr(user, "access_token", None), "claims", {}) or {}
        key = claims.get("acct", acct_key(OID_A))
        snapshot = mw.store.snapshot(key)
        read = McpRead(key, claims.get("grant", GRANT), snapshot)
    read_token = MCP_READ.set(read)
    unavailable_token = MCP_UNAVAILABLE.set(unavailable)
    config_token = CURRENT_CONFIG.set(None)
    call = Call()
    try:
        await mw(
            {
                "type": "http",
                "path": path,
                "method": "POST",
                "headers": [],
                **scope_extra,
            },
            call.receive,
            call.send,
        )
    finally:
        MCP_READ.reset(read_token)
        MCP_UNAVAILABLE.reset(unavailable_token)
        CURRENT_CONFIG.reset(config_token)
    return call


class TestPassThrough:
    async def test_non_http_scopes_are_untouched(self):
        probe = Probe()
        await _middleware(probe, FakeStore())(
            {"type": "lifespan"}, Call().receive, Call().send
        )
        assert probe.seen["active"] is False and probe.seen["creds"] is None

    @pytest.mark.parametrize(
        "path",
        ["/account", "/healthz", "/.well-known/oauth-authorization-server", "/mcpx"],
    )
    async def test_other_paths_only_mark_http(self, path):
        probe, store = Probe(), FakeStore({acct_key(OID_A): SECRET_TOKEN})
        call = await _run(_middleware(probe, store), path, user=_user(_claims()))
        assert call.status == 200 and probe.seen["active"]
        assert probe.seen["creds"] is None and probe.seen["principal"] is None
        assert store.gets == [] and not is_http_request_active()

    @pytest.mark.parametrize("user", [None, UnauthenticatedUser()])
    async def test_unauthenticated_mcp_reaches_fastmcp(self, user):
        probe, store = Probe(), FakeStore()
        await _run(_middleware(probe, store), user=user)
        assert probe.calls == 1 and store.gets == []

    async def test_mcp_subpaths_use_the_same_gate(self):
        probe = Probe()
        call = await _run(
            _middleware(probe, FakeStore()),
            "/mcp/anything",
            user=_user(_claims(token_use="refresh")),
        )
        assert call.status == 403 and probe.calls == 0


class TestDenied:
    @pytest.mark.parametrize(
        "bad",
        [
            {"iss": "https://evil.example/"},
            {"iss": ...},
            {"acct": "not-a-uuid"},
            {"acct": ...},
            {"acct": 5},
            {"sub": acct_key(OID_B)},
            {"token_use": "refresh"},
            {"token_use": ...},
            {"acct": acct_key(OID_A).upper(), "sub": acct_key(OID_A).upper()},
        ],
    )
    async def test_bad_local_claims_never_decrypt(self, bad):
        probe, store = Probe(), FakeStore({acct_key(OID_A): SECRET_TOKEN})
        call = await _run(_middleware(probe, store), user=_user(_claims(**bad)))
        assert call.status == 403 and call.headers[b"cache-control"] == b"no-store"
        assert json.loads(call.body)["error"] and probe.calls == 0 and store.gets == []
        assert not is_http_request_active()

    @pytest.mark.parametrize(
        "read",
        [
            None,
            McpRead(acct_key(OID_B), GRANT, native_snapshot()),
            McpRead(
                acct_key(OID_A),
                "019a1234-5678-7000-8000-000000000003",
                native_snapshot(),
            ),
        ],
    )
    async def test_claims_require_the_matching_authenticated_read(self, read):
        probe = Probe()
        call = await _run(
            _middleware(probe, FakeStore()), read=read, user=_user(_claims())
        )
        assert call.status == 403 and probe.calls == 0

    @pytest.mark.parametrize("status", ["disabled", "pending", "missing"])
    async def test_snapshot_standing_is_authoritative(self, status):
        probe, store = Probe(), FakeStore({acct_key(OID_A): SECRET_TOKEN})
        store.snapshots[acct_key(OID_A)] = native_snapshot(status=status)
        call = await _run(
            _middleware(probe, store),
            user=_user(_claims(role="owner", roles=["Canvas.Owner"])),
        )
        assert call.status == 403 and store.gets == [] and probe.calls == 0

    async def test_missing_claim_mapping_is_refused(self):
        call = await _run(
            _middleware(Probe(), FakeStore()), user=_user(None, claims_attr=False)
        )
        assert call.status == 403

    async def test_database_unavailable_is_503(self):
        probe, store = Probe(), FakeStore({acct_key(OID_A): SECRET_TOKEN})
        call = await _run(
            _middleware(probe, store), unavailable=True, user=_user(_claims())
        )
        assert call.status == 503 and probe.calls == 0 and store.gets == []

    async def test_denials_do_not_log_names_tokens_or_malformed_ids(self, caplog):
        caplog.set_level(logging.WARNING)
        probe = Probe()
        await _run(
            _middleware(probe, FakeStore()),
            user=_user(
                _claims(
                    acct="<script>",
                    sub="<script>",
                    name="Ada Lovelace",
                    preferred_username="ada@example.test",
                )
            ),
        )
        assert "bad_subject" in caplog.text
        assert all(
            s not in caplog.text
            for s in ("<script>", "Ada Lovelace", "ada@example.test", SECRET_TOKEN)
        )

    async def test_forged_credential_headers_cannot_supply_identity(self):
        probe = Probe()
        call = await _run(
            _middleware(probe, FakeStore()),
            user=_user({"tid": TENANT, "oid": OID_A, "roles": ["Canvas.User"]}),
            headers=[
                (b"x-canvas-token", SECRET_TOKEN.encode()),
                (b"x-ms-client-principal-id", OID_A.encode()),
            ],
        )
        assert call.status == 403 and probe.calls == 0


class TestCredentials:
    async def test_only_stored_school_and_token_are_mounted(self):
        probe, store = Probe(), FakeStore({acct_key(OID_A): SECRET_TOKEN})
        call = await _run(
            _middleware(probe, store),
            user=_user(_claims()),
            headers=[(b"x-canvas-url", b"https://evil.example/api/v1")],
        )
        assert call.status == 200
        assert (
            probe.seen["creds"].api_token == SECRET_TOKEN
            and probe.seen["creds"].api_url == CANVAS_URL
        )
        assert probe.seen["principal"].key == acct_key(OID_A)
        assert probe.seen["key"] == f"{acct_key(OID_A)}|{CANVAS_URL}|g1"
        assert store.gets == store.touches == [acct_key(OID_A)]

    @pytest.mark.parametrize(
        "changes, message",
        [
            ({"credential_id": None}, not_enrolled_message(ACCOUNT_URL)),
            ({"canvas_host": None}, school_not_offered_message(ACCOUNT_URL)),
            (
                {"canvas_host": "canvas.other.edu"},
                school_not_offered_message(ACCOUNT_URL),
            ),
            ({"custody_notice_version": None}, "custody"),
            ({"custody_notice_version": 0}, "custody"),
        ],
    )
    async def test_unusable_or_unacknowledged_credentials_are_never_decrypted(
        self, changes, message
    ):
        probe, store = Probe(), FakeStore({acct_key(OID_A): SECRET_TOKEN})
        store.snapshots[acct_key(OID_A)] = native_snapshot(**changes)
        call = await _run(_middleware(probe, store), user=_user(_claims()))
        assert (
            call.status == 200
            and probe.seen["creds"] is None
            and store.gets == store.touches == []
        )
        assert message.lower() in probe.seen["message"].lower()

    async def test_generation_disagreement_is_503_before_decrypt(self):
        probe, store = Probe(), FakeStore({acct_key(OID_A): SECRET_TOKEN})
        store.snapshots[acct_key(OID_A)] = native_snapshot(generation=2)
        call = await _run(_middleware(probe, store), user=_user(_claims()))
        assert call.status == 503 and probe.calls == 0 and store.gets == []

    async def test_unreadable_configuration_is_503_before_decrypt(self):
        probe, store = Probe(), FakeStore({acct_key(OID_A): SECRET_TOKEN})
        mw = _middleware(probe, store)
        mw.snapshots.fail = RuntimeError("secret configuration")
        call = await _run(mw, user=_user(_claims()))
        assert call.status == 503 and store.gets == [] and probe.calls == 0

    async def test_unreadable_token_is_503_without_sensitive_logs(self, caplog):
        caplog.set_level(logging.DEBUG)
        probe, store = (
            Probe(),
            FakeStore({acct_key(OID_A): SECRET_TOKEN}, fail=RuntimeError(SECRET_TOKEN)),
        )
        call = await _run(_middleware(probe, store), user=_user(_claims()))
        assert call.status == 503 and probe.calls == 0
        assert json.loads(call.body)["error"] == unreadable_token_message(ACCOUNT_URL)
        assert "stored Canvas token unreadable" in caplog.text
        assert SECRET_TOKEN not in caplog.text and "Traceback" not in caplog.text

    async def test_failing_usage_write_preserves_the_response(self):
        probe, store = Probe(), FakeStore({acct_key(OID_A): SECRET_TOKEN})
        store.touch_fails = True
        assert (
            await _run(_middleware(probe, store), user=_user(_claims()))
        ).status == 200

    async def test_usage_writes_are_deduplicated_within_the_interval(self):
        probe, store = Probe(), FakeStore({acct_key(OID_A): SECRET_TOKEN})
        mw = _middleware(probe, store)
        grants = []
        mw.touch_grant = grants.append
        for _ in range(3):
            await _run(mw, user=_user(_claims()))
        assert store.touches == [acct_key(OID_A)] and grants == [GRANT]

    async def test_two_simultaneous_users_never_share_state_or_school(self):
        host_b = "canvas.school-b.edu"
        schools = SchoolPolicy(
            featured=(
                School(CANVAS_HOST, CANVAS_URL, "A"),
                School(host_b, f"https://{host_b}/api/v1", "B"),
            ),
            search_enabled=False,
        )
        store = FakeStore(
            {acct_key(OID_A): SECRET_TOKEN, acct_key(OID_B): ("token-of-b", host_b)}
        )
        barrier = asyncio.Event()
        seen = {}

        async def app(scope, receive, send):
            key = get_request_principal().key
            bag = request_local_principal_state()
            bag["account"] = key
            seen[key] = (get_request_credentials(), bag)
            if len(seen) == 2:
                barrier.set()
            await asyncio.wait_for(barrier.wait(), timeout=2)
            assert (
                get_request_principal().key == key
                and request_local_principal_state()["account"] == key
            )
            await Probe()(scope, receive, send)

        mw = _middleware(app, store, schools)
        await asyncio.gather(
            _run(mw, user=_user(_claims())),
            _run(mw, user=_user(_claims(acct=acct_key(OID_B), sub=acct_key(OID_B)))),
        )
        assert seen[acct_key(OID_A)][0].api_token == SECRET_TOKEN
        assert seen[acct_key(OID_B)][0].api_url == f"https://{host_b}/api/v1"
        assert seen[acct_key(OID_A)][1] is not seen[acct_key(OID_B)][1]


class TestCleanup:
    @pytest.mark.parametrize("raises", [None, RuntimeError("tool blew up")])
    async def test_context_clears_even_on_application_failure(self, raises):
        probe, store = Probe(raises=raises), FakeStore({acct_key(OID_A): SECRET_TOKEN})
        if raises:
            with pytest.raises(RuntimeError, match="tool blew up"):
                await _run(_middleware(probe, store), user=_user(_claims()))
        else:
            await _run(_middleware(probe, store), user=_user(_claims()))
        assert get_request_credentials() is None and get_request_principal() is None
        assert not is_http_request_active() and current_principal_key() == "local"
        assert missing_credentials_message() == "Canvas token required for HTTP request"

    @pytest.mark.parametrize(
        "mode, local",
        [("request_local", True), ("per_principal", False), ("global", True)],
    )
    async def test_course_state_requires_explicit_opt_in(self, mode, local):
        probe, store = Probe(), FakeStore({acct_key(OID_A): SECRET_TOKEN})
        await _run(_middleware(probe, store, course_state=mode), user=_user(_claims()))
        assert probe.seen["local"] is local
        assert probe.seen["bag"] == ({} if local else None)
        assert request_local_principal_state() is None

    async def test_each_request_gets_a_fresh_bag_and_message(self):
        probe, store = Probe(), FakeStore()
        mw = _middleware(probe, store)
        await _run(mw, user=_user(_claims()))
        first = probe.seen["bag"]
        await _run(mw, user=_user(_claims()))
        assert first is not probe.seen["bag"]
        await _run(mw, "/account")
        assert probe.seen["message"] == "Canvas token required for HTTP request"
