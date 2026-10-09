"""Tests for the per-request identity middleware, driven as raw ASGI."""

import json
import logging
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
)
from canvas_mcp.core.selfhost.identity import ClaimsPolicy
from canvas_mcp.core.selfhost.request_context import (
    SelfhostRequestContextMiddleware,
    not_enrolled_message,
    unreadable_token_message,
)
from canvas_mcp.core.selfhost.schools import FeaturedSchool, SchoolPolicy

from .conftest import CLIENT, OID_A, OID_B, TENANT

POLICY = ClaimsPolicy(tenant_id=TENANT, client_id=CLIENT, required_role="Canvas.User", owner_role="Canvas.Owner")
CANVAS_URL = "https://canvas.example.test/api/v1"
ACCOUNT_URL = "https://mcp.example.test/account"
SECRET_TOKEN = "canvas-token-that-must-never-be-logged-1234567890"


class _Row:
    def __init__(self, api_token: str, canvas_host: str | None = None) -> None:
        self.api_token = api_token
        self.canvas_host = canvas_host


class FakeStore:
    """Rows map (tenant, oid) to a token (a legacy row) or (token, canvas_host)."""

    def __init__(
        self,
        rows: dict[tuple[str, str], str | tuple[str, str | None]] | None = None,
        *,
        fail: Exception | None = None,
    ) -> None:
        self.rows = rows or {}
        self.fail = fail
        self.gets: list[tuple[str, str]] = []
        self.touches: list[tuple[str, str]] = []
        self.touch_fails = False

    def get(self, tenant_id: str, object_id: str) -> _Row | None:
        self.gets.append((tenant_id, object_id))
        if self.fail is not None:
            raise self.fail
        value = self.rows.get((tenant_id, object_id))
        if value is None:
            return None
        return _Row(value) if isinstance(value, str) else _Row(*value)

    def touch(self, tenant_id: str, object_id: str, *, min_interval_seconds: int = 300) -> None:
        self.touches.append((tenant_id, object_id))
        if self.touch_fails:
            raise RuntimeError("touch exploded")


class Probe:
    """A fake inner app that records what the request context looked like."""

    def __init__(self, *, raises: Exception | None = None) -> None:
        self.calls = 0
        self.raises = raises
        self.seen: dict[str, Any] = {}

    async def __call__(self, scope, receive, send) -> None:
        self.calls += 1
        creds = get_request_credentials()
        principal = get_request_principal()
        self.seen = {
            "active": is_http_request_active(),
            "creds": creds,
            "principal": principal,
            "key": current_principal_key(),
            "message": missing_credentials_message(),
        }
        if self.raises is not None:
            raise self.raises
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _user(claims: dict[str, Any] | None, *, claims_attr: bool = True) -> AuthenticatedUser:
    token = AccessToken(token="upstream", client_id="client", scopes=["Canvas.Access"], claims=claims or {})
    if not claims_attr:
        class Bare:
            client_id = "client"
            scopes: list[str] = []
        return AuthenticatedUser(Bare())  # type: ignore[arg-type]
    return AuthenticatedUser(token)


def _claims(**overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {"tid": TENANT, "azp": CLIENT, "oid": OID_A, "roles": ["Canvas.User"], "name": "Ada"}
    claims.update(overrides)
    return claims


class Call:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    async def send(self, message: dict[str, Any]) -> None:
        self.sent.append(message)

    async def receive(self) -> dict[str, Any]:  # pragma: no cover - never read
        return {"type": "http.request", "body": b""}

    @property
    def status(self) -> int:
        return next(m["status"] for m in self.sent if m["type"] == "http.response.start")

    @property
    def headers(self) -> dict[bytes, bytes]:
        start = next(m for m in self.sent if m["type"] == "http.response.start")
        return dict(start["headers"])

    @property
    def body(self) -> bytes:
        return b"".join(m.get("body", b"") for m in self.sent if m["type"] == "http.response.body")


def _middleware(
    app: Probe, store: FakeStore, schools: SchoolPolicy | None = None
) -> SelfhostRequestContextMiddleware:
    return SelfhostRequestContextMiddleware(
        app,
        mcp_path="/mcp",
        policy=POLICY,
        store=store,
        schools=schools or SchoolPolicy.pinned(CANVAS_URL),
        account_url=ACCOUNT_URL,
    )


async def _run(mw: SelfhostRequestContextMiddleware, path: str = "/mcp", **scope_extra: Any) -> Call:
    call = Call()
    scope = {"type": "http", "path": path, "method": "POST", "headers": [], **scope_extra}
    await mw(scope, call.receive, call.send)
    return call


class TestPassThrough:
    async def test_non_http_scopes_are_untouched(self):
        probe = Probe()
        mw = _middleware(probe, FakeStore())
        await mw({"type": "lifespan"}, Call().receive, Call().send)
        assert probe.calls == 1
        assert probe.seen["active"] is False
        assert probe.seen["creds"] is None

    async def test_other_paths_only_mark_the_request_as_http(self):
        probe = Probe()
        store = FakeStore({(TENANT, OID_A): SECRET_TOKEN})
        for path in ("/account", "/healthz", "/.well-known/oauth-authorization-server", "/mcpx"):
            call = await _run(_middleware(probe, store), path, user=_user(_claims()))
            assert call.status == 200
            assert probe.seen["active"] is True
            assert probe.seen["creds"] is None
            assert probe.seen["principal"] is None
        assert store.gets == []
        assert is_http_request_active() is False

    async def test_unauthenticated_mcp_requests_reach_fastmcp_for_the_401(self):
        probe = Probe()
        store = FakeStore({(TENANT, OID_A): SECRET_TOKEN})
        for user in (UnauthenticatedUser(), None):
            scope_extra = {} if user is None else {"user": user}
            await _run(_middleware(probe, store), "/mcp", **scope_extra)
        assert probe.calls == 2
        assert probe.seen["creds"] is None
        assert probe.seen["principal"] is None
        assert store.gets == []

    async def test_subpaths_of_the_mcp_path_are_treated_as_mcp(self):
        probe = Probe()
        call = await _run(_middleware(probe, FakeStore()), "/mcp/anything", user=_user(_claims(roles=[])))
        assert call.status == 403
        assert probe.calls == 0


class TestDenied:
    @pytest.mark.parametrize("claims", [
        _claims(tid="00000000-0000-0000-0000-000000000000"),
        _claims(azp="00000000-0000-0000-0000-000000000000"),
        _claims(oid="not-a-guid"),
        _claims(roles=[]),
        _claims(roles="Canvas.User"),
        {k: v for k, v in _claims().items() if k != "roles"},
    ])
    async def test_403_without_running_anything(self, claims):
        probe = Probe()
        store = FakeStore({(TENANT, OID_A): SECRET_TOKEN})
        call = await _run(_middleware(probe, store), user=_user(claims))
        assert call.status == 403
        assert call.headers[b"content-type"] == b"application/json"
        assert json.loads(call.body)["error"]
        assert probe.calls == 0
        assert store.gets == []
        assert is_http_request_active() is False

    async def test_missing_claims_mapping_is_403(self):
        probe = Probe()
        call = await _run(_middleware(probe, FakeStore()), user=_user(None, claims_attr=False))
        assert call.status == 403
        assert probe.calls == 0

    async def test_denial_logs_the_reason_and_oid_only(self, caplog):
        caplog.set_level(logging.WARNING)
        claims = _claims(roles=[], name="Ada Lovelace", preferred_username="ada@example.test")
        await _run(_middleware(Probe(), FakeStore()), user=_user(claims))
        text = caplog.text
        assert "missing_role" in text
        assert OID_A in text
        assert "Ada Lovelace" not in text
        assert "ada@example.test" not in text

    async def test_a_malformed_oid_is_not_logged(self, caplog):
        caplog.set_level(logging.WARNING)
        await _run(_middleware(Probe(), FakeStore()), user=_user(_claims(oid="<script>alert(1)</script>")))
        assert "<script>" not in caplog.text

    async def test_forged_headers_are_ignored(self):
        probe = Probe()
        headers = [
            (b"x-ms-client-principal-id", OID_A.encode()),
            (b"x-canvas-token", SECRET_TOKEN.encode()),
        ]
        call = await _run(_middleware(probe, FakeStore({(TENANT, OID_A): SECRET_TOKEN})),
                          user=_user(_claims(roles=[])), headers=headers)
        assert call.status == 403
        assert probe.calls == 0


class TestEnrolled:
    async def test_credentials_use_the_pinned_url_and_the_stored_token(self):
        probe = Probe()
        store = FakeStore({(TENANT, OID_A): SECRET_TOKEN})
        # A client-supplied URL header must have no influence.
        headers = [(b"x-canvas-url", b"https://evil.example/api/v1")]
        call = await _run(_middleware(probe, store), user=_user(_claims()), headers=headers)
        assert call.status == 200
        assert probe.seen["active"] is True
        assert probe.seen["creds"].api_token == SECRET_TOKEN
        assert probe.seen["creds"].api_url == CANVAS_URL
        assert probe.seen["principal"].key == f"entra:{TENANT}:{OID_A}"
        assert probe.seen["key"] == f"entra:{TENANT}:{OID_A}|{CANVAS_URL}"
        assert store.gets == [(TENANT, OID_A)]
        assert store.touches == [(TENANT, OID_A)]

    async def test_mixed_case_guids_are_looked_up_lower_case(self):
        probe = Probe()
        store = FakeStore({(TENANT, OID_A): SECRET_TOKEN})
        await _run(_middleware(probe, store), user=_user(_claims(tid=TENANT.upper(), oid=OID_A.upper(), azp=CLIENT.upper())))
        assert store.gets == [(TENANT, OID_A)]
        assert probe.seen["creds"] is not None

    async def test_a_failing_touch_does_not_fail_the_request(self):
        probe = Probe()
        store = FakeStore({(TENANT, OID_A): SECRET_TOKEN})
        store.touch_fails = True
        call = await _run(_middleware(probe, store), user=_user(_claims()))
        assert call.status == 200
        assert probe.seen["creds"] is not None


FEATURED = (FeaturedSchool("canvas.school-a.edu", "School A"), FeaturedSchool("canvas.school-b.edu", "School B"))


class TestSchoolRouting:
    async def test_a_featured_host_routes_to_its_own_api_url(self):
        probe = Probe()
        store = FakeStore({(TENANT, OID_A): (SECRET_TOKEN, "canvas.school-b.edu")})
        schools = SchoolPolicy.build(CANVAS_URL, FEATURED, False)
        await _run(_middleware(probe, store, schools), user=_user(_claims()))
        assert probe.seen["creds"].api_url == "https://canvas.school-b.edu/api/v1"
        assert probe.seen["creds"].api_token == SECRET_TOKEN
        assert probe.seen["key"].endswith("|https://canvas.school-b.edu/api/v1")
        assert store.touches == [(TENANT, OID_A)]

    async def test_a_legacy_row_goes_to_the_default_school(self):
        probe = Probe()
        store = FakeStore({(TENANT, OID_A): (SECRET_TOKEN, None)})
        schools = SchoolPolicy.build(CANVAS_URL, FEATURED, False)
        await _run(_middleware(probe, store, schools), user=_user(_claims()))
        assert probe.seen["creds"].api_url == CANVAS_URL

    async def test_the_default_host_row_uses_the_default_url_verbatim(self):
        probe = Probe()
        url = "https://canvas.example.test:8443/lms/api/v1"
        store = FakeStore({(TENANT, OID_A): (SECRET_TOKEN, "canvas.example.test")})
        await _run(_middleware(probe, store, SchoolPolicy.pinned(url)), user=_user(_claims()))
        assert probe.seen["creds"].api_url == url

    async def test_a_host_the_settings_no_longer_allow_is_not_enrolled(self, caplog):
        caplog.set_level(logging.DEBUG)
        probe = Probe()
        store = FakeStore({(TENANT, OID_A): (SECRET_TOKEN, "canvas.school-b.edu")})
        only_a = SchoolPolicy.build("", FEATURED[:1], False)
        call = await _run(_middleware(probe, store, only_a), user=_user(_claims()))
        assert call.status == 200
        assert probe.seen["creds"] is None
        assert probe.seen["principal"] is not None
        assert probe.seen["message"] == not_enrolled_message(ACCOUNT_URL)
        assert store.touches == []
        assert "stored Canvas school not allowed" in caplog.text
        assert OID_A in caplog.text
        assert "school-b" not in caplog.text and SECRET_TOKEN not in caplog.text

    async def test_a_legacy_row_without_a_default_school_is_not_enrolled(self):
        probe = Probe()
        store = FakeStore({(TENANT, OID_A): (SECRET_TOKEN, None)})
        featured_only = SchoolPolicy.build("", FEATURED, True)
        await _run(_middleware(probe, store, featured_only), user=_user(_claims()))
        assert probe.seen["creds"] is None
        assert probe.seen["message"] == not_enrolled_message(ACCOUNT_URL)

    async def test_a_searched_host_is_allowed_only_while_search_is_on(self):
        store = FakeStore({(TENANT, OID_A): (SECRET_TOKEN, "canvas.found.edu")})
        on = Probe()
        await _run(_middleware(on, store, SchoolPolicy.build(CANVAS_URL, (), True)), user=_user(_claims()))
        assert on.seen["creds"].api_url == "https://canvas.found.edu/api/v1"
        off = Probe()
        await _run(_middleware(off, store, SchoolPolicy.build(CANVAS_URL, (), False)), user=_user(_claims()))
        assert off.seen["creds"] is None
        assert off.seen["message"] == not_enrolled_message(ACCOUNT_URL)

    async def test_two_users_at_two_schools_never_share_credentials(self):
        store = FakeStore({
            (TENANT, OID_A): ("token-of-a-" + "x" * 20, "canvas.school-a.edu"),
            (TENANT, OID_B): ("token-of-b-" + "y" * 20, "canvas.school-b.edu"),
        })
        schools = SchoolPolicy.build("", FEATURED, False)
        seen = {}
        for oid in (OID_A, OID_B):
            probe = Probe()
            await _run(_middleware(probe, store, schools), user=_user(_claims(oid=oid)))
            seen[oid] = (probe.seen["creds"].api_token, probe.seen["creds"].api_url)
        assert seen[OID_A] == ("token-of-a-" + "x" * 20, "https://canvas.school-a.edu/api/v1")
        assert seen[OID_B] == ("token-of-b-" + "y" * 20, "https://canvas.school-b.edu/api/v1")


class TestNotEnrolled:
    async def test_message_points_to_the_account_page(self):
        probe = Probe()
        store = FakeStore()
        call = await _run(_middleware(probe, store), user=_user(_claims()))
        assert call.status == 200
        assert probe.seen["creds"] is None
        assert probe.seen["principal"] is not None
        assert probe.seen["message"] == not_enrolled_message(ACCOUNT_URL)
        assert ACCOUNT_URL in probe.seen["message"]
        assert "never paste it into this chat" in probe.seen["message"]
        assert store.touches == []


class TestStoreFailure:
    async def test_unreadable_token_message_and_no_exception_text_in_logs(self, caplog):
        caplog.set_level(logging.DEBUG)
        probe = Probe()
        boom = RuntimeError(f"decrypt failed for key material {SECRET_TOKEN}")
        call = await _run(_middleware(probe, FakeStore(fail=boom)), user=_user(_claims()))
        assert call.status == 200
        assert probe.seen["creds"] is None
        assert probe.seen["message"] == unreadable_token_message(ACCOUNT_URL)
        assert "could not be read" in probe.seen["message"]
        assert "stored Canvas token unreadable" in caplog.text
        assert OID_A in caplog.text
        assert SECRET_TOKEN not in caplog.text
        assert "decrypt failed" not in caplog.text
        assert "Traceback" not in caplog.text


class TestCleanup:
    async def test_context_is_cleared_after_the_call(self):
        probe = Probe()
        await _run(_middleware(probe, FakeStore({(TENANT, OID_A): SECRET_TOKEN})), user=_user(_claims()))
        assert get_request_credentials() is None
        assert get_request_principal() is None
        assert is_http_request_active() is False
        assert current_principal_key() == "local"

    async def test_context_is_cleared_even_when_the_app_raises(self):
        probe = Probe(raises=RuntimeError("tool blew up"))
        mw = _middleware(probe, FakeStore({(TENANT, OID_A): SECRET_TOKEN}))
        with pytest.raises(RuntimeError, match="tool blew up"):
            await _run(mw, user=_user(_claims()))
        assert probe.seen["creds"] is not None
        assert get_request_credentials() is None
        assert get_request_principal() is None
        assert is_http_request_active() is False
        assert missing_credentials_message() == "Canvas token required for HTTP request"

    async def test_the_message_does_not_leak_into_the_next_request(self):
        store = FakeStore()
        mw = _middleware(Probe(), store)
        await _run(mw, user=_user(_claims()))
        probe = Probe()
        await _run(_middleware(probe, FakeStore({(TENANT, OID_A): SECRET_TOKEN})), "/healthz")
        assert probe.seen["message"] == "Canvas token required for HTTP request"
