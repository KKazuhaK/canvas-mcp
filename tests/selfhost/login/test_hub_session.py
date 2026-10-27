"""Hub session trust, browser binding and existing-account preservation, offline."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from canvas_mcp.core.selfhost.accounts import parse_rule
from canvas_mcp.core.selfhost.login.config import HubConfig, parse_login_providers
from canvas_mcp.core.selfhost.login.http import SafeHttp
from canvas_mcp.core.selfhost.login.hub import (
    BRIDGE_COOKIE,
    BRIDGE_PATH,
    TICKET_KIND,
    HubLoginProvider,
)
from canvas_mcp.core.selfhost.login.protocol import SignInRejected
from canvas_mcp.core.selfhost.login.provider_config import (
    ProviderConfigurationError,
    validate_provider,
)
from canvas_mcp.core.selfhost.login_state import InMemoryLoginStateStore

from ..authz.stack import ALICE, BASE, Browser
from .stack_providers import Person, ProviderStack, provider_stack
from .test_linking_web import api

HUB = "https://hub.example.test"


class FakeHub:
    def __init__(self, clock: Any) -> None:
        self.clock = clock
        self.subject = "stable-user-a"
        self.username = "alice@example.test"
        self.expired = False
        self.allowed = True
        self.bad_subject = False
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        assert (
            request.headers["cookie"]
            == "__Secure-better-auth.session_token=hub-session"
        )
        assert "authorization" not in request.headers
        if request.url.path == "/api/auth/better/get-session":

            def stamp(delta: float) -> str:
                return datetime.fromtimestamp(self.clock() + delta, UTC).isoformat()

            return httpx.Response(
                200,
                json={
                    "session": {
                        "userId": "wrong" if self.bad_subject else self.subject,
                        "createdAt": stamp(-3600),
                        "expiresAt": stamp(-1 if self.expired else 3600),
                    },
                    "user": {
                        "id": self.subject,
                        "email": "same@example.test",
                        "emailVerified": True,
                    },
                },
            )
        assert request.url.path == "/api/better-auth/user"
        return httpx.Response(
            200 if self.allowed else 403,
            json={
                "success": True,
                "user": {"username": self.username, "isAdmin": True},
            },
        )


@pytest.fixture
def hub_stack(
    tmp_path: Any, monkeypatch: Any
) -> Iterator[tuple[ProviderStack, FakeHub]]:
    with provider_stack(
        tmp_path, monkeypatch, providers="entra,hub", env={"HUB_ORIGIN": HUB}
    ) as ps:
        hub = FakeHub(ps.clock)
        ps.net.add("hub.example.test", hub)
        yield ps, hub


def bridge_get(person: Person, start: httpx.Response) -> httpx.Response:
    assert start.status_code == 302, start.text
    person.client.cookies.set(
        "__Secure-better-auth.session_token",
        "hub-session",
        domain="hub.example.test",
        path="/",
    )
    return person.get(start.headers["location"])


def confirm(person: Person, page: httpx.Response, **headers: str) -> httpx.Response:
    assert page.status_code == 200, page.text
    csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', page.text)
    assert csrf
    return person.client.post(
        HUB + BRIDGE_PATH, data={"csrf": csrf[1]}, headers={"Origin": HUB, **headers}
    )


def login(person: Person) -> httpx.Response:
    page = bridge_get(person, person.get("/auth/login/hub"))
    authorized = confirm(person, page)
    assert authorized.status_code == 303, authorized.text
    return person.get(authorized.headers["location"])


def test_hub_login_manifest_and_two_accounts_stay_separate(hub_stack: Any) -> None:
    ps, hub = hub_stack
    inventory = ps.stack.client.get("/api/v1/providers").json()["providers"]
    assert [p["id"] for p in inventory] == ["entra", "hub"]
    alice = ps.person()
    assert login(alice).status_code == 303
    a = alice.account()
    assert api(alice, "GET", "/me").json()["account"]["provider_id"] == "hub"
    assert api(alice, "GET", "/me").json()["account"]["role"] == "user"
    hub.subject = "stable-user-b"
    bob = ps.person()
    assert login(bob).status_code == 303
    assert bob.account() != a
    assert ps.store.account_counts()["total"] == 2
    # A Hub username change retains the stable identity, including the account's data.
    hub.subject, hub.username = "stable-user-a", "renamed@example.test"
    again = ps.person()
    assert login(again).status_code == 303
    assert again.account() == a
    assert ps.store.account_counts()["total"] == 2


def test_existing_canvas_identity_is_linked_explicitly_and_keeps_tokens(
    hub_stack: Any,
) -> None:
    ps, hub = hub_stack
    person = ps.person()
    assert person.sign_in_entra(ALICE).status_code == 303
    account = person.account()
    ps.enroll_canvas(account)
    old = ps.store.get(account)
    started = person.post_link("hub")
    assert started.status_code == 200, started.text
    page = bridge_get(
        person, httpx.Response(302, headers={"location": started.json()["redirect_to"]})
    )
    response = person.get(confirm(person, page).headers["location"])
    assert "linked=1" in response.headers["location"], response.headers
    assert person.account() == account
    assert ps.account_of("hub", HUB, hub.subject) == account
    assert ps.store.get(account) == old
    assert ps.store.account_counts()["total"] == 1
    fresh = ps.person()
    assert login(fresh).status_code == 303
    assert fresh.account() == account


@pytest.mark.parametrize("failure", ["expired", "allowed", "bad_subject"])
def test_invalid_or_unadmitted_hub_session_changes_no_account(
    hub_stack: Any, failure: str
) -> None:
    ps, hub = hub_stack
    setattr(hub, failure, failure != "allowed")
    person = ps.person()
    page = bridge_get(person, person.get("/auth/login/hub"))
    assert page.status_code == 401
    assert ps.store.account_counts()["total"] == 0
    assert not person.client.cookies.get("__Host-cmcp_session")


def test_session_change_during_confirmation_is_refused(hub_stack: Any) -> None:
    ps, hub = hub_stack
    person = ps.person()
    page = bridge_get(person, person.get("/auth/login/hub"))
    hub.subject = "another-user"
    assert confirm(person, page).status_code == 403
    assert ps.store.account_counts()["total"] == 0


def test_bridge_requires_same_origin_confirmation_and_browser_flow(
    hub_stack: Any,
) -> None:
    ps, _ = hub_stack
    person = ps.person()
    page = bridge_get(person, person.get("/auth/login/hub"))
    assert confirm(person, page, Origin="https://evil.example").status_code == 403
    assert confirm(person, page, **{"Sec-Fetch-Site": "cross-site"}).status_code == 403
    authorized = confirm(person, page)
    callback = authorized.headers["location"]
    # A different browser cannot redeem the code, even knowing its URL.
    stranger = ps.person()
    failed = stranger.get(callback)
    assert "error=state_invalid" in failed.headers["location"]
    assert person.get(callback).status_code == 303
    assert person.client.cookies.get("__Host-cmcp_session")
    replay = person.get(callback)
    assert "error=state_invalid" in replay.headers["location"]
    assert confirm(person, page).status_code == 403
    assert ps.store.account_counts()["total"] == 1


def test_bridge_does_not_open_core_apis_on_hub_host_or_accept_canvas_host(
    hub_stack: Any,
) -> None:
    ps, _ = hub_stack
    client = ps.stack.client
    assert client.post(HUB + "/mcp").status_code == 401
    assert client.get(BASE + BRIDGE_PATH).status_code == 404
    assert (
        client.post(
            HUB + BRIDGE_PATH, headers={"Origin": "https://evil.example"}
        ).status_code
        == 403
    )
    assert client.get(HUB + BRIDGE_PATH).status_code == 400
    assert client.options(HUB + BRIDGE_PATH).status_code == 405


def test_bridge_hides_credentials_and_escapes_identity(hub_stack: Any) -> None:
    ps, hub = hub_stack
    hub.username = '<script>alert("x")</script>'
    person = ps.person()
    page = bridge_get(person, person.get("/auth/login/hub"))
    assert "<script>" not in page.text
    assert "&lt;script&gt;" in page.text
    assert "Connect Canvas MCP" in page.text
    assert "Sign in with MCPHub" in page.text
    assert "Your saved Canvas LMS connection is kept" in page.text
    assert "only for a first-time connection or when existing credentials expire" in page.text
    assert "hub-session" not in page.text
    assert page.headers["referrer-policy"] == "no-referrer"
    assert page.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert person.client.cookies.get(BRIDGE_COOKIE)


@pytest.mark.parametrize(
    "cookie",
    [
        "",
        "other=value",
        "better-auth.session_token=a; better-auth.session_token=b",
        "__Secure-better-auth.session_token=x; better-auth.session_token=y",
    ],
)
async def test_no_session_cookie_no_outbound_call(cookie: str) -> None:
    def reject(request: httpx.Request) -> httpx.Response:
        pytest.fail("No upstream call should be made")

    provider = HubLoginProvider(
        HubConfig(HUB),
        public_base_url=BASE,
        http=SafeHttp(transport=httpx.MockTransport(reject)),
        flow_store=InMemoryLoginStateStore(),
    )
    with pytest.raises(SignInRejected):
        await provider.verify_session(cookie)


async def test_ticket_requires_pkce_nonce_and_is_single_use() -> None:
    store = InMemoryLoginStateStore()
    provider = HubLoginProvider(
        HubConfig(HUB), public_base_url=BASE, http=SafeHttp(), flow_store=store
    )
    code = await store.put(
        TICKET_KIND,
        json.dumps(
            {
                "nonce": "nonce",
                "issuer": HUB,
                "subject": "stable-user",
                "username": "alice",
            }
        ).encode(),
        60,
        binding_hash=hashlib.sha256(b"verifier").hexdigest(),
    )
    with pytest.raises(SignInRejected):
        await provider.finish(code=code, code_verifier="other", nonce="nonce")
    claims = await provider.finish(code=code, code_verifier="verifier", nonce="nonce")
    assert claims.subject == "stable-user" and claims.email is None and not claims.roles
    with pytest.raises(SignInRejected):
        await provider.finish(code=code, code_verifier="verifier", nonce="nonce")


def test_hub_configuration_is_secretless_and_rejects_email_linking_fields() -> None:
    config = validate_provider("hub", {"origin": HUB}, None)
    assert config.issuer == HUB and config.client_secret is None
    for raw in [
        "http://hub.example.test",
        "https://127.0.0.1",
        HUB + "/path",
        HUB + "?x=1",
    ]:
        with pytest.raises(ProviderConfigurationError):
            validate_provider("hub", {"origin": raw}, None)
    problems: list[str] = []
    parsed = parse_login_providers(
        {"SELFHOST_LOGIN_PROVIDERS": "hub", "HUB_ORIGIN": HUB}, problems
    )
    assert not problems and parsed.hub == HubConfig(HUB)
    assert parse_rule("hub:any", providers={"hub"}).provider == "hub"
    assert isinstance(parse_rule("hub:email:a@example.test", providers={"hub"}), str)


def test_hub_login_continues_oauth_and_mcp_as_the_correct_account(
    hub_stack: Any,
) -> None:
    ps, hub = hub_stack
    subjects = []
    for subject in ("stable-user-a", "stable-user-b"):
        hub.subject = subject
        person = ps.person()
        client_id, verifier, authorize = person.begin_connect()
        txn = authorize.split("txn=")[1].split("&")[0]
        page = bridge_get(person, person.get("/auth/login/hub", params={"txn": txn}))
        callback = person.get(confirm(person, page).headers["location"])
        assert callback.headers["location"].startswith("/account/consent?txn=")
        landed = Browser(ps.stack, client=person.client).decide_api(
            callback.headers["location"], "approve"
        )
        tokens = person.tokens(landed, client_id, verifier)
        account = ps.account_of("hub", HUB, subject)
        ps.enroll_canvas(account)
        assert ps.stack.whoami(tokens["access_token"]) == account
        assert ps.stack.mcp_status(tokens["access_token"]) == 200
        foreign = ps.stack.client.post(
            BASE + "/mcp",
            headers={
                "Host": "hub.example.test",
                "Authorization": "Bearer " + tokens["access_token"],
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        assert foreign.status_code == 421, foreign.text
        subjects.append(account)
    assert subjects[0] != subjects[1]


def test_confirmation_expiry_creates_no_account(hub_stack: Any) -> None:
    ps, _ = hub_stack
    person = ps.person()
    page = bridge_get(person, person.get("/auth/login/hub"))
    ps.clock.advance(301)
    assert confirm(person, page).status_code == 403
    assert ps.store.account_counts()["total"] == 0


async def test_ticket_nonce_mismatch_and_expiry_fail_closed() -> None:
    now = [0.0]
    store = InMemoryLoginStateStore(clock=lambda: now[0])
    provider = HubLoginProvider(
        HubConfig(HUB), public_base_url=BASE, http=SafeHttp(), flow_store=store
    )
    payload = json.dumps(
        {
            "nonce": "correct",
            "issuer": HUB,
            "subject": "stable-user",
            "username": "alice",
        }
    ).encode()
    binding = hashlib.sha256(b"verifier").hexdigest()
    code = await store.put(TICKET_KIND, payload, 60, binding_hash=binding)
    with pytest.raises(SignInRejected):
        await provider.finish(code=code, code_verifier="verifier", nonce="wrong")
    code = await store.put(TICKET_KIND, payload, 60, binding_hash=binding)
    now[0] = 61
    with pytest.raises(SignInRejected):
        await provider.finish(code=code, code_verifier="verifier", nonce="correct")
