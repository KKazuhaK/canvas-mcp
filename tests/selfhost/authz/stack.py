"""The whole self-hosted stack in ``SELFHOST_AUTH_MODE=local``, with a scripted browser.

Nothing on our side is stubbed: the real ``LocalAuthorizationServer``, the request-context
middleware, the credential gate, the /account pages (the sign-in and the consent page), the
encrypted token store and the edge guard all run. Only the outside parties are faked:

* Microsoft Entra ID: the id-token verifier returns the claims the test sets, and the code
  exchange is a mock transport (``FakeIdp``);
* the CIMD document host: ``FakeCimd`` is injected where production uses the SSRF-pinned fetcher
  (the real fetcher is exercised, offline, by its own tests);
* the clock: one settable ``Clock`` is shared by the store, the services and the pages.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import socket
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import fastmcp
import httpx
import httpx2
import pytest
import uvicorn
from dbbackend import stack_env
from fastmcp import FastMCP
from starlette.testclient import TestClient

from canvas_mcp.core.credentials import get_request_principal
from canvas_mcp.core.selfhost.app import (
    SelfhostRuntime,
    build_selfhost_asgi_app,
    install_selfhost,
    prepare_selfhost,
)
from canvas_mcp.core.selfhost.authz import fastmcp_compat as compat
from canvas_mcp.core.selfhost.authz.runtime import build_authz_runtime
from canvas_mcp.core.selfhost.oauth import build_auth_provider
from canvas_mcp.core.selfhost.settings import SelfhostSettings, load_selfhost_settings
from canvas_mcp.core.selfhost.token_store import Keyring

from ..conftest import CLIENT as ENTRA_CLIENT_ID
from ..conftest import TENANT as ENTRA_TENANT

BASE = "https://canvas.example.test"
ISSUER = BASE + "/"
AUDIENCE = BASE + "/mcp"
CANVAS_HOST = "canvas.example.edu"
CLAUDE_REDIRECT = "https://claude.ai/api/mcp/auth_callback"
SCOPE = "Canvas.Access"
ORIGIN = {"Origin": BASE}
SESSION_SECRET = base64.b64encode(bytes(range(32))).decode()
TOKEN_KEYS = "k1:" + base64.b64encode(bytes(range(32, 64))).decode()
LOOPBACK_REDIRECT = "http://127.0.0.1:39211/callback"


@dataclass(frozen=True)
class User:
    name: str
    oid: str
    roles: tuple[str, ...] = ("Canvas.User",)
    canvas_token: str = ""

    @property
    def upn(self) -> str:
        return f"{self.name.lower()}@example.test"


ALICE = User("Alice", "aaaaaaaa-0000-4000-8000-00000000000a", canvas_token="canvas-pat-alice-0123456789abcdef")
BOB = User("Bob", "bbbbbbbb-0000-4000-8000-00000000000b", canvas_token="canvas-pat-bob-0123456789abcdefgh")
OWNER = User(
    "Olive", "eeeeeeee-0000-4000-8000-00000000000e", roles=("Canvas.Owner",),
    canvas_token="canvas-pat-olive-0123456789abcdefg",
)


class Clock:
    """Wall clock with an offset: real time plus whatever the test advanced it by."""

    def __init__(self) -> None:
        self.offset = 0.0

    def __call__(self) -> float:
        return time.time() + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += seconds


class FakeIdp:
    """Entra as far as ``/account`` can see it: the claims of the id token, set by the test."""

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.claims: dict[str, Any] = {}
        self.token_requests = 0

    def set_user(self, user: User, nonce: str, **overrides: Any) -> None:
        now = int(self.clock())
        self.claims = {
            "tid": ENTRA_TENANT, "oid": user.oid, "name": user.name,
            "preferred_username": user.upn, "roles": list(user.roles), "nonce": nonce,
            "iat": now, "exp": now + 3600, "aud": ENTRA_CLIENT_ID,
        }
        if not user.roles:
            self.claims.pop("roles")
        self.claims.update(overrides)

    async def verify(self, _token: str) -> Mapping[str, Any] | None:
        return dict(self.claims)

    def factory(self) -> httpx.AsyncClient:
        def handler(request: httpx.Request) -> httpx.Response:
            self.token_requests += 1
            return httpx.Response(200, json={"id_token": "fake-id-token"})

        return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class FakeCimd:
    """Stands in for the SSRF-pinned fetcher: serves documents the test registers."""

    def __init__(self) -> None:
        self.documents: dict[str, tuple[bytes, dict[str, str]]] = {}
        self.errors: dict[str, Exception] = {}
        self.calls: list[str] = []
        self.delay: float = 0.0

    def serve(self, url: str, doc: Mapping[str, Any] | bytes, **headers: str) -> None:
        raw = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
        self.documents[url] = (raw, {"cache-control": "max-age=300", **{k.replace("_", "-"): v for k, v in headers.items()}})
        self.errors.pop(url, None)

    def fail(self, url: str, error: Exception) -> None:
        self.errors[url] = error

    async def __call__(self, url: str, timeout_s: float) -> compat.FetchedDocument:
        import asyncio

        self.calls.append(url)
        if self.delay:
            await asyncio.sleep(self.delay)
        if url in self.errors:
            raise self.errors[url]
        if url not in self.documents:
            raise compat.MetadataFetchError(compat.FETCH_HTTP_STATUS)
        raw, headers = self.documents[url]
        return compat.FetchedDocument(200, headers, raw)


def cimd_document(url: str, **overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "client_id": url,
        "client_name": "Test CIMD client",
        "redirect_uris": [CLAUDE_REDIRECT],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    doc.update(overrides)
    return doc


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


@dataclass
class Stack:
    client: Any  # a TestClient (in process) or an httpx2.Client (served by uvicorn)
    runtime: SelfhostRuntime
    settings: SelfhostSettings
    mcp: FastMCP
    idp: FakeIdp
    cimd: FakeCimd
    clock: Clock
    tmp_path: Path
    enrolled: dict[str, str] = field(default_factory=dict)
    #: Builds another client with its own cookie jar (another browser) for the same app.
    new_client: Callable[[], Any] = field(default=lambda: None)

    # -- accounts -------------------------------------------------------------------------

    @property
    def store(self) -> Any:
        return self.runtime.store

    @property
    def react(self) -> bool:
        """Whether the account UI is the single-page app (consent through the JSON API)."""
        return bool(self.settings.account_ui == "react")

    @property
    def authz(self) -> Any:
        assert self.runtime.authz is not None
        return self.runtime.authz

    def account_of(self, user: User) -> str:
        key = self.store.resolve_legacy_key(f"entra:{ENTRA_TENANT}:{user.oid}".lower())
        assert key is not None, "the user has no account yet"
        return str(key)

    def enroll(self, user: User) -> str:
        """Give ``user`` an account (via the real sign-in) and a Canvas token; returns the account key."""
        browser = Browser(self)
        browser.sign_in(user)
        key = self.account_of(user)
        self.store.put(
            principal_key=key, api_token=user.canvas_token, canvas_user_id="1",
            canvas_user_name=user.name, canvas_host=CANVAS_HOST,
        )
        return key

    # -- OAuth helpers ------------------------------------------------------------------------

    def register(self, *redirect_uris: str, **extra: Any) -> str:
        body = {
            "client_name": "Test app",
            "redirect_uris": list(redirect_uris or (CLAUDE_REDIRECT,)),
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            **extra,
        }
        response = self.client.post("/register", json=body)
        assert response.status_code == 201, response.text
        return str(response.json()["client_id"])

    def authorize_params(
        self, client_id: str, challenge: str, *, redirect_uri: str = CLAUDE_REDIRECT,
        state: str | None = "state-1", **overrides: str | None,
    ) -> dict[str, str]:
        params: dict[str, str | None] = {
            "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
            "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
            "scope": SCOPE, "resource": AUDIENCE, **overrides,
        }
        return {k: v for k, v in params.items() if v is not None}

    def token(self, **form: str) -> httpx.Response:
        return self.client.post("/token", data=form)

    def code_for(
        self, user: User, *, client_id: str | None = None, browser: Browser | None = None,
        redirect_uri: str = CLAUDE_REDIRECT, **overrides: str | None,
    ) -> tuple[str, str, str, Browser]:
        """Run the browser part for ``user``. Returns (client id, verifier, code, browser)."""
        client_id = client_id or self.register(redirect_uri)
        verifier, challenge = pkce()
        browser = browser or Browser(self, react=self.react)
        result = browser.connect(
            self.authorize_params(client_id, challenge, redirect_uri=redirect_uri, **overrides), user
        )
        assert "code" in result.query, result
        return client_id, verifier, result.query["code"], browser

    def tokens_for(self, user: User, **kw: Any) -> tuple[str, dict[str, Any]]:
        client_id, verifier, code, _ = self.code_for(user, **kw)
        response = self.token(
            grant_type="authorization_code", code=code, client_id=client_id,
            redirect_uri=kw.get("redirect_uri", CLAUDE_REDIRECT), code_verifier=verifier, resource=AUDIENCE,
        )
        assert response.status_code == 200, response.text
        return client_id, response.json()

    def refresh(self, client_id: str, refresh_token: str, **extra: str) -> httpx.Response:
        return self.token(grant_type="refresh_token", refresh_token=refresh_token, client_id=client_id, **extra)

    # -- MCP ------------------------------------------------------------------------------------

    def rpc(self, bearer: str | None, method: str, params: dict[str, Any] | None = None) -> httpx.Response:
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        return self.client.post("/mcp", json=body, headers=headers)

    def mcp_status(self, bearer: str | None) -> int:
        return self.rpc(bearer, "tools/list").status_code

    def whoami(self, bearer: str) -> str:
        response = self.rpc(bearer, "tools/call", {"name": "list_courses", "arguments": {}})
        assert response.status_code == 200, response.text
        text = response.text
        if response.headers["content-type"].startswith("text/event-stream"):
            text = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")][-1]
        payload = json.loads(text)
        assert "error" not in payload, payload
        result = payload["result"]
        assert not result.get("isError"), result
        return str("".join(block.get("text", "") for block in result["content"]))


@dataclass
class Landed:
    """Where the browser ended up: the app's redirect URI (query parsed) or an error response."""

    url: str
    query: dict[str, str]
    response: httpx.Response | None = None


class Browser:
    """A scripted user agent (own cookie jar) that follows /authorize through sign-in and consent."""

    def __init__(self, stack: Stack, *, client: Any = None, react: bool = False) -> None:
        self.stack = stack
        self.client = client or stack.new_client()
        #: Decide on a request through the single-page UI's JSON API (``ACCOUNT_UI=react``)
        #: instead of the server-rendered consent page.
        self.react = react
        self.trail: list[str] = []

    def get(self, url: str, **kw: Any) -> httpx.Response:
        response = self.client.get(url, **kw)
        self.trail.append(f"{response.status_code} {urlsplit(str(response.request.url)).path}")
        return response

    # -- /account sign-in -----------------------------------------------------------------------

    def entra_login(self, user: User, response: httpx.Response, **claim_overrides: Any) -> httpx.Response:
        """Given the redirect to Entra, 'sign in' as ``user`` and return the callback response."""
        assert response.status_code == 302, response.text
        location = urlsplit(response.headers["location"])
        assert location.netloc == "login.microsoftonline.com", location
        query = {k: v[0] for k, v in parse_qs(location.query).items()}
        self.stack.idp.set_user(user, query["nonce"], **claim_overrides)
        return self.get("/account/callback", params={"code": "entra-code", "state": query["state"]})

    def sign_in(self, user: User, **claim_overrides: Any) -> httpx.Response:
        login = self.get("/account/login")
        return self.entra_login(user, login, **claim_overrides)

    # -- the app's request ------------------------------------------------------------------------

    def start(self, params: Mapping[str, str]) -> httpx.Response:
        return self.get("/authorize", params=dict(params))

    def consent_form(self, page: httpx.Response) -> tuple[str, str]:
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)
        txn = re.search(r'name="txn" value="([^"]+)"', page.text)
        assert csrf and txn, page.text[:500]
        return csrf.group(1), txn.group(1)

    def decide(self, page: httpx.Response, decision: str = "approve", **headers: str) -> httpx.Response:
        csrf, txn = self.consent_form(page)
        return self.client.post(
            "/account/consent", data={"csrf": csrf, "txn": txn, "decision": decision},
            headers={**ORIGIN, **headers},
        )

    # -- the single-page UI's JSON API ----------------------------------------------------------

    def api(
        self, method: str, path: str, *, body: Any = None, csrf: str | None = None, **headers: str
    ) -> httpx.Response:
        """A call to ``/account/api`` as the page makes it (cookie jar, Origin and CSRF header)."""
        sent = {"Origin": BASE, "Sec-Fetch-Site": "same-origin", **headers}
        if csrf is not None:
            sent["X-CSRF-Token"] = csrf
        response = self.client.request(method, "/account/api" + path, json=body, headers=sent)
        self.trail.append(f"{response.status_code} api {method} {path.split('/')[1] if '/' in path else path}")
        return response

    def csrf_token(self) -> str:
        me = self.api("GET", "/me")
        assert me.status_code == 200, me.text
        return str(me.json()["csrf_token"])

    def decide_api(self, location: str, decision: str = "approve") -> Landed:
        """What the consent screen does: read the request, decide, return where the browser goes."""
        txn = query_of(location)["txn"]
        csrf = self.csrf_token()
        shown = self.api("GET", f"/consent/{txn}")
        assert shown.status_code == 200, shown.text
        done = self.api("POST", f"/consent/{txn}", body={"decision": decision}, csrf=csrf)
        assert done.status_code == 200, done.text
        target = str(done.json()["redirect_to"])
        return Landed(target, query_of(target))

    def connect(self, params: Mapping[str, str], user: User, *, decision: str = "approve") -> Landed:
        """/authorize, sign in if needed, decide on the consent page; stop at the app's redirect."""
        response = self.start(params)
        for _ in range(8):
            if response.status_code in (301, 302, 303):
                location = urljoin(str(response.request.url), response.headers["location"])
                if not location.startswith(BASE):
                    split = urlsplit(location)
                    query = {k: v[0] for k, v in parse_qs(split.query).items()}
                    return Landed(location, query, response)
                path = urlsplit(location).path
                if path == "/account/consent" and self.react:
                    return self.decide_api(location, decision)
                if path == "/account/login":
                    response = self.get(location)
                    if response.status_code == 302 and "login.microsoftonline.com" in response.headers["location"]:
                        response = self.entra_login(user, response)
                    continue
                response = self.get(location)
                continue
            if response.status_code == 200 and "/account/consent" in response.text and 'name="decision"' in response.text:
                response = self.decide(response, decision)
                continue
            return Landed(str(response.request.url), {}, response)
        raise AssertionError("too many redirects: " + " > ".join(self.trail))


def default_env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    env = {
        "PUBLIC_BASE_URL": BASE,
        "ENTRA_TENANT_ID": ENTRA_TENANT,
        "ENTRA_CLIENT_ID": ENTRA_CLIENT_ID,
        "ENTRA_CLIENT_SECRET": "entra-client-secret-0123456789",
        "OAUTH_JWT_SIGNING_KEY": "jwt-signing-key-" + "z" * 40,
        "ACCOUNT_SESSION_SECRET": SESSION_SECRET,
        "CANVAS_TOKEN_KEYS": TOKEN_KEYS,
        "FASTMCP_HOME": str(tmp_path / "fastmcp"),
        "SELFHOST_DATA_DIR": str(tmp_path / "data"),
        "SELFHOST_AUTH_MODE": "local",
        **stack_env(),
    }
    env.update(overrides)
    return env


def _build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    env: Mapping[str, str] | None,
    clock: Clock | None,
    tools: bool,
) -> tuple[Any, Stack]:
    """The app and a Stack around it (without a client yet)."""
    monkeypatch.setattr(fastmcp.settings, "test_mode", True)
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path / "fastmcp")
    monkeypatch.setenv("CANVAS_API_URL", f"https://{CANVAS_HOST}")
    for name in ("CANVAS_API_TOKEN", "CANVAS_ROLE", "MCP_ACCESS_KEYS"):
        monkeypatch.delenv(name, raising=False)
    from canvas_mcp.core.config import reset_config

    reset_config()
    clock = clock or Clock()
    settings = load_selfhost_settings(default_env(tmp_path, **dict(env or {})))
    cimd = FakeCimd()
    idp = FakeIdp(clock)
    runtime = prepare_selfhost(settings)
    # The same runtime, but with the test clock and the fake CIMD host.
    from dataclasses import replace

    if settings.authz_mode == "local":
        authz = build_authz_runtime(
            settings, runtime.store, Keyring.parse(settings.canvas_token_keys_raw), runtime.access,
            clock=clock, fetch=cimd,
        )
        runtime = replace(runtime, authz=authz)
    config: Any = SimpleNamespace(canvas_api_url=f"https://{CANVAS_HOST}/api/v1")
    mcp = FastMCP("local-authz", auth=build_auth_provider(settings, runtime))
    if tools:
        # A read tool by name, so the credential gate treats it like one.
        @mcp.tool(name="list_courses")
        def whoami() -> str:
            """The account key of the caller."""
            principal = get_request_principal()
            return principal.key if principal is not None else "anonymous"

    install_selfhost(
        mcp, runtime, config,
        id_token_verifier=idp.verify, http_client_factory=idp.factory, clock=clock,
    )
    app = build_selfhost_asgi_app(mcp, runtime, config)
    return app, Stack(None, runtime, settings, mcp, idp, cimd, clock, tmp_path)


@contextmanager
def local_stack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    env: Mapping[str, str] | None = None,
    clock: Clock | None = None,
    tools: bool = True,
) -> Iterator[Stack]:
    """Start the app in local mode and yield the stack (a context manager: it stops the app)."""
    app, stack = _build(tmp_path, monkeypatch, env, clock, tools)
    with TestClient(app, base_url=BASE, follow_redirects=False) as client:
        stack.client = client
        stack.new_client = lambda: TestClient(app, base_url=BASE, follow_redirects=False)
        yield stack


# -- served over real HTTP -----------------------------------------------------------------------


def _free_socket() -> socket.socket:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    return sock


class Runner:
    """uvicorn in a thread, on a socket we own, with the lifespan on."""

    def __init__(self, app: Any, sock: socket.socket) -> None:
        self.server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="on"))
        self.sock = sock
        self.thread = threading.Thread(target=lambda: self.server.run(sockets=[sock]), daemon=True)

    def start(self) -> None:
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("uvicorn did not start")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


def _rewrite(url: httpx2.URL, port: int) -> httpx2.URL:
    if url.host == "canvas.example.test":
        return url.copy_with(scheme="http", host="127.0.0.1", port=port)
    return url


class RewriteTransport(httpx2.HTTPTransport):
    """Sends https://canvas.example.test to the local server, keeping the Host header (and the cookie jar's view)."""

    def __init__(self, port: int) -> None:
        super().__init__()
        self.port = port

    def handle_request(self, request: httpx2.Request) -> httpx2.Response:
        forwarded = httpx2.Request(
            request.method, _rewrite(request.url, self.port), headers=request.headers,
            stream=request.stream, extensions=request.extensions,
        )
        return super().handle_request(forwarded)


class AsyncRewriteTransport(httpx2.AsyncHTTPTransport):
    def __init__(self, port: int) -> None:
        super().__init__()
        self.port = port

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        forwarded = httpx2.Request(
            request.method, _rewrite(request.url, self.port), headers=request.headers,
            stream=request.stream, extensions=request.extensions,
        )
        return await super().handle_async_request(forwarded)


@dataclass
class Served:
    stack: Stack
    port: int

    def async_transport(self) -> AsyncRewriteTransport:
        return AsyncRewriteTransport(self.port)


@contextmanager
def served_stack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    env: Mapping[str, str] | None = None,
    clock: Clock | None = None,
) -> Iterator[Served]:
    """The same app served by uvicorn; clients reach it as https://canvas.example.test."""
    app, stack = _build(tmp_path, monkeypatch, env, clock, True)
    sock = _free_socket()
    port = sock.getsockname()[1]
    runner = Runner(app, sock)
    runner.start()

    def new_client() -> httpx2.Client:
        return httpx2.Client(
            transport=RewriteTransport(port), base_url=BASE, follow_redirects=False, timeout=20
        )

    stack.new_client = new_client
    stack.client = new_client()
    try:
        yield Served(stack, port)
    finally:
        stack.client.close()
        runner.stop()


def query_of(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


def with_query(path: str, **params: str) -> str:
    return f"{path}?{urlencode(params)}"

