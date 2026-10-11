"""The whole self-hosted stack in local mode with Google, GitHub, a generic OIDC provider and Entra.

Composes the authorization-server stack of ``tests/selfhost/authz`` with the offline provider
fakes of ``fake_idp``: the server's own outbound requests (discovery, JWKS, token, userinfo, the
GitHub API) land in handlers, the clock is the stack's shared clock, and a scripted
:class:`Person` plays the browser.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from ..authz.stack import (
    BASE,
    ORIGIN,
    Browser,
    Clock,
    Landed,
    Stack,
    User,
    local_stack,
    pkce,
)
from .fake_idp import (
    FakeGitHub,
    FakeNetwork,
    FakeOidcIdp,
    GitHubUser,
    IdpUser,
    google_idp,
)

SCHOOL_ISSUER = "https://idp.example.edu/realms/school"
ALL = "entra,google,github,oidc:school"

#: Open admission with the public-provider acknowledgement: every provider's person gets in.
OPEN_POLICY = {"ACCESS_POLICY": "open", "ACCESS_OPEN_ACKNOWLEDGE_PUBLIC": "true"}


@dataclass
class ProviderStack:
    stack: Stack
    net: FakeNetwork
    google: FakeOidcIdp
    github: FakeGitHub
    school: FakeOidcIdp
    people: list[Person] = field(default_factory=list)

    @property
    def store(self) -> Any:
        return self.stack.store

    @property
    def clock(self) -> Clock:
        return self.stack.clock

    def person(self, *, fresh_client: bool = True) -> Person:
        person = Person(self, self.stack.new_client() if fresh_client else self.stack.client)
        self.people.append(person)
        return person

    def enroll_canvas(self, key: str) -> str:
        """Give an account a Canvas token (the tool call of the stack needs one) and return the key."""
        from ..authz.stack import CANVAS_HOST

        self.store.put(
            principal_key=key, api_token="canvas-pat-" + key[-12:] + "-0123456789abcdef",
            canvas_user_id="1", canvas_user_name="Someone", canvas_host=CANVAS_HOST,
        )
        return key

    def account_of(self, provider_id: str, issuer: str, subject: str) -> str | None:
        key = self.store.lookup_identity(provider_id, issuer, subject)
        return None if key is None else str(key)


class Person:
    """A browser: its own cookie jar, and the steps of signing in with each provider."""

    def __init__(self, ps: ProviderStack, client: Any) -> None:
        self.ps = ps
        self.client = client
        self.last: httpx.Response | None = None

    def get(self, url: str, **kw: Any) -> httpx.Response:
        self.last = self.client.get(url, **kw)
        return self.last

    def post(self, path: str, data: Mapping[str, str], **headers: str) -> httpx.Response:
        self.last = self.client.post(path, data=dict(data), headers={**ORIGIN, **headers})
        return self.last

    def csrf(self) -> str:
        """The CSRF token of the legacy pages (read from the sign-in methods page)."""
        page = self.get("/account/sign-in-methods")
        assert page.status_code == 200, page.text
        import re

        match = re.search(r'name="csrf" value="([^"]+)"', page.text)
        assert match, page.text[:300]
        return match.group(1)

    # -- starting and finishing a sign-in ----------------------------------------------------

    def start(self, provider: str, **params: str) -> httpx.Response:
        path = {
            "google": "/auth/login/google",
            "github": "/auth/login/github",
            "school": "/auth/login/oidc/school",
            "entra": "/auth/login/entra",
        }[provider]
        return self.get(path, params=params)

    def callback_url(self, provider: str, start: httpx.Response, **options: Any) -> str:
        """The callback URL the provider redirects to, given the server's redirect to it."""
        assert start.status_code == 302, (start.status_code, start.text[:300])
        location = start.headers["location"]
        if provider == "google":
            return self.ps.google.authorize(location, **options)
        if provider == "school":
            return self.ps.school.authorize(location, **options)
        if provider == "github":
            return self.ps.github.authorize(location, **options)
        raise AssertionError(provider)

    def sign_in(self, provider: str, *, user: Any = None, **params: str) -> httpx.Response:
        """Run a whole sign-in with ``provider`` and return the callback response."""
        if provider == "google" and user is not None:
            self.ps.google.user = user
        if provider == "school" and user is not None:
            self.ps.school.user = user
        if provider == "github" and user is not None:
            self.ps.github.user = user
        start = self.start(provider, **params)
        return self.get(self.callback_url(provider, start))

    def sign_in_entra(self, user: User, **claims: Any) -> httpx.Response:
        browser = Browser(self.ps.stack, client=self.client)
        login = browser.get("/auth/login/entra")
        return browser.entra_login(user, login, **claims)

    # -- linking ---------------------------------------------------------------------------------

    def post_link(self, provider: str, *, csrf: str | None = None, **headers: str) -> httpx.Response:
        """POST /account/identities/link (the page's form)."""
        provider_id = "oidc:school" if provider == "school" else provider
        return self.post(
            "/account/identities/link",
            {"csrf": self.csrf() if csrf is None else csrf, "provider": provider_id},
            **headers,
        )

    @staticmethod
    def meta_url(page: httpx.Response) -> str:
        import html
        import re

        match = re.search(r'<meta http-equiv="refresh" content="0;url=([^"]+)"', page.text)
        assert match, page.text[:400]
        return html.unescape(match.group(1))

    def finish_link(
        self, provider: str, page: httpx.Response, *, user: Any = None, **options: Any
    ) -> httpx.Response:
        """Play the provider's part of a link started by ``post_link`` and return the callback response."""
        assert page.status_code == 200, (page.status_code, page.text[:300])
        url = self.meta_url(page)
        if provider == "entra":
            nonce = query_of(url)["nonce"]
            self.ps.stack.idp.set_user(user, nonce)
            return self.get(
                "/auth/callback/entra", params={"code": "entra-code", "state": query_of(url)["state"]}
            )
        if user is not None:
            self.set_user(provider, user)
        idp = {"google": self.ps.google, "github": self.ps.github, "school": self.ps.school}[provider]
        return self.get(idp.authorize(url, **options))

    def link(self, provider: str, *, user: Any = None, **options: Any) -> httpx.Response:
        return self.finish_link(provider, self.post_link(provider), user=user, **options)

    def identities(self) -> list[Any]:
        return list(self.ps.store.list_identities(self.account()))

    def account(self) -> str:
        """The account key of the browser's session (from the signed-in account page's data)."""
        cookie = self.client.cookies.get("__Host-cmcp_session")
        assert cookie, "not signed in"
        return self._account_from_session(cookie)

    def _account_from_session(self, cookie: str) -> str:
        from canvas_mcp.core.selfhost.account_core import SESSION_COOKIE, _CookieCodec

        codec = _CookieCodec(self.ps.stack.settings.account_session_secret)
        payload = codec.unseal(SESSION_COOKIE, cookie)
        assert payload is not None
        return str(payload["acct"])

    # -- connecting an app (the P6 authorization server) ---------------------------------------

    def begin_connect(self) -> tuple[str, str, str]:
        """Start an app's authorization request: ``(client id, pkce verifier, login url with txn)``."""
        stack = self.ps.stack
        client_id = stack.register()
        verifier, challenge = pkce()
        response = Browser(stack, client=self.client).start(stack.authorize_params(client_id, challenge))
        assert response.status_code in (302, 303), response.text
        parts = urlsplit(response.headers["location"])
        location = parts.path + "?" + parts.query
        assert location.startswith("/auth/login?txn="), location
        return client_id, verifier, location

    def connect(
        self, provider: str, *, user: Any = None, decision: str = "approve", reauth: bool = False
    ) -> tuple[Landed, str, str]:
        """Authorize an app by signing in with ``provider``. Returns (landing, client id, verifier)."""
        client_id, verifier, login = self.begin_connect()
        txn = query_of(login)["txn"]
        browser = Browser(self.ps.stack, client=self.client)
        params = {"txn": txn, **({"reauth": "1"} if reauth else {})}
        if provider == "entra":
            assert user is not None
            chooser = self.get("/auth/login/entra", params=params)
            callback = chooser if chooser.status_code == 303 else browser.entra_login(user, chooser)
        else:
            if user is not None:
                self.set_user(provider, user)
            start = self.start(provider, **params)
            if start.status_code == 303:  # already signed in: straight to the consent page
                callback = start
            elif start.status_code != 302:
                return Landed(str(start.request.url), {}, start), client_id, verifier
            else:
                callback = self.get(self.callback_url(provider, start))
        if callback.status_code != 303:
            return Landed(str(callback.request.url), {}, callback), client_id, verifier
        page = self.get(callback.headers["location"])
        if page.status_code != 200 or 'name="decision"' not in page.text:
            return Landed(str(page.request.url), {}, page), client_id, verifier
        done = browser.decide(page, decision)
        assert done.status_code == 303, done.text
        target = done.headers["location"]
        return Landed(target, query_of(target), done), client_id, verifier

    def set_user(self, provider: str, user: Any) -> None:
        if provider == "google":
            self.ps.google.user = user
        elif provider == "school":
            self.ps.school.user = user
        elif provider == "github":
            self.ps.github.user = user

    def tokens(self, landed: Landed, client_id: str, verifier: str) -> dict[str, Any]:
        from ..authz.stack import AUDIENCE, CLAUDE_REDIRECT

        response = self.ps.stack.token(
            grant_type="authorization_code", code=landed.query["code"], client_id=client_id,
            redirect_uri=CLAUDE_REDIRECT, code_verifier=verifier, resource=AUDIENCE,
        )
        assert response.status_code == 200, response.text
        return dict(response.json())

    # -- what the browser holds -------------------------------------------------------------------

    def signed_in(self) -> bool:
        return "__Host-cmcp_session" in self.client.cookies

    def session_account(self) -> str | None:
        """The account key of the current session, read through the signed-in account page."""
        response = self.get("/account/sign-in-methods")
        return None if response.status_code != 200 else "ok"


@contextmanager
def provider_stack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    providers: str = ALL,
    env: Mapping[str, str] | None = None,
    policy: Mapping[str, str] | None = None,
    entra: bool = True,
    **stack_kw: Any,
) -> Iterator[ProviderStack]:
    net = FakeNetwork()
    google = google_idp(net)
    github = FakeGitHub(net)
    school = FakeOidcIdp(net, SCHOOL_ISSUER)
    options: dict[str, str] = {
        "SELFHOST_LOGIN_PROVIDERS": providers,
        "GOOGLE_CLIENT_ID": google.client_id,
        "GOOGLE_CLIENT_SECRET": google.client_secret,
        "GITHUB_CLIENT_ID": github.client_id,
        "GITHUB_CLIENT_SECRET": github.client_secret,
        "OIDC_SCHOOL_ISSUER": SCHOOL_ISSUER,
        "OIDC_SCHOOL_CLIENT_ID": school.client_id,
        "OIDC_SCHOOL_CLIENT_SECRET": school.client_secret,
        **(OPEN_POLICY if policy is None else dict(policy)),
        **dict(env or {}),
    }
    # Only the providers that are listed may have variables: drop the others.
    listed = {p.strip() for p in providers.split(",")}
    if "google" not in listed:
        options["GOOGLE_CLIENT_ID"] = options["GOOGLE_CLIENT_SECRET"] = ""
    if "github" not in listed:
        options["GITHUB_CLIENT_ID"] = options["GITHUB_CLIENT_SECRET"] = ""
    if "oidc:school" not in listed:
        for suffix in ("ISSUER", "CLIENT_ID", "CLIENT_SECRET"):
            options[f"OIDC_SCHOOL_{suffix}"] = ""
    if "entra" not in listed:
        for name in ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET"):
            options[name] = ""
        # Without Entra nobody becomes an owner through the provider: the operator promotes one.
        options.setdefault("SELFHOST_BOOTSTRAP_OWNER", "token_admin")
    with local_stack(
        tmp_path, monkeypatch, env=options, account_options={"login_transport": net.transport},
        **stack_kw,
    ) as stack:
        net.handlers.update(stack.idp.net.handlers)
        for idp in (google, school):
            idp.now = stack.clock
        yield ProviderStack(stack, net, google, github, school)


def query_of(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


def user_of(**kw: Any) -> IdpUser:
    return IdpUser(**kw)


__all__ = [
    "ALL",
    "BASE",
    "GitHubUser",
    "IdpUser",
    "OPEN_POLICY",
    "Person",
    "ProviderStack",
    "provider_stack",
    "query_of",
]
