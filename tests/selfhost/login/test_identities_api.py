"""The sign-in methods in the JSON API (``/account/api/me/identities`` and ``/admin/identities``).

They exist for a server with two or more sign-in providers (local mode). Everywhere else every
one of them answers ``not_found`` before any other check, so an Entra-only server is unchanged.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any

import httpx
import pytest

from canvas_mcp.core.selfhost import account_api
from canvas_mcp.core.selfhost import account_web as web

from ..authz.stack import ALICE, BOB, OWNER, Browser, User
from ..test_account_api_parity import (
    LEGACY_TO_API,
    LINKING_LEGACY_TO_API,
    LOCAL_LEGACY_TO_API,
    READ_MODELS,
)
from ..test_account_spa import make_dist
from .fake_idp import IdpUser
from .stack_providers import ProviderStack, provider_stack, query_of
from .test_entra_only_golden import account_app

IDENTITY_KEYS = {
    "id", "provider_id", "username", "email", "email_verified", "linked_at", "last_login_at",
    "current", "can_unlink",
}
PREFIX = "https://github.com/login/oauth/authorize?"


@pytest.fixture
def ps(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    env = {"ACCOUNT_UI": "react", "ACCOUNT_WEB_DIST": str(make_dist(tmp_path / "dist"))}
    with provider_stack(tmp_path / "app", monkeypatch, env=env) as stack:
        yield stack


class Spa:
    """A browser that talks to the API the way the single-page app does."""

    def __init__(self, ps: ProviderStack, person: Any) -> None:
        self.ps = ps
        self.person = person
        self.browser = Browser(ps.stack, client=person.client, react=True)
        self._csrf: str | None = None

    @property
    def csrf(self) -> str:
        if self._csrf is None:
            self._csrf = self.browser.csrf_token()
        return self._csrf

    def get(self, path: str, **kw: Any) -> httpx.Response:
        return self.browser.api("GET", path, **kw)

    def send(self, method: str, path: str, *, body: Any = None, **kw: Any) -> httpx.Response:
        return self.browser.api(method, path, body=body, csrf=self.csrf, **kw)

    def identities(self) -> dict[str, Any]:
        response = self.get("/me/identities")
        assert response.status_code == 200, response.text
        return dict(response.json())

    def link(self, provider: str) -> httpx.Response:
        return self.send("POST", "/me/identities/link", body={"provider": provider})

    def complete(self, response: httpx.Response, provider: str = "github", **options: Any) -> httpx.Response:
        """Play the provider's part of a link the API started and return the callback response."""
        assert response.status_code == 200, response.text
        idp = {"github": self.ps.github, "google": self.ps.google, "oidc:school": self.ps.school}[provider]
        return self.person.get(idp.authorize(response.json()["redirect_to"], **options))


def alice(ps: ProviderStack) -> Spa:
    person = ps.person()
    assert person.sign_in_entra(ALICE).status_code == 303
    return Spa(ps, person)


def owner(ps: ProviderStack) -> Spa:
    person = ps.person()
    if ps.stack.settings.login_providers.order == ("entra",):
        # Entra alone keeps its single start path.
        browser = Browser(ps.stack, client=person.client, react=True)
        assert browser.entra_login(OWNER, browser.get("/account/login")).status_code == 303
    else:
        assert person.sign_in_entra(OWNER).status_code == 303
    return Spa(ps, person)


def code_of(response: httpx.Response, status: int) -> str:
    assert response.status_code == status, (response.status_code, response.text)
    return str(response.json()["error"]["code"])


# -- not served without linking --------------------------------------------------------------------


class TestAbsentWithoutLinking:
    PATHS = [
        ("GET", "/me/identities"),
        ("POST", "/me/identities/link"),
        ("DELETE", "/me/identities/12"),
        ("DELETE", "/admin/identities/12"),
    ]

    @pytest.mark.parametrize("mode", ["one_provider", "entra_only"])
    def test_every_route_is_not_found_before_anything_else(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, mode: str
    ) -> None:
        env = {"ACCOUNT_UI": "react", "ACCOUNT_WEB_DIST": str(make_dist(tmp_path / "dist"))}
        providers = "google" if mode == "one_provider" else "entra"
        with provider_stack(tmp_path / "app", monkeypatch, providers=providers, env=env) as ps:
            person = ps.person()
            if mode == "one_provider":
                person.sign_in("google")
                spa = Spa(ps, person)
            else:
                spa = owner(ps)
            me = spa.get("/me").json()
            assert me["features"]["identities"] is False
            for method, path in self.PATHS:
                signed_in = spa.send(method, path, body={"provider": "github"} if method == "POST" else None)
                assert code_of(signed_in, 404) == "not_found", (method, path)
            # Not even a session, a CSRF token or an Origin is asked for first.
            anonymous = ps.person()
            for method, path in self.PATHS:
                response = anonymous.client.request(method, "/account/api" + path)
                assert code_of(response, 404) == "not_found", (method, path)

    def test_the_admin_account_views_have_no_identities_key_with_entra_alone(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env = {"ACCOUNT_UI": "react", "ACCOUNT_WEB_DIST": str(make_dist(tmp_path / "dist"))}
        with provider_stack(tmp_path / "app", monkeypatch, providers="entra", env=env) as ps:
            admin = owner(ps)
            accounts = admin.get("/admin/accounts").json()["accounts"]
            assert accounts and all("identities" not in account for account in accounts)
            assert admin.get("/providers").json()["providers"] == [
                {"id": "entra", "kind": "oidc", "name": "Microsoft", "icon": "microsoft", "start_url": "/account/login"}
            ]


class TestRouteTables:
    def test_the_legacy_pages_and_the_api_of_a_multi_provider_server_list_the_same_routes(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with provider_stack(tmp_path / "app", monkeypatch) as ps:
            app = account_app(ps.stack)
            legacy = {(method, path) for path, handlers in app.route_table() for method in handlers}
            sign_in_halves = {
                ("GET", "/account/login/entra"),
                ("GET", "/account/login/google"),
                ("GET", "/account/callback/google"),
                ("GET", "/account/login/github"),
                ("GET", "/account/callback/github"),
                ("GET", "/account/login/oidc/school"),
                ("GET", "/account/callback/oidc/school"),
                ("GET", web.SIGN_IN_METHODS_PATH),  # read model: GET /me/identities
            }
            assert legacy == set(LEGACY_TO_API) | set(LOCAL_LEGACY_TO_API) | set(LINKING_LEGACY_TO_API) | sign_in_halves
            registered = account_api.ApiApp(app).route_keys()
            for targets in LINKING_LEGACY_TO_API.values():
                for target in targets:
                    assert target in registered, target
            assert ("GET", "/account/api/me/identities") in registered and ("GET", "/account/api/me/identities") in READ_MODELS

    def test_the_page_a_link_returns_to_is_the_single_page_app(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        for query in ("?linked=1", "?error=identity_in_use"):
            page = spa.person.get("/account/sign-in-methods" + query)
            assert page.status_code == 200 and 'id="root"' in page.text, query

    def test_the_react_ui_registers_the_two_halves_of_every_provider_and_nothing_of_linking(
        self, ps: ProviderStack
    ) -> None:
        paths = {getattr(r, "path", "") for r in ps.stack.mcp._additional_http_routes}
        assert {"/account/login", "/account/callback", "/account/login/entra", "/account/login/google",
                "/account/callback/google", "/account/login/github", "/account/callback/github",
                "/account/login/oidc/school", "/account/callback/oidc/school"} <= paths
        assert not {"/account/identities/link", "/account/identities/unlink", "/account/sign-in-methods"} & paths
        api = {p for p in paths if p.startswith("/account/api")}
        assert {"/account/api/me/identities", "/account/api/me/identities/link",
                "/account/api/me/identities/{id}", "/account/api/admin/identities/{id}"} <= api


# -- the list ---------------------------------------------------------------------------------------


class TestList:
    def test_features_and_providers_say_the_screen_exists(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        assert spa.get("/me").json()["features"]["identities"] is True
        providers = spa.get("/providers").json()["providers"]
        assert [p["id"] for p in providers] == ["entra", "google", "github", "oidc:school"]
        assert [p["kind"] for p in providers] == ["oidc", "oidc", "oauth2", "oidc"]
        assert [p["icon"] for p in providers] == ["microsoft", "google", "github", "key"]

    def test_the_list_has_the_current_method_and_what_can_still_be_linked(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        body = spa.identities()
        assert set(body) == {"identities", "linkable", "fresh", "fresh_window_s"}
        assert body["linkable"] == ["google", "github", "oidc:school"]
        assert body["fresh"] is True and body["fresh_window_s"] == 600
        (entra,) = body["identities"]
        assert set(entra) == IDENTITY_KEYS
        assert re.fullmatch(r"[1-9][0-9]{0,17}", entra["id"])
        assert entra["provider_id"] == "entra" and entra["current"] is True
        assert entra["can_unlink"] is False  # the only one
        assert entra["linked_at"].endswith("Z") and entra["email_verified"] is False

    def test_it_is_no_store_and_needs_a_session(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        response = spa.get("/me/identities")
        assert response.headers["cache-control"] == "no-store"
        anonymous = ps.person()
        assert code_of(anonymous.client.get("/account/api/me/identities"), 401) == "not_authenticated"

    def test_a_cross_site_read_is_refused(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        response = spa.get("/me/identities", **{"Sec-Fetch-Site": "cross-site"})
        assert code_of(response, 403) == "origin_not_allowed"

    def test_a_waiting_account_is_told_so(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        env = {"ACCOUNT_UI": "react", "ACCOUNT_WEB_DIST": str(make_dist(tmp_path / "dist"))}
        policy = {"ACCESS_POLICY": "approval", "ACCESS_OPEN_ACKNOWLEDGE_PUBLIC": "true"}
        with provider_stack(tmp_path / "app", monkeypatch, env=env, policy=policy) as ps:
            person = ps.person()
            person.sign_in("google")
            spa = Spa(ps, person)
            assert spa.get("/me").json()["features"]["identities"] is False
            assert code_of(spa.get("/me/identities"), 403) == "pending_approval"
            assert code_of(spa.link("github"), 403) == "pending_approval"

    def test_the_email_is_shown_for_display_only_and_only_when_verified_is_it_marked(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        assert spa.complete(spa.link("github")).headers["location"] == "/account/sign-in-methods?linked=1"
        by_provider = {i["provider_id"]: i for i in spa.identities()["identities"]}
        github = by_provider["github"]
        assert github["username"] == "octocat" and github["email"] == "octocat@example.test"
        assert github["email_verified"] is True
        assert by_provider["entra"]["email"] is None and by_provider["entra"]["email_verified"] is False


# -- linking ----------------------------------------------------------------------------------------


class TestLink:
    def test_a_link_returns_the_providers_page_and_the_ceremony_cookie(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        response = spa.link("github")
        assert response.status_code == 200 and set(response.json()) == {"redirect_to"}
        target = response.json()["redirect_to"]
        assert target.startswith(PREFIX)
        assert query_of(target)["prompt"] == "select_account"
        header = next(h for h in response.headers.get_list("set-cookie") if h.startswith("__Host-cmcp_flow="))
        assert "Secure" in header and "HttpOnly" in header and "Max-Age=600" in header
        assert response.headers["cache-control"] == "no-store"

    def test_the_whole_link_adds_a_method_that_signs_in_to_the_same_account(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        key = spa.person.account()
        landed = spa.complete(spa.link("github"))
        assert landed.status_code == 303 and landed.headers["location"] == "/account/sign-in-methods?linked=1"
        body = spa.identities()
        assert [i["provider_id"] for i in body["identities"]] == ["entra", "github"]
        assert all(i["can_unlink"] for i in body["identities"])
        assert body["linkable"] == ["google", "oidc:school"]
        other = ps.person()
        other.sign_in("github")
        assert other.account() == key
        history = spa.get("/me/login-history").json()["events"]
        assert "identity_linked" in [event["reason"] for event in history]

    @pytest.mark.parametrize("provider", ["google", "oidc:school"])
    def test_the_other_providers_link_too(self, ps: ProviderStack, provider: str) -> None:
        spa = alice(ps)
        landed = spa.complete(spa.link(provider), provider)
        assert landed.headers["location"] == "/account/sign-in-methods?linked=1"
        assert provider in [i["provider_id"] for i in spa.identities()["identities"]]

    def test_an_identity_of_another_account_is_refused_and_nothing_changes(self, ps: ProviderStack) -> None:
        theirs = ps.person()
        theirs.sign_in("github")
        spa = alice(ps)
        landed = spa.complete(spa.link("github"))
        assert landed.headers["location"] == "/account/sign-in-methods?error=identity_in_use"
        assert [i["provider_id"] for i in spa.identities()["identities"]] == ["entra"]
        assert [i.provider_id for i in ps.store.list_identities(theirs.account())] == ["github"]

    def test_a_provider_already_linked_is_refused_up_front(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        assert code_of(spa.link("entra"), 409) == "provider_already_linked"
        spa.complete(spa.link("github"))
        assert code_of(spa.link("github"), 409) == "provider_already_linked"

    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"provider": 5},
            {"provider": None},
            {"provider": ""},
            {"provider": "Google"},
            {"provider": "../x"},
            {"provider": "x" * 80},
            {"provider": "facebook"},
            {"provider": "google", "extra": 1},
        ],
    )
    def test_the_body_is_closed_and_the_provider_must_be_configured(self, ps: ProviderStack, body: Any) -> None:
        spa = alice(ps)
        response = spa.send("POST", "/me/identities/link", body=body)
        assert code_of(response, 422) == "validation_failed"
        assert "__Host-cmcp_flow" not in spa.person.client.cookies

    def test_csrf_origin_and_a_json_body_are_required(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        csrf = spa.csrf
        no_csrf = spa.browser.api("POST", "/me/identities/link", body={"provider": "github"})
        assert code_of(no_csrf, 403) == "csrf_invalid"
        wrong = spa.browser.api("POST", "/me/identities/link", body={"provider": "github"}, csrf="nope")
        assert code_of(wrong, 403) == "csrf_invalid"
        origin = spa.browser.api(
            "POST", "/me/identities/link", body={"provider": "github"}, csrf=csrf,
            Origin="https://evil.example",
        )
        assert origin.status_code == 403  # the edge guard answers a foreign Origin before the API does
        site = spa.browser.api(
            "POST", "/me/identities/link", body={"provider": "github"}, csrf=csrf,
            **{"Sec-Fetch-Site": "cross-site"},
        )
        assert site.status_code == 403
        form = spa.person.client.post(
            "/account/api/me/identities/link", data={"provider": "github"},
            headers={"Origin": "https://canvas.example.test", "X-CSRF-Token": csrf},
        )
        assert code_of(form, 415) == "unsupported_media_type"
        assert "__Host-cmcp_flow" not in spa.person.client.cookies

    def test_a_get_cannot_start_a_link(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        response = spa.get("/me/identities/link")
        assert code_of(response, 405) == "method_not_allowed"
        assert response.headers["allow"] == "POST"

    def test_a_stale_sign_in_must_sign_in_again(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        csrf = spa.csrf
        ps.clock.advance(601)
        response = spa.link("github")
        assert code_of(response, 403) == "reauth_required"
        assert response.json()["error"]["params"] == {"max_age_s": 600}
        assert spa.identities()["fresh"] is False
        assert csrf  # the session is still good for reading

    def test_starts_are_limited_per_account(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        statuses = [spa.link("oidc:school").status_code for _ in range(6)]
        assert statuses[:5] == [200] * 5 and statuses[5] == 429
        last = spa.link("oidc:school")
        assert last.json()["error"]["params"] == {"retry_after_s": 600}

    def test_a_provider_that_cannot_be_reached_is_unavailable_and_writes_nothing(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        ps.net.blocked.add("idp.example.edu")
        response = spa.link("oidc:school")
        assert code_of(response, 503) == "provider_unavailable"
        assert "idp.example.edu" not in response.text
        assert "__Host-cmcp_flow" not in spa.person.client.cookies

    def test_the_session_changing_in_between_ends_the_link(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        response = spa.link("github")
        spa.person.client.cookies.delete("__Host-cmcp_session")
        landed = spa.complete(response)
        assert landed.headers["location"] == "/account/sign-in-methods?error=link_session_ended"
        assert ps.account_of("github", "https://github.com", "583231") is None

    def test_the_rules_decide_what_may_be_attached(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from .fake_idp import GitHubUser

        env = {"ACCOUNT_UI": "react", "ACCOUNT_WEB_DIST": str(make_dist(tmp_path / "dist"))}
        policy = {"ACCESS_POLICY": "rules", "ACCESS_RULES": "entra:role:Canvas.User,github:user:583231"}
        with provider_stack(tmp_path / "app", monkeypatch, env=env, policy=policy) as ps:
            spa = alice(ps)
            ps.github.user = GitHubUser(id=999, login="stranger")
            landed = spa.complete(spa.link("github"))
            assert landed.headers["location"] == "/account/sign-in-methods?error=access_denied"
            assert len(spa.identities()["identities"]) == 1


# -- unlinking --------------------------------------------------------------------------------------


class TestUnlink:
    def linked(self, ps: ProviderStack) -> tuple[Spa, dict[str, str]]:
        spa = alice(ps)
        spa.complete(spa.link("github"))
        return spa, {i["provider_id"]: i["id"] for i in spa.identities()["identities"]}

    def test_removing_another_method_keeps_this_session_and_ends_the_other_browsers(self, ps: ProviderStack) -> None:
        spa, ids = self.linked(ps)
        other = ps.person()
        other.sign_in("github")
        other_spa = Spa(ps, other)
        assert other_spa.get("/me").status_code == 200
        response = spa.send("DELETE", f"/me/identities/{ids['github']}")
        assert response.status_code == 200 and response.json() == {"signed_out": False}
        assert any(h.startswith("__Host-cmcp_session=") and "Max-Age" in h for h in response.headers.get_list("set-cookie"))
        assert spa.get("/me").status_code == 200  # re-issued under the new epoch
        assert code_of(other_spa.get("/me"), 401) == "not_authenticated"
        assert [i["provider_id"] for i in spa.identities()["identities"]] == ["entra"]

    def test_removing_the_method_in_use_signs_the_caller_out(self, ps: ProviderStack) -> None:
        spa, ids = self.linked(ps)
        response = spa.send("DELETE", f"/me/identities/{ids['entra']}")
        assert response.status_code == 200 and response.json() == {"signed_out": True}
        assert code_of(spa.get("/me"), 401) == "not_authenticated"
        assert ps.account_of("entra", *self._entra_issuer_subject(ps)) is None

    @staticmethod
    def _entra_issuer_subject(ps: ProviderStack) -> tuple[str, str]:
        from canvas_mcp.core.selfhost import accounts as acc

        return f"{acc.ENTRA_ISSUER_PREFIX}{ps.stack.settings.tenant_id}/v2.0", ALICE.oid

    def test_the_last_method_cannot_be_removed(self, ps: ProviderStack) -> None:
        spa = alice(ps)
        (entra,) = spa.identities()["identities"]
        assert code_of(spa.send("DELETE", f"/me/identities/{entra['id']}"), 409) == "last_identity"
        assert len(spa.identities()["identities"]) == 1

    @pytest.mark.parametrize("raw", ["abc", "0", "01", "-1", "1.5", "9" * 25, "%20"])
    def test_a_malformed_id_is_refused(self, ps: ProviderStack, raw: str) -> None:
        spa, _ = self.linked(ps)
        assert code_of(spa.send("DELETE", f"/me/identities/{raw}"), 422) == "validation_failed"

    def test_an_unknown_id_and_someone_elses_id_are_not_found(self, ps: ProviderStack) -> None:
        spa, _ = self.linked(ps)
        bob = ps.person()
        bob.sign_in("google")
        theirs = ps.store.list_identities(bob.account())[0]
        assert code_of(spa.send("DELETE", "/me/identities/99999"), 404) == "not_found"
        assert code_of(spa.send("DELETE", f"/me/identities/{theirs.id}"), 404) == "not_found"
        assert len(ps.store.list_identities(bob.account())) == 1

    def test_it_needs_a_fresh_sign_in_csrf_and_an_empty_body(self, ps: ProviderStack) -> None:
        spa, ids = self.linked(ps)
        path = f"/me/identities/{ids['github']}"
        assert code_of(spa.browser.api("DELETE", path), 403) == "csrf_invalid"
        body = spa.browser.api("DELETE", path, body={"x": 1}, csrf=spa.csrf)
        assert code_of(body, 400) == "malformed_request"
        ps.clock.advance(601)
        stale = spa.send("DELETE", path)
        assert code_of(stale, 403) == "reauth_required"
        assert len(spa.identities()["identities"]) == 2

    def test_removals_are_limited_per_account(self, ps: ProviderStack) -> None:
        spa, _ = self.linked(ps)
        statuses = [spa.send("DELETE", "/me/identities/99999").status_code for _ in range(11)]
        assert statuses[:10] == [404] * 10 and statuses[10] == 429

    def test_an_unlinked_method_is_a_stranger_at_its_next_sign_in(self, ps: ProviderStack) -> None:
        spa, ids = self.linked(ps)
        key = spa.person.account()
        spa.send("DELETE", f"/me/identities/{ids['github']}")
        again = ps.person()
        again.sign_in("github")
        assert again.account() != key


# -- the owner's view -------------------------------------------------------------------------------


class TestAdmin:
    def seeded(self, ps: ProviderStack) -> tuple[Spa, Spa, str, dict[str, str]]:
        user = ps.person()
        user.sign_in("google")
        user_spa = Spa(ps, user)
        user_spa.complete(user_spa.link("github"))
        key = user.account()
        admin = owner(ps)
        ids = {i.provider_id: str(i.id) for i in ps.store.list_identities(key)}
        return admin, user_spa, key, ids

    def test_the_account_views_list_every_method_with_what_an_unlink_needs(self, ps: ProviderStack) -> None:
        admin, _, key, ids = self.seeded(ps)
        accounts = admin.get("/admin/accounts").json()["accounts"]
        mine = next(a for a in accounts if a["key"] == key)
        assert [i["provider_id"] for i in mine["identities"]] == ["google", "github"]
        google = mine["identities"][0]
        assert set(google) == {"id", "provider_id", "username", "subject", "issuer", "linked_at", "last_login_at", "can_unlink"}
        assert google["id"] == ids["google"] and google["issuer"] == "https://accounts.google.com"
        assert google["can_unlink"] is True and google["subject"]
        # The existing keys and the actions list are exactly what they were.
        assert {"identity", "enrollment", "actions"} <= set(mine)
        assert mine["identity"]["provider_id"] == "google"
        # An account with one method cannot lose it.
        alone = next(a for a in accounts if a["key"] == admin.person.account())
        assert [i["can_unlink"] for i in alone["identities"]] == [False]
        rows = admin.get("/admin/enrollments").json()["rows"]
        assert all("identities" in row for row in rows)

    def test_an_owner_unlinks_a_method_and_gets_the_account_back(self, ps: ProviderStack) -> None:
        admin, user_spa, key, ids = self.seeded(ps)
        response = admin.send("DELETE", f"/admin/identities/{ids['github']}")
        assert response.status_code == 200
        body = response.json()
        assert body["changed"] is True and body["account"]["key"] == key
        assert [i["provider_id"] for i in body["account"]["identities"]] == ["google"]
        assert body["account"]["identities"][0]["can_unlink"] is False
        assert code_of(user_spa.get("/me"), 401) == "not_authenticated"  # their sessions ended
        entry = [e for e in ps.store.list_audit(200) if e.action == "identity_unlinked"][0]
        assert entry.detail["by"] == "owner" and entry.target == key

    def test_the_last_method_of_an_account_stays(self, ps: ProviderStack) -> None:
        admin, _, _, ids = self.seeded(ps)
        admin.send("DELETE", f"/admin/identities/{ids['github']}")
        assert code_of(admin.send("DELETE", f"/admin/identities/{ids['google']}"), 409) == "last_identity"

    def test_an_unknown_or_malformed_id(self, ps: ProviderStack) -> None:
        admin, *_ = self.seeded(ps)
        assert code_of(admin.send("DELETE", "/admin/identities/999999"), 404) == "not_found"
        assert code_of(admin.send("DELETE", "/admin/identities/abc"), 422) == "validation_failed"

    def test_a_plain_user_is_forbidden_and_nothing_changes(self, ps: ProviderStack) -> None:
        _, user_spa, key, ids = self.seeded(ps)
        assert code_of(user_spa.send("DELETE", f"/admin/identities/{ids['github']}"), 403) == "forbidden"
        assert len(ps.store.list_identities(key)) == 2

    def test_a_stale_owner_must_sign_in_again(self, ps: ProviderStack) -> None:
        admin, _, key, ids = self.seeded(ps)
        csrf = admin.csrf
        ps.clock.advance(601)
        response = admin.send("DELETE", f"/admin/identities/{ids['github']}")
        assert code_of(response, 403) == "reauth_required" and csrf
        assert len(ps.store.list_identities(key)) == 2

    def test_an_owner_removing_their_own_current_method_is_signed_out(self, ps: ProviderStack) -> None:
        admin, *_ = self.seeded(ps)
        admin.complete(admin.link("oidc:school"), "oidc:school")
        mine = {i["provider_id"]: i["id"] for i in admin.identities()["identities"]}
        # The only owner, whose role comes from the Entra owner rule, keeps its Entra identity.
        refused = admin.send("DELETE", f"/admin/identities/{mine['entra']}")
        assert code_of(refused, 409) == "last_owner"
        assert admin.get("/me").status_code == 200
        # With a second active owner the first may let it go and is signed out.
        other = ps.person()
        assert other.sign_in_entra(User("Otto", "dddddddd-0000-4000-8000-00000000000d", roles=("Canvas.Owner",))).status_code == 303
        response = admin.send("DELETE", f"/admin/identities/{mine['entra']}")
        assert response.status_code == 200
        assert code_of(admin.get("/me"), 401) == "not_authenticated"

    def test_two_rules_owners_cannot_both_drop_their_entra_identity(self, ps: ProviderStack) -> None:
        # Both owner roles come from the Entra owner rule: once one of them has no Entra identity
        # left, the other is the only owner that can still get an owner session.
        first = owner(ps)
        first.complete(first.link("oidc:school"), "oidc:school")
        second_person = ps.person()
        otto = User("Otto", "dddddddd-0000-4000-8000-00000000000d", roles=("Canvas.Owner",))
        assert second_person.sign_in_entra(otto).status_code == 303
        second = Spa(ps, second_person)
        ps.school.user = IdpUser(sub="user-2", email="otto@example.edu", name="Otto", preferred_username="otto")
        second.complete(second.link("oidc:school"), "oidc:school")
        mine = {i["provider_id"]: i["id"] for i in first.identities()["identities"]}
        theirs = {i["provider_id"]: i["id"] for i in second.identities()["identities"]}
        assert ps.store.count_usable_owners(ps.stack.settings.login_providers.ids) == 2
        assert first.send("DELETE", f"/admin/identities/{mine['entra']}").status_code == 200
        refused = second.send("DELETE", f"/admin/identities/{theirs['entra']}")
        assert code_of(refused, 409) == "last_owner"
        assert second.get("/me").status_code == 200
        assert [i["provider_id"] for i in second.identities()["identities"]] == ["entra", "oidc:school"]
        assert ps.store.count_usable_owners(ps.stack.settings.login_providers.ids) == 1

    def test_the_view_needs_no_new_state_for_a_pending_row(self, ps: ProviderStack) -> None:
        # Bob signs in and is admitted by the open policy; the owner sees his single method.
        bob = ps.person()
        assert bob.sign_in_entra(BOB).status_code == 303
        admin = owner(ps)
        accounts = admin.get("/admin/accounts").json()["accounts"]
        row = next(a for a in accounts if a["key"] == bob.account())
        assert len(row["identities"]) == 1 and row["identities"][0]["can_unlink"] is False
