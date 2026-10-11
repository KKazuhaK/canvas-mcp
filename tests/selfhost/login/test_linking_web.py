"""Native API linking and unlinking, with real browser sessions and provider callbacks."""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
from dbbackend import raw_sql

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.token_store import OPERATOR

from ..authz.stack import ALICE, BOB, Browser
from .fake_idp import GitHubUser
from .stack_providers import Person, ProviderStack, provider_stack, query_of
from .test_identities_api import code_of

GITHUB = ("github", acc.GITHUB_ISSUER, "583231")
METHODS = "/account/sign-in-methods"


@pytest.fixture
def ps(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    with provider_stack(tmp_path, monkeypatch) as stack:
        yield stack


def alice(ps: ProviderStack) -> Person:
    """A browser signed in as Alice through Entra."""
    person = ps.person()
    assert person.sign_in_entra(ALICE).status_code == 303
    return person


def outcome(response: Any) -> dict[str, str]:
    assert response.status_code == 303, (response.status_code, response.text[:300])
    location = response.headers["location"]
    assert location.startswith(METHODS + "?"), location
    return query_of(location)


def api(
    person: Person,
    method: str,
    path: str,
    *,
    body: Any = None,
    csrf: bool | str | None = True,
    **headers: Any,
) -> Any:
    token = person.csrf() if csrf is True else csrf if isinstance(csrf, str) else None
    return Browser(person.ps.stack, client=person.client).api(
        method,
        path,
        body=body,
        csrf=token,
        **headers,
    )


def audit_actions(ps: ProviderStack) -> list[str]:
    return [e.action for e in ps.store.iter_audit()]


class TestLinkStart:
    def test_link_start_returns_the_redirect_and_sets_the_ceremony_cookie(
        self, ps: ProviderStack
    ) -> None:
        person = alice(ps)
        page = person.post_link("github")
        assert page.status_code == 200
        url = person.meta_url(page)
        assert url.startswith("https://github.com/login/oauth/authorize?")
        assert page.json() == {"redirect_to": url}
        assert page.headers["content-type"].startswith("application/json")
        header = next(
            h
            for h in page.headers.get_list("set-cookie")
            if h.startswith("__Host-cmcp_flow=")
        )
        assert "Secure" in header and "HttpOnly" in header and "Max-Age=600" in header
        assert page.headers["cache-control"] == "no-store"
        assert "<script" not in page.text

    def test_the_link_forces_the_provider_to_ask_again(self, ps: ProviderStack) -> None:
        person = alice(ps)
        person.link("school")
        assert ps.school.last_authorize["prompt"] == "login"
        person.link("github")
        assert ps.github.last_authorize["prompt"] == "select_account"

    def test_a_get_cannot_start_a_link(self, ps: ProviderStack) -> None:
        person = alice(ps)
        assert api(person, "GET", "/me/identities/link").status_code == 405
        identity = person.identities()[0].id
        assert api(person, "GET", f"/me/identities/{identity}").status_code == 405

    def test_csrf_origin_and_login_are_required(self, ps: ProviderStack) -> None:
        person = alice(ps)
        csrf = person.csrf()
        assert (
            code_of(
                api(
                    person,
                    "POST",
                    "/me/identities/link",
                    body={"provider": "github"},
                    csrf=None,
                ),
                403,
            )
            == "csrf_invalid"
        )
        assert (
            code_of(
                api(
                    person,
                    "POST",
                    "/me/identities/link",
                    body={"provider": "github"},
                    csrf="wrong",
                ),
                403,
            )
            == "csrf_invalid"
        )
        wrong_origin = api(
            person,
            "POST",
            "/me/identities/link",
            body={"provider": "github"},
            csrf=csrf,
            Origin="https://evil.example",
        )
        # The outer origin middleware refuses this before the JSON API runs.
        assert wrong_origin.status_code == 403
        anonymous = ps.person()
        assert (
            code_of(
                api(
                    anonymous,
                    "POST",
                    "/me/identities/link",
                    body={"provider": "github"},
                    csrf=csrf,
                ),
                401,
            )
            == "not_authenticated"
        )
        assert "__Host-cmcp_flow" not in anonymous.client.cookies

    def test_a_stale_sign_in_is_asked_to_sign_in_again(self, ps: ProviderStack) -> None:
        person = alice(ps)
        csrf = person.csrf()
        ps.clock.advance(601)
        response = person.post_link("github", csrf=csrf)
        assert code_of(response, 403) == "reauth_required"
        assert "__Host-cmcp_flow" not in person.client.cookies

    def test_a_provider_that_is_not_configured_or_already_linked_is_refused(
        self, ps: ProviderStack
    ) -> None:
        person = alice(ps)
        assert code_of(person.post_link("facebook"), 422) == "validation_failed"
        assert person.post_link("entra").status_code == 409  # Alice already has it
        assert outcome(person.link("github")) == {"linked": "1"}
        again = person.post_link("github")
        assert code_of(again, 409) == "provider_already_linked"

    def test_a_pending_account_may_not_link(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy = {"ACCESS_POLICY": "approval", "ACCESS_OPEN_ACKNOWLEDGE_PUBLIC": "true"}
        with provider_stack(tmp_path, monkeypatch, policy=policy) as ps:
            person = ps.person()
            person.sign_in("google")
            assert (
                code_of(api(person, "GET", "/me/identities"), 403) == "pending_approval"
            )
            assert code_of(person.post_link("github"), 403) == "pending_approval"

    def test_starts_are_limited_per_account(self, ps: ProviderStack) -> None:
        person = alice(ps)
        csrf = person.csrf()
        statuses = [person.post_link("school", csrf=csrf).status_code for _ in range(6)]
        assert statuses[:5] == [200] * 5 and statuses[5] == 429


class TestLinkSucceeds:
    def test_github_is_linked_and_a_github_sign_in_reaches_the_same_account(
        self, ps: ProviderStack
    ) -> None:
        person = alice(ps)
        key = person.account()
        assert outcome(person.link("github")) == {"linked": "1"}
        assert [i.provider_id for i in ps.store.list_identities(key)] == [
            "entra",
            "github",
        ]
        other = ps.person()
        assert other.sign_in("github").status_code == 303
        assert other.account() == key
        assert ps.store.account_counts()["total"] == 1
        events = ps.store.auth_events_page(key).items
        assert [
            (e.provider_id, e.reason) for e in events if e.reason == "identity_linked"
        ] == [("github", "identity_linked")]
        assert "identity_linked" in audit_actions(ps)

    def test_the_account_keeps_its_canvas_token_across_providers(
        self, ps: ProviderStack
    ) -> None:
        person = alice(ps)
        key = ps.enroll_canvas(person.account())
        person.link("google")
        other = ps.person()
        other.sign_in("google")
        assert other.account() == key
        assert ps.store.info(key) is not None

    def test_identity_inventory_marks_the_current_method_and_linkable_providers(
        self, ps: ProviderStack
    ) -> None:
        person = alice(ps)
        person.link("github")
        response = api(person, "GET", "/me/identities")
        assert response.status_code == 200
        body = response.json()
        by_provider = {i["provider_id"]: i for i in body["identities"]}
        assert by_provider["entra"]["current"] is True
        assert by_provider["github"]["current"] is False
        assert all(i["can_unlink"] for i in body["identities"])
        assert by_provider["github"]["username"] == "octocat"
        assert by_provider["github"]["email"] == "octocat@example.test"
        assert by_provider["github"]["email_verified"] is True
        assert body["linkable"] == ["google", "oidc:school"]

    def test_callback_query_is_not_reflected_into_the_react_shell(
        self, ps: ProviderStack
    ) -> None:
        person = alice(ps)
        clean = person.get(METHODS)
        assert clean.status_code == 200 and 'id="root"' in clean.text
        for error in ("<script>alert(1)</script>", "identity_in_use"):
            page = person.get(METHODS, params={"error": error})
            assert page.status_code == 200 and page.text == clean.text


class TestLinkRefused:
    def test_an_identity_that_belongs_to_another_account_is_not_merged(
        self, ps: ProviderStack
    ) -> None:
        owner_of_github = ps.person()
        owner_of_github.sign_in("github")
        theirs = owner_of_github.account()
        person = alice(ps)
        mine = person.account()
        assert outcome(person.link("github")) == {"error": "identity_in_use"}
        assert [i.provider_id for i in ps.store.list_identities(mine)] == ["entra"]
        assert [i.provider_id for i in ps.store.list_identities(theirs)] == ["github"]
        refused = [
            e for e in ps.store.iter_audit() if e.action == "identity_link_refused"
        ]
        assert (
            refused
            and refused[0].reason == "identity_in_use"
            and refused[0].target == mine
        )

    def test_a_signed_out_browser_cannot_complete_a_link(
        self, ps: ProviderStack
    ) -> None:
        person = alice(ps)
        page = person.post_link("github")
        person.client.cookies.delete("__Host-cmcp_session")
        assert outcome(person.finish_link("github", page)) == {
            "error": "link_session_ended"
        }
        assert ps.account_of(*GITHUB) is None

    def test_a_different_account_signed_in_meanwhile_cannot_complete_it(
        self, ps: ProviderStack
    ) -> None:
        person = alice(ps)
        page = person.post_link("github")
        cookie = person.client.cookies.get("__Host-cmcp_flow")
        assert (
            person.sign_in_entra(BOB).status_code == 303
        )  # same browser, another account
        person.client.cookies.set(
            "__Host-cmcp_flow", cookie, domain="canvas.example.test"
        )
        assert outcome(person.finish_link("github", page)) == {
            "error": "link_session_ended"
        }
        assert ps.account_of(*GITHUB) is None

    def test_a_new_sign_in_of_the_same_account_ends_the_link(
        self, ps: ProviderStack
    ) -> None:
        person = alice(ps)
        page = person.post_link("github")
        cookie = person.client.cookies.get("__Host-cmcp_flow")
        ps.clock.advance(5)
        person.sign_in_entra(ALICE)  # a new session: a new iat
        person.client.cookies.set(
            "__Host-cmcp_flow", cookie, domain="canvas.example.test"
        )
        assert outcome(person.finish_link("github", page)) == {
            "error": "link_session_ended"
        }

    def test_a_disable_and_enable_in_between_ends_the_link(
        self, ps: ProviderStack
    ) -> None:
        person = alice(ps)
        key = person.account()
        page = person.post_link("github")
        assert ps.store.disable_principal(
            key, actor=OPERATOR, reason="operator_disabled"
        )
        assert ps.store.enable_principal(key, actor=OPERATOR)
        assert outcome(person.finish_link("github", page)) == {
            "error": "link_session_ended"
        }
        assert len(ps.store.list_identities(key)) == 1

    def test_a_replayed_link_callback_is_refused(self, ps: ProviderStack) -> None:
        person = alice(ps)
        page = person.post_link("github")
        cookie = person.client.cookies.get("__Host-cmcp_flow")
        url = person.meta_url(page)
        callback = ps.github.authorize(url)
        assert outcome(person.get(callback)) == {"linked": "1"}
        person.client.cookies.set(
            "__Host-cmcp_flow", cookie, domain="canvas.example.test"
        )
        # Like the Entra replay: a closed code on the Sign-in methods screen, nothing linked twice.
        assert outcome(person.get(callback)) == {"error": "state_invalid"}
        assert len(ps.github.token_requests) == 1

    def test_the_rules_decide_what_may_be_attached(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy = {
            "ACCESS_POLICY": "rules",
            "ACCESS_RULES": "entra:role:Canvas.User,github:user:583231",
        }
        with provider_stack(tmp_path, monkeypatch, policy=policy) as ps:
            person = alice(ps)
            ps.github.user = GitHubUser(id=999, login="stranger")
            assert outcome(person.link("github")) == {"error": "access_denied"}
            assert len(person.identities()) == 1
            ps.github.user = GitHubUser(id=583231)
            assert outcome(person.link("github")) == {"linked": "1"}

    def test_an_account_the_operator_admitted_may_link_anything(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy = {"ACCESS_POLICY": "rules", "ACCESS_RULES": "entra:role:Canvas.User"}
        with provider_stack(tmp_path, monkeypatch, policy=policy) as ps:
            person = alice(ps)
            # Alice came in by rule, so a GitHub identity no rule admits is refused...
            assert outcome(person.link("github")) == {"error": "access_denied"}
            # ...until the operator admits her personally (approval is a personal decision).
            raw_sql(
                ps.store,
                "UPDATE accounts SET admitted_via = 'approval' WHERE id = :i",
                {"i": person.account()},
            )
            assert outcome(person.link("github")) == {"linked": "1"}

    def test_a_link_is_refused_when_the_provider_cannot_be_reached(
        self, ps: ProviderStack
    ) -> None:
        person = alice(ps)
        ps.net.blocked.add("idp.example.edu")
        refused = person.post_link("school")
        assert refused.status_code == 503 and "idp.example.edu" not in refused.text
        assert "__Host-cmcp_flow" not in person.client.cookies


class TestLinkFailsBeforeTheRecordIsPopped:
    """A link that fails early still ends on the Sign-in methods screen (the cookie says what it is for)."""

    @pytest.mark.parametrize("provider", ["google", "github", "school"])
    def test_a_cancelled_consent_returns_to_the_sign_in_methods_screen(
        self, ps: ProviderStack, provider: str
    ) -> None:
        person = alice(ps)
        page = person.post_link(provider)
        response = person.finish_link(provider, page, error="access_denied")
        assert outcome(response) == {"error": "provider_error"}
        assert (
            "secret idp text" not in response.text
            and "must never be shown" not in response.text
        )

    def test_a_cancelled_entra_link_returns_to_the_sign_in_methods_screen(
        self, ps: ProviderStack
    ) -> None:
        person = ps.person()
        person.sign_in("google")
        page = person.post_link("entra")
        state = query_of(person.meta_url(page))["state"]
        response = person.get(
            "/auth/callback/entra", params={"error": "access_denied", "state": state}
        )
        assert outcome(response) == {"error": "provider_error"}

    def test_an_expired_state_of_a_link_returns_to_the_sign_in_methods_screen(
        self, ps: ProviderStack
    ) -> None:
        person = alice(ps)
        page = person.post_link("github")
        callback = ps.github.authorize(person.meta_url(page))
        ps.clock.advance(601)
        assert outcome(person.get(callback)) == {"error": "state_invalid"}

    def test_a_cancelled_sign_in_of_a_signed_in_person_is_not_reported_as_a_link(
        self, ps: ProviderStack
    ) -> None:
        person = alice(ps)
        start = person.start("google", reauth="1")
        response = person.get(
            person.callback_url("google", start, error="access_denied")
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/account/sign-in?error=provider_error"

    def test_a_cookie_without_a_purpose_is_refused(self, ps: ProviderStack) -> None:
        from canvas_mcp.core.selfhost.login.ceremony import (
            FlowCookie,
            new_cookie_payload,
        )

        payload = new_cookie_payload("S" * 43, "B" * 43, "google", 100, "link")
        assert FlowCookie.from_payload(payload) == FlowCookie(
            "S" * 43, "B" * 43, "google", 100, "link"
        )
        del payload["pp"]
        assert FlowCookie.from_payload(payload) is None
        assert FlowCookie.from_payload({**payload, "pp": "root"}) is None


class TestEntraLink:
    def test_a_google_account_links_entra_and_the_record_is_popped_once(
        self, ps: ProviderStack
    ) -> None:
        person = ps.person()
        person.sign_in("google")
        key = person.account()
        page = person.post_link("entra")
        assert page.status_code == 200
        assert "login.microsoftonline.com" in person.meta_url(page)
        cookie = next(
            h
            for h in page.headers.get_list("set-cookie")
            if h.startswith("__Host-cmcp_flow=")
        )
        value = cookie.split(";", 1)[0].split("=", 1)[1]
        assert outcome(person.finish_link("entra", page, user=ALICE)) == {"linked": "1"}
        assert [i.provider_id for i in ps.store.list_identities(key)] == [
            "google",
            "entra",
        ]
        # The same Entra callback again (cookie restored) finds no record any more.
        person.client.cookies.set(
            "__Host-cmcp_flow", value, domain="canvas.example.test"
        )
        again = person.finish_link("entra", page, user=ALICE)
        assert outcome(again) == {"error": "state_invalid"}
        assert len(ps.store.list_identities(key)) == 2

    def test_entra_identity_of_another_account_is_in_use(
        self, ps: ProviderStack
    ) -> None:
        ps.person().sign_in_entra(ALICE)
        person = ps.person()
        person.sign_in("google")
        assert outcome(person.link("entra", user=ALICE)) == {"error": "identity_in_use"}

    def test_an_entra_sign_in_that_is_not_a_link_ignores_link_state(
        self, ps: ProviderStack
    ) -> None:
        person = ps.person()
        assert person.sign_in_entra(ALICE).status_code == 303


class TestUnlink:
    def two(self, ps: ProviderStack) -> tuple[Person, str]:
        person = alice(ps)
        person.link("github")
        return person, person.account()

    def unlink(self, person: Person, provider: str, key: str, ps: ProviderStack) -> Any:
        identity = next(
            i for i in ps.store.list_identities(key) if i.provider_id == provider
        )
        return api(person, "DELETE", f"/me/identities/{identity.id}")

    def test_the_last_identity_cannot_be_removed(self, ps: ProviderStack) -> None:
        person = alice(ps)
        key = person.account()
        response = self.unlink(person, "entra", key, ps)
        assert code_of(response, 409) == "last_identity"
        assert len(ps.store.list_identities(key)) == 1

    def test_unlinking_another_provider_keeps_the_session_and_ends_the_other_browsers(
        self, ps: ProviderStack
    ) -> None:
        person, key = self.two(ps)
        elsewhere = ps.person()
        elsewhere.sign_in("github")  # a second browser of the same account
        before = ps.store.get_principal_status(key).session_epoch
        response = self.unlink(person, "github", key, ps)
        assert response.status_code == 200 and response.json() == {"signed_out": False}
        assert ps.store.get_principal_status(key).session_epoch == before + 1
        assert (
            api(person, "GET", "/me", csrf=None).status_code == 200
        )  # re-issued under the new epoch
        assert (
            api(elsewhere, "GET", "/me", csrf=None).status_code == 401
        )  # its epoch is stale
        assert [i.provider_id for i in ps.store.list_identities(key)] == ["entra"]

    def test_unlinking_the_provider_you_signed_in_with_signs_you_out(
        self, ps: ProviderStack
    ) -> None:
        person, key = self.two(ps)
        github_session = ps.person()
        github_session.sign_in("github")
        response = self.unlink(github_session, "github", key, ps)
        assert response.status_code == 200 and response.json() == {"signed_out": True}
        assert "__Host-cmcp_session" not in github_session.client.cookies or any(
            "Max-Age=0" in h for h in response.headers.get_list("set-cookie")
        )
        assert api(github_session, "GET", "/me", csrf=None).status_code == 401

    def test_an_unlinked_identity_is_a_stranger_at_its_next_sign_in(
        self, ps: ProviderStack
    ) -> None:
        person, key = self.two(ps)
        self.unlink(person, "github", key, ps)
        stranger = ps.person()
        stranger.sign_in("github")
        assert stranger.account() != key and ps.store.account_counts()["total"] == 2

    def test_pending_authorization_codes_die_with_the_epoch_bump(
        self, ps: ProviderStack
    ) -> None:
        person, key = self.two(ps)
        landed, client_id, verifier = person.connect(
            "entra", user=ALICE, decision="approve"
        )
        assert "code" in landed.query  # approved, not yet redeemed
        self.unlink(person, "github", key, ps)
        from ..authz.stack import AUDIENCE, CLAUDE_REDIRECT

        redeemed = ps.stack.token(
            grant_type="authorization_code",
            code=landed.query["code"],
            client_id=client_id,
            redirect_uri=CLAUDE_REDIRECT,
            code_verifier=verifier,
            resource=AUDIENCE,
        )
        assert redeemed.status_code == 401

    def test_connected_apps_survive_an_unlink(self, ps: ProviderStack) -> None:
        person, key = self.two(ps)
        landed, client_id, verifier = person.connect("entra", user=ALICE)
        tokens = person.tokens(landed, client_id, verifier)
        self.unlink(person, "github", key, ps)
        assert ps.stack.mcp_status(tokens["access_token"]) == 200

    def test_unlinking_needs_a_fresh_sign_in_and_the_csrf_token(
        self, ps: ProviderStack
    ) -> None:
        person, key = self.two(ps)
        identity = ps.store.list_identities(key)[1]
        assert (
            code_of(
                api(person, "DELETE", f"/me/identities/{identity.id}", csrf=None), 403
            )
            == "csrf_invalid"
        )
        csrf = person.csrf()
        ps.clock.advance(601)
        response = api(person, "DELETE", f"/me/identities/{identity.id}", csrf=csrf)
        assert code_of(response, 403) == "reauth_required"
        assert len(ps.store.list_identities(key)) == 2

    def test_a_malformed_or_foreign_identity_id_is_refused(
        self, ps: ProviderStack
    ) -> None:
        person, key = self.two(ps)
        other = ps.person()
        other.sign_in("google")
        theirs = ps.store.list_identities(other.account())[0].id
        for bad in ("x", "-1", "1e3", "9" * 30):
            response = api(person, "DELETE", f"/me/identities/{bad}")
            assert code_of(response, 422) == "validation_failed", bad
        assert (
            code_of(api(person, "DELETE", f"/me/identities/{theirs}"), 404)
            == "not_found"
        )
        assert len(ps.store.list_identities(other.account())) == 1


class TestOwnerForceUnlink:
    def owner_stack(self, ps: ProviderStack) -> tuple[Person, str]:
        owner = ps.person()
        owner.sign_in_entra(replace_roles(ALICE, ("Canvas.Owner",)))
        return owner, owner.account()

    def test_an_owner_removes_an_identity_of_someone_else(
        self, ps: ProviderStack
    ) -> None:
        user = ps.person()
        user.sign_in("google")
        key = user.account()
        user.link("github")
        owner, _ = self.owner_stack(ps)
        identity = next(
            i for i in ps.store.list_identities(key) if i.provider_id == "github"
        )
        response = api(owner, "DELETE", f"/admin/identities/{identity.id}")
        assert response.status_code == 200
        assert response.json()["account"]["id"] == key
        assert [i.provider_id for i in ps.store.list_identities(key)] == ["google"]
        entry = [e for e in ps.store.iter_audit() if e.action == "identity_unlinked"][0]
        assert entry.detail["by"] == "owner" and entry.target == key

    def test_a_plain_user_cannot_and_a_stale_owner_cannot(
        self, ps: ProviderStack
    ) -> None:
        user = ps.person()
        user.sign_in("google")
        key = user.account()
        user.link("github")
        identity = next(
            i for i in ps.store.list_identities(key) if i.provider_id == "github"
        )
        assert (
            code_of(api(user, "DELETE", f"/admin/identities/{identity.id}"), 403)
            == "forbidden"
        )
        owner, _ = self.owner_stack(ps)
        csrf = owner.csrf()
        ps.clock.advance(601)
        stale = api(owner, "DELETE", f"/admin/identities/{identity.id}", csrf=csrf)
        assert code_of(stale, 403) == "reauth_required"
        assert len(ps.store.list_identities(key)) == 2


def replace_roles(user: Any, roles: tuple[str, ...]) -> Any:
    from dataclasses import replace

    return replace(user, roles=roles)
