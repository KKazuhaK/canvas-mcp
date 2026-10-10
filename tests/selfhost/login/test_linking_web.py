"""Linking and unlinking sign-in methods from /account (the server-rendered pages), end to end."""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
from dbbackend import raw_sql

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.token_store import OPERATOR

from ..authz.stack import ALICE, BOB
from .fake_idp import GitHubUser
from .stack_providers import Person, ProviderStack, provider_stack, query_of

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


def audit_actions(ps: ProviderStack) -> list[str]:
    return [e.action for e in ps.store.list_audit(200)]


class TestLinkStart:
    def test_the_interstitial_sets_the_cookie_and_offers_a_visible_continue_link(self, ps: ProviderStack) -> None:
        person = alice(ps)
        page = person.post_link("github")
        assert page.status_code == 200
        url = person.meta_url(page)
        assert url.startswith("https://github.com/login/oauth/authorize?")
        assert f'href="{url.replace("&", "&amp;")}"' in page.text and "Continue" in page.text
        header = next(h for h in page.headers.get_list("set-cookie") if h.startswith("__Host-cmcp_flow="))
        assert "Secure" in header and "HttpOnly" in header and "Max-Age=600" in header
        assert page.headers["cache-control"] == "no-store"
        # The page's CSP forbids nothing the refresh needs, but never allows a script.
        assert "script-src" not in page.headers["content-security-policy"] and "<script" not in page.text

    def test_the_link_forces_the_provider_to_ask_again(self, ps: ProviderStack) -> None:
        person = alice(ps)
        person.link("school")
        assert ps.school.last_authorize["prompt"] == "login"
        person.link("github")
        assert ps.github.last_authorize["prompt"] == "select_account"

    def test_a_get_cannot_start_a_link(self, ps: ProviderStack) -> None:
        person = alice(ps)
        assert person.get("/account/identities/link", params={"provider": "github"}).status_code == 405
        assert person.get("/account/identities/unlink").status_code == 405

    def test_csrf_origin_and_login_are_required(self, ps: ProviderStack) -> None:
        person = alice(ps)
        csrf = person.csrf()
        assert person.post("/account/identities/link", {"provider": "github"}).status_code == 403
        assert person.post("/account/identities/link", {"csrf": "wrong", "provider": "github"}).status_code == 403
        wrong_origin = person.client.post(
            "/account/identities/link", data={"csrf": csrf, "provider": "github"},
            headers={"Origin": "https://evil.example"},
        )
        assert wrong_origin.status_code == 403
        anonymous = ps.person()
        assert anonymous.post("/account/identities/link", {"csrf": csrf, "provider": "github"}).status_code == 303
        assert "__Host-cmcp_flow" not in anonymous.client.cookies

    def test_a_stale_sign_in_is_asked_to_sign_in_again(self, ps: ProviderStack) -> None:
        person = alice(ps)
        csrf = person.csrf()
        ps.clock.advance(601)
        response = person.post_link("github", csrf=csrf)
        assert response.status_code == 403 and "last 10 minutes" in response.text
        assert "__Host-cmcp_flow" not in person.client.cookies

    def test_a_provider_that_is_not_configured_or_already_linked_is_refused(self, ps: ProviderStack) -> None:
        person = alice(ps)
        assert person.post_link("facebook").status_code == 400
        assert person.post_link("entra").status_code == 409  # Alice already has it
        assert outcome(person.link("github")) == {"linked": "1"}
        again = person.post_link("github")
        assert again.status_code == 409 and "already have" in again.text

    def test_a_pending_account_may_not_link(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        policy = {"ACCESS_POLICY": "approval", "ACCESS_OPEN_ACKNOWLEDGE_PUBLIC": "true"}
        with provider_stack(tmp_path, monkeypatch, policy=policy) as ps:
            person = ps.person()
            person.sign_in("google")
            assert person.get(METHODS).status_code == 403
            response = person.post("/account/identities/link", {"csrf": "x", "provider": "github"})
            assert response.status_code == 403

    def test_starts_are_limited_per_account(self, ps: ProviderStack) -> None:
        person = alice(ps)
        csrf = person.csrf()
        statuses = [person.post_link("school", csrf=csrf).status_code for _ in range(6)]
        assert statuses[:5] == [200] * 5 and statuses[5] == 429


class TestLinkSucceeds:
    def test_github_is_linked_and_a_github_sign_in_reaches_the_same_account(self, ps: ProviderStack) -> None:
        person = alice(ps)
        key = person.account()
        assert outcome(person.link("github")) == {"linked": "1"}
        assert [i.provider_id for i in ps.store.list_identities(key)] == ["entra", "github"]
        other = ps.person()
        assert other.sign_in("github").status_code == 303
        assert other.account() == key
        assert len(ps.store.list_principal_statuses()) == 1
        events = ps.store.list_auth_events(key)
        assert [(e.provider_id, e.reason) for e in events if e.reason == "identity_linked"] == [
            ("github", "identity_linked")
        ]
        assert "identity_linked" in audit_actions(ps)

    def test_the_account_keeps_its_canvas_token_across_providers(self, ps: ProviderStack) -> None:
        person = alice(ps)
        key = ps.enroll_canvas(person.account())
        person.link("google")
        other = ps.person()
        other.sign_in("google")
        assert other.account() == key
        assert ps.store.info(key) is not None

    def test_the_sign_in_methods_page_lists_both_and_marks_the_current_one(self, ps: ProviderStack) -> None:
        person = alice(ps)
        person.link("github")
        page = person.get(METHODS, params={"linked": "1"})
        assert page.status_code == 200
        text = page.text
        assert "Sign-in method added" in text and "Microsoft" in text and "GitHub" in text
        assert "this sign-in" in text
        assert "octocat" in text and "octocat@example.test" in text and "verified e-mail" in text
        assert text.count('action="/account/identities/unlink"') == 2
        assert 'value="google"' in text and 'value="github"' not in text  # only unlinked providers are offered
        zh = person.get(METHODS, params={"lang": "zh"})
        assert "登录方式" in zh.text and "Sign-in methods" not in zh.text

    def test_a_flash_error_is_a_closed_code_never_provider_text(self, ps: ProviderStack) -> None:
        person = alice(ps)
        page = person.get(METHODS, params={"error": "<script>alert(1)</script>"})
        assert "<script>" not in page.text and 'class="notice error"' not in page.text
        shown = person.get(METHODS, params={"error": "identity_in_use"})
        assert "already linked to another user" in shown.text


class TestLinkRefused:
    def test_an_identity_that_belongs_to_another_account_is_not_merged(self, ps: ProviderStack) -> None:
        owner_of_github = ps.person()
        owner_of_github.sign_in("github")
        theirs = owner_of_github.account()
        person = alice(ps)
        mine = person.account()
        assert outcome(person.link("github")) == {"error": "identity_in_use"}
        assert [i.provider_id for i in ps.store.list_identities(mine)] == ["entra"]
        assert [i.provider_id for i in ps.store.list_identities(theirs)] == ["github"]
        refused = [e for e in ps.store.list_audit(200) if e.action == "identity_link_refused"]
        assert refused and refused[0].reason == "identity_in_use" and refused[0].target == mine
        assert "already linked to another user" in person.get(METHODS, params={"error": "identity_in_use"}).text

    def test_a_signed_out_browser_cannot_complete_a_link(self, ps: ProviderStack) -> None:
        person = alice(ps)
        page = person.post_link("github")
        person.client.cookies.delete("__Host-cmcp_session")
        assert outcome(person.finish_link("github", page)) == {"error": "link_session_ended"}
        assert ps.account_of(*GITHUB) is None

    def test_a_different_account_signed_in_meanwhile_cannot_complete_it(self, ps: ProviderStack) -> None:
        person = alice(ps)
        page = person.post_link("github")
        cookie = person.client.cookies.get("__Host-cmcp_flow")
        assert person.sign_in_entra(BOB).status_code == 303  # same browser, another account
        person.client.cookies.set("__Host-cmcp_flow", cookie, domain="canvas.example.test")
        assert outcome(person.finish_link("github", page)) == {"error": "link_session_ended"}
        assert ps.account_of(*GITHUB) is None

    def test_a_new_sign_in_of_the_same_account_ends_the_link(self, ps: ProviderStack) -> None:
        person = alice(ps)
        page = person.post_link("github")
        cookie = person.client.cookies.get("__Host-cmcp_flow")
        ps.clock.advance(5)
        person.sign_in_entra(ALICE)  # a new session: a new iat
        person.client.cookies.set("__Host-cmcp_flow", cookie, domain="canvas.example.test")
        assert outcome(person.finish_link("github", page)) == {"error": "link_session_ended"}

    def test_a_disable_and_enable_in_between_ends_the_link(self, ps: ProviderStack) -> None:
        person = alice(ps)
        key = person.account()
        page = person.post_link("github")
        assert ps.store.disable_principal(key, actor=OPERATOR, reason="operator_disabled")
        assert ps.store.enable_principal(key, actor=OPERATOR)
        assert outcome(person.finish_link("github", page)) == {"error": "link_session_ended"}
        assert len(ps.store.list_identities(key)) == 1

    def test_a_replayed_link_callback_is_refused(self, ps: ProviderStack) -> None:
        person = alice(ps)
        page = person.post_link("github")
        cookie = person.client.cookies.get("__Host-cmcp_flow")
        url = person.meta_url(page)
        callback = ps.github.authorize(url)
        assert outcome(person.get(callback)) == {"linked": "1"}
        person.client.cookies.set("__Host-cmcp_flow", cookie, domain="canvas.example.test")
        replay = person.get(callback)
        assert replay.status_code == 400 and "invalid or expired" in replay.text
        assert len(ps.github.token_requests) == 1

    def test_the_rules_decide_what_may_be_attached(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        policy = {"ACCESS_POLICY": "rules", "ACCESS_RULES": "entra:role:Canvas.User,github:user:583231"}
        with provider_stack(tmp_path, monkeypatch, policy=policy) as ps:
            person = alice(ps)
            ps.github.user = GitHubUser(id=999, login="stranger")
            assert outcome(person.link("github")) == {"error": "access_denied"}
            assert len(person.identities()) == 1
            ps.github.user = GitHubUser(id=583231)
            assert outcome(person.link("github")) == {"linked": "1"}

    def test_an_account_the_operator_admitted_may_link_anything(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        policy = {"ACCESS_POLICY": "rules", "ACCESS_RULES": "entra:role:Canvas.User"}
        with provider_stack(tmp_path, monkeypatch, policy=policy) as ps:
            person = alice(ps)
            # Alice came in by rule, so a GitHub identity no rule admits is refused...
            assert outcome(person.link("github")) == {"error": "access_denied"}
            # ...until the operator admits her personally (approval is a personal decision).
            raw_sql(ps.store, "UPDATE accounts SET admitted_via = 'approval' WHERE id = :i", {"i": person.account().removeprefix("acct:")})
            assert outcome(person.link("github")) == {"linked": "1"}

    def test_a_link_is_refused_when_the_provider_cannot_be_reached(self, ps: ProviderStack) -> None:
        person = alice(ps)
        ps.net.blocked.add("idp.example.edu")
        refused = person.post_link("school")
        assert refused.status_code == 503 and "idp.example.edu" not in refused.text
        assert "__Host-cmcp_flow" not in person.client.cookies


class TestEntraLink:
    def test_a_google_account_links_entra_and_the_record_is_popped_once(self, ps: ProviderStack) -> None:
        person = ps.person()
        person.sign_in("google")
        key = person.account()
        page = person.post_link("entra")
        assert page.status_code == 200
        assert "login.microsoftonline.com" in person.meta_url(page)
        cookie = next(h for h in page.headers.get_list("set-cookie") if h.startswith("__Host-cmcp_login="))
        value = cookie.split(";", 1)[0].split("=", 1)[1]
        assert outcome(person.finish_link("entra", page, user=ALICE)) == {"linked": "1"}
        assert [i.provider_id for i in ps.store.list_identities(key)] == ["google", "entra"]
        # The same Entra callback again (cookie restored) finds no record any more.
        person.client.cookies.set("__Host-cmcp_login", value, domain="canvas.example.test")
        again = person.finish_link("entra", page, user=ALICE)
        assert outcome(again) == {"error": "state_invalid"}
        assert len(ps.store.list_identities(key)) == 2

    def test_entra_identity_of_another_account_is_in_use(self, ps: ProviderStack) -> None:
        ps.person().sign_in_entra(ALICE)
        person = ps.person()
        person.sign_in("google")
        assert outcome(person.link("entra", user=ALICE)) == {"error": "identity_in_use"}

    def test_an_entra_sign_in_that_is_not_a_link_ignores_link_state(self, ps: ProviderStack) -> None:
        person = ps.person()
        assert person.sign_in_entra(ALICE).status_code == 303


class TestUnlink:
    def two(self, ps: ProviderStack) -> tuple[Person, str]:
        person = alice(ps)
        person.link("github")
        return person, person.account()

    def unlink(self, person: Person, provider: str, key: str, ps: ProviderStack) -> Any:
        identity = next(i for i in ps.store.list_identities(key) if i.provider_id == provider)
        return person.post("/account/identities/unlink", {"csrf": person.csrf(), "identity": str(identity.id)})

    def test_the_last_identity_cannot_be_removed(self, ps: ProviderStack) -> None:
        person = alice(ps)
        key = person.account()
        response = self.unlink(person, "entra", key, ps)
        assert response.status_code == 409 and "at least one sign-in method" in response.text
        assert len(ps.store.list_identities(key)) == 1

    def test_unlinking_another_provider_keeps_the_session_and_ends_the_other_browsers(self, ps: ProviderStack) -> None:
        person, key = self.two(ps)
        elsewhere = ps.person()
        elsewhere.sign_in("github")  # a second browser of the same account
        before = ps.store.get_principal_status(key).session_epoch
        response = self.unlink(person, "github", key, ps)
        assert response.status_code == 303 and response.headers["location"] == f"{METHODS}?unlinked=1"
        assert ps.store.get_principal_status(key).session_epoch == before + 1
        assert person.get(METHODS).status_code == 200  # re-issued under the new epoch
        assert elsewhere.get(METHODS).status_code == 303  # signed out: its epoch is stale
        assert [i.provider_id for i in ps.store.list_identities(key)] == ["entra"]

    def test_unlinking_the_provider_you_signed_in_with_signs_you_out(self, ps: ProviderStack) -> None:
        person, key = self.two(ps)
        github_session = ps.person()
        github_session.sign_in("github")
        response = self.unlink(github_session, "github", key, ps)
        assert response.status_code == 303 and response.headers["location"] == "/account"
        assert "__Host-cmcp_session" not in github_session.client.cookies or any(
            "Max-Age=0" in h for h in response.headers.get_list("set-cookie")
        )
        assert github_session.get(METHODS).status_code == 303

    def test_an_unlinked_identity_is_a_stranger_at_its_next_sign_in(self, ps: ProviderStack) -> None:
        person, key = self.two(ps)
        self.unlink(person, "github", key, ps)
        stranger = ps.person()
        stranger.sign_in("github")
        assert stranger.account() != key and len(ps.store.list_principal_statuses()) == 2

    def test_pending_authorization_codes_die_with_the_epoch_bump(self, ps: ProviderStack) -> None:
        person, key = self.two(ps)
        landed, client_id, verifier = person.connect("entra", user=ALICE, decision="approve")
        assert "code" in landed.query  # approved, not yet redeemed
        self.unlink(person, "github", key, ps)
        from ..authz.stack import AUDIENCE, CLAUDE_REDIRECT

        redeemed = ps.stack.token(
            grant_type="authorization_code", code=landed.query["code"], client_id=client_id,
            redirect_uri=CLAUDE_REDIRECT, code_verifier=verifier, resource=AUDIENCE,
        )
        assert redeemed.status_code == 401

    def test_connected_apps_survive_an_unlink(self, ps: ProviderStack) -> None:
        person, key = self.two(ps)
        landed, client_id, verifier = person.connect("entra", user=ALICE)
        tokens = person.tokens(landed, client_id, verifier)
        self.unlink(person, "github", key, ps)
        assert ps.stack.mcp_status(tokens["access_token"]) == 200

    def test_unlinking_needs_a_fresh_sign_in_and_the_csrf_token(self, ps: ProviderStack) -> None:
        person, key = self.two(ps)
        identity = ps.store.list_identities(key)[1]
        assert person.post("/account/identities/unlink", {"identity": str(identity.id)}).status_code == 403
        csrf = person.csrf()
        ps.clock.advance(601)
        response = person.post("/account/identities/unlink", {"csrf": csrf, "identity": str(identity.id)})
        assert response.status_code == 403 and "last 10 minutes" in response.text
        assert len(ps.store.list_identities(key)) == 2

    def test_a_malformed_or_foreign_identity_id_is_refused(self, ps: ProviderStack) -> None:
        person, key = self.two(ps)
        other = ps.person()
        other.sign_in("google")
        theirs = ps.store.list_identities(other.account())[0].id
        for bad in ("", "x", "-1", "1e3", "9" * 30, str(theirs)):
            response = person.post("/account/identities/unlink", {"csrf": person.csrf(), "identity": bad})
            assert response.status_code in (400, 404), (bad, response.status_code)
        assert len(ps.store.list_identities(other.account())) == 1


class TestOwnerForceUnlink:
    def owner_stack(self, ps: ProviderStack) -> tuple[Person, str]:
        owner = ps.person()
        owner.sign_in_entra(replace_roles(ALICE, ("Canvas.Owner",)))
        return owner, owner.account()

    def test_an_owner_removes_an_identity_of_someone_else(self, ps: ProviderStack) -> None:
        user = ps.person()
        user.sign_in("google")
        key = user.account()
        user.link("github")
        owner, _ = self.owner_stack(ps)
        identity = next(i for i in ps.store.list_identities(key) if i.provider_id == "github")
        response = owner.post(
            "/account/admin/identities/unlink",
            {"csrf": owner.csrf(), "identity": str(identity.id), "principal_key": key},
        )
        assert response.status_code == 303 and response.headers["location"] == "/account/admin"
        assert [i.provider_id for i in ps.store.list_identities(key)] == ["google"]
        entry = [e for e in ps.store.list_audit(200) if e.action == "identity_unlinked"][0]
        assert entry.detail["by"] == "owner" and entry.target == key

    def test_a_plain_user_cannot_and_a_stale_owner_cannot(self, ps: ProviderStack) -> None:
        user = ps.person()
        user.sign_in("google")
        key = user.account()
        user.link("github")
        identity = next(i for i in ps.store.list_identities(key) if i.provider_id == "github")
        form = {"csrf": user.csrf(), "identity": str(identity.id), "principal_key": key}
        assert user.post("/account/admin/identities/unlink", form).status_code == 403
        owner, _ = self.owner_stack(ps)
        csrf = owner.csrf()
        ps.clock.advance(601)
        stale = owner.post(
            "/account/admin/identities/unlink",
            {"csrf": csrf, "identity": str(identity.id), "principal_key": key},
        )
        assert stale.status_code == 403
        assert len(ps.store.list_identities(key)) == 2


def replace_roles(user: Any, roles: tuple[str, ...]) -> Any:
    from dataclasses import replace

    return replace(user, roles=roles)
