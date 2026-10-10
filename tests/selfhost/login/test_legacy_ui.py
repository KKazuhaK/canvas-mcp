"""The server-rendered pages with several sign-in providers: chooser, admin view, history, labels."""

from __future__ import annotations

import pathlib
import re

import pytest

from ..authz.stack import OWNER
from .fake_idp import GitHubUser
from .stack_providers import Person, ProviderStack, provider_stack, query_of

ADMIN = "/account/admin"
AUDIT = "/account/admin/audit"


def cjk(*parts: int | str) -> str:
    """Chinese text from code points (ints) and plain pieces (strings): this file stays English."""
    return "".join(chr(part) if isinstance(part, int) else part for part in parts)


@pytest.fixture
def ps(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    with provider_stack(tmp_path, monkeypatch) as stack:
        yield stack


def owner(ps: ProviderStack) -> Person:
    person = ps.person()
    assert person.sign_in_entra(OWNER).status_code == 303
    return person


def linked_user(ps: ProviderStack) -> tuple[Person, str]:
    person = ps.person()
    person.sign_in("google")
    person.link("github")
    # The admin page lists accounts that hold a Canvas token.
    return person, ps.enroll_canvas(person.account())


class TestChooser:
    def test_the_language_toggle_keeps_the_waiting_app_and_only_that(self, ps: ProviderStack) -> None:
        person = ps.person()
        _, _, login = person.begin_connect()
        txn = query_of(login)["txn"]
        page = person.get(login)
        assert page.status_code == 200 and "Sign in with Google" in page.text
        assert f'href="/account/login?txn={txn}&amp;lang=zh"' in page.text
        page = person.get(login + "&reauth=1")
        assert f'href="/account/login?txn={txn}&amp;reauth=1&amp;lang=zh"' in page.text
        # The buttons carry the request id too (this is what the toggle must not lose).
        assert f'href="/account/login/google?txn={txn}"' in person.get(login).text

    def test_the_toggle_never_reflects_a_value_that_is_not_a_request_id(self, ps: ProviderStack) -> None:
        person = ps.person()
        page = person.get("/account/login", params={"txn": "<script>alert(1)</script>"})
        assert "<script>alert" not in page.text
        assert "txn=" not in re.findall(r'href="([^"]*lang=zh[^"]*)"', page.text)[0]
        plain = person.get("/account/login")
        assert 'href="/account/login?lang=zh"' in plain.text

    def test_every_provider_has_an_inline_icon_and_nothing_is_fetched(self, ps: ProviderStack) -> None:
        page = ps.person().get("/account/login")
        assert page.status_code == 200
        buttons = re.findall(r'<a class="btn provider"[^>]*>(.*?)</a>', page.text, re.S)
        assert len(buttons) == 4
        for button in buttons:
            assert button.startswith('<svg class="pico"') and "<img" not in button
        # Microsoft squares, the four-colour Google G, the GitHub mark and the key.
        assert "#f25022" in buttons[0] and "#4285F4" in buttons[1]
        assert 'fill="currentColor"' in buttons[2] and "stroke-linecap" in buttons[3]
        assert not re.search(r"https?://|url\(", "".join(buttons))
        assert "img-src" not in page.headers["content-security-policy"] or "'self'" in page.headers["content-security-policy"]

    def test_the_chooser_in_chinese(self, ps: ProviderStack) -> None:
        page = ps.person().get("/account/login", params={"lang": "zh"})
        # "Sign in with Google" in Chinese (built from code points: this file is English).
        assert cjk(0x4f7f, 0x7528, " Google ", 0x767b, 0x5f55) in page.text and "Sign in with Google" not in page.text


class TestAdminPage:
    def test_the_user_column_is_named_for_the_server_not_for_entra(self, ps: ProviderStack) -> None:
        linked_user(ps)
        page = owner(ps).get(ADMIN)
        assert page.status_code == 200
        assert "<th>User</th>" in page.text and "Entra user" not in page.text

    def test_every_sign_in_method_is_listed_with_its_subject_and_issuer(self, ps: ProviderStack) -> None:
        user, key = linked_user(ps)
        school = ps.person()
        school.sign_in("school")
        ps.enroll_canvas(school.account())
        page = owner(ps).get(ADMIN)
        text = page.text
        assert "<dt>Google: " in text
        assert "<dt>GitHub: octocat</dt>" in text and "<code>583231</code>" in text
        # An OIDC provider's issuer is shown; the others' is not.
        assert "https://idp.example.edu/realms/school" in text
        assert text.count("Issuer:") == 1
        assert key and user

    def test_the_owner_gets_an_unlink_form_only_where_a_method_would_remain(self, ps: ProviderStack) -> None:
        _, key = linked_user(ps)
        single = ps.person()
        single.sign_in("school")
        ps.enroll_canvas(single.account())
        admin = owner(ps)
        page = admin.get(ADMIN)
        forms = re.findall(r'<form method="post" action="/account/admin/identities/unlink">(.*?)</form>', page.text, re.S)
        assert len(forms) == 2  # Google and GitHub of the linked user; the lone school method has none
        assert all(f'name="principal_key" value="{key}"' in form for form in forms)
        assert all(re.search(r'name="identity" value="\d+"', form) for form in forms)
        csrf = re.search(r'name="csrf" value="([^"]+)"', forms[0]).group(1)  # type: ignore[union-attr]
        identity = re.search(r'name="identity" value="(\d+)"', forms[0]).group(1)  # type: ignore[union-attr]
        done = admin.post(
            "/account/admin/identities/unlink",
            {"csrf": csrf, "identity": identity, "principal_key": key},
        )
        assert done.status_code == 303 and done.headers["location"] == ADMIN
        after = admin.get(ADMIN)
        assert len(re.findall(r'action="/account/admin/identities/unlink"', after.text)) == 0

    def test_the_audit_log_names_the_linking_actions(self, ps: ProviderStack) -> None:
        person, key = linked_user(ps)
        theirs = ps.person()
        theirs.sign_in("school")
        # A refused link: the school identity belongs to someone else.
        refused = ps.person()
        refused.sign_in("github", user=GitHubUser(id=42, login="other"))
        refused.link("school")
        admin = owner(ps)
        identity = next(i for i in ps.store.list_identities(key) if i.provider_id == "github")
        admin.post(
            "/account/admin/identities/unlink",
            {"csrf": admin.csrf(), "identity": str(identity.id), "principal_key": key},
        )
        text = admin.get(AUDIT).text
        for label in ("Sign-in method linked", "Sign-in method unlinked", "Sign-in method link refused"):
            assert label in text, label
        assert person.account() == key

    def test_entra_alone_keeps_its_wording(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from ..authz.stack import Browser

        with provider_stack(tmp_path, monkeypatch, providers="entra") as ps:
            person = ps.person()
            browser = Browser(ps.stack, client=person.client)
            browser.entra_login(OWNER, browser.get("/account/login"))
            ps.enroll_canvas(person.account())
            page = person.get(ADMIN)
            assert "<th>Entra user</th>" in page.text and "<th>User</th>" not in page.text
            assert "<dt>Tenant</dt>" in page.text and "<dt>Object</dt>" in page.text


class TestAccountPage:
    def test_the_identity_line_and_the_history_name_the_provider(self, ps: ProviderStack) -> None:
        person = ps.person()
        person.sign_in("github")
        person.link("google")
        page = person.get("/account")
        assert "GitHub account: octocat" in page.text
        history = page.text[page.text.index('id="sign-ins"') :]
        assert ">GitHub<" in history and "Linked a sign-in method" in history
        # Microsoft is named Microsoft; a configured OIDC provider by its display name.
        other = ps.person()
        other.sign_in("school")
        assert ">school<" in other.get("/account").text

    def test_a_refusal_is_provider_neutral_in_both_languages(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy = {"ACCESS_POLICY": "rules", "ACCESS_RULES": "entra:role:Canvas.User"}
        with provider_stack(tmp_path, monkeypatch, policy=policy) as ps:
            english = ps.person().sign_in("github")
            assert english.status_code == 403
            assert "This account is not allowed to use this server. Ask the server owner for access." in english.text
            assert "Microsoft" not in english.text
            person = ps.person()
            person.client.cookies.set("canvas_mcp_lang", "zh", domain="canvas.example.test")
            chinese = person.sign_in("github")
            assert chinese.status_code == 403
            # The neutral refusal in Chinese (built from code points: this file is English).
            assert cjk(0x6b64, 0x8d26, 0x53f7, 0x6ca1, 0x6709, 0x4f7f, 0x7528, 0x6b64, 0x670d, 0x52a1, 0x5668, 0x7684, 0x6743, 0x9650) in chinese.text
            assert "Ask the server owner" not in chinese.text
