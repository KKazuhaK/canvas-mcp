"""The /account pages of the account model: waiting for approval, history, admin and audit."""

from __future__ import annotations

import pathlib
import re

import pytest

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.accounts import AccessPolicy, AccessRule
from canvas_mcp.core.selfhost.token_store import OPERATOR

from .conftest import make_account
from .test_account_web import (
    ACCOUNT_PATH,
    CANVAS_TOKEN,
    KEY,
    KEY_2,
    OID,
    OID_2,
    OID_OWNER,
    Harness,
    _display_in_utc,  # noqa: F401 - autouse fixture: timestamps render in UTC
    build_harness,
    csrf_of,
    post_form,
    sign_in,
)

OWNER_RULE = AccessRule("entra", "role", "Canvas.Owner")
APPROVAL = AccessPolicy(mode="approval", owner_rules=(OWNER_RULE,))
RULES_OR_QUEUE = AccessPolicy(
    mode="rules", rules=(AccessRule("entra", "role", "Canvas.User"),), fallback="approval",
    owner_rules=(OWNER_RULE,),
)


@pytest.fixture
def h(tmp_path: pathlib.Path) -> Harness:
    return build_harness(tmp_path)


@pytest.fixture
def waiting(tmp_path: pathlib.Path) -> Harness:
    return build_harness(tmp_path, policy=APPROVAL)


def sign_in_owner(h: Harness) -> None:
    out = sign_in(h, oid=OID_OWNER, name="Olive Owner", roles=("Canvas.Owner",))
    assert out.status_code == 303


class TestPendingAccount:
    def test_a_newcomer_signs_in_and_is_told_to_wait(self, waiting: Harness) -> None:
        assert sign_in(waiting, roles=()).status_code == 303
        page = waiting.client.get(ACCOUNT_PATH)
        assert page.status_code == 200
        assert "the server owner has to approve it" in page.text
        assert 'name="canvas_token"' not in page.text  # no form to add a token
        assert 'href="/account/admin"' not in page.text
        status = waiting.store.get_principal_status(KEY)
        assert status.pending and waiting.store.count() == 0

    def test_a_pending_account_cannot_save_or_change_anything(self, waiting: Harness) -> None:
        sign_in(waiting, roles=())
        csrf = csrf_of(waiting)
        for path, fields in (
            ("/account/token", {"canvas_token": CANVAS_TOKEN}),
            ("/account/token/delete", {}),
            ("/account/write-tools", {"tool": "send_message"}),
            ("/account/token/recheck", {}),
        ):
            response = post_form(waiting, path, {"csrf": csrf, **fields})
            assert response.status_code in (303, 403, 404), (path, response.status_code)
            assert waiting.store.count() == 0
        assert waiting.store.get_principal_status(KEY).pending

    def test_the_owner_sees_the_request_and_approves_it(self, waiting: Harness) -> None:
        sign_in(waiting, roles=())
        sign_in_owner(waiting)
        admin = waiting.client.get("/account/admin")
        assert admin.status_code == 200
        assert "1 account(s) waiting for approval." in admin.text
        assert "Waiting for approval" in admin.text
        assert 'action="/account/admin/approve"' in admin.text and 'action="/account/admin/deny"' in admin.text
        response = post_form(
            waiting, "/account/admin/approve", {"csrf": csrf_of(waiting), "principal_key": KEY}
        )
        assert response.status_code == 303 and response.headers["location"] == "/account/admin"
        status = waiting.store.get_principal_status(KEY)
        assert status.active and status.admitted_via == "approval"
        assert "account(s) waiting for approval" not in waiting.client.get("/account/admin").text
        # Signing in again now shows the normal page, with the token form.
        sign_in(waiting, roles=())
        assert 'name="canvas_token"' in waiting.client.get(ACCOUNT_PATH).text

    def test_the_owner_denies_a_request_and_the_account_is_refused_from_then_on(
        self, waiting: Harness
    ) -> None:
        sign_in(waiting, roles=())
        sign_in_owner(waiting)
        response = post_form(
            waiting, "/account/admin/deny", {"csrf": csrf_of(waiting), "principal_key": KEY}
        )
        assert response.status_code == 303
        status = waiting.store.get_principal_status(KEY)
        assert status.disabled and status.disabled_reason == "approval_denied"
        assert "Request denied" in waiting.client.get("/account/admin").text
        refused = sign_in(waiting, roles=())
        assert refused.status_code == 403
        assert "disabled" in refused.text.lower()

    def test_a_user_cannot_decide(self, waiting: Harness) -> None:
        sign_in(waiting, roles=())
        csrf = csrf_of(waiting)
        for path in ("/account/admin/approve", "/account/admin/deny"):
            response = post_form(waiting, path, {"csrf": csrf, "principal_key": KEY})
            assert response.status_code == 403
        assert waiting.store.get_principal_status(KEY).pending

    @pytest.mark.parametrize("path", ["/account/admin/approve", "/account/admin/deny"])
    def test_a_decision_needs_origin_csrf_and_a_valid_key(self, waiting: Harness, path: str) -> None:
        sign_in(waiting, roles=())
        sign_in_owner(waiting)
        csrf = csrf_of(waiting)
        good = {"csrf": csrf, "principal_key": KEY}
        assert post_form(waiting, path, {**good, "csrf": "bad"}).status_code == 403
        assert post_form(waiting, path, good, origin=None).status_code == 403
        assert post_form(waiting, path, good, origin="https://evil.example").status_code == 403
        for bad in ("x", f"entra:t:{OID}", KEY.upper(), ""):
            assert post_form(waiting, path, {**good, "principal_key": bad}).status_code == 400
        assert waiting.store.get_principal_status(KEY).pending

    def test_a_decision_on_something_already_decided_changes_nothing(self, waiting: Harness) -> None:
        sign_in(waiting, roles=())
        sign_in_owner(waiting)
        csrf = csrf_of(waiting)
        form = {"csrf": csrf, "principal_key": KEY}
        assert post_form(waiting, "/account/admin/approve", form).status_code == 303
        epoch = waiting.store.get_principal_status(KEY).session_epoch
        assert post_form(waiting, "/account/admin/deny", form).status_code == 303
        status = waiting.store.get_principal_status(KEY)
        assert status.active and status.session_epoch == epoch  # the second decision found nothing pending

    def test_rules_admit_most_and_the_rest_wait(self, tmp_path: pathlib.Path) -> None:
        h = build_harness(tmp_path, policy=RULES_OR_QUEUE)
        sign_in(h, oid=OID, roles=("Canvas.User",))
        sign_in(h, oid=OID_2, roles=())
        assert h.store.get_principal_status(KEY).active
        assert h.store.get_principal_status(KEY_2).pending


class TestSignInHistory:
    def test_the_account_page_lists_the_last_sign_ins(self, h: Harness) -> None:
        sign_in(h)
        h.now += 60
        sign_in(h)
        text = h.client.get(ACCOUNT_PATH).text
        assert 'id="sign-ins"' in text and "Recent sign-ins" in text
        assert "Signed in (account created)" in text
        assert text.count("<td data-label=\"Method\">Microsoft</td>") == 2
        assert "evil" not in text

    def test_it_shows_at_most_twenty(self, h: Harness) -> None:
        for _ in range(23):
            sign_in(h)
            h.now += 1
        text = h.client.get(ACCOUNT_PATH).text
        section = text[text.index('id="sign-ins"') :]
        assert section.count("<tr>") == 1 + 20  # header row plus twenty

    def test_a_pending_account_sees_its_history_too(self, waiting: Harness) -> None:
        sign_in(waiting, roles=())
        text = waiting.client.get(ACCOUNT_PATH).text
        assert "Waiting for approval" in text[text.index('id="sign-ins"') :]

    def test_only_the_digest_of_the_user_agent_is_stored(self, h: Harness) -> None:
        agent = "Mozilla/5.0 (X11) TestBrowser/1.0 unique-marker-9f3a"
        h.client.headers["user-agent"] = agent
        sign_in(h)
        from dbbackend import raw_sql

        rows = raw_sql(h.store, "SELECT ua_hash, ip FROM auth_events")
        assert rows and re.fullmatch(r"[0-9a-f]{16}", rows[0][0])
        assert "unique-marker" not in repr(raw_sql(h.store, "SELECT * FROM auth_events"))
        assert agent not in h.client.get(ACCOUNT_PATH).text

    def test_a_refused_sign_in_is_in_the_history_of_nobody_but_is_recorded(self, h: Harness) -> None:
        from dbbackend import raw_sql

        response = sign_in(h, roles=())
        assert response.status_code == 403
        rows = raw_sql(h.store, "SELECT account_id, outcome, reason FROM auth_events")
        assert rows == [(None, "denied", "access_denied")]
        assert h.store.list_accounts() == []


class TestAuditPage:
    def test_the_owner_reads_the_actions_and_nobody_else_does(self, waiting: Harness) -> None:
        assert waiting.client.get("/account/admin/audit").status_code == 403  # signed out
        sign_in(waiting, roles=())
        assert waiting.client.get("/account/admin/audit").status_code == 403  # a pending user
        sign_in_owner(waiting)
        post_form(waiting, "/account/admin/approve", {"csrf": csrf_of(waiting), "principal_key": KEY})
        page = waiting.client.get("/account/admin/audit")
        assert page.status_code == 200
        assert "Audit log" in page.text and "Account approved" in page.text
        assert "Olive Owner" in page.text  # the actor, by name
        assert CANVAS_TOKEN not in page.text

    def test_it_pages_back_in_time(self, waiting: Harness) -> None:
        sign_in_owner(waiting)
        key = make_account(waiting.store, OID_2)
        for _ in range(55):  # 110 audit rows
            waiting.store.disable_principal(key, actor=OPERATOR, reason="operator_disabled")
            waiting.store.enable_principal(key, actor=OPERATOR)
        first = waiting.client.get("/account/admin/audit")
        assert first.status_code == 200 and "Older entries" in first.text
        link = re.search(r'href="(/account/admin/audit\?before=\d+)"', first.text)
        assert link
        older = waiting.client.get(link.group(1).replace("&amp;", "&"))
        assert older.status_code == 200 and "<tbody>" in older.text
        assert waiting.client.get("/account/admin/audit", params={"before": "1"}).status_code == 200
        assert waiting.client.get("/account/admin/audit", params={"before": "junk"}).status_code == 200

    def test_an_owner_sees_the_audit_link_on_the_admin_page(self, waiting: Harness) -> None:
        sign_in_owner(waiting)
        assert 'href="/account/admin/audit"' in waiting.client.get("/account/admin").text


class TestAdminListing:
    def test_accounts_without_an_enrollment_are_listed_only_when_they_need_a_decision(
        self, waiting: Harness
    ) -> None:
        sign_in(waiting, oid=OID, name="Ada", upn="ada@example.test", roles=())  # pending
        make_account(waiting.store, OID_2, name="Bob", username="bob@example.test")  # active, no token
        sign_in_owner(waiting)
        text = waiting.client.get("/account/admin").text
        assert "ada@example.test" in text and f'value="{KEY}"' in text  # someone to decide on
        assert "bob@example.test" not in text  # nothing to administer yet
        assert "Entra user" in text


def test_the_admission_vocabulary_is_closed() -> None:
    # The pages print codes through fixed labels only; an unknown code falls back to a generic one.
    assert acc.DENIAL_MESSAGES and acc.AUTH_REASONS
