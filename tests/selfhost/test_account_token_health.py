"""/account and /account/admin for tokens that stopped working (English pages)."""

from __future__ import annotations

import json
import pathlib
import re
import sqlite3
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from canvas_mcp.core import audit
from canvas_mcp.core.selfhost.account_web import (
    ACCOUNT_PATH,
    CanvasCheckError,
    CanvasIdentity,
)
from canvas_mcp.core.selfhost.token_store import (
    REASON_CANVAS_TOKEN_REJECTED,
    REASON_DECRYPT_FAILED,
    REASON_REVOKED_BY_ADMIN,
    STATUS_ACTIVE,
    STATUS_INVALID,
)

from .test_account_schools import DEFAULT_HOST, HOST_A, enroll, rig
from .test_account_web import (
    CANVAS_TOKEN,
    CJK,
    OID,
    OID_2,
    OID_OWNER,
    TID,
    Harness,
    assert_security_headers,
    build_harness,
    csrf_of,
    post_form,
    sign_in,
    strip_chrome,
)

HOST = "canvas.example.test"  # the pinned default school of the test harness
KEY = f"entra:{TID}:{OID}"
KEY_2 = f"entra:{TID}:{OID_2}"
RECHECK = "/account/token/recheck"
SETTINGS_URL = f"https://{HOST}/profile/settings"
# The harness clock and the store clock both read 2027-01-15 08:00 UTC.
TODAY = datetime(2027, 1, 15, tzinfo=UTC)


def utc_midnight(year: int, month: int, day: int) -> int:
    return int(datetime(year, month, day, tzinfo=UTC).timestamp())


def seed(
    h: Harness,
    *,
    oid: str = OID,
    token: str = CANVAS_TOKEN,
    host: str | None = HOST,
    user_id: str = "42",
    name: str = "Ada Canvas",
    expires: int | None = None,
) -> None:
    h.store.put(
        tenant_id=TID, object_id=oid, api_token=token, canvas_user_id=user_id,
        canvas_user_name=name, entra_display_name="Ada", entra_upn="ada@example.test",
        canvas_host=host, expires_hint_at=expires,
    )


@pytest.fixture
def h(tmp_path: pathlib.Path) -> Harness:
    return build_harness(tmp_path)


@pytest.fixture
def events(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The raw audit lines, with the audit log switched on."""
    lines: list[str] = []

    class Recorder:
        def info(self, line: str) -> None:
            lines.append(line)

    monkeypatch.setattr(audit, "_audit_logger", Recorder())
    monkeypatch.setattr(audit, "_access_events_enabled", True)
    return lines


def tokens_events(lines: list[str]) -> list[dict[str, Any]]:
    """The canvas_token events among the audit lines."""
    return [json.loads(line) for line in lines if '"canvas_token"' in line]


def page(h: Harness) -> str:
    response = h.client.get(ACCOUNT_PATH)
    assert response.status_code == 200
    assert_security_headers(response)
    return response.text


def info(h: Harness, oid: str = OID) -> Any:
    row = h.store.info(TID, oid)
    assert row is not None
    return row


class TestBanner:
    def test_a_rejected_token_shows_a_banner_with_the_date_and_the_way_out(self, h: Harness) -> None:
        seed(h)
        h.store.mark_invalid(KEY, reason=REASON_CANVAS_TOKEN_REJECTED)
        sign_in(h)
        text = page(h)

        assert "Your Canvas token stopped working on 2027-01-15." in text
        assert "Canvas → Account → Settings → New Access Token" in text
        assert f'href="{SETTINGS_URL}"' in text
        assert 'rel="noopener noreferrer"' in text
        assert "Needs a new token" in text
        assert not CJK.search(strip_chrome(text))
        # The replace form is open, so "paste it below" works at once.
        assert re.search(r"<details class=\"card\" open>", text)
        assert 'name="canvas_token"' in text

    def test_the_check_again_button_is_a_csrf_protected_post(self, h: Harness) -> None:
        seed(h)
        h.store.mark_invalid(KEY, reason=REASON_CANVAS_TOKEN_REJECTED)
        sign_in(h)
        text = page(h)
        form = re.search(r'<form method="post" action="/account/token/recheck">(.*?)</form>', text, re.S)
        assert form is not None
        assert 'name="csrf"' in form.group(1)
        assert "Check again" in form.group(1)

    def test_an_active_token_has_no_banner_and_no_check_button(self, h: Harness) -> None:
        seed(h)
        sign_in(h)
        text = page(h)
        assert "stopped working" not in text
        assert "Check again" not in text
        assert RECHECK not in text
        assert "<dd>Active</dd>" in text

    def test_an_unreadable_token_banner(self, h: Harness) -> None:
        seed(h)
        h.store.mark_invalid(KEY, reason=REASON_DECRYPT_FAILED)
        sign_in(h)
        text = page(h)
        assert "the server cannot read your saved Canvas token" in text
        assert "Check again" in text  # fixing the keys can make it readable again

    def test_an_admin_marked_token_banner_has_no_check_button(self, h: Harness) -> None:
        seed(h)
        h.store.mark_invalid(KEY, reason=REASON_REVOKED_BY_ADMIN)
        sign_in(h)
        text = page(h)
        assert "An administrator marked your Canvas token as invalid on 2027-01-15." in text
        assert "Check again" not in text and RECHECK not in text

    def test_the_settings_link_is_only_offered_for_a_school_the_server_still_allows(
        self, h: Harness
    ) -> None:
        seed(h, host="canvas.gone.example")
        h.store.mark_invalid(KEY, reason=REASON_CANVAS_TOKEN_REJECTED)
        sign_in(h)
        text = page(h)
        assert "stopped working" in text
        assert "/profile/settings" not in text

    def test_names_in_the_banner_are_escaped(self, h: Harness) -> None:
        seed(h, name="<script>alert(1)</script>")
        h.store.mark_invalid(KEY, reason=REASON_CANVAS_TOKEN_REJECTED)
        sign_in(h)
        text = page(h)
        assert "<script>alert(1)" not in text


class TestExpiryReminder:
    def test_a_reminder_appears_seven_days_before(self, h: Harness) -> None:
        seed(h, expires=utc_midnight(2027, 1, 20))
        sign_in(h)
        text = page(h)
        assert "Your Canvas token expires on 2027-01-20." in text
        assert 'class="card banner soon"' in text
        assert "<dd>2027-01-20</dd>" in text

    def test_no_reminder_earlier_than_seven_days(self, h: Harness) -> None:
        seed(h, expires=utc_midnight(2027, 1, 25))
        sign_in(h)
        text = page(h)
        assert "Your Canvas token expires on" not in text
        assert "<dd>2027-01-25</dd>" in text  # still listed in the status card

    def test_a_passed_expiry_date_is_said_so(self, h: Harness) -> None:
        seed(h, expires=utc_midnight(2027, 1, 10))
        sign_in(h)
        assert "passed its expiry date of 2027-01-10" in page(h)

    def test_no_hint_no_reminder(self, h: Harness) -> None:
        seed(h)
        sign_in(h)
        assert "Your Canvas token expires on" not in page(h)

    def test_the_banner_for_an_invalid_token_wins_over_the_reminder(self, h: Harness) -> None:
        seed(h, expires=utc_midnight(2027, 1, 20))
        h.store.mark_invalid(KEY, reason=REASON_CANVAS_TOKEN_REJECTED)
        sign_in(h)
        text = page(h)
        assert "stopped working" in text
        assert "Your Canvas token expires on" not in text


class TestRecheck:
    @pytest.fixture
    def invalid(self, h: Harness) -> Harness:
        seed(h)
        h.store.mark_invalid(KEY, reason=REASON_CANVAS_TOKEN_REJECTED)
        sign_in(h)
        return h

    def test_success_restores_the_token(self, invalid: Harness, events: list[str]) -> None:
        h = invalid
        response = post_form(h, RECHECK, {"csrf": csrf_of(h)})

        assert response.status_code == 200
        assert "Canvas accepts this token again. It is active." in response.text
        assert "stopped working" not in response.text
        row = info(h)
        assert row.status == STATUS_ACTIVE and row.invalid_reason is None and row.invalid_since is None
        assert h.whoami_calls == [CANVAS_TOKEN]  # the stored token was probed
        assert h.whoami_urls == [f"https://{HOST}/api/v1"]
        assert [(e["action"], e.get("outcome"), e["principal"]) for e in tokens_events(events)] == [
            ("recheck", "restored", KEY)
        ]

    def test_canvas_still_rejecting_leaves_it_invalid(
        self, invalid: Harness, events: list[str]
    ) -> None:
        h = invalid
        h.whoami_result = CanvasCheckError("invalid")
        response = post_form(h, RECHECK, {"csrf": csrf_of(h)})
        assert response.status_code == 400
        assert "Canvas still rejects this token." in response.text
        assert info(h).status == STATUS_INVALID
        assert [e.get("outcome") for e in tokens_events(events)] == ["still_rejected"]

    def test_canvas_being_down_changes_nothing(
        self, invalid: Harness, events: list[str]
    ) -> None:
        h = invalid
        h.whoami_result = CanvasCheckError("unavailable")
        response = post_form(h, RECHECK, {"csrf": csrf_of(h)})
        assert response.status_code == 503
        assert "Canvas is unavailable right now." in response.text
        assert info(h).status == STATUS_INVALID
        assert [e.get("outcome") for e in tokens_events(events)] == ["unavailable"]

    def test_once_a_minute_per_user(self, invalid: Harness) -> None:
        h = invalid
        h.whoami_result = CanvasCheckError("invalid")
        csrf = csrf_of(h)
        assert post_form(h, RECHECK, {"csrf": csrf}).status_code == 400
        h.now += 30
        limited = post_form(h, RECHECK, {"csrf": csrf})
        assert limited.status_code == 429
        assert "You can check once a minute." in limited.text
        assert len(h.whoami_calls) == 1  # the second click never reached Canvas
        h.now += 31  # a full minute after the first check
        h.whoami_result = CanvasIdentity("42", "Ada Canvas")
        assert post_form(h, RECHECK, {"csrf": csrf}).status_code == 200
        assert len(h.whoami_calls) == 2
        assert info(h).status == STATUS_ACTIVE

    def test_the_limit_is_per_user(self, invalid: Harness) -> None:
        h = invalid
        seed(h, oid=OID_2, token="9~" + "U" * 62)
        h.store.mark_invalid(KEY_2, reason=REASON_CANVAS_TOKEN_REJECTED)
        h.whoami_result = CanvasCheckError("invalid")
        post_form(h, RECHECK, {"csrf": csrf_of(h)})
        sign_in(h, oid=OID_2)
        assert post_form(h, RECHECK, {"csrf": csrf_of(h)}).status_code == 400  # not 429

    def test_csrf_origin_and_session_are_required(self, invalid: Harness) -> None:
        h = invalid
        csrf = csrf_of(h)
        assert post_form(h, RECHECK, {"csrf": "wrong"}).status_code == 403
        assert post_form(h, RECHECK, {}).status_code == 403
        assert post_form(h, RECHECK, {"csrf": csrf}, origin="https://evil.example").status_code == 403
        assert post_form(h, RECHECK, {"csrf": csrf}, origin=None).status_code == 403
        assert h.whoami_calls == []
        assert info(h).status == STATUS_INVALID
        h.client.cookies.clear()
        response = post_form(h, RECHECK, {"csrf": csrf})
        assert response.status_code == 303 and response.headers["location"] == ACCOUNT_PATH

    def test_get_is_not_allowed(self, invalid: Harness) -> None:
        assert invalid.client.get(RECHECK).status_code == 405

    def test_an_active_token_is_not_probed(self, h: Harness) -> None:
        seed(h)
        sign_in(h)
        response = post_form(h, RECHECK, {"csrf": csrf_of(h)})
        assert response.status_code == 303
        assert h.whoami_calls == []

    def test_an_admin_decision_cannot_be_undone_by_the_user(self, h: Harness) -> None:
        seed(h)
        h.store.mark_invalid(KEY, reason=REASON_REVOKED_BY_ADMIN)
        sign_in(h)
        response = post_form(h, RECHECK, {"csrf": csrf_of(h)})
        assert response.status_code == 303
        assert h.whoami_calls == []
        assert info(h).status == STATUS_INVALID

    def test_an_enrollment_that_is_gone_just_redirects(self, h: Harness) -> None:
        sign_in(h)
        response = post_form(h, RECHECK, {"csrf": csrf_of(h)})
        assert response.status_code == 303 and h.whoami_calls == []

    def test_a_still_unreadable_token_is_reported(
        self, h: Harness, events: list[str]
    ) -> None:
        seed(h)
        h.store.mark_invalid(KEY, reason=REASON_DECRYPT_FAILED)
        with sqlite3.connect(str(h.store._path)) as conn:
            conn.execute("UPDATE canvas_tokens SET ciphertext = ?", (b"x" * 40,))
        sign_in(h)
        response = post_form(h, RECHECK, {"csrf": csrf_of(h)})
        assert response.status_code == 400
        assert "still cannot be read" in response.text
        assert h.whoami_calls == []
        assert info(h).status == STATUS_INVALID
        assert [e.get("outcome") for e in tokens_events(events)] == ["unreadable"]

    def test_a_school_the_server_no_longer_offers_is_reported(self, h: Harness) -> None:
        seed(h, host="canvas.gone.example")
        h.store.mark_invalid(KEY, reason=REASON_CANVAS_TOKEN_REJECTED)
        sign_in(h)
        response = post_form(h, RECHECK, {"csrf": csrf_of(h)})
        assert response.status_code == 400
        assert "no longer offers your school" in response.text
        assert h.whoami_calls == []

    def test_a_token_replaced_during_the_check_is_left_alone(
        self, invalid: Harness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        h = invalid
        real = h.store.restore_active

        def replaced_meanwhile(*args: Any, **kwargs: Any) -> bool:
            h.store.put(
                tenant_id=TID, object_id=OID, api_token="the-replacement-token-0123456789",
                canvas_user_id="42", canvas_user_name="Ada Canvas", entra_display_name="Ada",
                entra_upn="ada@example.test", canvas_host=HOST, expires_hint_at=None,
            )
            return real(*args, **kwargs)

        monkeypatch.setattr(h.store, "restore_active", replaced_meanwhile)
        response = post_form(h, RECHECK, {"csrf": csrf_of(h)})
        assert response.status_code == 303
        row = info(h)
        assert row.status == STATUS_ACTIVE
        got = h.store.get(TID, OID)
        assert got is not None and got.api_token == "the-replacement-token-0123456789"


class TestEnrollmentFields:
    def enroll_with(self, h: Harness, **fields: str) -> httpx.Response:
        return post_form(h, "/account/token", {"csrf": csrf_of(h), "canvas_token": CANVAS_TOKEN, **fields})

    def test_the_form_asks_for_an_optional_expiry_date(self, h: Harness) -> None:
        sign_in(h)
        text = page(h)
        assert 'name="expires_on"' in text and 'type="date"' in text
        assert "Token expires on (optional)" in text

    def test_a_valid_date_is_stored_as_the_reminder_hint(self, h: Harness) -> None:
        sign_in(h)
        assert self.enroll_with(h, expires_on="2027-01-20").status_code == 303
        assert info(h).expires_hint_at == utc_midnight(2027, 1, 20)

    def test_today_is_accepted(self, h: Harness) -> None:
        sign_in(h)
        assert self.enroll_with(h, expires_on="2027-01-15").status_code == 303
        assert info(h).expires_hint_at == utc_midnight(2027, 1, 15)

    def test_leaving_it_blank_stores_no_hint(self, h: Harness) -> None:
        sign_in(h)
        assert self.enroll_with(h, expires_on="").status_code == 303
        assert info(h).expires_hint_at is None
        assert self.enroll_with(h).status_code == 303
        assert info(h).expires_hint_at is None

    def test_a_new_token_replaces_the_old_hint(self, h: Harness) -> None:
        sign_in(h)
        self.enroll_with(h, expires_on="2027-02-01")
        assert info(h).expires_hint_at == utc_midnight(2027, 2, 1)
        self.enroll_with(h)  # the replacement token has its own (unknown) expiry
        assert info(h).expires_hint_at is None

    @pytest.mark.parametrize(
        "value",
        ["2027-01-14", "yesterday", "2027-02-30", "27-01-20", "2099-01-01", "2027-1-20", "2027-01-20T10:00"],
    )
    def test_a_bad_date_is_refused_before_canvas_is_asked(self, h: Harness, value: str) -> None:
        sign_in(h)
        response = self.enroll_with(h, expires_on=value)
        assert response.status_code == 400
        assert "That expiry date is not valid." in response.text
        assert h.whoami_calls == []
        assert h.store.count() == 0

    def test_enrolling_a_new_token_restores_an_invalid_row(self, h: Harness) -> None:
        seed(h)
        h.store.mark_invalid(KEY, reason=REASON_CANVAS_TOKEN_REJECTED)
        sign_in(h)
        assert self.enroll_with(h, canvas_token="7~" + "N" * 62).status_code == 303
        row = info(h)
        assert row.status == STATUS_ACTIVE and row.invalid_reason is None
        assert "stopped working" not in page(h)


def confirmation_of(response: httpx.Response) -> str:
    """The value of the identity-change checkbox on the page that warned the user."""
    found = re.search(r'name="confirm_identity_change" value="([^"]+)"', response.text)
    assert found is not None
    return found.group(1)


class SpyHealth:
    """Stands in for the shared TokenHealth: records which principals were forgotten."""

    def __init__(self) -> None:
        self.forgotten: list[str] = []

    def forget(self, principal_key: str) -> None:
        self.forgotten.append(principal_key)


class TestProbeVerdictIsForgotten:
    """A cached "Canvas rejected it" verdict must not outlive a restored or replaced token."""

    def spy_harness(self, tmp_path: pathlib.Path) -> tuple[Harness, SpyHealth]:
        spy = SpyHealth()
        return build_harness(tmp_path, health=spy), spy

    def test_a_successful_recheck_drops_the_cached_verdict(self, tmp_path: pathlib.Path) -> None:
        h, spy = self.spy_harness(tmp_path)
        seed(h)
        h.store.mark_invalid(KEY, reason=REASON_CANVAS_TOKEN_REJECTED)
        sign_in(h)
        assert post_form(h, RECHECK, {"csrf": csrf_of(h)}).status_code == 200
        assert spy.forgotten == [KEY]

    def test_a_recheck_that_changes_nothing_keeps_it(self, tmp_path: pathlib.Path) -> None:
        h, spy = self.spy_harness(tmp_path)
        seed(h)
        h.store.mark_invalid(KEY, reason=REASON_CANVAS_TOKEN_REJECTED)
        sign_in(h)
        h.whoami_result = CanvasCheckError("invalid")
        assert post_form(h, RECHECK, {"csrf": csrf_of(h)}).status_code == 400
        assert spy.forgotten == []

    def test_saving_a_token_drops_the_cached_verdict(self, tmp_path: pathlib.Path) -> None:
        h, spy = self.spy_harness(tmp_path)
        seed(h)
        h.store.mark_invalid(KEY, reason=REASON_CANVAS_TOKEN_REJECTED)
        sign_in(h)
        response = post_form(
            h, "/account/token", {"csrf": csrf_of(h), "canvas_token": "7~" + "N" * 62}
        )
        assert response.status_code == 303
        assert spy.forgotten == [KEY]


class TestIdentityChange:
    def test_a_token_for_another_canvas_user_needs_an_explicit_confirmation(
        self, h: Harness, events: list[str]
    ) -> None:
        seed(h, user_id="42", name="Ada <b>Old</b>")
        sign_in(h)
        h.whoami_result = CanvasIdentity("99", "Grace <i>New</i>")
        csrf = csrf_of(h)
        new_token = "7~" + "Z" * 62

        response = post_form(h, "/account/token", {"csrf": csrf, "canvas_token": new_token})

        assert response.status_code == 409
        text = response.text
        assert "This token belongs to a different Canvas user." in text
        assert 'name="confirm_identity_change"' in text and "required" in text
        assert "Grace &lt;i&gt;New&lt;/i&gt;" in text and "Ada &lt;b&gt;Old&lt;/b&gt;" in text
        assert "<i>New</i>" not in text
        assert new_token not in text  # the form never echoes a token back
        # Nothing was saved.
        row = info(h)
        assert row.canvas_user_id == "42"
        got = h.store.get(TID, OID)
        assert got is not None and got.api_token == CANVAS_TOKEN
        assert [(e["action"], e["principal"]) for e in tokens_events(events)] == [
            ("identity_change_detected", KEY)
        ]

        confirmed = post_form(
            h, "/account/token",
            {
                "csrf": csrf,
                "canvas_token": new_token,
                "confirm_identity_change": confirmation_of(response),
            },
        )
        assert confirmed.status_code == 303
        row = info(h)
        assert row.canvas_user_id == "99" and row.status == STATUS_ACTIVE
        got = h.store.get(TID, OID)
        assert got is not None and got.api_token == new_token
        assert [e["action"] for e in tokens_events(events)] == [
            "identity_change_detected",
            "identity_change_confirmed",
        ]
        blob = json.dumps(tokens_events(events))
        assert "Grace" not in blob and "Ada" not in blob and new_token not in blob

    def test_a_confirmation_sent_with_the_first_post_does_not_skip_the_warning(
        self, h: Harness
    ) -> None:
        seed(h, user_id="42")
        sign_in(h)
        h.whoami_result = CanvasIdentity("99", "Grace")
        csrf = csrf_of(h)
        for value in ("1", "", "0", "yes", "true", "x" * 43):
            response = post_form(
                h, "/account/token",
                {"csrf": csrf, "canvas_token": CANVAS_TOKEN, "confirm_identity_change": value},
            )
            assert response.status_code == 409, value
        assert info(h).canvas_user_id == "42"

    def test_a_confirmation_for_one_user_does_not_accept_a_token_for_another(
        self, h: Harness
    ) -> None:
        seed(h, user_id="42")
        sign_in(h)
        csrf = csrf_of(h)
        h.whoami_result = CanvasIdentity("99", "Grace")
        warned = post_form(h, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN})
        assert warned.status_code == 409
        confirmation_for_grace = confirmation_of(warned)

        # The user pastes a token for a third Canvas user and keeps the box ticked.
        h.whoami_result = CanvasIdentity("123", "Heidi")
        again = post_form(
            h, "/account/token",
            {
                "csrf": csrf,
                "canvas_token": "7~" + "H" * 62,
                "confirm_identity_change": confirmation_for_grace,
            },
        )

        assert again.status_code == 409
        assert "Heidi" in again.text and "Grace" not in again.text  # warned about the new user
        assert confirmation_of(again) != confirmation_for_grace
        assert info(h).canvas_user_id == "42"

    def test_a_confirmation_from_another_session_is_refused(self, h: Harness) -> None:
        seed(h, user_id="42")
        sign_in(h)
        h.whoami_result = CanvasIdentity("99", "Grace")
        warned = post_form(h, "/account/token", {"csrf": csrf_of(h), "canvas_token": CANVAS_TOKEN})
        stolen = confirmation_of(warned)

        h.client.cookies.clear()
        sign_in(h)  # a new session has its own CSRF value
        response = post_form(
            h, "/account/token",
            {"csrf": csrf_of(h), "canvas_token": CANVAS_TOKEN, "confirm_identity_change": stolen},
        )
        assert response.status_code == 409
        assert info(h).canvas_user_id == "42"

    def test_the_same_canvas_user_needs_no_confirmation(self, h: Harness) -> None:
        seed(h, user_id="42")
        sign_in(h)
        h.whoami_result = CanvasIdentity("42", "Ada Canvas")
        response = post_form(h, "/account/token", {"csrf": csrf_of(h), "canvas_token": "7~" + "Y" * 62})
        assert response.status_code == 303

    def test_a_first_enrollment_needs_no_confirmation(self, h: Harness) -> None:
        sign_in(h)
        h.whoami_result = CanvasIdentity("99", "Grace")
        response = post_form(h, "/account/token", {"csrf": csrf_of(h), "canvas_token": CANVAS_TOKEN})
        assert response.status_code == 303

    def test_an_invalid_row_still_checks_the_identity(self, h: Harness) -> None:
        seed(h, user_id="42")
        h.store.mark_invalid(KEY, reason=REASON_CANVAS_TOKEN_REJECTED)
        sign_in(h)
        h.whoami_result = CanvasIdentity("99", "Grace")
        response = post_form(h, "/account/token", {"csrf": csrf_of(h), "canvas_token": CANVAS_TOKEN})
        assert response.status_code == 409
        assert info(h).status == STATUS_INVALID

    def test_a_legacy_row_is_compared_with_the_default_school(self, h: Harness) -> None:
        seed(h, user_id="42", host=None)
        sign_in(h)
        h.whoami_result = CanvasIdentity("99", "Grace")
        response = post_form(h, "/account/token", {"csrf": csrf_of(h), "canvas_token": CANVAS_TOKEN})
        assert response.status_code == 409

    def test_a_different_school_is_a_different_account_and_needs_no_confirmation(
        self, tmp_path: pathlib.Path
    ) -> None:
        r = rig(tmp_path)
        r.h.store.put(
            tenant_id=TID, object_id=OID, api_token=CANVAS_TOKEN, canvas_user_id="7",
            canvas_user_name="Old", entra_display_name="Old", entra_upn="o@example.test",
            canvas_host=HOST_A,
        )
        sign_in(r.h)
        # Canvas user ids are per school: id 42 at another school is not a change.
        assert enroll(r, DEFAULT_HOST).status_code == 303
        row = r.h.store.info(TID, OID)
        assert row is not None and row.canvas_host == DEFAULT_HOST and row.canvas_user_id == "42"


class TestAdminHealth:
    def owner_page(self, h: Harness, query: str = "") -> httpx.Response:
        response = h.client.get("/account/admin" + query)
        assert response.status_code == 200
        return response

    def seed_three(self, h: Harness) -> None:
        seed(h, oid=OID, name="Active Ann")
        seed(h, oid=OID_2, name="Dead Dan", token="9~" + "D" * 62)
        h.store.mark_invalid(KEY_2, reason=REASON_CANVAS_TOKEN_REJECTED)
        seed(h, oid="cccccccc-1111-2222-3333-444444444444", name="Gone Gus", token="9~" + "G" * 62)
        h.store.mark_invalid(
            f"entra:{TID}:cccccccc-1111-2222-3333-444444444444", reason=REASON_REVOKED_BY_ADMIN
        )

    def test_columns_for_status_reason_since_and_last_verified(self, h: Harness) -> None:
        self.seed_three(h)
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        text = self.owner_page(h).text

        for heading in ("Status", "Last verified", "Last used"):
            assert f"<th>{heading}</th>" in text
        assert "<td data-label=\"Status\">Active</td>" in text
        assert "<strong>Needs re-enroll</strong>" in text
        assert "Rejected by Canvas" in text
        assert "Marked invalid by an administrator" in text
        assert "Invalid since: 2027-01-15 08:00 UTC" in text
        assert "2027-01-15 08:00 UTC" in text  # last verified of the active row
        assert not CJK.search(strip_chrome(text))

    def test_the_count_and_the_filter(self, h: Harness) -> None:
        self.seed_three(h)
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        text = self.owner_page(h).text
        assert "2 of 3 enrollments need a new token." in text
        assert 'href="/account/admin?filter=needs_reenroll"' in text
        assert "Active Ann" in text and "Dead Dan" in text and "Gone Gus" in text

        filtered = self.owner_page(h, "?filter=needs_reenroll").text
        assert "Active Ann" not in filtered
        assert "Dead Dan" in filtered and "Gone Gus" in filtered
        assert "2 of 3 enrollments need a new token." in filtered
        assert 'href="/account/admin"' in filtered and "Show all" in filtered

    def test_an_unknown_filter_value_shows_everything(self, h: Harness) -> None:
        self.seed_three(h)
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        text = self.owner_page(h, "?filter=<script>").text
        assert "Active Ann" in text and "<script>" not in text

    def test_an_empty_filter_result_says_so(self, h: Harness) -> None:
        seed(h)
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        text = self.owner_page(h, "?filter=needs_reenroll").text
        assert "No enrollments need a new token." in text
        assert "0 of 1 enrollments need a new token." in text

    def test_the_mark_button_is_only_for_active_rows(self, h: Harness) -> None:
        self.seed_three(h)
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        text = self.owner_page(h).text
        assert text.count('action="/account/admin/invalidate"') == 1
        assert text.count('action="/account/admin/remove"') == 3

    def test_marking_invalid_needs_an_owner_origin_and_csrf(self, h: Harness) -> None:
        seed(h)
        target = {"tenant_id": TID, "object_id": OID}
        url = "/account/admin/invalidate"
        assert post_form(h, url, {"csrf": "x", **target}).status_code == 403  # signed out
        sign_in(h, oid=OID_2)
        assert post_form(h, url, {"csrf": csrf_of(h), **target}).status_code == 403  # not an owner
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        csrf = csrf_of(h)
        assert post_form(h, url, {"csrf": "bad", **target}).status_code == 403
        assert post_form(h, url, {"csrf": csrf, **target}, origin=None).status_code == 403
        assert post_form(h, url, {"csrf": csrf, **target}, origin="https://evil.example").status_code == 403
        assert info(h).status == STATUS_ACTIVE

    def test_marking_invalid_records_the_reason_and_audits_it(
        self, h: Harness, events: list[str]
    ) -> None:
        seed(h)
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        response = post_form(
            h, "/account/admin/invalidate", {"csrf": csrf_of(h), "tenant_id": TID, "object_id": OID}
        )
        assert response.status_code == 303 and response.headers["location"] == "/account/admin"

        row = info(h)
        assert row.status == STATUS_INVALID and row.invalid_reason == REASON_REVOKED_BY_ADMIN
        recorded = tokens_events(events)
        assert len(recorded) == 1
        assert recorded[0]["action"] == "admin_marked_invalid"
        assert recorded[0]["principal"] == KEY  # the target, not the administrator
        assert recorded[0]["actor"] == f"entra:{TID}:{OID_OWNER}"
        assert recorded[0]["reason"] == REASON_REVOKED_BY_ADMIN

        # The user now sees the administrator's banner and must enroll again.
        sign_in(h)
        text = page(h)
        assert "An administrator marked your Canvas token as invalid" in text
        assert "Check again" not in text

    def test_marking_twice_audits_once(self, h: Harness, events: list[str]) -> None:
        seed(h)
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        fields = {"csrf": csrf_of(h), "tenant_id": TID, "object_id": OID}
        post_form(h, "/account/admin/invalidate", fields)
        post_form(h, "/account/admin/invalidate", fields)
        assert len(tokens_events(events)) == 1

    @pytest.mark.parametrize(
        "fields",
        [{"tenant_id": "x", "object_id": OID}, {"tenant_id": TID, "object_id": "../../etc"}, {}],
    )
    def test_marking_validates_the_identifiers(self, h: Harness, fields: dict[str, str]) -> None:
        seed(h)
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        response = post_form(h, "/account/admin/invalidate", {"csrf": csrf_of(h), **fields})
        assert response.status_code == 400
        assert info(h).status == STATUS_ACTIVE

    def test_marking_an_unknown_user_is_harmless(self, h: Harness) -> None:
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        response = post_form(
            h, "/account/admin/invalidate", {"csrf": csrf_of(h), "tenant_id": TID, "object_id": OID_2}
        )
        assert response.status_code == 303
        assert h.store.count() == 0
