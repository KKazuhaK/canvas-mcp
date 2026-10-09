"""Revocation as an authorization decision, through the /account pages.

The reproduction behind these tests: enroll, an administrator revokes by deleting the
row, the user re-enrolls with the still-valid sealed /account session and the row is
back. Now the administrator disables the user; that decision lives apart from the row
and from the browser session, and every path below checks it again.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any

import pytest

from canvas_mcp.core import audit
from canvas_mcp.core.selfhost import account_web
from canvas_mcp.core.selfhost.account_web import ACCOUNT_PATH, SESSION_COOKIE
from canvas_mcp.core.selfhost.principal_access import PrincipalAccessCache
from canvas_mcp.core.selfhost.token_store import (
    DISABLE_REASON_OPERATOR,
    OPERATOR,
    AccessActionRefused,
    PrincipalDisabledError,
)

from .test_account_web import (
    CANVAS_TOKEN,
    OID,
    OID_2,
    OID_OWNER,
    SESSION_SECRET,
    TID,
    Harness,
    build_harness,
    csrf_of,
    post_form,
    sign_in,
)

OID_OWNER_2 = "dddddddd-eeee-ffff-0000-111111111111"
USER = f"entra:{TID}:{OID}"
USER_2 = f"entra:{TID}:{OID_2}"
OWNER = f"entra:{TID}:{OID_OWNER}"
OWNER_2 = f"entra:{TID}:{OID_OWNER_2}"
DISABLE = "/account/admin/disable"
ENABLE = "/account/admin/enable"
REMOVE = "/account/admin/remove"
SIGN_IN_TEXT = "Sign in with Microsoft"


@pytest.fixture
def h(tmp_path: pathlib.Path) -> Harness:
    return build_harness(tmp_path)


@pytest.fixture
def events(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    lines: list[str] = []

    class Recorder:
        def info(self, line: str) -> None:
            lines.append(line)

    monkeypatch.setattr(audit, "_audit_logger", Recorder())
    monkeypatch.setattr(audit, "_access_events_enabled", True)
    return lines


def principal_events(lines: list[str]) -> list[dict[str, Any]]:
    return [json.loads(line) for line in lines if '"principal_status"' in line]


def cookie(h: Harness) -> str:
    value = h.client.cookies.get(SESSION_COOKIE)
    assert value
    return value


def use_cookie(h: Harness, value: str) -> None:
    h.client.cookies.set(SESSION_COOKIE, value, domain="canvas.example.test", path="/")


def signed_out(h: Harness) -> bool:
    return SIGN_IN_TEXT in h.client.get(ACCOUNT_PATH).text


def enroll(h: Harness) -> None:
    csrf = csrf_of(h)
    assert post_form(h, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN}).status_code == 303


def two_owners_and_a_user(h: Harness) -> dict[str, str]:
    """Owner 1 and owner 2 exist (signed in once each); the user is enrolled.

    Returns the three sealed session cookies.
    """
    sign_in(h, oid=OID_OWNER_2, name="Second Owner", roles=("Canvas.Owner",))
    jar = {"owner2": cookie(h)}
    sign_in(h)  # the plain user
    enroll(h)
    jar["user"] = cookie(h)
    sign_in(h, oid=OID_OWNER, name="Olive Owner", roles=("Canvas.Owner",))
    jar["owner"] = cookie(h)
    return jar


def disable_user(h: Harness, target: str = USER) -> Any:
    return post_form(h, DISABLE, {"csrf": csrf_of(h), "principal_key": target})


class TestTheReportedSequence:
    def test_a_stale_session_cannot_restore_a_disabled_users_enrollment(self, h: Harness) -> None:
        jar = two_owners_and_a_user(h)
        # The owner disables the user, then removes the stored token as well.
        assert disable_user(h).status_code == 303
        assert post_form(
            h, REMOVE, {"csrf": csrf_of(h), "tenant_id": TID, "object_id": OID}
        ).status_code == 303
        assert h.store.info(USER) is None
        # The user's sealed session is still within its lifetime and sealed by us.
        use_cookie(h, jar["user"])
        assert signed_out(h)
        response = post_form(h, "/account/token", {"csrf": "whatever", "canvas_token": CANVAS_TOKEN})
        assert response.status_code == 303 and response.headers["location"] == ACCOUNT_PATH
        assert h.store.info(USER) is None  # the row did not come back
        assert h.whoami_calls == [CANVAS_TOKEN]  # only the first, legitimate enrollment

    def test_signing_in_again_is_refused_with_a_clear_message(self, h: Harness) -> None:
        two_owners_and_a_user(h)
        disable_user(h)
        response = sign_in(h)
        assert response.status_code == 403
        assert "disabled by an administrator" in response.text
        assert SESSION_COOKIE not in response.headers.get("set-cookie", "")

    def test_enrolling_with_a_session_that_is_still_valid_is_refused_at_the_store(
        self, h: Harness, events: list[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The window between the session check and the write: the store refuses.
        sign_in(h)
        csrf = csrf_of(h)

        def refuse(**_kw: Any) -> None:
            raise PrincipalDisabledError("this principal is disabled")

        monkeypatch.setattr(h.store, "put", refuse)
        response = post_form(h, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN})
        assert response.status_code == 403
        assert "disabled by an administrator" in response.text
        assert [e["action"] for e in principal_events(events)] == ["enroll_refused"]
        assert CANVAS_TOKEN not in "".join(events)

    def test_enabling_again_does_not_revive_the_old_session_but_a_new_sign_in_works(
        self, h: Harness
    ) -> None:
        jar = two_owners_and_a_user(h)
        disable_user(h)
        assert post_form(h, ENABLE, {"csrf": csrf_of(h), "principal_key": USER}).status_code == 303
        use_cookie(h, jar["user"])
        assert signed_out(h)  # the epoch moved on twice since this session was issued
        assert sign_in(h).status_code == 303
        assert "Canvas token enrolled" in h.client.get(ACCOUNT_PATH).text  # the kept enrollment
        enroll(h)  # and they can replace it

    def test_the_users_open_session_is_dead_the_moment_they_are_disabled(self, h: Harness) -> None:
        jar = two_owners_and_a_user(h)
        use_cookie(h, jar["user"])
        assert "Canvas token enrolled" in h.client.get(ACCOUNT_PATH).text
        use_cookie(h, jar["owner"])
        disable_user(h)
        use_cookie(h, jar["user"])
        assert signed_out(h)  # no waiting for the cookie to expire, no cache here
        # Every state-changing route behaves as signed out.
        for path in ("/account/token/delete", "/account/token/recheck", "/account/write-tools"):
            response = post_form(h, path, {"csrf": "x"})
            assert response.status_code == 303 and response.headers["location"] == ACCOUNT_PATH
        assert h.store.info(USER) is not None  # the delete route did nothing


class TestSelfDisconnectIsNotRevocation:
    def test_deleting_your_own_token_leaves_you_free_to_enroll_again(
        self, h: Harness, events: list[str]
    ) -> None:
        sign_in(h)
        enroll(h)
        response = post_form(h, "/account/token/delete", {"csrf": csrf_of(h)})
        assert response.status_code == 303
        assert h.store.info(USER) is None
        assert not h.store.get_principal_status(USER).disabled
        assert h.store.get_principal_status(USER).session_epoch == 0  # the session stays valid
        enroll(h)
        assert h.store.get(USER) is not None
        assert [e["action"] for e in principal_events(events)] == ["self_disconnected"]

    def test_the_page_says_it_is_only_a_disconnect(self, h: Harness) -> None:
        sign_in(h)
        enroll(h)
        text = h.client.get(ACCOUNT_PATH).text
        assert "This only disconnects your own Canvas token" in text

    def test_removing_an_enrollment_as_an_owner_leaves_the_user_free_to_enroll(
        self, h: Harness
    ) -> None:
        jar = two_owners_and_a_user(h)
        assert post_form(
            h, REMOVE, {"csrf": csrf_of(h), "tenant_id": TID, "object_id": OID}
        ).status_code == 303
        assert h.store.info(USER) is None
        use_cookie(h, jar["user"])
        enroll(h)
        assert h.store.get(USER) is not None


class TestOwnersAreCheckedAgain:
    def test_an_owner_session_older_than_ten_minutes_cannot_use_the_admin_pages(
        self, h: Harness
    ) -> None:
        two_owners_and_a_user(h)
        csrf = csrf_of(h)
        h.now += 601
        page = h.client.get("/account/admin")
        assert page.status_code == 403 and "last 10 minutes" in page.text
        response = post_form(h, DISABLE, {"csrf": csrf, "principal_key": USER})
        assert response.status_code == 403
        assert not h.store.get_principal_status(USER).disabled
        # The link in the header is still shown (the cookie is valid), the page asks to sign in.
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        assert h.client.get("/account/admin").status_code == 200

    def test_an_owner_whose_role_a_later_sign_in_no_longer_shows_loses_the_admin_pages(
        self, h: Harness
    ) -> None:
        jar = two_owners_and_a_user(h)
        csrf = csrf_of(h)
        assert h.client.get("/account/admin").status_code == 200
        # The same person signs in again (another browser) and the Entra role is gone.
        sign_in(h, oid=OID_OWNER, roles=("Canvas.User",))
        use_cookie(h, jar["owner"])  # back to the old session, whose cookie says owner
        assert h.client.get("/account/admin").status_code == 403
        assert 'href="/account/admin"' not in h.client.get(ACCOUNT_PATH).text
        assert post_form(h, DISABLE, {"csrf": csrf, "principal_key": USER}).status_code == 403
        assert not h.store.get_principal_status(USER).disabled

    def test_an_owner_demoted_by_a_newer_request_token_loses_the_admin_pages(
        self, h: Harness
    ) -> None:
        two_owners_and_a_user(h)
        assert h.client.get("/account/admin").status_code == 200
        # The MCP path saw a token issued after the sign-in without the owner role.
        assert h.store.demote_owner(OWNER, evidence_issued_at=int(h.now) + 5)
        assert h.client.get("/account/admin").status_code == 403

    def test_an_owner_who_was_disabled_has_no_session_at_all(self, h: Harness) -> None:
        jar = two_owners_and_a_user(h)
        sign_in(h, oid=OID_OWNER_2, roles=("Canvas.Owner",))  # owner 2 acts ...
        assert disable_user(h, OWNER).status_code == 303  # ... and disables owner 1
        use_cookie(h, jar["owner"])  # owner 1's sealed session is still within its lifetime
        assert signed_out(h)
        assert h.client.get("/account/admin").status_code == 403

    def test_a_forged_owner_flag_in_the_cookie_is_not_trusted(self, h: Harness) -> None:
        # A cookie sealed by us that claims owner for someone the store never saw as one.
        sign_in(h)
        codec = account_web._CookieCodec(SESSION_SECRET)
        forged = codec.seal(
            SESSION_COOKIE,
            {
                "v": 2, "ep": 0, "tid": TID, "oid": OID, "name": "x", "upn": "x",
                "owner": True, "iat": int(h.now), "exp": int(h.now) + 600, "csrf": "c",
            },
        )
        use_cookie(h, forged)
        assert h.client.get("/account/admin").status_code == 403

    def test_a_non_owner_and_a_signed_out_visitor_cannot_use_the_actions(self, h: Harness) -> None:
        two_owners_and_a_user(h)
        sign_in(h)
        csrf = csrf_of(h)
        for path in (DISABLE, ENABLE):
            assert post_form(h, path, {"csrf": csrf, "principal_key": USER_2}).status_code == 403
        assert h.store.list_principal_statuses() != []  # only the two owners' records
        assert not any(st.disabled for st in h.store.list_principal_statuses())
        h.client.cookies.clear()
        assert post_form(h, DISABLE, {"csrf": "x", "principal_key": USER}).status_code == 403

    def test_actions_need_csrf_and_the_right_origin(self, h: Harness) -> None:
        two_owners_and_a_user(h)
        csrf = csrf_of(h)
        fields = {"principal_key": USER}
        assert post_form(h, DISABLE, {"csrf": "bad", **fields}).status_code == 403
        assert post_form(h, DISABLE, {"csrf": csrf, **fields}, origin=None).status_code == 403
        assert post_form(
            h, DISABLE, {"csrf": csrf, **fields}, origin="https://evil.example"
        ).status_code == 403
        assert not h.store.get_principal_status(USER).disabled

    @pytest.mark.parametrize("value", ["", "NOT A KEY", "entra:x:y", "UPPER:case", "a" * 300])
    def test_the_target_must_be_a_well_formed_principal_key(self, h: Harness, value: str) -> None:
        two_owners_and_a_user(h)
        response = post_form(h, DISABLE, {"csrf": csrf_of(h), "principal_key": value})
        assert response.status_code == 400


class TestGuardrails:
    def test_an_owner_cannot_disable_themselves(self, h: Harness, events: list[str]) -> None:
        two_owners_and_a_user(h)
        response = disable_user(h, OWNER)
        assert response.status_code == 400 and "cannot disable your own account" in response.text
        assert not h.store.get_principal_status(OWNER).disabled
        assert [(e["action"], e["outcome"]) for e in principal_events(events)
                if e["action"] == "refused"] == [("refused", "self")]

    def test_the_own_row_has_no_disable_button(self, h: Harness) -> None:
        two_owners_and_a_user(h)
        h.store.put(
            tenant_id=TID, object_id=OID_OWNER, api_token=CANVAS_TOKEN, canvas_user_id="1",
            canvas_user_name="Olive", entra_display_name="Olive", entra_upn="o@example.test",
        )
        text = h.client.get("/account/admin").text
        assert "(you)" in text
        assert f'name="principal_key" value="{OWNER}"' not in text

    def test_the_last_active_owner_is_protected_from_the_operator_too(self, h: Harness) -> None:
        two_owners_and_a_user(h)
        h.store.disable_principal(OWNER_2, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        # Owner 1 is now the last active owner: only the explicit break-glass flag
        # of the operator CLI can disable them.
        with pytest.raises(AccessActionRefused) as exc:
            h.store.disable_principal(OWNER, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
        assert exc.value.code == AccessActionRefused.LAST_OWNER
        assert not h.store.get_principal_status(OWNER).disabled


class TestAdminPage:
    def test_active_users_get_disable_and_remove_as_separate_actions(self, h: Harness) -> None:
        two_owners_and_a_user(h)
        text = h.client.get("/account/admin").text
        assert f'action="{DISABLE}"' in text and f'name="principal_key" value="{USER}"' in text
        assert f'action="{REMOVE}"' in text
        assert "Disable user" in text and "Remove enrollment" in text
        assert f'action="{ENABLE}"' not in text
        assert "self-disconnect" in text  # the explanation of the difference

    def test_a_disabled_user_is_listed_with_enable_even_without_an_enrollment(
        self, h: Harness
    ) -> None:
        two_owners_and_a_user(h)
        disable_user(h)
        post_form(h, REMOVE, {"csrf": csrf_of(h), "tenant_id": TID, "object_id": OID})
        text = h.client.get("/account/admin").text
        assert "Disabled" in text and "Disabled by an administrator" in text
        assert f'action="{ENABLE}"' in text and f'name="principal_key" value="{USER}"' in text
        assert "ada@example.test" in text  # remembered for the admin page
        assert "no saved token" in text
        assert "1 user(s) disabled" in text
        # No remove, mark-invalid or disable button for a row that has no enrollment.
        row = re.search(r"<tr>(?:(?!</tr>).)*ada@example\.test(?:(?!</tr>).)*</tr>", text, re.S)
        assert row is not None
        assert DISABLE not in row.group(0) and REMOVE not in row.group(0)

    def test_the_labels_follow_the_page_language(self, h: Harness) -> None:
        two_owners_and_a_user(h)
        text = h.client.get("/account/admin", params={"lang": "zh"}).text
        assert "停用用户" in text and "移除绑定" in text
        assert "Disable user" not in text and "Remove enrollment" not in text
        disable_user(h)
        zh = h.client.get("/account/admin", params={"lang": "zh"}).text
        assert "重新启用用户" in zh and "已停用" in zh

    def test_the_needs_reenroll_filter_does_not_hide_the_disabled_count(self, h: Harness) -> None:
        two_owners_and_a_user(h)
        disable_user(h)
        text = h.client.get("/account/admin", params={"filter": "needs_reenroll"}).text
        assert "1 user(s) disabled" in text


class TestInProcessCacheInvalidation:
    def test_disabling_and_enabling_drop_the_mcp_cache_entry_at_once(
        self, tmp_path: pathlib.Path
    ) -> None:
        class LazySource:
            store: Any = None

            def get_principal_status(self, key: str) -> Any:
                return self.store.get_principal_status(key)

        source = LazySource()
        access = PrincipalAccessCache(source, ttl_seconds=3600)
        h = build_harness(tmp_path, access=access)
        source.store = h.store
        two_owners_and_a_user(h)
        assert not access.status(USER).disabled  # warm the cache
        disable_user(h)
        assert access.status(USER).disabled  # no waiting for the TTL
        post_form(h, ENABLE, {"csrf": csrf_of(h), "principal_key": USER})
        assert not access.status(USER).disabled


class TestSessionCookieFormat:
    def test_a_session_without_an_epoch_or_of_the_old_version_is_refused(self, h: Harness) -> None:
        sign_in(h)
        codec = account_web._CookieCodec(SESSION_SECRET)
        base = {
            "tid": TID, "oid": OID, "name": "x", "upn": "x", "owner": False,
            "iat": int(h.now), "exp": int(h.now) + 600, "csrf": "c",
        }
        for payload in (
            {**base, "v": 1},  # the old format: no epoch
            {**base, "v": 2},  # no epoch
            {**base, "v": 2, "ep": "0"},
            {**base, "v": 2, "ep": True},
            {**base, "v": 2, "ep": -1},
        ):
            use_cookie(h, codec.seal(SESSION_COOKIE, payload))
            assert signed_out(h), payload

    def test_a_session_with_another_epoch_is_refused(self, h: Harness) -> None:
        sign_in(h)
        codec = account_web._CookieCodec(SESSION_SECRET)
        base = {
            "v": 2, "tid": TID, "oid": OID, "name": "x", "upn": "x", "owner": False,
            "iat": int(h.now), "exp": int(h.now) + 600, "csrf": "c",
        }
        use_cookie(h, codec.seal(SESSION_COOKIE, {**base, "ep": 0}))
        assert not signed_out(h)
        use_cookie(h, codec.seal(SESSION_COOKIE, {**base, "ep": 5}))
        assert signed_out(h)

    def test_a_fresh_session_carries_the_current_epoch(self, h: Harness) -> None:
        two_owners_and_a_user(h)
        disable_user(h)
        post_form(h, ENABLE, {"csrf": csrf_of(h), "principal_key": USER})
        assert sign_in(h).status_code == 303
        codec = account_web._CookieCodec(SESSION_SECRET)
        payload = codec.unseal(SESSION_COOKIE, cookie(h))
        assert payload is not None and payload["ep"] == 2 and payload["v"] == 2

    def test_a_failing_status_read_fails_closed(
        self, h: Harness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sign_in(h)
        csrf = csrf_of(h)

        def boom(*_a: Any, **_k: Any) -> None:
            raise RuntimeError("database is locked")

        monkeypatch.setattr(h.store, "get_principal_status", boom)
        page = h.client.get(ACCOUNT_PATH)
        assert page.status_code == 503 and "unavailable" in page.text
        response = post_form(h, "/account/token/delete", {"csrf": csrf})
        assert response.status_code == 503
        assert h.store.info(USER) is None  # nothing was changed
        assert "locked" not in page.text

    def test_sign_in_fails_closed_when_the_status_cannot_be_recorded(
        self, h: Harness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*_a: Any, **_k: Any) -> None:
            raise RuntimeError("database is locked")

        monkeypatch.setattr(h.store, "record_sign_in", boom)
        response = sign_in(h)
        assert response.status_code == 503
        assert SESSION_COOKIE not in response.headers.get("set-cookie", "")


class TestSignInRecordsOwners:
    def test_an_owner_sign_in_is_recorded_and_a_user_sign_in_leaves_no_row(self, h: Harness) -> None:
        sign_in(h)
        assert h.store.list_principal_statuses() == []
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        rows = h.store.list_principal_statuses()
        assert [(r.principal_key, r.is_owner) for r in rows] == [(OWNER, True)]


class TestAudit:
    def test_every_transition_is_audited_with_actor_and_no_personal_data(
        self, h: Harness, events: list[str]
    ) -> None:
        two_owners_and_a_user(h)
        events.clear()  # the owners' own sign-ins are covered by their own test
        disable_user(h)
        sign_in(h)  # refused
        post_form(h, REMOVE, {"csrf": csrf_of(h), "tenant_id": TID, "object_id": OID})
        post_form(h, ENABLE, {"csrf": csrf_of(h), "principal_key": USER})
        got = principal_events(events)
        assert [(e["action"], e["principal"]) for e in got] == [
            ("disabled", USER),
            ("sign_in_refused", USER),
            ("enrollment_removed", USER),
            ("enabled", USER),
        ]
        disabled = got[0]
        assert disabled["actor"] == OWNER and disabled["reason"] == "admin_disabled"
        assert got[2]["actor"] == OWNER
        raw = "\n".join(events)
        for private in ("ada@example.test", "Ada Lovelace", CANVAS_TOKEN):
            assert private not in raw

    def test_owner_changes_seen_at_sign_in_are_audited_once_each(
        self, h: Harness, events: list[str]
    ) -> None:
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))
        sign_in(h, oid=OID_OWNER, roles=("Canvas.Owner",))  # unchanged: nothing new
        sign_in(h, oid=OID_OWNER, roles=("Canvas.User",))
        sign_in(h, oid=OID_OWNER, roles=("Canvas.User",))  # unchanged
        assert [(e["action"], e["principal"], e["reason"]) for e in principal_events(events)] == [
            ("owner_gained", OWNER, "sign_in"),
            ("owner_lost", OWNER, "sign_in"),
        ]

    def test_a_repeated_disable_is_not_audited_twice(self, h: Harness, events: list[str]) -> None:
        two_owners_and_a_user(h)
        events.clear()
        disable_user(h)
        disable_user(h)
        assert [e["action"] for e in principal_events(events)] == ["disabled"]

    def test_the_database_history_covers_the_same_transitions(self, h: Harness) -> None:
        two_owners_and_a_user(h)
        disable_user(h)
        post_form(h, ENABLE, {"csrf": csrf_of(h), "principal_key": USER})
        history = [(e.action, e.actor) for e in h.store.list_status_events(USER)]
        assert history == [("enabled", OWNER), ("disabled", OWNER)]
