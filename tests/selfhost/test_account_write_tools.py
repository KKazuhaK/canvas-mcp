"""The "Write tools" section of /account and the POST that saves it (English pages)."""

from __future__ import annotations

import json
import pathlib
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

import pytest

from canvas_mcp.core import audit
from canvas_mcp.core.selfhost import account_web
from canvas_mcp.core.selfhost.account_web import ACCOUNT_PATH, SESSION_COOKIE
from canvas_mcp.core.selfhost.token_store import ToolPrefs
from canvas_mcp.core.selfhost.tool_prefs import ToolPrefsCache, WriteToolCatalog

from .test_account_web import (
    CANVAS_TOKEN,
    CJK,
    OID,
    OID_2,
    SESSION_SECRET,
    TID,
    Harness,
    assert_security_headers,
    build_harness,
    csrf_of,
    post_form,
    sign_in,
    strip_chrome,
)

PATH = "/account/write-tools"
KEY = f"entra:{TID}:{OID}"
KEY_2 = f"entra:{TID}:{OID_2}"

REGISTERED = [
    "list_courses",
    "send_message",
    "reply_to_conversation",
    "submit_assignment",
    "comment_on_my_submission",
    "mark_module_item_done",
    "create_planner_note",
    "update_planner_note",
    "delete_planner_note",
    "mark_planner_item_complete",
    "create_personal_calendar_event",
    "delete_personal_calendar_event",
    "create_assignment",
    "delete_page",
]
# What the operator allows: the others are registered but over the ceiling.
CEILING = {
    "send_message",
    "reply_to_conversation",
    "mark_module_item_done",
    "create_planner_note",
    "create_assignment",
}


class LazySource:
    """Lets the cache be built before the harness creates the store."""

    store: Any = None

    def get_tool_prefs(self, principal_key: str) -> ToolPrefs | None:
        return self.store.get_tool_prefs(principal_key)


@dataclass
class Rig:
    h: Harness
    cache: ToolPrefsCache
    registered: list[str]


def make_rig(
    tmp_path: pathlib.Path,
    *,
    ceiling: set[str] | None = None,
    registered: list[str] | None = None,
    with_catalog: bool = True,
) -> Rig:
    names = list(REGISTERED if registered is None else registered)
    source = LazySource()
    cache = ToolPrefsCache(source)

    async def listing() -> list[str]:
        return list(names)

    kwargs: dict[str, Any] = {}
    if with_catalog:
        kwargs["write_tools"] = WriteToolCatalog(
            ceiling=CEILING if ceiling is None else ceiling, list_registered=listing
        )
        kwargs["tool_prefs"] = cache
    h = build_harness(tmp_path, **kwargs)
    source.store = h.store
    return Rig(h, cache, names)


@pytest.fixture
def r(tmp_path: pathlib.Path) -> Rig:
    return make_rig(tmp_path)


@pytest.fixture
def events(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    lines: list[str] = []

    class Recorder:
        def info(self, line: str) -> None:
            lines.append(line)

    monkeypatch.setattr(audit, "_audit_logger", Recorder())
    monkeypatch.setattr(audit, "_access_events_enabled", True)
    return lines


def write_events(lines: list[str]) -> list[dict[str, Any]]:
    return [json.loads(line) for line in lines if '"write_tools"' in line]


def save(r: Rig, *tools: str, **extra: str) -> Any:
    fields = {"csrf": csrf_of(r.h), **extra}
    for name in tools:
        fields[f"tool.{name}"] = "1"
    return post_form(r.h, PATH, fields)


def stored(r: Rig, key: str = KEY) -> frozenset[str]:
    prefs = r.h.store.get_tool_prefs(key)
    return prefs.enabled_write_tools if prefs is not None else frozenset()


def row_for(text: str, name: str) -> str:
    match = re.search(rf'<label class="choice"><input type="checkbox" name="tool\.{name}".*?</label>', text, re.S)
    assert match, f"no row for {name}"
    return match.group(0)


def is_checked(text: str, name: str) -> bool:
    """True if the page has a ticked, enabled box for this tool (False when it has no box)."""
    return f'name="tool.{name}" value="1" checked>' in text


def advance(r: Rig, seconds: float) -> None:
    r.h.now += seconds


class TestSection:
    def test_it_is_off_for_everything_by_default(self, r: Rig) -> None:
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH).text
        assert "<h2>Write tools</h2>" in text
        for name in CEILING:
            assert not is_checked(text, name), name
        assert stored(r) == frozenset()

    def test_the_three_layers_and_the_cache_tip_are_explained(self, r: Rig) -> None:
        sign_in(r.h)
        text = strip_chrome(r.h.client.get(ACCOUNT_PATH).text)
        assert "The server allows it" in text
        assert "You turn it on" in text
        assert "Your course allows it" in text
        assert "only narrow what you turned on" in text
        assert "still show a preview and ask for confirmation" in text
        assert "start a new chat or reconnect the connector" in text
        assert "last 10 minutes" in text
        assert not CJK.search(text)

    def test_tools_are_grouped_and_each_has_a_one_line_risk_note(self, r: Rig) -> None:
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH).text
        for title in (
            "Planner and calendar",
            "Submissions and comments",
            "Module completion",
            "Inbox",
            "Other write tools",
        ):
            assert f"<legend>{title}</legend>" in text, title
        assert "Sends a Canvas inbox message in your name" in row_for(text, "send_message")
        assert "Submits work for an assignment in your name" in row_for(text, "submit_assignment")
        assert "Changes things in Canvas in your name" in row_for(text, "create_assignment")

    def test_offered_tools_are_ticks_and_the_others_are_disabled(self, r: Rig) -> None:
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH).text
        for name in CEILING:
            assert "disabled" not in row_for(text, name).split("</code>")[0], name
            assert "not offered on this server" not in row_for(text, name)
        for name in ("submit_assignment", "comment_on_my_submission", "update_planner_note"):
            row = row_for(text, name)
            assert " disabled>" in row
            assert "not offered on this server" in row

    def test_a_tool_that_is_registered_but_over_the_ceiling_is_not_offered(self, r: Rig) -> None:
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH).text
        # delete_page is registered and a write tool, but the operator did not allow it.
        assert 'name="tool.delete_page"' not in text
        assert 'name="tool.list_courses"' not in text  # read tools have no switch

    def test_a_tool_the_operator_allows_but_nothing_registers_is_not_offered(
        self, tmp_path: pathlib.Path
    ) -> None:
        r2 = make_rig(tmp_path, ceiling=CEILING | {"delete_module"})
        sign_in(r2.h)
        assert 'name="tool.delete_module"' not in r2.h.client.get(ACCOUNT_PATH).text

    def test_when_nothing_is_offered_the_section_says_so_and_has_no_save_button(
        self, tmp_path: pathlib.Path
    ) -> None:
        r2 = make_rig(tmp_path, ceiling=set())
        sign_in(r2.h)
        text = r2.h.client.get(ACCOUNT_PATH).text
        assert "does not offer any write tools" in text
        assert ">Save<" not in text and "Turn all off" not in text
        assert 'type="checkbox" name="tool.send_message" value="1" disabled' in text

    def test_without_a_catalog_there_is_no_section_and_no_form(self, tmp_path: pathlib.Path) -> None:
        r2 = make_rig(tmp_path, with_catalog=False)
        sign_in(r2.h)
        text = r2.h.client.get(ACCOUNT_PATH).text
        assert "Write tools" not in text
        response = post_form(r2.h, PATH, {"csrf": csrf_of(r2.h)})
        assert response.status_code == 404

    def test_the_page_keeps_working_when_the_settings_cannot_be_read(
        self, r: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sign_in(r.h)

        def boom(_key: str) -> Any:
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(r.h.store, "get_tool_prefs", boom)
        response = r.h.client.get(ACCOUNT_PATH)
        assert response.status_code == 200
        assert "write-tool settings cannot be read" in response.text
        assert 'name="tool.send_message"' not in response.text
        assert "database is locked" not in response.text

    def test_saved_ticks_show_when_they_were_turned_on(self, r: Rig) -> None:
        sign_in(r.h)
        assert save(r, "send_message").status_code == 200
        text = r.h.client.get(ACCOUNT_PATH).text
        assert is_checked(text, "send_message")
        assert "on since 2027-01-15" in row_for(text, "send_message")
        assert not is_checked(text, "reply_to_conversation")

    def test_headers_are_the_usual_strict_ones(self, r: Rig) -> None:
        sign_in(r.h)
        assert_security_headers(r.h.client.get(ACCOUNT_PATH))
        assert_security_headers(save(r, "send_message"))


class TestSaving:
    def test_ticking_a_tool_stores_exactly_that_name(self, r: Rig) -> None:
        sign_in(r.h)
        response = save(r, "send_message", "mark_module_item_done")
        assert response.status_code == 200
        assert "Write-tool settings saved." in response.text
        assert stored(r) == {"send_message", "mark_module_item_done"}

    def test_unticking_turns_a_tool_off(self, r: Rig) -> None:
        sign_in(r.h)
        save(r, "send_message", "mark_module_item_done")
        assert save(r, "mark_module_item_done").status_code == 200
        assert stored(r) == {"mark_module_item_done"}

    def test_saving_with_nothing_ticked_clears_what_was_on(self, r: Rig) -> None:
        sign_in(r.h)
        save(r, "send_message")
        save(r)
        assert stored(r) == frozenset()

    def test_turn_all_off_clears_everything(self, r: Rig) -> None:
        sign_in(r.h)
        save(r, "send_message", "create_assignment")
        response = save(r, "send_message", disable_all="1")  # the button wins over ticks
        assert response.status_code == 200
        assert stored(r) == frozenset()

    def test_saving_without_a_change_says_so_and_writes_nothing(self, r: Rig) -> None:
        sign_in(r.h)
        save(r, "send_message")
        before = r.h.store.get_tool_prefs(KEY)
        advance(r, 5)
        response = save(r, "send_message")
        assert "Nothing to change." in response.text
        assert r.h.store.get_tool_prefs(KEY) == before

    def test_the_mcp_side_sees_the_change_at_once(self, r: Rig) -> None:
        sign_in(r.h)
        assert r.cache.enabled(KEY) == frozenset()  # now cached as "nothing"
        save(r, "send_message")
        assert r.cache.enabled(KEY) == {"send_message"}
        save(r)
        assert r.cache.enabled(KEY) == frozenset()

    def test_the_user_layer_cannot_widen_the_server_ceiling(self, r: Rig) -> None:
        sign_in(r.h)
        response = save(
            r,
            "send_message",
            "delete_page",  # registered, but the operator did not allow it
            "submit_assignment",  # same
            "delete_module",  # not even registered
            "execute_typescript",  # code execution
            "list_courses",  # a read tool
            "all",
        )
        assert response.status_code == 200
        assert stored(r) == {"send_message"}

    def test_a_name_that_is_not_in_the_form_as_a_tool_field_is_ignored(self, r: Rig) -> None:
        sign_in(r.h)
        response = post_form(
            r.h,
            PATH,
            {"csrf": csrf_of(r.h), "send_message": "1", "tools": "send_message", "tool.send_message": "0"},
        )
        assert response.status_code == 200
        assert stored(r) == frozenset()

    def test_names_the_server_no_longer_offers_are_kept_when_saving(self, r: Rig) -> None:
        sign_in(r.h)
        r.h.store.set_tool_prefs(KEY, ["create_assignment", "send_message"])
        r.registered.remove("create_assignment")  # the registry no longer has it
        save(r, "send_message", "reply_to_conversation")
        assert stored(r) == {"create_assignment", "send_message", "reply_to_conversation"}
        # ... and they are shown as kept, not as active.
        text = r.h.client.get(ACCOUNT_PATH).text
        assert "Kept, but not offered on this server:" in text
        assert "<code>create_assignment</code>" in text

    def test_a_kept_name_is_ignored_but_comes_back_when_the_server_offers_it_again(self, r: Rig) -> None:
        sign_in(r.h)
        r.h.store.set_tool_prefs(KEY, ["create_assignment"])
        text = r.h.client.get(ACCOUNT_PATH).text
        assert is_checked(text, "create_assignment")
        r.registered.remove("create_assignment")
        text = r.h.client.get(ACCOUNT_PATH).text
        assert not is_checked(text, "create_assignment")
        assert "Kept, but not offered" in text
        r.registered.append("create_assignment")
        assert is_checked(r.h.client.get(ACCOUNT_PATH).text, "create_assignment")

    def test_a_catalog_tool_that_is_not_offered_says_the_choice_is_kept(self, r: Rig) -> None:
        sign_in(r.h)
        r.h.store.set_tool_prefs(KEY, ["submit_assignment"])
        row = row_for(r.h.client.get(ACCOUNT_PATH).text, "submit_assignment")
        assert "not offered on this server" in row and "your earlier choice is kept" in row
        assert " checked" not in row.split(">")[0]

    def test_turn_all_off_also_clears_names_that_are_only_kept(self, r: Rig) -> None:
        sign_in(r.h)
        r.h.store.set_tool_prefs(KEY, ["submit_assignment", "send_message"])
        save(r, disable_all="1")
        assert stored(r) == frozenset()

    def test_users_do_not_affect_each_other(self, r: Rig) -> None:
        sign_in(r.h, oid=OID)
        save(r, "send_message")
        sign_in(r.h, oid=OID_2)
        text = r.h.client.get(ACCOUNT_PATH).text
        assert not is_checked(text, "send_message")
        save(r, "mark_module_item_done")
        assert stored(r, KEY) == {"send_message"}
        assert stored(r, KEY_2) == {"mark_module_item_done"}

    def test_replacing_or_deleting_the_canvas_token_does_not_change_the_switches(self, r: Rig) -> None:
        sign_in(r.h)
        r.h.store.put(
            tenant_id=TID, object_id=OID, api_token=CANVAS_TOKEN, canvas_user_id="42",
            canvas_user_name="Ada", entra_display_name="Ada", entra_upn="a@example.test",
            canvas_host="canvas.example.test",
        )
        save(r, "send_message")
        post_form(r.h, "/account/token/delete", {"csrf": csrf_of(r.h)})
        assert r.h.store.info(TID, OID) is None
        assert stored(r) == {"send_message"}

    def test_a_save_that_fails_is_reported_and_changes_nothing(
        self, r: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sign_in(r.h)
        csrf = csrf_of(r.h)

        def boom(*_args: Any, **_kwargs: Any) -> Any:
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(r.h.store, "set_tool_prefs", boom)
        response = post_form(r.h, PATH, {"csrf": csrf, "tool.send_message": "1"})
        assert response.status_code == 503
        assert "could not be saved right now" in response.text
        assert "disk I/O error" not in response.text
        assert stored(r) == frozenset()

    def test_a_read_that_fails_before_saving_changes_nothing(
        self, r: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sign_in(r.h)
        csrf = csrf_of(r.h)

        def boom(_key: str) -> Any:
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(r.h.store, "get_tool_prefs", boom)
        response = post_form(r.h, PATH, {"csrf": csrf, "tool.send_message": "1"})
        assert response.status_code == 503
        monkeypatch.undo()
        assert stored(r) == frozenset()

    def test_a_large_form_with_many_tools_is_accepted(self, tmp_path: pathlib.Path) -> None:
        many = [f"extra_tool_{i}" for i in range(60)]
        r2 = make_rig(tmp_path, ceiling=set(many), registered=["list_courses", *many])
        sign_in(r2.h)
        response = save(r2, *many)
        assert response.status_code == 200
        assert stored(r2) == set(many)


class TestFeedbackPlacement:
    """The result of a save is visible without scrolling to the last card."""

    @staticmethod
    def top_notice_precedes_the_card(text: str, message: str) -> bool:
        top = text.find(message)
        card = text.find('<section class="card" id="write-tools">')
        return 0 <= top < card

    def test_the_form_returns_the_user_to_the_card(self, r: Rig) -> None:
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH).text
        assert f'<form method="post" action="{PATH}#write-tools">' in text

    def test_a_saved_change_is_reported_above_the_cards(self, r: Rig) -> None:
        sign_in(r.h)
        response = save(r, "send_message")
        assert self.top_notice_precedes_the_card(response.text, "Write-tool settings saved.")
        assert "Write-tool settings saved." in response.text.split('id="write-tools"')[1]

    def test_nothing_to_change_is_reported_above_the_cards(self, r: Rig) -> None:
        sign_in(r.h)
        save(r, "send_message")
        response = save(r, "send_message")
        assert self.top_notice_precedes_the_card(response.text, "Nothing to change.")

    def test_the_sign_in_refusal_is_reported_above_the_cards(self, r: Rig) -> None:
        sign_in(r.h)
        csrf = csrf_of(r.h)
        advance(r, 601)
        response = post_form(r.h, PATH, {"csrf": csrf, "tool.send_message": "1"})
        assert response.status_code == 403
        assert self.top_notice_precedes_the_card(
            response.text, "needs a sign-in from the last 10 minutes"
        )
        assert re.search(
            r'<div class="notice error" role="alert">[^<]*needs a sign-in', response.text
        )


class TestSignInAge:
    """Turning something ON needs a sign-in from the last 10 minutes; OFF never does."""

    def test_turning_on_with_a_recent_sign_in_works(self, r: Rig) -> None:
        sign_in(r.h)
        advance(r, 600)
        assert save(r, "send_message").status_code == 200
        assert stored(r) == {"send_message"}

    def test_turning_on_after_ten_minutes_asks_the_user_to_sign_in_again(
        self, r: Rig, events: list[str]
    ) -> None:
        sign_in(r.h)
        csrf = csrf_of(r.h)
        advance(r, 601)  # the session itself lasts 15 minutes
        response = post_form(r.h, PATH, {"csrf": csrf, "tool.send_message": "1"})
        assert response.status_code == 403
        assert "needs a sign-in from the last 10 minutes" in response.text
        assert "Sign out, sign in again and retry" in response.text
        assert stored(r) == frozenset()
        refused = write_events(events)
        assert [e["action"] for e in refused] == ["refused"]
        assert refused[0]["outcome"] == "sign_in_too_old"
        assert refused[0]["enabled"] == ["send_message"]
        # The page still renders as the signed-in user, with the old state.
        assert not is_checked(response.text, "send_message")

    def test_turning_off_works_with_an_old_session(self, r: Rig) -> None:
        sign_in(r.h)
        save(r, "send_message", "mark_module_item_done")
        csrf = csrf_of(r.h)
        advance(r, 800)
        response = post_form(r.h, PATH, {"csrf": csrf, "tool.mark_module_item_done": "1"})
        assert response.status_code == 200
        assert stored(r) == {"mark_module_item_done"}
        response = post_form(r.h, PATH, {"csrf": csrf, "disable_all": "1"})
        assert response.status_code == 200
        assert stored(r) == frozenset()

    def test_a_save_that_turns_one_on_and_another_off_is_refused_as_a_whole(self, r: Rig) -> None:
        sign_in(r.h)
        save(r, "send_message")
        csrf = csrf_of(r.h)
        advance(r, 700)
        response = post_form(r.h, PATH, {"csrf": csrf, "tool.reply_to_conversation": "1"})
        assert response.status_code == 403
        assert stored(r) == {"send_message"}

    def test_saving_the_same_set_needs_no_recent_sign_in(self, r: Rig) -> None:
        sign_in(r.h)
        save(r, "send_message")
        csrf = csrf_of(r.h)
        advance(r, 800)
        response = post_form(r.h, PATH, {"csrf": csrf, "tool.send_message": "1"})
        assert response.status_code == 200
        assert "Nothing to change." in response.text

    def test_signing_in_again_makes_it_possible(self, r: Rig) -> None:
        sign_in(r.h)
        csrf = csrf_of(r.h)
        advance(r, 700)
        assert post_form(r.h, PATH, {"csrf": csrf, "tool.send_message": "1"}).status_code == 403
        sign_in(r.h)
        assert save(r, "send_message").status_code == 200
        assert stored(r) == {"send_message"}

    def test_a_session_cookie_without_an_issue_time_counts_as_old(self, r: Rig) -> None:
        sign_in(r.h)
        csrf = csrf_of(r.h)
        codec = account_web._CookieCodec(SESSION_SECRET)
        old_style = codec.seal(
            SESSION_COOKIE,
            {
                "v": 1, "tid": TID, "oid": OID, "name": "Ada", "upn": "a@example.test",
                "owner": False, "exp": int(r.h.now) + 900, "csrf": csrf,
            },
        )
        r.h.client.cookies.set(SESSION_COOKIE, old_style)
        response = post_form(r.h, PATH, {"csrf": csrf, "tool.send_message": "1"})
        assert response.status_code == 403
        assert stored(r) == frozenset()

    def test_a_session_issued_in_the_future_does_not_count_as_recent(self, r: Rig) -> None:
        sign_in(r.h)
        csrf = csrf_of(r.h)
        codec = account_web._CookieCodec(SESSION_SECRET)
        forged = codec.seal(
            SESSION_COOKIE,
            {
                "v": 1, "tid": TID, "oid": OID, "name": "Ada", "upn": "a@example.test",
                "owner": False, "iat": int(r.h.now) + 100_000, "exp": int(r.h.now) + 900, "csrf": csrf,
            },
        )
        r.h.client.cookies.set(SESSION_COOKIE, forged)
        assert post_form(r.h, PATH, {"csrf": csrf, "tool.send_message": "1"}).status_code == 403


class TestRequestChecks:
    def test_the_route_only_takes_post(self, r: Rig) -> None:
        sign_in(r.h)
        for method in ("get", "put", "delete", "patch"):
            response = getattr(r.h.client, method)(PATH)
            assert response.status_code == 405, method
            assert response.headers["allow"] == "POST"

    def test_without_a_session_the_user_is_sent_to_the_sign_in_page(self, r: Rig) -> None:
        response = post_form(r.h, PATH, {"csrf": "x", "tool.send_message": "1"})
        assert response.status_code == 303 and response.headers["location"] == ACCOUNT_PATH
        assert stored(r) == frozenset()

    @pytest.mark.parametrize("csrf", ["", "wrong", "x" * 100])
    def test_a_missing_or_wrong_csrf_token_is_refused(self, r: Rig, csrf: str) -> None:
        sign_in(r.h)
        response = post_form(r.h, PATH, {"csrf": csrf, "tool.send_message": "1"})
        assert response.status_code == 403
        assert stored(r) == frozenset()

    def test_a_form_without_a_csrf_field_is_refused(self, r: Rig) -> None:
        sign_in(r.h)
        assert post_form(r.h, PATH, {"tool.send_message": "1"}).status_code == 403
        assert stored(r) == frozenset()

    @pytest.mark.parametrize("origin", [None, "https://evil.example.test", "http://canvas.example.test", "null"])
    def test_a_wrong_or_missing_origin_is_refused(self, r: Rig, origin: str | None) -> None:
        sign_in(r.h)
        csrf = csrf_of(r.h)
        response = post_form(r.h, PATH, {"csrf": csrf, "tool.send_message": "1"}, origin=origin)
        assert response.status_code == 403
        assert stored(r) == frozenset()

    def test_a_wrong_content_type_is_refused(self, r: Rig) -> None:
        sign_in(r.h)
        csrf = csrf_of(r.h)
        response = post_form(
            r.h, PATH, {"csrf": csrf, "tool.send_message": "1"}, content_type="application/json"
        )
        assert response.status_code == 415
        assert stored(r) == frozenset()

    def test_a_huge_body_is_refused(self, r: Rig) -> None:
        sign_in(r.h)
        csrf = csrf_of(r.h)
        response = r.h.client.post(
            PATH,
            content=b"csrf=" + csrf.encode() + b"&junk=" + b"x" * 20_000,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://canvas.example.test"},
        )
        assert response.status_code == 413
        assert stored(r) == frozenset()

    def test_too_many_fields_are_refused(self, r: Rig) -> None:
        sign_in(r.h)
        fields = {"csrf": csrf_of(r.h)}
        fields.update({f"tool.t{i}": "1" for i in range(200)})
        response = post_form(r.h, PATH, fields)
        assert response.status_code == 400
        assert stored(r) == frozenset()

    def test_get_with_the_same_query_changes_nothing(self, r: Rig) -> None:
        sign_in(r.h)
        r.h.client.get(ACCOUNT_PATH, params={"tool.send_message": "1", "csrf": "x"})
        assert stored(r) == frozenset()


class TestAudit:
    def test_each_change_is_audited_with_the_principal_and_tool_names_only(
        self, r: Rig, events: list[str]
    ) -> None:
        sign_in(r.h)
        save(r, "send_message", "mark_module_item_done")
        save(r, "send_message", "reply_to_conversation")
        save(r, disable_all="1")
        got = write_events(events)
        assert [e["action"] for e in got] == ["changed", "changed", "cleared"]
        assert got[0]["principal"] == KEY
        assert got[0]["enabled"] == ["mark_module_item_done", "send_message"]
        assert got[0]["disabled"] == []
        assert got[1]["enabled"] == ["reply_to_conversation"]
        assert got[1]["disabled"] == ["mark_module_item_done"]
        assert got[2]["enabled"] == [] and got[2]["disabled"] == ["reply_to_conversation", "send_message"]
        for event in got:
            assert event["event_type"] == "write_tools"
            assert set(event) <= {
                "timestamp", "event_type", "action", "principal", "enabled", "disabled", "outcome"
            }
        raw = "\n".join(events)
        assert CANVAS_TOKEN not in raw

    def test_a_save_that_changes_nothing_is_not_audited(self, r: Rig, events: list[str]) -> None:
        sign_in(r.h)
        save(r, "send_message")
        events.clear()
        save(r, "send_message")
        assert write_events(events) == []

    def test_nothing_is_audited_when_the_audit_log_is_off(
        self, r: Rig, events: list[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(audit, "_access_events_enabled", False)
        sign_in(r.h)
        save(r, "send_message")
        assert write_events(events) == []
        assert stored(r) == {"send_message"}
