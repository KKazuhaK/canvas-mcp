"""The school picker, the school search and school-aware enrollment on /account."""

from __future__ import annotations

import pathlib
import re
import sqlite3
from collections.abc import Sequence
from typing import Any

import httpx
import pytest

from canvas_mcp.core.selfhost.account_web import (
    ACCOUNT_PATH,
    AccountConfig,
    CanvasCheckError,
)
from canvas_mcp.core.selfhost.schools import (
    DirectoryEntry,
    DirectoryError,
    FeaturedSchool,
    SchoolPolicy,
)
from canvas_mcp.core.selfhost.token_store import TokenDecryptionError

from .test_account_web import (
    CANVAS_TOKEN,
    CJK,
    OID,
    OID_2,
    OID_OWNER,
    TID,
    Harness,
    assert_security_headers,
    bi_calls,
    build_harness,
    csrf_of,
    make_cfg,
    post_form,
    sign_in,
    static_text,
    strip_chrome,
    use_lang,
)

DEFAULT_URL = "https://canvas.default.edu/api/v1"
DEFAULT_HOST = "canvas.default.edu"
HOST_A = "canvas.school-a.edu"
HOST_B = "canvas.school-b.edu"
FOUND = "canvas.found.edu"
PUBLIC_IP = "93.184.216.34"
FEATURED = (FeaturedSchool(HOST_A, "School <b>A</b>"), FeaturedSchool(HOST_B, "School B"))


class FakeDirectory:
    """Stands in for Instructure's directory; records every call."""

    def __init__(self, entries: Sequence[DirectoryEntry] = (), error: bool = False) -> None:
        self.entries = list(entries)
        self.error = error
        self.searches: list[str] = []
        self.confirms: list[str] = []

    async def search(self, term: str, *, limit: int = 10) -> list[DirectoryEntry]:
        self.searches.append(term)
        if self.error:
            raise DirectoryError("down")
        return list(self.entries)

    async def confirm(self, host: str) -> DirectoryEntry | None:
        self.confirms.append(host)
        if self.error:
            raise DirectoryError("down")
        for entry in self.entries:
            if entry.domain == host:
                return entry
        return None

    @property
    def calls(self) -> int:
        return len(self.searches) + len(self.confirms)


class FakeResolver:
    def __init__(self, table: dict[str, Sequence[str] | BaseException] | None = None) -> None:
        self.table = table or {}
        self.calls: list[str] = []

    async def __call__(self, host: str) -> Sequence[str]:
        self.calls.append(host)
        value = self.table.get(host, [PUBLIC_IP])
        if isinstance(value, BaseException):
            raise value
        return value


class Rig:
    def __init__(self, h: Harness, directory: FakeDirectory, resolver: FakeResolver) -> None:
        self.h = h
        self.directory = directory
        self.resolver = resolver


def rig(
    tmp_path: pathlib.Path,
    *,
    default: str = DEFAULT_URL,
    featured: Sequence[FeaturedSchool] = FEATURED,
    search: bool = False,
    entries: Sequence[DirectoryEntry] = (),
    directory_error: bool = False,
    resolver: FakeResolver | None = None,
    **extra: Any,
) -> Rig:
    directory = FakeDirectory(entries, error=directory_error)
    fake_resolver = resolver or FakeResolver()
    policy = SchoolPolicy.build(default, featured, search)
    h = build_harness(
        tmp_path,
        cfg=make_cfg(schools=policy),
        directory=directory,
        resolve_host=fake_resolver,
        **extra,
    )
    return Rig(h, directory, fake_resolver)


def enroll(r: Rig, school: str | None, token: str = CANVAS_TOKEN, *, csrf: str | None = None) -> httpx.Response:
    fields = {"csrf": csrf or csrf_of(r.h), "canvas_token": token}
    if school is not None:
        fields["school"] = school
    return post_form(r.h, "/account/token", fields)


def stored_host(r: Rig, oid: str = OID) -> str | None:
    info = r.h.store.info(TID, oid)
    assert info is not None
    return info.canvas_host


# -- pinned mode (backward compatible) -----------------------------------------------


class TestPinnedMode:
    def test_no_picker_and_no_search_form(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, featured=(), search=False)
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH).text
        assert 'type="radio"' not in text and 'name="school"' not in text
        assert "/account/schools" not in text and 'type="search"' not in text

    def test_post_without_school_stores_the_default_host(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, featured=(), search=False)
        sign_in(r.h)
        assert enroll(r, None).status_code == 303
        assert stored_host(r) == DEFAULT_HOST
        assert r.h.whoami_urls == [DEFAULT_URL]
        assert r.resolver.calls == []  # the operator's pin is trusted, no DNS check
        assert r.directory.calls == 0

    def test_a_posted_school_other_than_the_default_is_refused(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, featured=(), search=False)
        sign_in(r.h)
        assert enroll(r, HOST_A).status_code == 400
        assert r.h.whoami_calls == [] and r.h.store.count() == 0

    def test_the_default_host_may_be_posted_explicitly(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, featured=(), search=False)
        sign_in(r.h)
        assert enroll(r, DEFAULT_HOST.upper()).status_code == 303
        assert stored_host(r) == DEFAULT_HOST and r.resolver.calls == []

    def test_a_default_with_port_and_prefix_is_used_verbatim(self, tmp_path: pathlib.Path) -> None:
        url = "https://canvas.default.edu:8443/lms/api/v1"
        r = rig(tmp_path, default=url, featured=(), search=False)
        sign_in(r.h)
        assert enroll(r, None).status_code == 303
        assert r.h.whoami_urls == [url]

    def test_a_featured_only_single_school_without_default_is_the_sole_school(
        self, tmp_path: pathlib.Path
    ) -> None:
        r = rig(tmp_path, default="", featured=FEATURED[:1], search=False)
        sign_in(r.h)
        page = r.h.client.get(ACCOUNT_PATH).text
        assert 'type="radio"' not in page and HOST_A in page
        assert enroll(r, None).status_code == 303
        assert stored_host(r) == HOST_A
        assert r.h.whoami_urls == [f"https://{HOST_A}/api/v1"]
        assert r.resolver.calls == [HOST_A]  # a featured school still gets the address check

    def test_the_status_card_shows_the_school(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, featured=(), search=False)
        sign_in(r.h)
        enroll(r, None)
        text = r.h.client.get(ACCOUNT_PATH).text
        assert "<dt>School</dt>" in text and DEFAULT_HOST in text


# -- the picker -----------------------------------------------------------------------


class TestPicker:
    def test_radios_default_checked_and_names_escaped(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path)
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH).text
        radios = re.findall(r'<input type="radio" name="school" value="([^"]+)"( checked)?>', text)
        assert [v for v, _ in radios] == [DEFAULT_HOST, HOST_A, HOST_B]
        assert [bool(c) for _, c in radios] == [True, False, False]
        assert "School &lt;b&gt;A&lt;/b&gt;" in text and "<b>A</b>" not in text
        assert "Your school" in text
        assert 'type="search"' not in text  # search is off

    def test_without_a_default_the_first_featured_school_is_checked(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, default="")
        sign_in(r.h)
        radios = re.findall(r'value="([^"]+)"( checked)?>', r.h.client.get(ACCOUNT_PATH).text)
        assert [(v, bool(c)) for v, c in radios if v in (HOST_A, HOST_B)] == [(HOST_A, True), (HOST_B, False)]

    def test_search_only_with_nothing_selected_asks_to_search(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, default="", featured=(), search=True)
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH).text
        assert "Search for your school first." in text
        assert 'name="canvas_token"' not in text and 'type="radio"' not in text
        assert 'action="/account/schools"' in text

    def test_the_enrolled_school_is_preselected_for_a_replacement(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path)
        sign_in(r.h)
        assert enroll(r, HOST_B).status_code == 303
        text = r.h.client.get(ACCOUNT_PATH).text
        assert re.search(rf'value="{HOST_B}" checked', text)
        assert not re.search(rf'value="{DEFAULT_HOST}" checked', text)

    def test_post_featured_school_checks_dns_then_whoami_and_stores_the_host(
        self, tmp_path: pathlib.Path
    ) -> None:
        r = rig(tmp_path)
        sign_in(r.h)
        response = enroll(r, HOST_B)
        assert response.status_code == 303
        assert r.resolver.calls == [HOST_B]
        assert r.h.whoami_urls == [f"https://{HOST_B}/api/v1"]
        assert r.h.whoami_calls == [CANVAS_TOKEN]
        assert stored_host(r) == HOST_B
        assert r.h.store.get(TID, OID).api_token == CANVAS_TOKEN  # type: ignore[union-attr]
        assert r.directory.calls == 0  # featured schools need no directory

    def test_the_default_school_needs_no_dns_check(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path)
        sign_in(r.h)
        assert enroll(r, DEFAULT_HOST).status_code == 303
        assert r.resolver.calls == [] and stored_host(r) == DEFAULT_HOST

    def test_an_empty_school_means_the_default_when_there_is_one(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path)
        sign_in(r.h)
        assert enroll(r, "").status_code == 303
        assert stored_host(r) == DEFAULT_HOST

    def test_an_empty_school_without_a_default_is_refused(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, default="")
        sign_in(r.h)
        response = enroll(r, "")
        assert response.status_code == 400 and "Choose your school" in response.text
        assert r.h.whoami_calls == []

    def test_the_host_is_case_insensitive(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path)
        sign_in(r.h)
        assert enroll(r, "  " + HOST_A.upper() + " ").status_code == 303
        assert stored_host(r) == HOST_A

    def test_an_unlisted_host_with_search_off_is_refused(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path)
        sign_in(r.h)
        response = enroll(r, "canvas.other.edu")
        assert response.status_code == 400
        assert "does not offer that school" in response.text
        assert r.h.whoami_calls == [] and r.h.store.count() == 0
        assert r.resolver.calls == [] and r.directory.calls == 0

    @pytest.mark.parametrize(
        "value",
        [
            f"https://{HOST_A}",
            f"{HOST_A}:8443",
            f"{HOST_A}/lms",
            f"user@{HOST_A}",
            "127.0.0.1",
            "10.0.0.5",
            "[::1]",
            "2130706433",
            "localhost",
            "canvas.local",
            "db.internal",
            "intranet",
            f"{HOST_A}\n.evil.test",
            "a" * 300,
        ],
    )
    def test_invalid_school_values_are_refused_before_anything_is_sent(
        self, tmp_path: pathlib.Path, value: str
    ) -> None:
        r = rig(tmp_path, search=True, entries=[DirectoryEntry("X", HOST_A)])
        sign_in(r.h)
        response = enroll(r, value)
        assert response.status_code == 400
        assert "not valid" in response.text
        assert r.h.whoami_calls == [] and r.h.store.count() == 0
        assert r.resolver.calls == [] and r.directory.calls == 0

    @pytest.mark.parametrize(
        "answers",
        [
            ["10.0.0.5"],
            ["127.0.0.1"],
            ["169.254.169.254"],
            ["100.100.100.200"],
            ["192.168.1.1"],
            ["::1"],
            ["fd00:ec2::254"],
            ["::ffff:10.0.0.1"],
            ["0.0.0.0"],
            [PUBLIC_IP, "10.0.0.5"],  # one private address among public ones
            ["2606:4700:4700::1111", "fe80::1"],
        ],
    )
    def test_a_school_resolving_to_a_non_public_address_is_refused(
        self, tmp_path: pathlib.Path, answers: list[str]
    ) -> None:
        r = rig(tmp_path, resolver=FakeResolver({HOST_A: answers}))
        sign_in(r.h)
        response = enroll(r, HOST_A)
        assert response.status_code == 400
        assert "not allowed" in response.text
        assert r.h.whoami_calls == [] and r.h.store.count() == 0

    @pytest.mark.parametrize("answer", [OSError("nxdomain"), TimeoutError(), []])
    def test_an_unresolvable_school_is_refused(self, tmp_path: pathlib.Path, answer: Any) -> None:
        r = rig(tmp_path, resolver=FakeResolver({HOST_A: answer}))
        sign_in(r.h)
        response = enroll(r, HOST_A)
        assert response.status_code == 400 and "Could not find" in response.text
        assert r.h.whoami_calls == []

    def test_canvas_errors_for_another_school_keep_the_choice(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path)
        sign_in(r.h)
        r.h.whoami_result = CanvasCheckError("invalid")
        response = enroll(r, HOST_B)
        assert response.status_code == 400
        assert re.search(rf'value="{HOST_B}" checked', response.text)
        assert r.h.store.count() == 0

    def test_csrf_and_origin_still_apply_when_a_school_is_posted(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path)
        sign_in(r.h)
        csrf = csrf_of(r.h)
        fields = {"csrf": "nope", "canvas_token": CANVAS_TOKEN, "school": HOST_A}
        assert post_form(r.h, "/account/token", fields).status_code == 403
        fields["csrf"] = csrf
        assert post_form(r.h, "/account/token", fields, origin="https://evil.example").status_code == 403
        assert post_form(r.h, "/account/token", fields, origin=None).status_code == 403
        assert r.h.store.count() == 0 and r.resolver.calls == [] and r.h.whoami_calls == []

    def test_the_token_is_only_checked_after_the_format_check(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path)
        sign_in(r.h)
        assert enroll(r, HOST_A, token="short").status_code == 400
        assert r.resolver.calls == [] and r.h.whoami_calls == []

    def test_resaving_a_legacy_row_reseals_it_with_the_default_host(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path)
        r.h.store.put(
            tenant_id=TID, object_id=OID, api_token=CANVAS_TOKEN, canvas_user_id="1",
            canvas_user_name="Old", entra_display_name="Old", entra_upn="o@example.test",
        )
        assert stored_host(r) is None
        sign_in(r.h)
        assert enroll(r, DEFAULT_HOST).status_code == 303
        assert stored_host(r) == DEFAULT_HOST
        with sqlite3.connect(str(r.h.store._path)) as conn:
            conn.execute("UPDATE canvas_tokens SET canvas_host = NULL")
        with pytest.raises(TokenDecryptionError):
            r.h.store.get(TID, OID)

    def test_two_users_two_schools(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path)
        sign_in(r.h)
        enroll(r, HOST_A)
        sign_in(r.h, oid=OID_2)
        enroll(r, HOST_B, token="9~" + "U" * 62)
        assert stored_host(r, OID) == HOST_A and stored_host(r, OID_2) == HOST_B
        assert r.h.whoami_urls == [f"https://{HOST_A}/api/v1", f"https://{HOST_B}/api/v1"]


# -- searched schools -------------------------------------------------------------------


class TestSearchedSchools:
    def entries(self, *domains: str) -> list[DirectoryEntry]:
        return [DirectoryEntry(f"Name of {d}", d) for d in domains]

    def test_an_exact_directory_match_is_accepted(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True, entries=self.entries(FOUND))
        sign_in(r.h)
        assert enroll(r, FOUND).status_code == 303
        assert r.directory.confirms == [FOUND]
        assert r.resolver.calls == [FOUND]
        assert r.h.whoami_urls == [f"https://{FOUND}/api/v1"]
        assert stored_host(r) == FOUND

    def test_the_host_is_lowercased_before_confirmation(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True, entries=self.entries(FOUND))
        sign_in(r.h)
        assert enroll(r, FOUND.upper()).status_code == 303
        assert r.directory.confirms == [FOUND]

    @pytest.mark.parametrize("listed", ["canvas.found.edu.evil.com", "found.edu", "xcanvas.found.edu"])
    def test_near_misses_are_refused(self, tmp_path: pathlib.Path, listed: str) -> None:
        r = rig(tmp_path, search=True, entries=self.entries(listed))
        sign_in(r.h)
        response = enroll(r, FOUND)
        assert response.status_code == 400 and "not in the school directory" in response.text
        assert r.h.whoami_calls == [] and r.h.store.count() == 0 and r.resolver.calls == []

    def test_a_directory_error_fails_closed(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True, directory_error=True)
        sign_in(r.h)
        response = enroll(r, FOUND)
        assert response.status_code == 503 and "directory is unavailable" in response.text
        assert r.h.whoami_calls == [] and r.h.store.count() == 0

    def test_a_confirmed_school_that_resolves_privately_is_refused(self, tmp_path: pathlib.Path) -> None:
        r = rig(
            tmp_path, search=True, entries=self.entries(FOUND),
            resolver=FakeResolver({FOUND: ["10.1.2.3"]}),
        )
        sign_in(r.h)
        assert enroll(r, FOUND).status_code == 400
        assert r.h.whoami_calls == [] and r.h.store.count() == 0

    def test_featured_schools_skip_the_directory_even_when_search_is_on(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        assert enroll(r, HOST_A).status_code == 303
        assert r.directory.calls == 0

    def test_search_off_never_asks_the_directory(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=False, entries=self.entries(FOUND))
        sign_in(r.h)
        assert enroll(r, FOUND).status_code == 400
        assert r.directory.calls == 0

    def test_a_failed_attempt_keeps_the_searched_school_selected(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True, entries=self.entries(FOUND))
        sign_in(r.h)
        r.h.whoami_result = CanvasCheckError("invalid")
        response = enroll(r, FOUND)
        assert response.status_code == 400
        assert re.search(rf'value="{FOUND}" checked', response.text)
        assert "verified when you save" in response.text

    def test_an_enrolled_searched_school_stays_selectable_while_search_is_on(
        self, tmp_path: pathlib.Path
    ) -> None:
        r = rig(tmp_path, search=True, entries=self.entries(FOUND))
        sign_in(r.h)
        enroll(r, FOUND)
        text = r.h.client.get(ACCOUNT_PATH).text
        assert re.search(rf'value="{FOUND}" checked', text)
        assert "your current school" in text


# -- ?school= preselection ---------------------------------------------------------------


class TestPreselection:
    def test_a_directory_host_gets_an_extra_checked_radio(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH, params={"school": FOUND}).text
        assert re.search(rf'value="{FOUND}" checked', text)
        assert not re.search(rf'value="{DEFAULT_HOST}" checked', text)
        assert "verified when you save" in text

    def test_a_featured_host_is_preselected(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH, params={"school": HOST_B.upper()}).text
        assert re.search(rf'value="{HOST_B}" checked', text)
        assert text.count('type="radio"') == 3

    @pytest.mark.parametrize(
        "value",
        ["<script>alert(1)</script>", "127.0.0.1", "localhost", "x.local", f"https://{FOUND}", f"{FOUND}:8443", "", "a" * 400],
    )
    def test_invalid_values_are_ignored(self, tmp_path: pathlib.Path, value: str) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        response = r.h.client.get(ACCOUNT_PATH, params={"school": value})
        assert response.status_code == 200
        assert response.text.count('type="radio"') == 3
        assert re.search(rf'value="{DEFAULT_HOST}" checked', response.text)
        assert "<script>alert" not in response.text

    def test_unlisted_hosts_are_ignored_when_search_is_off(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=False)
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH, params={"school": FOUND}).text
        assert FOUND not in text and text.count('type="radio"') == 3

    def test_the_replace_form_opens_when_a_school_is_chosen(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        enroll(r, HOST_A)
        closed = r.h.client.get(ACCOUNT_PATH).text
        opened = r.h.client.get(ACCOUNT_PATH, params={"school": FOUND}).text
        assert '<details class="card">' in closed and '<details class="card" open>' not in closed
        assert '<details class="card" open>' in opened


# -- GET /account/schools ------------------------------------------------------------------


def search(r: Rig, q: str) -> httpx.Response:
    return r.h.client.get("/account/schools", params={"q": q})


class TestSchoolsPage:
    def test_signed_out_is_redirected_without_a_directory_call(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        response = search(r, "irvine")
        assert response.status_code == 303 and response.headers["location"] == "/account"
        assert r.directory.calls == 0

    def test_search_off_is_404(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=False)
        sign_in(r.h)
        response = search(r, "irvine")
        assert response.status_code == 404
        assert r.directory.calls == 0
        assert "/account/schools" not in r.h.client.get(ACCOUNT_PATH).text

    def test_security_headers_and_form(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        response = r.h.client.get("/account/schools")
        assert response.status_code == 200
        assert_security_headers(response)
        assert 'method="get" action="/account/schools"' in response.text
        assert 'type="search"' in response.text and 'maxlength="64"' in response.text
        assert "Search terms are sent to" in response.text
        assert r.directory.calls == 0

    def test_post_is_not_allowed(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        assert post_form(r.h, "/account/schools", {"q": "irvine"}).status_code == 405

    def test_results_are_links_to_the_account_page(self, tmp_path: pathlib.Path) -> None:
        entries = [DirectoryEntry("Found University", FOUND), DirectoryEntry("Other", "canvas.other.edu")]
        r = rig(tmp_path, search=True, entries=entries)
        sign_in(r.h)
        response = search(r, "found")
        assert response.status_code == 200
        assert r.directory.searches == ["found"]
        assert f'href="/account?school={FOUND}"' in response.text
        assert "Found University" in response.text and "canvas.other.edu" in response.text

    def test_results_and_query_are_escaped(self, tmp_path: pathlib.Path) -> None:
        entries = [DirectoryEntry('<script>alert("x")</script>', FOUND)]
        r = rig(tmp_path, search=True, entries=entries)
        sign_in(r.h)
        response = search(r, '"><img src=x onerror=alert(1)>')
        text = response.text
        assert "<script>" not in text and "<img src=x" not in text
        assert "&lt;script&gt;" in text
        assert 'value="&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"' in text

    def test_blocked_names_are_not_offered(self, tmp_path: pathlib.Path) -> None:
        entries = [DirectoryEntry("Printer", "printer.local"), DirectoryEntry("Real", FOUND)]
        r = rig(tmp_path, search=True, entries=entries)
        sign_in(r.h)
        text = search(r, "x" * 5).text
        assert "printer.local" not in text and FOUND in text

    def test_no_results(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        assert "No schools found." in search(r, "zzzz").text

    def test_empty_query_shows_only_the_form(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        assert search(r, "   ").status_code == 200
        assert r.directory.calls == 0

    @pytest.mark.parametrize("query", ["a", "x" * 65, "ab\x07cd", "ab\x7fcd", "ab\x85cd"])
    def test_bad_queries_are_400_without_a_directory_call(self, tmp_path: pathlib.Path, query: str) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        response = search(r, query)
        assert response.status_code == 400 and "2 to 64 characters" in response.text
        assert r.directory.calls == 0
        assert "\x07" not in response.text

    def test_a_64_character_query_is_allowed(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        assert search(r, "x" * 64).status_code == 200
        assert r.directory.searches == ["x" * 64]

    def test_the_31st_search_is_rate_limited(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        for i in range(30):
            assert search(r, f"school {i}").status_code == 200
        assert r.directory.calls == 30
        response = search(r, "one more")
        assert response.status_code == 429 and "Too many searches" in response.text
        assert r.directory.calls == 30
        r.h.now += 601
        assert search(r, "later").status_code == 200

    def test_the_search_limit_is_per_user(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        for i in range(31):
            search(r, f"school {i}")
        assert search(r, "again").status_code == 429
        sign_in(r.h, oid=OID_2)
        assert search(r, "again").status_code == 200

    def test_invalid_queries_do_not_use_up_the_limit(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        for _ in range(40):
            search(r, "x")
        assert search(r, "valid").status_code == 200

    def test_a_directory_error_is_503(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True, directory_error=True)
        sign_in(r.h)
        response = search(r, "irvine")
        assert response.status_code == 503 and "directory is unavailable" in response.text

    def test_search_terms_are_not_logged(self, tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        caplog.set_level(logging.DEBUG)
        r = rig(tmp_path, search=True, entries=[DirectoryEntry("N", FOUND)])
        sign_in(r.h)
        search(r, "very-secret-term")
        ours = " ".join(rec.getMessage() for rec in caplog.records if rec.name.startswith("canvas_mcp"))
        assert "very-secret-term" not in ours
        assert "results=1" in ours

    def test_the_real_directory_client_drops_invalid_domains(self, tmp_path: pathlib.Path) -> None:
        """Wire it through the app's own HTTP client: query shape and filtering."""
        seen: list[httpx.Request] = []
        h = build_harness(tmp_path, cfg=make_cfg(schools=SchoolPolicy.build(DEFAULT_URL, FEATURED, True)))

        def respond(request: httpx.Request) -> httpx.Response:
            if request.url.host != "canvas.instructure.com":
                return httpx.Response(200, json={"id_token": "fake-id-token"})
            seen.append(request)
            return httpx.Response(200, json=[
                {"id": 1, "name": "Good U", "domain": FOUND, "distance": None},
                {"id": 2, "name": "Port U", "domain": "canvas.port.edu:8443"},
                {"id": 3, "name": "Scheme U", "domain": "https://canvas.scheme.edu"},
                {"id": 4, "name": "Loopback", "domain": "127.0.0.1"},
            ])

        h.token_response = respond
        sign_in(h)
        text = h.client.get("/account/schools", params={"q": "good"}).text
        assert FOUND in text
        assert "port.edu" not in text and "scheme.edu" not in text and "127.0.0.1" not in text
        (request,) = seen
        assert request.url.host == "canvas.instructure.com"
        assert request.url.path == "/api/v1/accounts/search"
        assert request.url.params["search_term"] == "good"


# -- status card and admin -----------------------------------------------------------------


class TestStatusAndAdmin:
    def test_the_status_card_names_the_school(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path)
        sign_in(r.h)
        enroll(r, HOST_A)
        text = r.h.client.get(ACCOUNT_PATH).text
        assert "<dt>School</dt>" in text
        assert "School &lt;b&gt;A&lt;/b&gt;" in text and f"({HOST_A})" in text

    def test_a_legacy_row_shows_the_default_school(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path)
        r.h.store.put(
            tenant_id=TID, object_id=OID, api_token=CANVAS_TOKEN, canvas_user_id="1",
            canvas_user_name="Old", entra_display_name="O", entra_upn="o@example.test",
        )
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH).text
        assert DEFAULT_HOST in text and "no longer offers" not in text

    def test_a_legacy_row_without_a_default_says_no_school_recorded(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, default="")
        r.h.store.put(
            tenant_id=TID, object_id=OID, api_token=CANVAS_TOKEN, canvas_user_id="1",
            canvas_user_name="Old", entra_display_name="O", entra_upn="o@example.test",
        )
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH).text
        assert "No school recorded" in text and "no longer offers your school" in text

    def test_a_school_the_server_no_longer_offers_gets_a_notice(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path)
        r.h.store.put(
            tenant_id=TID, object_id=OID, api_token=CANVAS_TOKEN, canvas_user_id="1",
            canvas_user_name="Old", entra_display_name="O", entra_upn="o@example.test",
            canvas_host="canvas.gone.edu",
        )
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH).text
        assert "canvas.gone.edu" in text
        assert "This server no longer offers your school. Enroll again." in text

    def test_a_searched_school_is_fine_while_search_is_on(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        r.h.store.put(
            tenant_id=TID, object_id=OID, api_token=CANVAS_TOKEN, canvas_user_id="1",
            canvas_user_name="Old", entra_display_name="O", entra_upn="o@example.test",
            canvas_host=FOUND,
        )
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH).text
        assert FOUND in text and "no longer offers" not in text

    def test_the_admin_page_shows_each_users_school(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=False)
        put = r.h.store.put
        base = {
            "api_token": CANVAS_TOKEN, "canvas_user_id": "1",
            "entra_display_name": "N", "entra_upn": "n@example.test",
        }
        put(tenant_id=TID, object_id=OID, canvas_user_name="Featured", canvas_host=HOST_A, **base)
        put(tenant_id=TID, object_id=OID_2, canvas_user_name="Legacy", **base)
        put(tenant_id=TID, object_id="dddddddd-0000-4000-8000-000000000000",
            canvas_user_name="Gone", canvas_host="canvas.gone.edu", **base)
        sign_in(r.h, oid=OID_OWNER, roles=("Canvas.Owner",))
        text = r.h.client.get("/account/admin").text
        assert "<th>School</th>" in text
        assert f'data-label="School">{HOST_A}</td>' in text
        assert f'data-label="School">{DEFAULT_HOST} <span class="muted">(default)</span></td>' in text
        assert text.count("Not allowed by the current settings") == 1
        gone_cell = text[text.index("canvas.gone.edu") :]
        assert "Not allowed by the current settings" in gone_cell[:200]

    def test_the_admin_page_in_a_server_without_a_default(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, default="")
        r.h.store.put(
            tenant_id=TID, object_id=OID, api_token=CANVAS_TOKEN, canvas_user_id="1",
            canvas_user_name="Legacy", entra_display_name="N", entra_upn="n@example.test",
        )
        sign_in(r.h, oid=OID_OWNER, roles=("Canvas.Owner",))
        text = r.h.client.get("/account/admin").text
        assert 'data-label="School">-<br>' in text
        assert "Not allowed by the current settings" in text


# -- languages ------------------------------------------------------------------------------


class TestLanguages:
    @pytest.mark.parametrize("lang", ["zh", "en"])
    def test_the_new_pages_render_one_language_only(self, tmp_path: pathlib.Path, lang: str) -> None:
        r = rig(tmp_path, search=True, entries=[DirectoryEntry("Found U", FOUND)])
        use_lang(r.h, lang)
        pages = []
        sign_in(r.h)
        pages.append(r.h.client.get(ACCOUNT_PATH))  # picker + search card, not enrolled
        pages.append(r.h.client.get(ACCOUNT_PATH, params={"school": FOUND}))  # extra radio
        pages.append(r.h.client.get("/account/schools"))
        pages.append(search(r, "found"))
        pages.append(search(r, "x"))  # 400
        pages.append(enroll(r, "canvas.nowhere.edu"))  # directory refuses -> 400
        enroll(r, HOST_A)
        pages.append(r.h.client.get(ACCOUNT_PATH))  # status card with School
        r.h.store.put(
            tenant_id=TID, object_id=OID, api_token=CANVAS_TOKEN, canvas_user_id="1",
            canvas_user_name="Old", entra_display_name="O", entra_upn="o@example.test",
            canvas_host="canvas.gone.edu",
        )
        pages.append(r.h.client.get(ACCOUNT_PATH))  # no longer offered notice
        sign_in(r.h, oid=OID_OWNER, roles=("Canvas.Owner",))
        pages.append(r.h.client.get("/account/admin"))
        r.h.client.get(ACCOUNT_PATH, params={"lang": lang})
        pairs = [(static_text(zh), static_text(en)) for _, zh, en in bi_calls()]
        for page in pages:
            assert_security_headers(page)
            body = strip_chrome(page.text)
            if lang == "en":
                assert not CJK.search(body)
            for zh_text, en_text in pairs:
                if zh_text is None or en_text is None or zh_text == en_text:
                    continue
                if lang == "zh" and len(en_text) >= 10:
                    assert en_text not in body, en_text
                if lang == "en":
                    assert zh_text not in body, zh_text

    def test_the_new_strings_exist_in_both_languages(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True, entries=[DirectoryEntry("Found U", FOUND)])
        use_lang(r.h, "zh")
        sign_in(r.h)
        text = r.h.client.get(ACCOUNT_PATH).text
        assert "你的学校" in text and "搜索其他学校" in text
        assert "搜索词会发送给 Instructure 的公共学校目录。" in text
        assert "Your school" not in text
        assert "学校目录" in enroll(r, "canvas.nowhere.edu").text

    def test_the_language_toggle_works_on_the_search_page(self, tmp_path: pathlib.Path) -> None:
        r = rig(tmp_path, search=True)
        sign_in(r.h)
        text = r.h.client.get("/account/schools").text
        assert 'href="/account/schools?lang=zh"' in text
        zh = r.h.client.get("/account/schools", params={"lang": "zh"}).text
        assert 'href="/account/schools?lang=en"' in zh


def test_account_config_requires_a_policy() -> None:
    cfg = make_cfg()
    assert isinstance(cfg, AccountConfig) and cfg.schools.default is not None
    assert not hasattr(cfg, "canvas_api_url")
