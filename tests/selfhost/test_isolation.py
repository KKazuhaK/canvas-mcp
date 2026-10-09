"""Two principals, interleaved: no process-global cache may carry data across them."""

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock

import pytest

from canvas_mcp.core import anonymization, cache, course_policy
from canvas_mcp.core.credentials import (
    RequestCredentials,
    current_principal_key,
    get_request_credentials,
    set_http_request_active,
    set_request_credentials,
    set_request_principal,
)
from canvas_mcp.core.write_confirmation import ConfirmationGuard
from canvas_mcp.tools import discussions

from .conftest import OID_A, OID_B, make_principal

CANVAS_URL = "https://canvas.example.test/api/v1"

COURSES = {
    OID_A: [{"id": 101, "course_code": "ICS 33", "name": "Intermediate Python", "sis_course_id": "A-SIS"}],
    OID_B: [{"id": 202, "course_code": "MATH 2B", "name": "Calculus", "sis_course_id": "B-SIS"}],
}


async def as_user(oid: str, fn: Callable[[], Awaitable[Any]]) -> Any:
    """Run ``fn`` as the given principal (call inside asyncio.gather: own context)."""
    set_request_principal(make_principal(oid))
    set_request_credentials(RequestCredentials(api_token=f"canvas-token-of-{oid}", api_url=CANVAS_URL))
    set_http_request_active(True)
    return await fn()


def school_key(oid: str, api_url: str = CANVAS_URL) -> str:
    """The cache key of a principal at a school and credential generation (``g0`` here)."""
    return f"{make_principal(oid).key}|{api_url.rstrip('/').lower()}|g0"


def as_user_sync(oid: str) -> None:
    set_request_principal(make_principal(oid))
    set_request_credentials(RequestCredentials(api_token=f"canvas-token-of-{oid}", api_url=CANVAS_URL))


@pytest.fixture(autouse=True)
def clean_global_state():
    course_policy.reset_policy_cache()
    anonymization.clear_anonymization_cache()
    anonymization._anonymization_cache.clear()
    discussions._unservable_topics.clear()
    yield
    course_policy.reset_policy_cache()
    anonymization._anonymization_cache.clear()
    discussions._unservable_topics.clear()


class CourseListCanvas:
    """Canvas stand-in: answers /courses with the CALLER's own courses."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.reads: list[str] = []
        monkeypatch.setattr(cache, "fetch_all_paginated_results", self.paginate)
        monkeypatch.setattr(cache, "make_canvas_request", self.request)

    async def paginate(self, endpoint: str, params: dict[str, Any] | None = None) -> Any:
        assert endpoint == "/courses"
        creds = get_request_credentials()
        assert creds is not None
        oid = creds.api_token.removeprefix("canvas-token-of-")
        self.reads.append(oid)
        await asyncio.sleep(0)  # let the other caller's request interleave
        await asyncio.sleep(0)
        return [dict(course) for course in COURSES[oid]]

    async def request(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        await asyncio.sleep(0)
        return {"error": "HTTP error: 404"}


class TestCourseCache:
    async def test_interleaved_lookups_resolve_only_the_callers_own_courses(self, monkeypatch):
        canvas = CourseListCanvas(monkeypatch)
        a, b = await asyncio.gather(
            as_user(OID_A, lambda: cache.resolve_numeric_course_id("ICS 33")),
            as_user(OID_B, lambda: cache.resolve_numeric_course_id("ICS 33")),
        )
        assert a == ("101", None)
        assert b[0] is None
        assert b[1] is not None and "among your Canvas courses" in b[1]
        assert "101" not in b[1]
        # Each caller's miss read the course list with its OWN token.
        assert sorted(canvas.reads) == sorted([OID_A, OID_B])

    async def test_each_caller_sees_only_their_own_records_afterwards(self, monkeypatch):
        CourseListCanvas(monkeypatch)
        await asyncio.gather(
            as_user(OID_A, lambda: cache.resolve_numeric_course_id("ICS 33")),
            as_user(OID_B, lambda: cache.resolve_numeric_course_id("MATH 2B")),
        )

        async def snapshot() -> tuple[list[tuple[str, str, str, str]], dict[str, str]]:
            state = cache.current_cache_state()
            return list(state.records), dict(state.code_to_id)

        (records_a, codes_a), (records_b, codes_b) = await asyncio.gather(
            as_user(OID_A, snapshot), as_user(OID_B, snapshot)
        )
        assert [r[0] for r in records_a] == ["101"] and codes_a == {"ICS 33": "101"}
        assert [r[0] for r in records_b] == ["202"] and codes_b == {"MATH 2B": "202"}

    async def test_refresh_is_shared_only_with_the_same_caller(self, monkeypatch):
        canvas = CourseListCanvas(monkeypatch)

        async def lookup(name: str) -> tuple[str | None, str | None]:
            return await cache.resolve_numeric_course_id(name)

        results = await asyncio.gather(
            as_user(OID_A, lambda: lookup("ICS 33")),
            as_user(OID_A, lambda: lookup("Intermediate Python")),
            as_user(OID_B, lambda: lookup("MATH 2B")),
            as_user(OID_B, lambda: lookup("Calculus")),
        )
        assert [r[0] for r in results] == ["101", "101", "202", "202"]
        # Two callers, one refresh each: A's in-flight refresh (run with A's
        # token) was never awaited by B, and B's never by A.
        assert sorted(canvas.reads) == sorted([OID_A, OID_B])

    async def test_refresh_task_lives_on_the_callers_state(self, monkeypatch):
        CourseListCanvas(monkeypatch)

        async def start() -> asyncio.Task[bool] | None:
            await cache.resolve_numeric_course_id("nothing like this")
            return cache.current_cache_state().refresh_task

        task_a, task_b = await asyncio.gather(as_user(OID_A, start), as_user(OID_B, start))
        assert task_a is not None and task_b is not None
        assert task_a is not task_b

    async def test_course_codes_learned_for_one_caller_do_not_resolve_for_another(self, monkeypatch):
        CourseListCanvas(monkeypatch)

        async def remember() -> None:
            cache.remember_course_code("999", "OLD 1")

        async def lookup() -> tuple[str | None, str | None]:
            return await cache.resolve_numeric_course_id("OLD 1")

        await as_user(OID_A, remember)
        assert (await as_user(OID_A, lookup))[0] == "999"
        assert (await as_user(OID_B, lookup))[0] is None

    async def test_get_course_id_does_not_leak_a_cached_code(self, monkeypatch):
        CourseListCanvas(monkeypatch)
        a, b = await asyncio.gather(
            as_user(OID_A, lambda: cache.get_course_id("ICS 33")),
            as_user(OID_B, lambda: cache.get_course_id("ICS 33")),
        )
        assert a == "101"
        assert b == "ICS 33"  # unchanged pass-through: B has no such course

    def test_legacy_names_are_the_current_callers_live_objects(self):
        as_user_sync(OID_A)
        codes_a = cache.course_code_to_id_cache
        assert codes_a is cache.current_cache_state().code_to_id
        assert cache.id_to_course_code_cache is cache.current_cache_state().id_to_code
        assert cache.course_records_cache is cache.current_cache_state().records
        as_user_sync(OID_B)
        assert cache.course_code_to_id_cache is not codes_a
        with pytest.raises(AttributeError):
            cache.no_such_name  # noqa: B018

    def test_stdio_uses_the_local_state(self):
        state = cache.current_cache_state()
        assert list(cache._STATES) == ["local"]
        assert cache.current_cache_state() is state

    def test_legacy_http_tokens_are_isolated_from_each_other(self):
        set_request_credentials(RequestCredentials(api_token="legacy-token-one-1234567890", api_url=CANVAS_URL))
        first = cache.current_cache_state()
        set_request_credentials(RequestCredentials(api_token="legacy-token-two-1234567890", api_url=CANVAS_URL))
        second = cache.current_cache_state()
        assert first is not second
        assert all(key.startswith("token:") for key in cache._STATES)
        assert not any("legacy-token" in key for key in cache._STATES)

    def test_reset_for_one_principal_leaves_the_others(self):
        as_user_sync(OID_A)
        state_a = cache.current_cache_state()
        as_user_sync(OID_B)
        state_b = cache.current_cache_state()
        cache.reset_course_cache(make_principal(OID_A).key)
        assert cache.current_cache_state() is state_b
        as_user_sync(OID_A)
        assert cache.current_cache_state() is not state_a

    def test_lru_bound_holds_and_keeps_the_current_principal(self, monkeypatch):
        monkeypatch.setattr(cache, "MAX_CACHED_PRINCIPALS", 3)
        oids = [f"00000000-0000-4000-8000-{i:012d}" for i in range(6)]
        states = {}
        for oid in oids[:3]:
            as_user_sync(oid)
            states[oid] = cache.current_cache_state()
        # Touch the oldest so it becomes the most recently used.
        as_user_sync(oids[0])
        cache.current_cache_state()
        as_user_sync(oids[3])
        cache.current_cache_state()
        assert len(cache._STATES) == 3
        assert school_key(oids[1]) not in cache._STATES  # least recently used went
        assert school_key(oids[0]) in cache._STATES
        for oid in oids[4:]:
            as_user_sync(oid)
            cache.current_cache_state()
            assert len(cache._STATES) == 3
            assert current_principal_key() in cache._STATES


class TestPolicyCache:
    async def test_policy_read_with_one_token_is_not_served_to_another(self, monkeypatch):
        seen_tokens: list[str] = []

        async def fake_request(method: str, endpoint: str, **kwargs: Any) -> dict[str, Any]:
            creds = get_request_credentials()
            assert creds is not None
            seen_tokens.append(creds.api_token)
            await asyncio.sleep(0)
            if creds.api_token.endswith(OID_A):
                return {"syllabus_body": "agent_writes: allow\nnote: Course note for A"}
            return {"syllabus_body": "agent_writes: deny\nnote: Only B sees this"}

        monkeypatch.setattr(course_policy, "make_canvas_request", fake_request)

        async def read() -> Any:
            return await course_policy.get_course_policy(555)

        policy_a, policy_b = await asyncio.gather(as_user(OID_A, read), as_user(OID_B, read))
        assert policy_a.allow_writes is True and policy_a.note == "Course note for A"
        assert policy_b.allow_writes is False and policy_b.note == "Only B sees this"
        assert len(seen_tokens) == 2

        # Second round: each caller is served from THEIR OWN cache entry.
        again_a, again_b = await asyncio.gather(as_user(OID_A, read), as_user(OID_B, read))
        assert (again_a, again_b) == (policy_a, policy_b)
        assert len(seen_tokens) == 2
        assert set(course_policy._policy_cache) == {
            (school_key(OID_A), "555"), (school_key(OID_B), "555"),
        }


class TestAnonymization:
    async def test_pseudonym_maps_and_stats_do_not_cross(self):
        async def work(real_ids: list[int]) -> dict[str, Any]:
            for real_id in real_ids:
                anonymization.generate_anonymous_id(real_id)
                await asyncio.sleep(0)
            return anonymization.get_anonymization_stats()

        stats_a, stats_b = await asyncio.gather(
            as_user(OID_A, lambda: work([1, 2, 3, 4])), as_user(OID_B, lambda: work([77]))
        )
        assert stats_a["total_anonymized_ids"] == 4
        assert stats_b["total_anonymized_ids"] == 1
        assert list(stats_b["sample_mappings"].values()) == [
            "Student_" + hashlib.sha256(b"77").hexdigest()[:8]
        ]

    async def test_clear_acts_on_the_current_principal_only(self):
        async def fill() -> None:
            anonymization.generate_anonymous_id(5)

        async def clear_and_count() -> int:
            anonymization.clear_anonymization_cache()
            return anonymization.get_anonymization_stats()["total_anonymized_ids"]

        async def count() -> int:
            return anonymization.get_anonymization_stats()["total_anonymized_ids"]

        await as_user(OID_A, fill)
        await as_user(OID_B, fill)
        assert await as_user(OID_A, clear_and_count) == 0
        assert await as_user(OID_B, count) == 1

    def test_pseudonym_values_are_unchanged(self):
        expected = "Student_" + hashlib.sha256(b"12345").hexdigest()[:8]
        assert anonymization.generate_anonymous_id(12345) == expected
        assert anonymization.generate_anonymous_id("12345") == expected
        assert anonymization.generate_anonymous_id(12345, prefix="Teacher") == "Teacher_" + expected[8:]

    def test_the_prefix_is_part_of_the_key(self):
        student = anonymization.generate_anonymous_id(9, prefix="Student")
        teacher = anonymization.generate_anonymous_id(9, prefix="Teacher")
        assert student.startswith("Student_") and teacher.startswith("Teacher_")
        assert anonymization.get_anonymization_stats()["total_anonymized_ids"] == 2

    def test_principal_lru_bound(self, monkeypatch):
        monkeypatch.setattr(anonymization, "MAX_ANONYMIZATION_PRINCIPALS", 3)
        oids = [f"00000000-0000-4000-8000-{i:012d}" for i in range(5)]
        for oid in oids:
            as_user_sync(oid)
            anonymization.generate_anonymous_id(1)
            assert len(anonymization._anonymization_cache) <= 3
        assert list(anonymization._anonymization_cache) == [school_key(o) for o in oids[2:]]

    def test_entry_bound_per_principal_drops_the_oldest(self, monkeypatch):
        monkeypatch.setattr(anonymization, "MAX_ANONYMIZATION_ENTRIES", 5)
        as_user_sync(OID_A)
        for real_id in range(8):
            anonymization.generate_anonymous_id(real_id)
        cache_a = anonymization._anonymization_cache[school_key(OID_A)]
        assert len(cache_a) == 5
        assert ("Student", "0") not in cache_a and ("Student", "7") in cache_a
        assert anonymization.get_anonymization_stats()["total_anonymized_ids"] == 5


class TestConfirmationGuard:
    def test_a_preview_by_one_user_cannot_be_redeemed_by_another(self):
        guard = ConfirmationGuard()
        as_user_sync(OID_A)
        fp_a = guard.fingerprint("delete_page", "course-1", "page-9")
        token = guard.issue(fp_a)

        as_user_sync(OID_B)
        fp_b = guard.fingerprint("delete_page", "course-1", "page-9")
        assert fp_b != fp_a
        refusal = guard.check(token, fp_b)
        assert refusal is not None and "does not match" in refusal
        # B learns nothing about A's fingerprint or identity from the refusal.
        assert fp_a not in refusal and make_principal(OID_A).key not in refusal
        assert isinstance(guard.claim(token, fp_b), str)

        # The mismatch burned the token: even its owner must preview again.
        as_user_sync(OID_A)
        later = guard.check(token, fp_a)
        assert later is not None and "already used" in later
        assert isinstance(guard.claim(token, fp_a), str)

    def test_the_owner_can_redeem_once(self):
        guard = ConfirmationGuard()
        as_user_sync(OID_A)
        fp = guard.fingerprint("delete_page", "course-1", "page-9")
        token = guard.issue(fp)
        assert guard.check(token, fp) is None
        assert not isinstance(guard.claim(token, fp), str)
        assert isinstance(guard.claim(token, fp), str)

    def test_re_enrolling_a_canvas_token_does_not_void_a_pending_preview(self):
        guard = ConfirmationGuard()
        as_user_sync(OID_A)
        fp = guard.fingerprint("delete_page", "course-1", "page-9")
        token = guard.issue(fp)
        set_request_credentials(RequestCredentials(api_token="a-brand-new-canvas-token-9999", api_url=CANVAS_URL))
        assert guard.fingerprint("delete_page", "course-1", "page-9") == fp
        assert guard.check(token, fp) is None

    def test_identity_does_not_contain_the_principal_or_token(self):
        guard = ConfirmationGuard()
        as_user_sync(OID_A)
        identity = guard.caller_identity()
        assert len(identity) == 64 and OID_A not in identity and "canvas-token" not in identity

    def test_legacy_behaviour_is_unchanged(self):
        import hmac

        guard = ConfirmationGuard()
        assert guard.caller_identity() == "stdio"
        token = "legacy-canvas-token-1234567890"
        set_request_credentials(RequestCredentials(api_token=token, api_url=CANVAS_URL))
        assert guard.caller_identity() == hmac.new(
            guard._secret, token.encode(), hashlib.sha256
        ).hexdigest()


class TestUnservableTopics:
    async def test_a_routing_hint_learned_for_one_user_is_not_used_for_another(self, monkeypatch):
        monkeypatch.setattr(discussions, "get_config", lambda: type("C", (), {"discussion_graphql_enabled": True})())
        monkeypatch.setattr(discussions, "_find_listed_topic", AsyncMock(return_value={"id": 5, "title": "T"}))
        monkeypatch.setattr(discussions, "_read_discussion_via_graphql", AsyncMock(return_value=(object(), None)))

        async def learn() -> bool:
            discussion, message = await discussions._read_unservable_topic(
                "1", "/courses/1", 5, None, "HTTP error: 404, not found"
            )
            assert discussion is not None and message is None
            return discussions._is_known_unservable("/courses/1", 5)

        async def known() -> bool:
            return discussions._is_known_unservable("/courses/1", 5)

        assert await as_user(OID_A, learn) is True
        assert await as_user(OID_A, known) is True
        assert await as_user(OID_B, known) is False

        # Dropping A's hint (a failed GraphQL read) leaves B's own hint alone.
        assert await as_user(OID_B, learn) is True
        monkeypatch.setattr(discussions, "_read_discussion_via_graphql", AsyncMock(return_value=(None, "boom")))

        async def fall_back() -> Any:
            return await discussions._known_unservable_discussion("1", "/courses/1", 5, None)

        assert await as_user(OID_A, fall_back) is None
        assert await as_user(OID_A, known) is False
        assert await as_user(OID_B, known) is True

    def test_keys_start_with_the_principal(self):
        as_user_sync(OID_A)
        discussions._unservable_topics[(current_principal_key(), "/courses/1", "5")] = float("inf")
        assert discussions._is_known_unservable("/courses/1", 5)
        as_user_sync(OID_B)
        assert not discussions._is_known_unservable("/courses/1", 5)


SCHOOL_X = "https://canvas.school-x.edu/api/v1"
SCHOOL_Y = "https://canvas.school-y.edu/api/v1"


def at_school(oid: str, api_url: str, token: str = "one-and-the-same-token-1234567890") -> None:
    """The same principal (same Canvas token string even) routed to a school."""
    set_request_principal(make_principal(oid))
    set_request_credentials(RequestCredentials(api_token=token, api_url=api_url))


class TestSchoolChange:
    """One principal who moves from school X to school Y must see nothing of X."""

    def test_keys_differ_per_school(self):
        at_school(OID_A, SCHOOL_X)
        key_x = current_principal_key()
        at_school(OID_A, SCHOOL_Y)
        assert current_principal_key() != key_x

    async def test_course_cache_is_not_served_across_schools(self, monkeypatch):
        courses = {
            SCHOOL_X: [{"id": 101, "course_code": "ICS 33", "name": "At school X"}],
            SCHOOL_Y: [{"id": 909, "course_code": "BIO 1", "name": "At school Y"}],
        }
        reads: list[str] = []

        async def paginate(endpoint: str, params: dict[str, Any] | None = None) -> Any:
            creds = get_request_credentials()
            assert creds is not None
            reads.append(creds.api_url)
            return [dict(c) for c in courses[creds.api_url]]

        async def request(method: str, endpoint: str, **kwargs: Any) -> Any:
            return {"error": "HTTP error: 404"}

        monkeypatch.setattr(cache, "fetch_all_paginated_results", paginate)
        monkeypatch.setattr(cache, "make_canvas_request", request)

        at_school(OID_A, SCHOOL_X)
        assert (await cache.resolve_numeric_course_id("ICS 33"))[0] == "101"
        cache.remember_course_code("555", "OLD 7")

        at_school(OID_A, SCHOOL_Y)
        resolved, message = await cache.resolve_numeric_course_id("ICS 33")
        assert resolved is None and message is not None  # school X's course is gone
        assert (await cache.resolve_numeric_course_id("BIO 1"))[0] == "909"
        assert (await cache.resolve_numeric_course_id("OLD 7"))[0] is None  # the code map too
        assert reads == [SCHOOL_X, SCHOOL_Y]

        at_school(OID_A, SCHOOL_X)  # and back: X's own cache is still X's
        assert (await cache.resolve_numeric_course_id("ICS 33"))[0] == "101"
        assert reads == [SCHOOL_X, SCHOOL_Y]

    async def test_policy_cache_is_not_served_across_schools(self, monkeypatch):
        urls: list[str] = []

        async def fake_request(method: str, endpoint: str, **kwargs: Any) -> dict[str, Any]:
            creds = get_request_credentials()
            assert creds is not None
            urls.append(creds.api_url)
            note = "note: Only school X" if creds.api_url == SCHOOL_X else "note: Only school Y"
            return {"syllabus_body": f"agent_writes: allow\n{note}"}

        monkeypatch.setattr(course_policy, "make_canvas_request", fake_request)

        at_school(OID_A, SCHOOL_X)
        assert (await course_policy.get_course_policy(555)).note == "Only school X"
        at_school(OID_A, SCHOOL_Y)
        assert (await course_policy.get_course_policy(555)).note == "Only school Y"
        assert urls == [SCHOOL_X, SCHOOL_Y]

    def test_pseudonym_map_and_stats_do_not_cross(self):
        at_school(OID_A, SCHOOL_X)
        anonymization.generate_anonymous_id(1)
        anonymization.generate_anonymous_id(2)
        assert anonymization.get_anonymization_stats()["total_anonymized_ids"] == 2
        at_school(OID_A, SCHOOL_Y)
        assert anonymization.get_anonymization_stats()["total_anonymized_ids"] == 0
        anonymization.generate_anonymous_id(3)
        anonymization.clear_anonymization_cache()  # clearing at Y leaves X alone
        at_school(OID_A, SCHOOL_X)
        assert anonymization.get_anonymization_stats()["total_anonymized_ids"] == 2

    def test_unservable_topic_hint_does_not_cross(self):
        at_school(OID_A, SCHOOL_X)
        discussions._unservable_topics[(current_principal_key(), "/courses/1", "5")] = float("inf")
        assert discussions._is_known_unservable("/courses/1", 5)
        at_school(OID_A, SCHOOL_Y)
        assert not discussions._is_known_unservable("/courses/1", 5)

    def test_a_preview_made_at_one_school_cannot_be_redeemed_at_another(self):
        guard = ConfirmationGuard()
        at_school(OID_A, SCHOOL_X)
        fp_x = guard.fingerprint("delete_page", "course-1", "page-9")
        token = guard.issue(fp_x)
        at_school(OID_A, SCHOOL_Y)
        fp_y = guard.fingerprint("delete_page", "course-1", "page-9")
        assert fp_y != fp_x
        refusal = guard.check(token, fp_y)
        assert refusal is not None and "does not match" in refusal

    def test_a_preview_survives_re_enrolling_at_the_same_school(self):
        guard = ConfirmationGuard()
        at_school(OID_A, SCHOOL_X, token="the-first-canvas-token-1234567890")
        fp = guard.fingerprint("delete_page", "course-1", "page-9")
        token = guard.issue(fp)
        at_school(OID_A, SCHOOL_X, token="a-different-canvas-token-1234567")
        assert guard.fingerprint("delete_page", "course-1", "page-9") == fp
        assert guard.check(token, fp) is None

    def test_reset_for_a_principal_clears_every_school(self):
        at_school(OID_A, SCHOOL_X)
        state_x = cache.current_cache_state()
        at_school(OID_A, SCHOOL_Y)
        state_y = cache.current_cache_state()
        as_user_sync(OID_B)
        state_b = cache.current_cache_state()
        cache.reset_course_cache(make_principal(OID_A).key)
        assert cache.current_cache_state() is state_b
        at_school(OID_A, SCHOOL_X)
        assert cache.current_cache_state() is not state_x
        at_school(OID_A, SCHOOL_Y)
        assert cache.current_cache_state() is not state_y

    def test_reset_does_not_touch_a_principal_with_a_longer_key(self):
        """Prefix matching uses the '|' separator, so it cannot hit another principal."""
        at_school(OID_A, SCHOOL_X)
        state_a = cache.current_cache_state()
        other = make_principal(OID_A).key + "extra|https://x/api/v1"
        cache._STATES[other] = cache.CourseCacheState()
        cache.reset_course_cache(make_principal(OID_B).key)
        assert cache.current_cache_state() is state_a
        assert other in cache._STATES
        cache.reset_course_cache(make_principal(OID_A).key)
        assert other in cache._STATES
