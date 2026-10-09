"""Course state per auth mode: request-local upstream HTTP, principal-cached entra-oauth.

Upstream's HTTP modes (X-Canvas-Token, access key, Easy Auth) keep course
aliases and labels inside one request and publish nothing that outlives it.
Only a verified principal (MCP_AUTH_MODE=entra-oauth) gets a cache that
persists across that principal's requests. stdio keeps its single local cache.
"""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastmcp import FastMCP

from canvas_mcp.core import cache
from canvas_mcp.core.credentials import (
    RequestCredentials,
    clear_http_request_context,
    set_http_request_active,
    set_request_credentials,
    set_request_principal,
    uses_request_local_course_state,
)
from canvas_mcp.tools import courses as course_tools

from .conftest import OID_A, OID_B, make_principal

CANVAS_URL = "https://canvas.example.test/api/v1"


async def request_as(
    fn: Callable[[], Awaitable[Any]], *, token: str, oid: str | None = None
) -> Any:
    """Run ``fn`` as one HTTP request (call inside its own task: own context).

    With ``oid`` it is a verified self-hosted principal (entra-oauth); without,
    one of the upstream HTTP modes.
    """
    set_http_request_active(True)
    if oid is not None:
        set_request_principal(make_principal(oid))
    set_request_credentials(RequestCredentials(api_token=token, api_url=CANVAS_URL))
    try:
        return await fn()
    finally:
        clear_http_request_context()


def fresh_request(fn: Callable[[], Awaitable[Any]], **kwargs: Any) -> Awaitable[Any]:
    """A separate request: its own task, so its own ContextVar copy."""
    return asyncio.create_task(request_as(fn, **kwargs))


@pytest.fixture
def canvas(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Course-list reads; ``canvas.return_value`` is the list Canvas returns."""
    reads = AsyncMock(return_value=[{"id": 101, "course_code": "ICS 33", "name": "Python"}])
    monkeypatch.setattr(cache, "fetch_all_paginated_results", reads)
    monkeypatch.setattr(cache, "make_canvas_request", AsyncMock(return_value={"error": "HTTP error: 404"}))
    return reads


class TestMode:
    def test_the_predicate_by_mode(self):
        assert uses_request_local_course_state() is False  # stdio
        set_http_request_active(True)
        assert uses_request_local_course_state() is True  # token / access key / Easy Auth
        set_request_principal(make_principal(OID_A))
        assert uses_request_local_course_state() is False  # entra-oauth


class TestUpstreamHttpIsRequestLocal:
    async def test_nothing_is_registered_and_every_request_reads_its_own_course_list(self, canvas):
        for _ in range(3):
            result = await fresh_request(
                lambda: cache.resolve_numeric_course_id("ICS 33"), token="tok-a"
            )
            assert result == ("101", None)
        assert canvas.await_count == 3  # no throttle, no shared aliases between requests
        assert list(cache._STATES) == []

    async def test_a_later_request_with_the_same_token_sees_changed_courses(self, canvas):
        assert await fresh_request(
            lambda: cache.resolve_numeric_course_id("ICS 33"), token="tok-a"
        ) == ("101", None)
        canvas.return_value = [{"id": 999, "course_code": "ICS 33"}]
        assert await fresh_request(
            lambda: cache.resolve_numeric_course_id("ICS 33"), token="tok-a"
        ) == ("999", None)

    async def test_refresh_and_remembered_codes_do_not_outlive_the_request(self, canvas):
        async def work() -> bool:
            cache.remember_course_code("555", "OLD 1")
            assert cache.current_cache_state().code_to_id == {}  # throwaway state
            return await cache.refresh_course_cache()

        assert await fresh_request(work, token="tok-a") is True
        assert list(cache._STATES) == []

    async def test_stdio_cache_is_untouched_by_an_http_request(self, canvas):
        cache.remember_course_code("1", "LOCAL 1")
        await fresh_request(lambda: cache.resolve_numeric_course_id("ICS 33"), token="tok-a")
        assert list(cache._STATES) == ["local"]
        assert cache.current_cache_state().code_to_id == {"LOCAL 1": "1"}
        assert cache.current_cache_state().records == []

    async def test_legacy_names_inside_a_request_are_the_stdio_objects(self):
        cache.remember_course_code("1", "LOCAL 1")
        seen = await fresh_request(
            lambda: _async_value(dict(cache.course_code_to_id_cache)), token="tok-a"
        )
        assert seen == {"LOCAL 1": "1"}

    async def test_labels_are_read_per_request(self, monkeypatch):
        request = AsyncMock(return_value={"id": 202, "course_code": "B ONLY"})
        monkeypatch.setattr(cache, "make_canvas_request", request)

        async def twice() -> tuple[str | None, str | None]:
            return await cache.get_course_code("202"), await cache.get_course_code("202")

        assert await fresh_request(twice, token="tok-a") == ("B ONLY", "B ONLY")
        assert request.await_count == 1
        await fresh_request(twice, token="tok-a")
        assert request.await_count == 2
        assert list(cache._STATES) == []

    async def test_course_tools_publish_nothing(self, monkeypatch):
        course = {"id": 202, "course_code": "B ONLY", "name": "Private B Course"}
        monkeypatch.setattr(course_tools, "fetch_all_paginated_results", AsyncMock(return_value=[course]))
        monkeypatch.setattr(course_tools, "make_canvas_request", AsyncMock(return_value=course))
        mcp = FastMCP("course-state-modes")
        course_tools.register_course_tools(mcp)
        tools = {tool.name: tool for tool in await mcp.list_tools(run_middleware=False)}

        async def call_both() -> None:
            await tools["list_courses"].fn()
            await tools["get_course_details"].fn(course_identifier="202")

        await fresh_request(call_both, token="tok-a")
        assert list(cache._STATES) == []

    async def test_courses_module_legacy_names_are_the_cache_objects(self, monkeypatch):
        """#480's tests seed these names on tools.courses; they must be the cache's own."""
        seeded: dict[str, str] = {"SEED": "9"}
        monkeypatch.setattr(course_tools, "course_code_to_id_cache", seeded)
        monkeypatch.setattr(course_tools, "id_to_course_code_cache", {"9": "SEED"})
        assert cache.course_code_to_id_cache is seeded
        assert course_tools.course_code_to_id_cache is seeded
        assert course_tools.id_to_course_code_cache == {"9": "SEED"}

    async def test_seeded_legacy_names_never_register_a_request_state(self, monkeypatch):
        """Pins the boundary the #480 tests cannot see: legacy-name seeding is stdio's state."""
        codes: dict[str, str] = {}
        labels: dict[str, str] = {}
        for module in (cache, course_tools):
            monkeypatch.setattr(module, "course_code_to_id_cache", codes)
            monkeypatch.setattr(module, "id_to_course_code_cache", labels)
        course = {"id": 202, "course_code": "B ONLY", "name": "Private B Course"}
        monkeypatch.setattr(course_tools, "fetch_all_paginated_results", AsyncMock(return_value=[course]))
        monkeypatch.setattr(course_tools, "make_canvas_request", AsyncMock(return_value=course))
        mcp = FastMCP("course-state-modes")
        course_tools.register_course_tools(mcp)
        tools = {tool.name: tool for tool in await mcp.list_tools(run_middleware=False)}

        async def call_both() -> None:
            await tools["list_courses"].fn()
            await tools["get_course_details"].fn(course_identifier="202")

        await fresh_request(call_both, token="tok-a")
        assert codes == {} and labels == {}
        assert set(cache._STATES) <= {"local"}

    async def test_ambiguous_alias_is_refused(self, canvas):
        canvas.return_value = [
            {"id": 1, "course_code": "BADM_554"},
            {"id": 2, "course_code": "OTHER", "name": "BADM_554"},
        ]
        with pytest.raises(ValueError, match="IDs 1, 2"):
            await fresh_request(lambda: cache.get_course_id("BADM_554"), token="tok-a")


class TestEntraOauthKeepsThePrincipalCache:
    async def test_a_second_request_of_the_same_principal_reuses_the_cache(self, canvas):
        for _ in range(3):
            result = await fresh_request(
                lambda: cache.resolve_numeric_course_id("ICS 33"), token="tok-a", oid=OID_A
            )
            assert result == ("101", None)
        assert canvas.await_count == 1
        assert list(cache._STATES) == [f"{make_principal(OID_A).key}|{CANVAS_URL}"]

    async def test_principals_do_not_share_it(self, canvas):
        await fresh_request(lambda: cache.resolve_numeric_course_id("ICS 33"), token="a", oid=OID_A)
        canvas.return_value = []
        other = await fresh_request(
            lambda: cache.resolve_numeric_course_id("ICS 33"), token="b", oid=OID_B
        )
        assert other[0] is None
        assert len(cache._STATES) == 2

    async def test_remembered_codes_and_labels_persist_for_the_principal(self):
        async def remember() -> None:
            cache.remember_course_code("555", "OLD 7")

        async def label() -> str | None:
            return await cache.get_course_code("555")

        await fresh_request(remember, token="tok-a", oid=OID_A)
        assert await fresh_request(label, token="tok-a", oid=OID_A) == "OLD 7"

    async def test_legacy_names_are_the_principals_state(self):
        async def names() -> bool:
            return cache.course_code_to_id_cache is cache.current_cache_state().code_to_id

        assert await fresh_request(names, token="tok-a", oid=OID_A) is True

    async def test_course_tools_fill_the_principals_cache(self, monkeypatch):
        course = {"id": 202, "course_code": "B ONLY", "name": "Private B Course"}
        monkeypatch.setattr(course_tools, "fetch_all_paginated_results", AsyncMock(return_value=[course]))
        mcp = FastMCP("course-state-modes")
        course_tools.register_course_tools(mcp)
        tools = {tool.name: tool for tool in await mcp.list_tools(run_middleware=False)}

        async def list_then_read() -> dict[str, str]:
            await tools["list_courses"].fn()
            return dict(cache.current_cache_state().id_to_code)

        assert await fresh_request(list_then_read, token="tok-a", oid=OID_A) == {"202": "B ONLY"}


async def _async_value(value: Any) -> Any:
    return value
