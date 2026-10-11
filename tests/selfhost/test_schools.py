"""School host rules, address rules, the directory client and the policy."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import httpx
import pytest

from canvas_mcp.core.selfhost.schools import (
    CONFIRM_RESULTS,
    DIRECTORY_SEARCH_PATH,
    INSTRUCTURE_DIRECTORY_URL,
    MAX_SCHOOL_NAME,
    DirectoryEntry,
    DirectoryError,
    School,
    SchoolDirectory,
    SchoolPolicy,
    check_public_host,
    is_blocked_hostname,
    is_public_address,
    parse_hostname,
)

# -- parse_hostname -------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("canvas.school.edu", "canvas.school.edu"),
        ("  Canvas.School.EDU " + chr(10), "canvas.school.edu"),
        ("a-b.c-d.example.org", "a-b.c-d.example.org"),
        ("xn--bcher-kva.example.edu", "xn--bcher-kva.example.edu"),
        ("a" * 63 + ".edu", "a" * 63 + ".edu"),
    ],
)
def test_parse_hostname_accepts(raw: str, expected: str) -> None:
    assert parse_hostname(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "https://canvas.school.edu",
        "canvas.school.edu:8443",
        "canvas.school.edu/path",
        "canvas.school.edu/",
        "user@canvas.school.edu",
        "canvas.school.edu?x=1",
        "canvas.school.edu#frag",
        "canvas.school.edu\\x",
        "canvas.school.edu%2f",
        "[::1]",
        "127.0.0.1",
        "10.0.0.1",
        "8.8.8.8",
        "2130706433",
        "0x7f.1",
        "0x7f000001",
        "1.2.3.4",
        "::1",
        "localhost",
        "school",
        "canvas.school.123",
        "-bad.school.edu",
        "bad-.school.edu",
        "bad_label.school.edu",
        "a..edu",
        ".school.edu",
        "canvas.school.edu.",
        "a" * 64 + ".edu",
        "can vas.school.edu",
        "can\tvas.school.edu",
        "can\x00vas.school.edu",
        "can\x7fvas.school.edu",
        "café.school.edu",
        "сanvas.school.edu",
    ],
)
def test_parse_hostname_rejects(raw: str) -> None:
    assert parse_hostname(raw) is None


def test_254_character_host_is_rejected() -> None:
    host = ".".join(["a" * 50] * 5) + ".edu"
    assert len(host) > 253
    assert parse_hostname(host) is None


@pytest.mark.parametrize(
    ("host", "blocked"),
    [
        ("localhost", True),
        ("foo.localhost", True),
        ("printer.local", True),
        ("db.internal", True),
        ("router.lan", True),
        ("nas.home", True),
        ("x.corp", True),
        ("x.intranet", True),
        ("x.localdomain", True),
        ("home.arpa", True),
        ("x.invalid", True),
        ("x.test", True),
        ("canvas.example", True),
        ("hidden.onion", True),
        ("canvas.school.edu", False),
        ("local.school.edu", False),
        ("canvas.instructure.com", False),
        ("home.example.com", False),
    ],
)
def test_is_blocked_hostname(host: str, blocked: bool) -> None:
    assert is_blocked_hostname(host) is blocked


# -- is_public_address ------------------------------------------------------------


@pytest.mark.parametrize(
    "addr",
    [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "127.0.0.1",
        "127.1.2.3",
        "0.0.0.0",
        "100.64.0.1",
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "fe80::1%eth0",
        "fc00::1",
        "fec0::1",
        "fec0:0:0:ffff::1",
        "fd12:3456::1",
        "fd00:ec2::254",
        "ff02::1",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "64:ff9b::a00:1",
        "2002:a00:1::",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "not-an-ip",
        "",
    ],
)
def test_non_public_addresses_are_refused(addr: str) -> None:
    assert is_public_address(addr) is False


@pytest.mark.parametrize(
    "addr",
    ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "::ffff:8.8.8.8"],
)
def test_public_addresses_are_accepted(addr: str) -> None:
    assert is_public_address(addr) is True


# -- check_public_host --------------------------------------------------------------


def _resolver(result: Sequence[str] | BaseException) -> Any:
    async def resolve(host: str) -> Sequence[str]:
        if isinstance(result, BaseException):
            raise result
        return result

    return resolve


async def test_check_public_host_ok() -> None:
    assert (
        await check_public_host("x.edu", _resolver(["8.8.8.8", "2606:4700:4700::1111"]))
        == "ok"
    )


async def test_one_private_address_among_public_ones_blocks() -> None:
    assert (
        await check_public_host("x.edu", _resolver(["8.8.8.8", "10.0.0.5"]))
        == "blocked"
    )


async def test_metadata_address_blocks() -> None:
    assert await check_public_host("x.edu", _resolver(["169.254.169.254"])) == "blocked"


async def test_empty_answer_is_unresolvable() -> None:
    assert await check_public_host("x.edu", _resolver([])) == "unresolvable"


@pytest.mark.parametrize(
    "error", [OSError("nxdomain"), TimeoutError(), RuntimeError("boom")]
)
async def test_resolver_errors_are_unresolvable(error: BaseException) -> None:
    assert await check_public_host("x.edu", _resolver(error)) == "unresolvable"


async def test_system_resolve_uses_getaddrinfo(monkeypatch: pytest.MonkeyPatch) -> None:
    from canvas_mcp.core.selfhost import schools

    def fake_getaddrinfo(host: str, port: int, family: int, kind: int) -> list[Any]:
        assert (host, port) == ("x.edu", 443)
        return [(2, 1, 6, "", ("8.8.8.8", 443)), (2, 1, 6, "", ("8.8.8.8", 443))]

    monkeypatch.setattr(schools.socket, "getaddrinfo", fake_getaddrinfo)
    assert list(await schools.system_resolve("x.edu")) == ["8.8.8.8"]


async def test_system_resolve_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    from canvas_mcp.core.selfhost import schools

    monkeypatch.setattr(schools, "RESOLVE_TIMEOUT_SECONDS", 0.05)

    def slow(*_a: Any) -> list[Any]:
        # A late answer with a public address: only a real timeout makes the
        # host unresolvable, so this fails if the wait is not bounded.
        time.sleep(0.6)
        return [(2, 1, 6, "", ("8.8.8.8", 443))]

    monkeypatch.setattr(schools.socket, "getaddrinfo", slow)
    started = time.monotonic()
    assert await check_public_host("x.edu", schools.system_resolve) == "unresolvable"
    assert time.monotonic() - started < 0.4


# -- SchoolDirectory ------------------------------------------------------------------


class Recorder:
    def __init__(self, handler: Any) -> None:
        self.requests: list[httpx.Request] = []
        self._handler = handler

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request)

    def factory(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self))


def directory_with(handler: Any, **kw: Any) -> tuple[SchoolDirectory, Recorder]:
    rec = Recorder(handler)
    return SchoolDirectory(rec.factory, **kw), rec


def entry(domain: str, name: str = "A School", **extra: Any) -> dict[str, Any]:
    return {"id": 1, "name": name, "domain": domain, "distance": None, **extra}


async def test_search_request_shape_and_parsing() -> None:
    directory, rec = directory_with(
        lambda r: httpx.Response(
            200, json=[entry("Canvas.A.edu", "A U"), entry("canvas.b.edu", "B U")]
        )
    )
    result = await directory.search("irvine", limit=7)
    assert result == [
        DirectoryEntry("A U", "canvas.a.edu"),
        DirectoryEntry("B U", "canvas.b.edu"),
    ]
    (request,) = rec.requests
    assert request.method == "GET"
    assert str(request.url).startswith(
        INSTRUCTURE_DIRECTORY_URL + DIRECTORY_SEARCH_PATH
    )
    assert request.url.params["search_term"] == "irvine"
    assert request.url.params["per_page"] == "7"
    assert request.headers["accept"] == "application/json"
    assert "authorization" not in request.headers


async def test_base_url_is_injectable() -> None:
    directory, rec = directory_with(
        lambda r: httpx.Response(200, json=[]), base_url="https://dir.test.invalid/"
    )
    await directory.search("abc")
    assert rec.requests[0].url.host == "dir.test.invalid"
    assert rec.requests[0].url.path == DIRECTORY_SEARCH_PATH


async def test_redirects_are_not_followed() -> None:
    directory, rec = directory_with(
        lambda r: httpx.Response(302, headers={"Location": "https://evil.test/"})
    )
    with pytest.raises(DirectoryError):
        await directory.search("abc")
    assert len(rec.requests) == 1


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500),
        httpx.Response(404, json=[]),
        httpx.Response(200, content=b"<html>not json</html>"),
        httpx.Response(200, json={"errors": []}),
        httpx.Response(200, json="text"),
    ],
)
async def test_directory_failures_raise(response: httpx.Response) -> None:
    directory, _ = directory_with(lambda r: response)
    with pytest.raises(DirectoryError):
        await directory.search("abc")


async def test_network_error_raises_directory_error() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    directory, _ = directory_with(boom)
    with pytest.raises(DirectoryError):
        await directory.search("abc")


async def test_invalid_domains_are_dropped() -> None:
    body = [
        entry("https://canvas.a.edu"),
        entry("canvas.b.edu:8443"),
        entry("canvas.c.edu/lms"),
        entry("127.0.0.1"),
        entry(""),
        {"name": "No domain"},
        "not a dict",
        entry("canvas.ok.edu", "Fine"),
        entry(None),
    ]
    directory, _ = directory_with(lambda r: httpx.Response(200, json=body))
    assert await directory.search("x") == [DirectoryEntry("Fine", "canvas.ok.edu")]


async def test_names_are_cleaned_truncated_and_default_to_the_domain() -> None:
    body = [
        entry("a.school.edu", "Evil\x00\x1b[31m  Name\n\tHere"),
        entry("b.school.edu", "n" * 500),
        entry("c.school.edu", ""),
        entry("d.school.edu", None),
    ]
    directory, _ = directory_with(lambda r: httpx.Response(200, json=body))
    a, b, c, d = await directory.search("x")
    assert "\x00" not in a.name and "\x1b" not in a.name and "\n" not in a.name
    assert a.name.endswith("Name Here")
    assert len(b.name) == MAX_SCHOOL_NAME
    assert c.name == "c.school.edu"
    assert d.name == "d.school.edu"


async def test_results_are_deduplicated_and_capped() -> None:
    body = [entry(f"s{i}.school.edu") for i in range(20)] + [entry("s0.school.edu")]
    directory, _ = directory_with(lambda r: httpx.Response(200, json=body))
    assert len(await directory.search("x", limit=5)) == 5
    dup = [entry("a.school.edu"), entry("A.school.edu"), entry("b.school.edu")]
    directory2, _ = directory_with(lambda r: httpx.Response(200, json=dup))
    assert [e.domain for e in await directory2.search("x")] == [
        "a.school.edu",
        "b.school.edu",
    ]


async def test_confirm_requests_the_host_itself() -> None:
    directory, rec = directory_with(
        lambda r: httpx.Response(200, json=[entry("canvas.a.edu", "A U")])
    )
    found = await directory.confirm("canvas.a.edu")
    assert found == DirectoryEntry("A U", "canvas.a.edu")
    assert rec.requests[0].url.params["search_term"] == "canvas.a.edu"
    assert rec.requests[0].url.params["per_page"] == str(CONFIRM_RESULTS)


async def test_confirm_is_case_insensitive_and_exact() -> None:
    directory, _ = directory_with(
        lambda r: httpx.Response(200, json=[entry("Canvas.A.EDU", "A U")])
    )
    assert (await directory.confirm("CANVAS.a.edu")) == DirectoryEntry(
        "A U", "canvas.a.edu"
    )


@pytest.mark.parametrize(
    "domain",
    [
        "canvas.a.edu.evil.com",
        "a.edu",
        "xcanvas.a.edu",
        "canvas.a.edu.",
        "canvas.a.ed",
        "anvas.a.edu",
    ],
)
async def test_confirm_rejects_near_misses(domain: str) -> None:
    directory, _ = directory_with(lambda r: httpx.Response(200, json=[entry(domain)]))
    assert await directory.confirm("canvas.a.edu") is None


async def test_confirm_with_no_results_is_none() -> None:
    directory, _ = directory_with(lambda r: httpx.Response(200, json=[]))
    assert await directory.confirm("canvas.a.edu") is None


async def test_confirm_propagates_directory_errors() -> None:
    directory, _ = directory_with(lambda r: httpx.Response(503))
    with pytest.raises(DirectoryError):
        await directory.confirm("canvas.a.edu")


# -- SchoolPolicy -----------------------------------------------------------------------

FEATURED = (
    School("canvas.a.edu", "https://canvas.a.edu/api/v1", "A U"),
    School("canvas.b.edu", "https://canvas.b.edu/api/v1", "B U"),
)


def test_featured_policy_has_only_explicit_database_schools():
    policy = SchoolPolicy(featured=FEATURED, search_enabled=False)
    assert policy.featured == FEATURED and policy.picker_enabled
    assert policy.sole_school is None
    assert policy.resolve_stored(None) is None


def test_single_featured_school_is_the_sole_school():
    policy = SchoolPolicy(featured=FEATURED[:1], search_enabled=False)
    assert not policy.picker_enabled and policy.sole_school == FEATURED[0]


def test_search_enables_the_picker_even_for_one_school():
    policy = SchoolPolicy(featured=FEATURED[:1], search_enabled=True)
    assert policy.picker_enabled and policy.sole_school is None


def test_search_only_has_no_implicit_school():
    policy = SchoolPolicy()
    assert (
        policy.featured == () and policy.picker_enabled and policy.sole_school is None
    )
    assert policy.resolve_stored(None) is None


def test_empty_closed_policy_refuses_every_host():
    policy = SchoolPolicy(search_enabled=False)
    assert policy.sole_school is None and policy.resolve_stored(None) is None
    assert policy.resolve_stored("canvas.a.edu") is None


def test_resolve_stored_uses_explicit_school_url_verbatim():
    school = School(
        "canvas.private.edu",
        "https://canvas.private.edu:8443/lms/api/v1",
        "Private",
        True,
    )
    policy = SchoolPolicy(private=(school,), search_enabled=False)
    assert policy.resolve_stored(school.host) == school
    assert policy.resolve_stored(None) is None
    assert policy.featured_school(school.host) is None


def test_resolve_stored_searched_hosts_need_search_enabled():
    off = SchoolPolicy(featured=FEATURED, search_enabled=False)
    on = SchoolPolicy(featured=FEATURED, search_enabled=True)
    assert off.resolve_stored("canvas.found.edu") is None
    assert on.resolve_stored("canvas.found.edu") == School(
        "canvas.found.edu", "https://canvas.found.edu/api/v1", "canvas.found.edu"
    )
    assert off.resolve_stored("canvas.a.edu") == FEATURED[0]


@pytest.mark.parametrize(
    "stored",
    [
        None,
        "",
        "localhost",
        "127.0.0.1",
        "x.local",
        "Canvas.Found.edu",
        "canvas.found.edu:8443",
        "a/b.edu",
        " canvas.found.edu",
    ],
)
def test_resolve_stored_never_trusts_odd_stored_hosts(stored):
    assert SchoolPolicy().resolve_stored(stored) is None


def test_featured_school_lookup():
    policy = SchoolPolicy(featured=FEATURED, search_enabled=False)
    assert policy.featured_school("canvas.a.edu") == FEATURED[0]
    assert policy.featured_school("nope.edu") is None


def test_policy_is_immutable():
    policy = SchoolPolicy(featured=FEATURED, search_enabled=False)
    with pytest.raises(AttributeError):
        policy.search_enabled = True
