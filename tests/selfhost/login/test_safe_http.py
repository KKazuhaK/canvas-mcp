"""SafeHttp: what the server will and will not call, and what an error can carry."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from canvas_mcp.core.selfhost.login.http import SafeHttp, UpstreamError, check_url

URL = "https://idp.example.edu/.well-known/openid-configuration"


def make(handler: Any, **kw: Any) -> tuple[SafeHttp, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)  # type: ignore[no-any-return]

    return SafeHttp(transport=httpx.MockTransport(wrapped), **kw), seen


def ok(body: Any = None) -> Any:
    return lambda _r: httpx.Response(200, json={"ok": 1} if body is None else body)


async def code_of(http: SafeHttp, url: str = URL, **kw: Any) -> str:
    with pytest.raises(UpstreamError) as info:
        await http.get_json(url, max_bytes=kw.pop("max_bytes", 1000), **kw)
    return info.value.code


@pytest.mark.parametrize(
    "url",
    [
        "http://idp.example.edu/x",
        "ftp://idp.example.edu/x",
        "https://user:pw@idp.example.edu/x",
        "https://user@idp.example.edu/x",
        "https://localhost/x",
        "https://foo.localhost/x",
        "https://127.0.0.1/x",
        "https://[::1]/x",
        "https://169.254.169.254/latest/meta-data",
        "https://0.0.0.0/x",
        "https://[::ffff:127.0.0.1]/x",
        "https://224.0.0.1/x",
        "https:///x",
        "https://idp.example.edu/x#frag",
        "https://idp.example.edu:notaport/x",
        "https://idp.example.edu/a b",
        "",
    ],
)
async def test_urls_that_may_not_be_called_are_refused_before_any_request(url: str) -> None:
    http, seen = make(ok())
    assert await code_of(http, url) == "blocked_url"
    assert seen == []


def test_check_url_accepts_an_ordinary_https_url_with_port_and_query() -> None:
    assert check_url("https://idp.example.edu:8443/a?b=c") == "https://idp.example.edu:8443/a?b=c"


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
async def test_a_redirect_is_an_error_and_is_never_followed(status: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers={"location": "https://evil.example/steal"})

    http, seen = make(handler)
    assert await code_of(http) == "redirect"
    assert len(seen) == 1


async def test_a_body_over_the_cap_is_refused_while_streaming() -> None:
    http, _ = make(lambda _r: httpx.Response(200, json={"x": "a" * 5000}))
    assert await code_of(http, max_bytes=1000) == "too_large"


async def test_a_declared_length_over_the_cap_is_refused_at_once() -> None:
    http, _ = make(lambda _r: httpx.Response(200, headers={"content-length": "999999"}, content=b"{}"))
    assert await code_of(http, max_bytes=1000) == "too_large"


@pytest.mark.parametrize(
    ("content_type", "body"),
    [("text/html", b"{}"), ("text/plain", b'{"a":1}'), ("", b"{}")],
)
async def test_the_body_must_have_a_json_media_type(content_type: str, body: bytes) -> None:
    headers = {"content-type": content_type} if content_type else {}
    http, _ = make(lambda _r: httpx.Response(200, content=body, headers=headers))
    assert await code_of(http) == "not_json"


@pytest.mark.parametrize("media", ["application/json", "application/jwk-set+json", "application/problem+json; charset=utf-8"])
async def test_json_media_types_are_accepted(media: str) -> None:
    http, _ = make(lambda _r: httpx.Response(200, content=b'{"a":1}', headers={"content-type": media}))
    result = await http.get_json(URL, max_bytes=100)
    assert result.body == {"a": 1} and result.status == 200


@pytest.mark.parametrize(
    "body",
    [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b"[1,2]", b'"text"', b"not json", b"\xff\xfe", b""],
)
async def test_strict_json_refuses_ambiguous_or_non_object_bodies(body: bytes) -> None:
    http, _ = make(lambda _r: httpx.Response(200, content=body, headers={"content-type": "application/json"}))
    assert await code_of(http) == "not_json"


async def test_an_array_root_is_accepted_only_when_expected() -> None:
    http, _ = make(lambda _r: httpx.Response(200, json=[{"a": 1}]))
    assert (await http.get_json(URL, max_bytes=100, expect="array")).body == [{"a": 1}]
    assert await code_of(http) == "not_json"


async def test_a_transport_failure_is_network() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom with https://secret.example/path", request=request)

    http, _ = make(handler)
    with pytest.raises(UpstreamError) as info:
        await http.get_json(URL, max_bytes=100)
    assert info.value.code == "network"
    assert "secret.example" not in str(info.value) and "secret.example" not in repr(info.value)


class SlowTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200, json={})


async def test_the_whole_request_has_a_deadline() -> None:
    http = SafeHttp(transport=SlowTransport(), total_timeout=0.1)
    assert await code_of(http) == "timeout"


async def test_an_unexpected_status_carries_only_a_closed_code_and_the_status() -> None:
    body = {"error": "invalid_grant", "error_description": "secret-text-from-idp", "url": URL}
    http, _ = make(lambda _r: httpx.Response(400, json=body))
    with pytest.raises(UpstreamError) as info:
        await http.post_form(URL, {"a": "b"}, max_bytes=1000)
    exc = info.value
    assert (exc.code, exc.status, exc.oauth_error) == ("http_status", 400, "invalid_grant")
    for text in (str(exc), repr(exc)):
        assert "secret-text" not in text and "idp.example.edu" not in text


@pytest.mark.parametrize("value", ["Invalid Grant", "<script>", "x" * 70, "", 5, None])
async def test_an_oauth_error_that_is_not_a_plain_code_is_dropped(value: Any) -> None:
    http, _ = make(lambda _r: httpx.Response(400, json={"error": value}))
    with pytest.raises(UpstreamError) as info:
        await http.get_json(URL, max_bytes=1000)
    assert info.value.oauth_error is None


async def test_listed_statuses_are_returned_with_a_best_effort_body() -> None:
    http, _ = make(lambda _r: httpx.Response(404, content=b"<html>nope</html>", headers={"content-type": "text/html"}))
    result = await http.request("GET", URL, max_bytes=1000, ok_statuses=(200, 404))
    assert result.status == 404 and result.body is None


async def test_requests_identify_the_server_and_ask_for_json() -> None:
    http, seen = make(ok())
    await http.get_json(URL, max_bytes=100, headers={"X-Extra": "1"})
    headers = seen[0].headers
    assert headers["user-agent"] == "canvas-mcp-selfhost" and headers["accept"] == "application/json"
    assert headers["x-extra"] == "1"


async def test_post_form_sends_a_form_body_and_basic_auth_as_given() -> None:
    http, seen = make(ok())
    await http.post_form(URL, {"grant_type": "authorization_code", "code": "a b"}, max_bytes=100, basic_auth=("id", "se%3Acret"))
    request = seen[0]
    assert request.method == "POST"
    assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
    assert b"grant_type=authorization_code" in request.content and b"code=a+b" in request.content
    import base64

    assert request.headers["authorization"] == "Basic " + base64.b64encode(b"id:se%3Acret").decode()


async def test_no_cookie_or_environment_proxy_state_leaks_between_calls() -> None:
    jars: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        jars.append(request.headers.get("cookie", ""))
        return httpx.Response(200, json={}, headers={"set-cookie": "a=b"})

    http, _ = make(handler)
    await http.get_json(URL, max_bytes=100)
    await http.get_json(URL, max_bytes=100)
    assert jars == ["", ""]
