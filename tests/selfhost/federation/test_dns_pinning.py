"""SafeHttp resolves the host itself, refuses non-public answers and connects to the vetted address."""

from __future__ import annotations

import httpx
import pytest

from canvas_mcp.core.selfhost.login.http import SafeHttp, UpstreamError

PUBLIC = "93.184.216.34"


def client(*answers: list[str], allow_loopback: bool = False):
    """A client with a stub resolver (one answer per lookup) and a transport that records calls."""
    seen: list[httpx.Request] = []
    lookups: list[tuple[str, int]] = []
    queue = list(answers)

    async def resolver(host: str, port: int) -> list[str]:
        lookups.append((host, port))
        return queue.pop(0) if len(queue) > 1 else queue[0]

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    http = SafeHttp(
        transport=httpx.MockTransport(handler),
        resolver=resolver,
        allow_loopback=allow_loopback,
    )
    return http, seen, lookups


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    [
        "127.0.0.1",
        "127.8.8.8",
        "169.254.169.254",
        "10.0.0.5",
        "172.16.3.4",
        "192.168.1.1",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
    ],
)
async def test_a_host_that_resolves_to_a_non_public_address_is_refused(answer):
    http, seen, _ = client([answer])
    with pytest.raises(UpstreamError) as caught:
        await http.get_json("https://hub.example.test/jwks", max_bytes=1000)
    assert caught.value.code == "blocked_url" and seen == []


@pytest.mark.asyncio
async def test_one_bad_answer_among_good_ones_refuses_the_host():
    http, seen, _ = client([PUBLIC, "10.0.0.1"])
    with pytest.raises(UpstreamError):
        await http.get_json("https://hub.example.test/jwks", max_bytes=1000)
    assert seen == []


@pytest.mark.asyncio
async def test_no_answer_is_a_refusal():
    http, seen, _ = client([])
    with pytest.raises(UpstreamError):
        await http.get_json("https://hub.example.test/jwks", max_bytes=1000)
    assert seen == []


@pytest.mark.asyncio
async def test_a_private_address_literal_is_refused_too():
    http, seen, lookups = client([PUBLIC])
    for url in (
        "https://10.0.0.1/x",
        "https://[fd00::1]/x",
        "https://192.168.0.9:8443/x",
    ):
        with pytest.raises(UpstreamError):
            await http.get_json(url, max_bytes=1000)
    assert seen == [] and lookups == []


@pytest.mark.asyncio
async def test_the_connection_goes_to_the_vetted_address_with_the_real_name():
    http, seen, lookups = client([PUBLIC])
    result = await http.get_json(
        "https://hub.example.test:8443/jwks?x=1", max_bytes=1000
    )
    assert result.body == {"ok": True}
    assert lookups == [("hub.example.test", 8443)]
    (request,) = seen
    assert request.url.host == PUBLIC and request.url.port == 8443
    assert request.url.path == "/jwks" and request.url.query == b"x=1"
    assert request.headers["host"] == "hub.example.test:8443"
    assert request.extensions["sni_hostname"] == "hub.example.test"


@pytest.mark.asyncio
async def test_an_ipv6_answer_is_pinned_in_brackets():
    http, seen, _ = client(["2606:4700:4700::1111"])
    await http.get_json("https://hub.example.test/jwks", max_bytes=1000)
    assert seen[0].url.host == "2606:4700:4700::1111"
    assert seen[0].headers["host"] == "hub.example.test"


@pytest.mark.asyncio
async def test_a_second_dns_answer_cannot_swap_the_address():
    # First answer public, second private: one lookup per request, and it is the one used.
    http, seen, lookups = client([PUBLIC], ["127.0.0.1"])
    await http.get_json("https://hub.example.test/jwks", max_bytes=1000)
    assert lookups == [("hub.example.test", 443)]
    assert seen[0].url.host == PUBLIC


@pytest.mark.asyncio
async def test_the_loopback_client_is_not_resolved_or_vetted():
    http, seen, lookups = client(["10.0.0.1"], allow_loopback=True)
    await http.get_json("http://localhost:9099/jwks", max_bytes=1000)
    assert lookups == [] and seen[0].url.host == "localhost"


@pytest.mark.asyncio
async def test_without_a_resolver_a_transport_is_a_test_double():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    http = SafeHttp(transport=httpx.MockTransport(handler))
    await http.get_json("https://hub.example.test/x", max_bytes=100)
    assert seen[0].url.host == "hub.example.test"


def test_a_trusted_issuer_whose_name_resolves_inside_is_never_fetched(open_hub):
    open_hub.trust()

    async def inside(host: str, port: int) -> list[str]:
        return ["169.254.169.254"]

    open_hub.federation.http._resolver = inside
    assert open_hub.status(open_hub.issuer.mint()) == 401
    assert open_hub.issuer.log == [] and open_hub.accounts() == []
