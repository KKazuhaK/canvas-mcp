"""The CIMD resolver: freshness, stale-if-error, budgets, single flight, time limits, rejections."""

from __future__ import annotations

import asyncio
import time

import pytest

from canvas_mcp.core.selfhost.authz import fastmcp_compat as compat
from canvas_mcp.core.selfhost.authz.clients import (
    CIMD_BUDGET,
    ClientDirectory,
    CimdResolver,
    cimd_url_ok,
)
from canvas_mcp.core.selfhost.settings import AuthzSettings

from .helpers import Env, make_env
from .stack import FakeCimd, cimd_document

ALLOW = ("https://claude.ai/api/mcp/auth_callback", "http://localhost/callback")
SCOPES = ("Canvas.Access",)
URL = "https://client.example/cimd.json"


class Mono:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def env(tmp_path, keyring, clock) -> Env:
    return make_env(tmp_path, keyring, clock)


def build(env: Env, cimd, *, mono: Mono | None = None, **settings) -> CimdResolver:
    return CimdResolver(
        env.authz, AuthzSettings(**settings), ALLOW, SCOPES, fetch=cimd, clock=env.clock,
        monotonic=mono or Mono(),
    )


def doc(url: str = URL, **kw):
    return cimd_document(url, **kw)


class TestFreshness:
    async def test_a_fresh_snapshot_is_used_without_a_fetch(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.serve(URL, doc())
        resolver = build(env, cimd)
        assert await resolver.get(URL) is not None
        env.clock.advance(100)
        assert await resolver.get(URL) is not None
        assert cimd.calls == [URL]

    async def test_a_stale_snapshot_triggers_a_fetch_and_a_failure_refuses_an_authorization(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.serve(URL, doc())
        resolver = build(env, cimd)
        assert await resolver.get(URL) is not None
        env.clock.advance(301)  # max-age=300
        cimd.fail(URL, compat.MetadataFetchError(compat.FETCH_TIMEOUT))
        assert await resolver.get(URL, "authorize") is None
        assert len(cimd.calls) == 2
        snapshot = env.authz.cimd_snapshot(URL)
        assert snapshot is not None and snapshot.last_error == "timeout" and snapshot.last_error_at == int(env.clock())

    async def test_a_token_request_may_use_the_last_good_copy_for_the_stale_maximum(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.serve(URL, doc())
        resolver = build(env, cimd)
        assert await resolver.get(URL) is not None
        cimd.fail(URL, compat.MetadataFetchError(compat.FETCH_SSRF_BLOCKED))
        env.clock.advance(3600)
        served = await resolver.get(URL, "token")
        assert served is not None and served.url == URL
        env.clock.advance(7 * 86400)  # past CIMD_STALE_MAX (7d) in total
        assert await build(env, cimd).get(URL, "token") is None

    async def test_a_failing_host_is_not_asked_again_on_every_token_request(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.serve(URL, doc())
        mono = Mono()
        resolver = build(env, cimd, mono=mono)
        assert await resolver.get(URL) is not None
        cimd.fail(URL, compat.MetadataFetchError(compat.FETCH_TIMEOUT))
        env.clock.advance(3600)
        for _ in range(5):
            assert await resolver.get(URL, "token") is not None
        assert len(cimd.calls) == 2  # one try; the others were served from the copy
        mono.now += 61
        assert await resolver.get(URL, "token") is not None
        assert len(cimd.calls) == 3

    async def test_a_fresh_document_replaces_the_copy_and_clears_the_error(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.serve(URL, doc(client_name="v1"))
        resolver = build(env, cimd)
        await resolver.get(URL)
        env.clock.advance(400)
        cimd.serve(URL, doc(client_name="v2"))
        fresh = await resolver.get(URL)
        assert fresh is not None and fresh.client_name == "v2"
        assert env.authz.cimd_snapshot(URL).last_error is None

    async def test_no_store_documents_are_never_served_as_fresh_but_the_copy_serves_consent(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.serve(URL, doc(), cache_control="no-store")
        resolver = build(env, cimd)
        assert await resolver.get(URL) is not None
        assert await resolver.get(URL) is not None
        assert len(cimd.calls) == 2  # fetched again each time
        snapshot = env.authz.cimd_snapshot(URL)
        assert snapshot is not None and snapshot.fresh_until == snapshot.fetched_at
        assert await resolver.snapshot_only(URL, not_before=int(env.clock())) is not None
        assert len(cimd.calls) == 2  # consent never fetches

    @pytest.mark.parametrize(
        ("header", "expected"),
        [("max-age=5", 60), ("max-age=99999", 3600), ("max-age=600", 600), ("public", 3600), ("", 3600), ("MAX-AGE=120", 120)],
    )
    async def test_the_freshness_is_clamped_between_one_minute_and_one_hour(self, env: Env, header: str, expected: int) -> None:
        cimd = FakeCimd()
        cimd.serve(URL, doc())
        cimd.documents[URL] = (cimd.documents[URL][0], {"cache-control": header} if header else {})
        await build(env, cimd).get(URL)
        snapshot = env.authz.cimd_snapshot(URL)
        assert snapshot is not None and snapshot.fresh_until - snapshot.fetched_at == expected

    async def test_consent_needs_a_copy_no_older_than_the_request(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.serve(URL, doc())
        resolver = build(env, cimd)
        await resolver.get(URL)
        fetched = env.authz.cimd_snapshot(URL).fetched_at
        assert await resolver.snapshot_only(URL, not_before=fetched) is not None
        assert await resolver.snapshot_only(URL, not_before=fetched + 1) is None
        assert await resolver.snapshot_only("https://never.example/c.json", not_before=0) is None


class TestBudgets:
    async def test_a_host_gets_ten_fetches_a_minute(self, env: Env) -> None:
        cimd = FakeCimd()
        mono = Mono()
        resolver = build(env, cimd, mono=mono)
        urls = [f"https://busy.example/c{i}.json" for i in range(12)]
        for url in urls:
            cimd.serve(url, doc(url))
        results = [await resolver.get(url) for url in urls]
        assert [r is not None for r in results] == [True] * 10 + [False] * 2
        assert env.authz.cimd_snapshot(urls[0]) is not None
        mono.now += 61
        assert await resolver.get(urls[10]) is not None

    async def test_all_hosts_together_get_sixty_a_minute(self, env: Env) -> None:
        cimd = FakeCimd()
        resolver = build(env, cimd)
        urls = [f"https://h{i}.example/c.json" for i in range(62)]
        for url in urls:
            cimd.serve(url, doc(url))
        results = [await resolver.get(url) for url in urls]
        assert sum(r is not None for r in results) == 60

    async def test_the_refusal_is_noted_on_a_document_that_was_stored(self, env: Env) -> None:
        cimd = FakeCimd()
        mono = Mono()
        resolver = build(env, cimd, mono=mono)
        url = "https://busy.example/first.json"
        cimd.serve(url, doc(url))
        await resolver.get(url)
        for i in range(10):
            cimd.serve(f"https://busy.example/o{i}.json", doc(f"https://busy.example/o{i}.json"))
            await resolver.get(f"https://busy.example/o{i}.json")
        env.clock.advance(400)
        assert await resolver.get(url) is None
        assert env.authz.cimd_snapshot(url).last_error == CIMD_BUDGET


class TestSingleFlightAndTime:
    async def test_ten_concurrent_lookups_make_one_fetch(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.delay = 0.2
        cimd.serve(URL, doc())
        resolver = build(env, cimd)
        results = await asyncio.gather(*(resolver.get(URL) for _ in range(10)))
        assert all(r is not None for r in results) and cimd.calls == [URL]

    @pytest.mark.parametrize("purpose", ["authorize", "token"])
    async def test_a_hanging_fetch_gives_up_within_the_timeout(self, env: Env, purpose: str) -> None:
        cimd = FakeCimd()
        cimd.serve(URL, doc())
        resolver = build(env, cimd, cimd_fetch_timeout_s=1)
        await resolver.get(URL)  # a good copy first (token purpose may fall back to it)
        env.clock.advance(400)
        cimd.delay = 10
        started = time.monotonic()
        result = await resolver.get(URL, purpose)
        assert time.monotonic() - started < 2.0
        assert (result is None) == (purpose == "authorize")

    async def test_the_real_fetcher_refuses_internal_addresses_without_connecting(self, env: Env) -> None:
        resolver = CimdResolver(env.authz, AuthzSettings(), ALLOW, SCOPES, clock=env.clock)
        for url in ("https://127.0.0.1/x.json", "https://localhost/x.json", "https://169.254.169.254/x.json", "https://[::1]/x.json"):
            started = time.monotonic()
            assert await resolver.get(url) is None
            assert time.monotonic() - started < 3.0


class TestRejections:
    @pytest.mark.parametrize(
        ("label", "mutate"),
        [
            ("id mismatch", lambda d: d.update(client_id="https://client.example/other.json")),
            ("trailing slash", lambda d: d.update(client_id=URL + "/")),
            ("private_key_jwt", lambda d: d.update(token_endpoint_auth_method="private_key_jwt")),
            ("client_secret_post", lambda d: d.update(token_endpoint_auth_method="client_secret_post")),
            ("no redirect uris", lambda d: d.update(redirect_uris=[])),
            ("missing redirect uris", lambda d: d.pop("redirect_uris")),
            ("redirect not allowlisted", lambda d: d.update(redirect_uris=["https://evil.example/cb"])),
            ("no authorization_code", lambda d: d.update(grant_types=["refresh_token"])),
            ("only jwt-bearer", lambda d: d.update(grant_types=["urn:ietf:params:oauth:grant-type:jwt-bearer"])),
            ("no code response", lambda d: d.update(response_types=["token"])),
            ("foreign scope only", lambda d: d.update(scope="admin")),
        ],
    )
    async def test_these_documents_are_refused(self, env: Env, label: str, mutate) -> None:
        document = doc()
        mutate(document)
        cimd = FakeCimd()
        cimd.serve(URL, document)
        assert await build(env, cimd).get(URL) is None, label
        assert env.authz.cimd_snapshot(URL) is None  # nothing refused is stored

    @pytest.mark.parametrize("raw", [b"", b"not json", b"[]", b"null", b"\xff\xfe", b"{" * 10, b"x" * 6000])
    async def test_junk_is_refused(self, env: Env, raw: bytes) -> None:
        cimd = FakeCimd()
        cimd.serve(URL, raw)
        assert await build(env, cimd).get(URL) is None

    async def test_an_oversized_document_is_refused_even_if_it_is_valid_json(self, env: Env) -> None:
        document = doc()
        document["client_name"] = "n" * 6000
        cimd = FakeCimd()
        cimd.serve(URL, document)
        assert await build(env, cimd).get(URL) is None

    async def test_a_scope_in_the_document_is_reduced_to_ours(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.serve(URL, doc(scope="Canvas.Access admin"))
        data = await build(env, cimd).get(URL)
        assert data is not None and data.scope == "Canvas.Access"

    async def test_cimd_can_be_switched_off(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.serve(URL, doc())
        assert await build(env, cimd, cimd_enabled=False).get(URL) is None
        assert cimd.calls == []

    async def test_a_fetcher_that_explodes_gives_none_not_an_exception(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.fail(URL, RuntimeError("boom"))
        resolver = build(env, cimd)
        assert await resolver.get(URL) is None
        directory = ClientDirectory(env.authz, resolver, ALLOW, SCOPES, clock=env.clock)
        assert await directory.get(URL) is None

    async def test_the_allowlist_is_applied_again_on_every_load(self, env: Env) -> None:
        cimd = FakeCimd()
        cimd.serve(URL, doc())
        await build(env, cimd).get(URL)
        narrowed = CimdResolver(env.authz, AuthzSettings(), ("https://other.example/cb",), SCOPES, fetch=cimd, clock=env.clock)
        assert await narrowed.get(URL) is None  # the stored copy has no allowed redirect any more


class TestClientIdShape:
    @pytest.mark.parametrize(
        "url",
        [
            "https://client.example/cimd.json",
            "https://client.example/a/b/c.json",
            "https://client.example:8443/cimd",
            "https://claude.ai/oauth/mcp-oauth-client-metadata",
        ],
    )
    def test_good_ones(self, url: str) -> None:
        assert cimd_url_ok(url)

    @pytest.mark.parametrize(
        "url",
        [
            "http://client.example/cimd.json",
            "https://client.example",
            "https://client.example/",
            "https://client.example/cimd.json?x=1",
            "https://client.example/cimd.json#frag",
            "https://user@client.example/cimd.json",
            "https://client.example/a/../cimd.json",
            "https://client.example/a/./cimd.json",
            "https://CLIENT.example/cimd.json",
            "https://client.example:443/cimd.json",
            "https://client.example/cimd json",
            "https://client.example/*",
            "https://" + "a" * 600 + ".example/x",
            "https://clïent.example/x",
            "",
            "ftp://client.example/x",
        ],
    )
    def test_bad_ones(self, url: str) -> None:
        assert not cimd_url_ok(url)

    async def test_the_directory_dispatches_on_the_shape_of_the_id(self, env: Env) -> None:
        cimd = FakeCimd()
        resolver = build(env, cimd)
        directory = ClientDirectory(env.authz, resolver, ALLOW, SCOPES, clock=env.clock)
        for client_id in ("", "x", "javascript:alert(1)", "http://client.example/x", "not-a-uuid",
                          "00000000-0000-0000-0000-000000000000", "A" * 5000, "https://client.example"):
            assert await directory.get(client_id) is None
        assert cimd.calls == []
