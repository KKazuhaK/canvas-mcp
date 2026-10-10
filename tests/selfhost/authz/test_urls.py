"""Redirect URI matching, resource normalisation and the issuer/audience strings."""

from __future__ import annotations

import pytest

from canvas_mcp.core.selfhost.authz import urls

BASE = "https://canvas.example.test"


class TestIssuerAndAudience:
    def test_the_issuer_has_a_trailing_slash_and_the_audience_does_not(self) -> None:
        assert urls.issuer_of(BASE) == "https://canvas.example.test/"
        assert urls.audience_of(BASE, "/mcp") == "https://canvas.example.test/mcp"

    @pytest.mark.parametrize(
        ("base", "ok"),
        [
            ("https://canvas.example.test", True),
            ("https://canvas.example.test:8443", True),
            ("https://canvas.example.test/", False),
            ("https://Canvas.example.test", False),
            ("HTTPS://canvas.example.test", False),
            ("https://canvas.example.test:443", False),
            ("https://canvas.example.test/path", False),
            ("https://canvas.example.test?x=1", False),
            ("https://u@canvas.example.test", False),
            ("canvas.example.test", False),
            ("https://", False),
            ("ftp://canvas.example.test", False),
        ],
    )
    def test_is_canonical_base(self, base: str, ok: bool) -> None:
        assert urls.is_canonical_base(base) is ok


class TestNormalizeResource:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("https://canvas.example.test/mcp", "https://canvas.example.test/mcp"),
            ("https://canvas.example.test/mcp/", "https://canvas.example.test/mcp"),
            ("HTTPS://Canvas.Example.TEST/mcp", "https://canvas.example.test/mcp"),
            ("https://canvas.example.test:443/mcp", "https://canvas.example.test/mcp"),
            ("https://canvas.example.test", "https://canvas.example.test"),
            ("https://canvas.example.test/", "https://canvas.example.test"),
            ("http://canvas.example.test:80/mcp", "http://canvas.example.test/mcp"),
            ("https://canvas.example.test:8443/mcp", "https://canvas.example.test:8443/mcp"),
            ("https://[::1]/mcp", "https://[::1]/mcp"),
        ],
    )
    def test_equivalent_spellings(self, value: str, expected: str) -> None:
        assert urls.normalize_resource(value) == expected

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "https://canvas.example.test/mcp#frag",
            "https://canvas.example.test/mcp?x=1",
            "https://user@canvas.example.test/mcp",
            "urn:example:mcp",
            "canvas.example.test/mcp",
            "https://canvas.example.test/ mcp",
            "https://canvas.example.test:99999/mcp",
            "https:///mcp",
            "https://canvas.example.test/mcp\n",
        ],
    )
    def test_unusable_values(self, value: str) -> None:
        assert urls.normalize_resource(value) is None

    def test_a_different_path_is_a_different_resource(self) -> None:
        mcp = urls.normalize_resource("https://canvas.example.test/mcp")
        assert urls.normalize_resource("https://canvas.example.test/mcp2") != mcp
        assert urls.normalize_resource("https://canvas.example.test") != mcp


class TestRedirectSyntax:
    @pytest.mark.parametrize(
        "uri",
        [
            "https://claude.ai/api/mcp/auth_callback",
            "https://app.example.com/cb?x=1",
            "http://localhost/callback",
            "http://localhost:53682/callback",
            "http://127.0.0.1:39211/callback",
            "http://[::1]:5000/callback",
            "https://example.com:8443/cb",
        ],
    )
    def test_accepted(self, uri: str) -> None:
        assert urls.redirect_uri_syntax_ok(uri)

    @pytest.mark.parametrize(
        "uri",
        [
            "",
            "javascript:alert(1)",
            "data:text/html,x",
            "ftp://example.com/cb",
            "myapp://callback",
            "http://evil.example/cb",
            "https://localhost/callback",
            "https://127.0.0.1/callback",
            "https://app.localhost/cb",
            "https://[::1]/cb",
            "http://localhost.evil.example/cb",
            "https://claude.ai/cb#frag",
            "https://user:pw@claude.ai/cb",
            "https://claude.ai@evil.example/cb",
            "https://claude.ai/*",
            "https://*.claude.ai/cb",
            "https://claude.ai/a/../b",
            "https://claude.ai/a/./b",
            "https://claude.ai/a/%2e%2e/b",
            "https://claude.ai/a/%2E%2E/b",
            "https://claude.ai/a/%252e%252e/b",
            "https://claude.ai",
            "https://claude.ai/ cb",
            "https://claude.ai/cb\n",
            "https://claude.ai\\@evil.example/cb",
            "HTTPS://claude.ai/cb",
            "https://claude.ai:99999/cb",
            "https://" + "a" * 2100 + ".example/cb",
        ],
    )
    def test_rejected(self, uri: str) -> None:
        assert not urls.redirect_uri_syntax_ok(uri)


class TestRedirectMatching:
    @pytest.mark.parametrize(
        ("candidate", "registered", "expected"),
        [
            # exact match only
            ("https://claude.ai/api/mcp/auth_callback", "https://claude.ai/api/mcp/auth_callback", True),
            ("https://claude.ai/api/mcp/auth_callback/", "https://claude.ai/api/mcp/auth_callback", False),
            ("https://claude.ai/api/mcp/other", "https://claude.ai/api/mcp/auth_callback", False),
            ("https://claude.com/api/mcp/auth_callback", "https://claude.ai/api/mcp/auth_callback", False),
            ("https://claude.ai:8443/api/mcp/auth_callback", "https://claude.ai/api/mcp/auth_callback", False),
            ("https://claude.ai/cb?x=1", "https://claude.ai/cb", False),
            # a registered port-less loopback http URI matches any port
            ("http://localhost:53682/callback", "http://localhost/callback", True),
            ("http://localhost/callback", "http://localhost/callback", True),
            ("http://127.0.0.1:39211/callback", "http://127.0.0.1/callback", True),
            ("http://[::1]:7000/callback", "http://[::1]/callback", True),
            ("http://LOCALHOST:5000/callback", "http://localhost/callback", True),
            # ... but host, path and query must still be equal
            ("http://localhost:53682/other", "http://localhost/callback", False),
            ("http://localhost:53682/callback?x=1", "http://localhost/callback", False),
            ("http://localhost:53682/callback", "http://localhost/callback?x=1", False),
            ("http://127.0.0.1:53682/callback", "http://localhost/callback", False),
            ("http://localhost:53682/callback", "http://127.0.0.1/callback", False),
            ("http://[::1]:53682/callback", "http://127.0.0.1/callback", False),
            ("http://127.0.0.1:53682/callback", "http://[::1]/callback", False),
            ("http://localhost.evil.example:5000/callback", "http://localhost/callback", False),
            ("http://localhost@evil.example/callback", "http://localhost/callback", False),
            ("http://user@localhost:5000/callback", "http://localhost/callback", False),
            # a registered port is exact
            ("http://localhost:5001/callback", "http://localhost:5000/callback", False),
            ("http://localhost:5000/callback", "http://localhost:5000/callback", True),
            # https loopback is never the exception
            ("https://localhost:5000/callback", "https://localhost/callback", False),
            ("https://localhost:5000/callback", "http://localhost/callback", False),
            # wildcards do not exist
            ("http://localhost:5000/callback", "http://localhost:*/callback", False),
            ("https://a.example.com/cb", "https://*.example.com/cb", False),
            ("https://claude.ai/anything", "https://claude.ai/*", False),
            ("https://claude.ai/*", "https://claude.ai/*", True),
        ],
    )
    def test_table(self, candidate: str, registered: str, expected: bool) -> None:
        assert urls.redirect_matches(candidate, registered) is expected

    def test_a_malformed_candidate_never_matches(self) -> None:
        assert not urls.redirect_matches("http://localhost:abc/callback", "http://localhost/callback")
        assert not urls.redirect_matches("http://localhost:0/callback", "http://localhost/callback")
        assert not urls.redirect_matches("", "http://localhost/callback")

    def test_host_helpers(self) -> None:
        assert urls.host_of("https://Claude.AI/x") == "claude.ai"
        assert urls.host_of("http://[::1]:5000/x") == "::1"
        assert urls.host_of("nonsense") == ""
        assert urls.is_loopback_host("LOCALHOST") and not urls.is_loopback_host("localhost.evil")
