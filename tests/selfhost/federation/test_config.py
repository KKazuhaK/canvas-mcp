"""The checks made when an issuer is configured, and the shapes that keep them simple."""

from __future__ import annotations

import pytest

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.federation.config import (
    DEFAULT_ALGORITHMS,
    IssuerConfigError,
    build_issuer,
    metadata_url,
)
from canvas_mcp.core.selfhost.login.http import SafeHttp, UpstreamError, check_url


def test_the_defaults():
    issuer = build_issuer("https://hub.example.test")
    assert (
        issuer.algorithms == DEFAULT_ALGORITHMS == ("ES256", "RS256", "PS256", "EdDSA")
    )
    assert issuer.require_typ_at_jwt is True
    assert issuer.subject_claim == "sub"
    assert (
        issuer.audience,
        issuer.jwks_url,
        issuer.read_scope,
        issuer.write_scope,
    ) == (
        None,
        None,
        None,
        None,
    )
    assert issuer.label == "hub.example.test"
    assert build_issuer("https://hub.example.test", name="MCPHub").label == "MCPHub"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"issuer": "http://hub.example.test"},
        {"issuer": "https://user:pw@hub.example.test"},
        {"issuer": "https://hub.example.test#frag"},
        {"issuer": "https://hub.example.test/?q=1"},
        {"issuer": "hub.example.test"},
        {
            "issuer": "https://hub.example.test",
            "jwks_url": "http://hub.example.test/jwks",
        },
        {
            "issuer": "https://hub.example.test",
            "jwks_url": "ftp://hub.example.test/jwks",
        },
        {"issuer": "https://hub.example.test", "algorithms": "ES256,HS256"},
        {"issuer": "https://hub.example.test", "algorithms": "FOO"},
        {"issuer": "https://hub.example.test", "subject_claim": "a b"},
        {"issuer": "https://hub.example.test", "read_scope": "a b"},
        {"issuer": "https://hub.example.test", "audience": "has space"},
        {"issuer": "https://hub.example.test", "name": "x" * 41},
    ],
)
def test_bad_configuration_is_refused(kwargs):
    with pytest.raises(IssuerConfigError):
        build_issuer(**kwargs)


def test_http_is_allowed_for_localhost_only():
    for host in ("http://localhost:8080", "http://127.0.0.1:9000", "http://[::1]:9000"):
        assert build_issuer(host).issuer == host
    build_issuer("http://localhost:9", jwks_url="http://localhost:1/jwks")
    # Localhost is only for an issuer that is itself on localhost.
    with pytest.raises(IssuerConfigError, match="localhost issuer"):
        build_issuer("https://hub.example.test", jwks_url="http://localhost:1/jwks")
    with pytest.raises(IssuerConfigError):
        build_issuer("http://192.168.1.5:8080")


def test_the_metadata_address_follows_rfc_8414():
    assert (
        metadata_url("https://hub.example.test")
        == "https://hub.example.test/.well-known/oauth-authorization-server"
    )
    assert (
        metadata_url("https://hub.example.test/")
        == "https://hub.example.test/.well-known/oauth-authorization-server"
    )
    assert (
        metadata_url("https://hub.example.test/tenant/one/")
        == "https://hub.example.test/.well-known/oauth-authorization-server/tenant/one"
    )


class TestOutboundHttp:
    def test_loopback_is_closed_to_the_sign_in_providers(self):
        for url in ("http://localhost/x", "https://localhost/x", "https://127.0.0.1/x"):
            with pytest.raises(UpstreamError):
                check_url(url)

    def test_loopback_is_open_to_trusted_issuers_only_when_asked(self):
        assert check_url("http://localhost:1/x", allow_loopback=True)
        assert check_url("https://127.0.0.1/x", allow_loopback=True)
        assert SafeHttp(allow_loopback=True)
        for url in (
            "http://hub.example.test/x",
            "http://10.0.0.1/x",
            "https://169.254.169.254/x",
        ):
            with pytest.raises(UpstreamError):
                check_url(url, allow_loopback=True)


class TestRule:
    def test_federated_any_is_the_only_rule_it_takes(self):
        rule = acc.parse_rule("federated:any")
        assert not isinstance(rule, str) and rule.provider == acc.PROVIDER_FEDERATED
        for bad in ("federated:", "federated:claim:a=b", "federated:email:a@b.example"):
            assert isinstance(acc.parse_rule(bad), str)

    def test_it_can_never_make_an_owner(self):
        assert isinstance(acc.parse_rule("federated:any", owner=True), str)
