"""The provider protocol is fully implemented, and the provider fails closed at start-up."""

from __future__ import annotations

import inspect

import pytest
from fastmcp.server.auth import OAuthProvider
from mcp.server.auth.provider import OAuthAuthorizationServerProvider

from canvas_mcp.core.selfhost.authz import server as authz_server
from canvas_mcp.core.selfhost.authz.server import (
    EXPECTED_ROUTES,
    LocalAuthorizationServer,
    assert_route_table,
)
from canvas_mcp.core.selfhost.settings import SelfhostConfigError

from .stack import Stack, local_stack

PROTOCOL_METHODS = (
    "get_client",
    "register_client",
    "authorize",
    "load_authorization_code",
    "exchange_authorization_code",
    "load_refresh_token",
    "exchange_refresh_token",
    "load_access_token",
    "revoke_token",
)


def test_the_protocol_has_the_nine_methods_plus_the_identity_assertion_one() -> None:
    names = {
        name for name, member in inspect.getmembers(OAuthAuthorizationServerProvider) if inspect.iscoroutinefunction(member)
    }
    assert set(PROTOCOL_METHODS) <= names
    assert names - set(PROTOCOL_METHODS) == {"exchange_identity_assertion"}


@pytest.mark.parametrize("name", PROTOCOL_METHODS)
def test_every_protocol_method_is_defined_on_our_class(name: str) -> None:
    """The base methods are not abstract and quietly return None: a missing override would be silent."""
    assert name in LocalAuthorizationServer.__dict__, name
    assert inspect.iscoroutinefunction(LocalAuthorizationServer.__dict__[name])
    assert LocalAuthorizationServer.__dict__[name] is not getattr(OAuthProvider, name, None)


def test_the_jwt_bearer_grant_is_deliberately_not_implemented() -> None:
    assert "exchange_identity_assertion" not in LocalAuthorizationServer.__dict__


def test_the_class_is_a_fastmcp_oauth_provider() -> None:
    assert issubclass(LocalAuthorizationServer, OAuthProvider)


def test_the_route_table_check_refuses_an_unexpected_route(stack: Stack) -> None:
    from starlette.routing import Route

    async def handler(request):  # type: ignore[no-untyped-def]
        return None

    routes = stack.mcp.auth.get_routes("/mcp")
    assert_route_table(routes)
    with pytest.raises(RuntimeError):
        assert_route_table([*routes, Route("/extra", handler, methods=["GET"])])
    with pytest.raises(RuntimeError):
        assert_route_table(routes[:-1])
    with pytest.raises(RuntimeError):
        assert_route_table([Route(r.path, handler, methods=["GET"]) for r in routes])
    assert len(EXPECTED_ROUTES) == 6


def test_the_audience_must_be_the_resource_url_fastmcp_advertises(stack: Stack, monkeypatch) -> None:
    provider = stack.mcp.auth
    provider.set_mcp_path("/mcp")  # fine
    monkeypatch.setattr(authz_server.compat, "resource_url_of", lambda *_a, **_k: "https://canvas.example.test/other")
    with pytest.raises(SelfhostConfigError):
        provider.set_mcp_path("/mcp")


def test_the_mcp_path_it_is_given_must_match(stack: Stack) -> None:
    with pytest.raises(SelfhostConfigError):
        stack.mcp.auth.set_mcp_path("/other")
    with pytest.raises(SelfhostConfigError):
        stack.mcp.auth.get_routes("/other")


def test_a_non_canonical_public_base_url_is_refused_at_construction(tmp_path, monkeypatch) -> None:
    from dataclasses import replace

    with local_stack(tmp_path, monkeypatch) as stack:
        for bad in ("https://Canvas.example.test", "https://canvas.example.test/", "https://canvas.example.test:443"):
            settings = replace(stack.settings, public_base_url=bad)
            with pytest.raises(SelfhostConfigError):
                LocalAuthorizationServer(settings, stack.authz)


def test_the_provider_has_one_issuer_string_with_a_trailing_slash(stack: Stack) -> None:
    provider = stack.mcp.auth
    assert provider.issuer == "https://canvas.example.test/" == str(provider.issuer_url)
    assert provider.audience == "https://canvas.example.test/mcp"
