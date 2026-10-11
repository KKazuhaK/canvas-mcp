"""The v1 configuration is explicit and never silently interprets old settings."""

import base64

import pytest

from canvas_mcp.core.selfhost.settings import (
    SelfhostConfigError,
    auth_mode,
    load_selfhost_settings,
)


def valid_environment() -> dict[str, str]:
    return {
        "MCP_AUTH_MODE": "selfhost",
        "PUBLIC_BASE_URL": "https://mcp.example.com",
        "ENTRA_TENANT_ID": "11111111-2222-3333-4444-555555555555",
        "ENTRA_CLIENT_ID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "ENTRA_CLIENT_SECRET": "fake-entra-client-secret",
        "ACCOUNT_SESSION_SECRET": base64.b64encode(bytes(range(32))).decode(),
        "CANVAS_TOKEN_KEYS": "k1:" + base64.b64encode(bytes(32)).decode(),
    }


def test_selfhost_is_the_explicit_opt_in() -> None:
    assert auth_mode({"MCP_AUTH_MODE": "selfhost"}) == "selfhost"


@pytest.mark.parametrize("env", [{}, {"MCP_AUTH_MODE": ""}, {"MCP_AUTH_MODE": "legacy"}])
def test_upstream_modes_stay_available(env: dict[str, str]) -> None:
    assert auth_mode(env) == "legacy"


def test_old_mode_value_names_the_replacement() -> None:
    with pytest.raises(SelfhostConfigError) as caught:
        auth_mode({"MCP_AUTH_MODE": "entra-oauth"})
    assert len(caught.value.problems) == 1
    assert "MCP_AUTH_MODE=selfhost" in caught.value.problems[0]


REMOVED = [
    "SELFHOST_AUTH_MODE",
    "OAUTH_JWT_SIGNING_KEY",
    "GRANT_STATUS_CACHE_S",
    "CANVAS_FEATURED_SCHOOLS",
    "CANVAS_SCHOOL_SEARCH",
    "CANVAS_API_URL",
    "OIDC_UNCONFIGURED_DISPLAY_NAME",
    "ACCOUNT_UI",
    "ENTRA_API_SCOPE",
]


@pytest.mark.parametrize("name", REMOVED)
@pytest.mark.parametrize("value", ["", "fake-secret-that-must-not-be-echoed"])
def test_removed_setting_is_refused_once_even_when_empty(name: str, value: str) -> None:
    env = valid_environment() | {name: value}
    with pytest.raises(SelfhostConfigError) as caught:
        load_selfhost_settings(env)
    assert len(caught.value.problems) == 1
    message = caught.value.problems[0]
    assert name in message
    if value:
        assert value not in message


def test_all_removed_settings_are_reported_together() -> None:
    with pytest.raises(SelfhostConfigError) as caught:
        load_selfhost_settings(valid_environment() | dict.fromkeys(REMOVED, ""))
    assert len(caught.value.problems) == len(REMOVED)
    for name in REMOVED:
        assert sum(name in message for message in caught.value.problems) == 1


def test_fastmcp_home_is_ignored() -> None:
    settings = load_selfhost_settings(valid_environment() | {"FASTMCP_HOME": "relative/path"})
    assert not hasattr(settings, "fastmcp_home")


def test_scope_default_and_override() -> None:
    assert load_selfhost_settings(valid_environment()).api_scope == "Canvas.Access"
    assert load_selfhost_settings(valid_environment() | {"MCP_SCOPE": "Mcp.Use"}).api_scope == "Mcp.Use"


def test_old_scope_is_refused_even_with_the_new_scope() -> None:
    with pytest.raises(SelfhostConfigError) as caught:
        load_selfhost_settings(valid_environment() | {"MCP_SCOPE": "Mcp.Use", "ENTRA_API_SCOPE": ""})
    assert len(caught.value.problems) == 1
    assert "ENTRA_API_SCOPE" in caught.value.problems[0]
    assert "MCP_SCOPE" in caught.value.problems[0]


@pytest.mark.parametrize("value", ["invalid scope", "x" * 65, "openid", "profile", "email"])
def test_invalid_scope_names_the_setting_without_echoing_the_value(value: str) -> None:
    with pytest.raises(SelfhostConfigError) as caught:
        load_selfhost_settings(valid_environment() | {"MCP_SCOPE": value})
    assert len(caught.value.problems) == 1
    assert "MCP_SCOPE" in caught.value.problems[0]
    assert value not in caught.value.problems[0]
