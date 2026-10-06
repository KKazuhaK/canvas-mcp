"""Tests for the entra-oauth environment contract."""

import base64
from dataclasses import fields
from pathlib import Path

import pytest

from canvas_mcp.core.selfhost.settings import (
    AUTH_MODE_ENTRA,
    AUTH_MODE_ENV,
    DEFAULT_REDIRECT_URIS,
    SelfhostConfigError,
    SelfhostSettings,
    auth_mode,
    load_selfhost_settings,
)

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CLIENT_SECRET = "s3cret-value-of-entra-client"
SIGNING_KEY = "k" * 48
SESSION_SECRET = base64.b64encode(bytes(range(32))).decode()
TOKEN_KEYS = "k1:" + base64.b64encode(bytes(32)).decode()


def _env(**overrides: str | None) -> dict[str, str]:
    env = {
        "PUBLIC_BASE_URL": "https://canvas.example.test",
        "ENTRA_TENANT_ID": TENANT,
        "ENTRA_CLIENT_ID": CLIENT,
        "ENTRA_CLIENT_SECRET": CLIENT_SECRET,
        "OAUTH_JWT_SIGNING_KEY": SIGNING_KEY,
        "ACCOUNT_SESSION_SECRET": SESSION_SECRET,
        "CANVAS_TOKEN_KEYS": TOKEN_KEYS,
        "FASTMCP_HOME": "/data/fastmcp",
    }
    for key, value in overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return env


def _problems(**overrides: str | None) -> list[str]:
    with pytest.raises(SelfhostConfigError) as info:
        load_selfhost_settings(_env(**overrides))
    return info.value.problems


class TestValidEnvironment:
    def test_minimal_environment_loads_with_defaults(self):
        settings = load_selfhost_settings(_env())
        assert settings.public_base_url == "https://canvas.example.test"
        assert settings.public_host == "canvas.example.test"
        assert settings.tenant_id == TENANT
        assert settings.client_id == CLIENT
        assert settings.api_scope == "Canvas.Access"
        assert settings.required_role == "Canvas.User"
        assert settings.owner_role == "Canvas.Owner"
        assert settings.allowed_client_redirect_uris == DEFAULT_REDIRECT_URIS
        assert settings.account_session_ttl_seconds == 900
        assert settings.account_session_secret == bytes(range(32))
        assert settings.data_dir == Path("/data")
        assert settings.fastmcp_home == Path("/data/fastmcp")
        assert settings.mcp_url == "https://canvas.example.test/mcp"
        assert settings.account_url == "https://canvas.example.test/account"
        assert settings.token_db_path == Path("/data") / "canvas-mcp" / "tokens.sqlite3"
        assert SelfhostSettings.mcp_path == "/mcp"

    def test_guids_are_lower_cased(self):
        settings = load_selfhost_settings(
            _env(ENTRA_TENANT_ID=TENANT.upper(), ENTRA_CLIENT_ID=CLIENT.upper())
        )
        assert settings.tenant_id == TENANT
        assert settings.client_id == CLIENT

    def test_overrides_are_honoured(self):
        settings = load_selfhost_settings(_env(
            ENTRA_API_SCOPE="Mcp.Use", ENTRA_REQUIRED_ROLE="Reader", ENTRA_OWNER_ROLE="Boss",
            ACCOUNT_SESSION_TTL_SECONDS="120", SELFHOST_DATA_DIR="/srv/state",
        ))
        assert (settings.api_scope, settings.required_role, settings.owner_role) == (
            "Mcp.Use", "Reader", "Boss",
        )
        assert settings.account_session_ttl_seconds == 120
        assert settings.token_db_path == Path("/srv/state") / "canvas-mcp" / "tokens.sqlite3"

    def test_session_secret_accepts_urlsafe_base64_without_padding(self):
        raw = bytes(range(200, 232))
        encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        assert load_selfhost_settings(_env(ACCOUNT_SESSION_SECRET=encoded)).account_session_secret == raw


class TestPublicBaseUrl:
    def test_trailing_slash_is_removed(self):
        assert load_selfhost_settings(
            _env(PUBLIC_BASE_URL="https://canvas.example.test/")
        ).public_base_url == "https://canvas.example.test"

    def test_host_is_lower_cased(self):
        settings = load_selfhost_settings(_env(PUBLIC_BASE_URL="https://Canvas.Example.TEST"))
        assert settings.public_host == "canvas.example.test"
        assert settings.public_base_url == "https://canvas.example.test"

    @pytest.mark.parametrize("value", [
        "http://canvas.example.test",
        "canvas.example.test",
        "https://canvas.example.test/app",
        "https://user:pw@canvas.example.test",
        "https://canvas.example.test/?x=1",
        "https://canvas.example.test/#frag",
        "https://",
        "https://canvas.example.test:notaport",
    ])
    def test_rejected(self, value):
        problems = _problems(PUBLIC_BASE_URL=value)
        assert any("PUBLIC_BASE_URL" in p for p in problems)

    def test_missing(self):
        assert any("PUBLIC_BASE_URL is required" in p for p in _problems(PUBLIC_BASE_URL=None))


class TestEntraIdentifiers:
    @pytest.mark.parametrize("name", ["ENTRA_TENANT_ID", "ENTRA_CLIENT_ID"])
    @pytest.mark.parametrize("value", [None, "", "not-a-guid", TENANT + "0", TENANT[:-1]])
    def test_guid_required(self, name, value):
        assert any(name in p for p in _problems(**{name: value}))

    @pytest.mark.parametrize("value", ["common", "organizations", "consumers", "Common"])
    def test_tenant_aliases_rejected(self, value):
        assert any("ENTRA_TENANT_ID" in p for p in _problems(ENTRA_TENANT_ID=value))

    def test_client_secret_required_and_long_enough(self):
        assert any("ENTRA_CLIENT_SECRET" in p for p in _problems(ENTRA_CLIENT_SECRET=None))
        assert any("ENTRA_CLIENT_SECRET" in p for p in _problems(ENTRA_CLIENT_SECRET="short"))

    @pytest.mark.parametrize("value", ["has space", "x" * 65, "bad/scope", "openid", "Profile", "offline_access", "email"])
    def test_api_scope_rejected(self, value):
        assert any("ENTRA_API_SCOPE" in p for p in _problems(ENTRA_API_SCOPE=value))

    def test_roles_validated_and_distinct(self):
        assert any("ENTRA_REQUIRED_ROLE" in p for p in _problems(ENTRA_REQUIRED_ROLE="bad role"))
        assert any("ENTRA_OWNER_ROLE" in p for p in _problems(ENTRA_OWNER_ROLE="x" * 121))
        assert any(
            "different" in p for p in _problems(ENTRA_REQUIRED_ROLE="Same", ENTRA_OWNER_ROLE="Same")
        )


class TestSecrets:
    def test_signing_key_needs_32_characters(self):
        assert any("OAUTH_JWT_SIGNING_KEY" in p for p in _problems(OAUTH_JWT_SIGNING_KEY="k" * 31))
        assert any("OAUTH_JWT_SIGNING_KEY" in p for p in _problems(OAUTH_JWT_SIGNING_KEY=None))

    def test_session_secret_validated(self):
        short = base64.b64encode(bytes(31)).decode()
        assert any("ACCOUNT_SESSION_SECRET" in p for p in _problems(ACCOUNT_SESSION_SECRET=short))
        assert any("ACCOUNT_SESSION_SECRET" in p for p in _problems(ACCOUNT_SESSION_SECRET="!!!not base64!!!"))
        assert any("ACCOUNT_SESSION_SECRET" in p for p in _problems(ACCOUNT_SESSION_SECRET=None))

    @pytest.mark.parametrize("value", ["59", "3601", "abc", "-5"])
    def test_ttl_bounds(self, value):
        assert any("ACCOUNT_SESSION_TTL_SECONDS" in p for p in _problems(ACCOUNT_SESSION_TTL_SECONDS=value))

    def test_ttl_edges_accepted(self):
        assert load_selfhost_settings(_env(ACCOUNT_SESSION_TTL_SECONDS="60")).account_session_ttl_seconds == 60
        assert load_selfhost_settings(_env(ACCOUNT_SESSION_TTL_SECONDS="3600")).account_session_ttl_seconds == 3600

    def test_token_keys_required(self):
        assert any("CANVAS_TOKEN_KEYS" in p for p in _problems(CANVAS_TOKEN_KEYS=None))
        assert any("CANVAS_TOKEN_KEYS" in p for p in _problems(CANVAS_TOKEN_KEYS="  "))

    def test_secrets_are_not_in_repr(self):
        text = repr(load_selfhost_settings(_env()))
        for secret in (CLIENT_SECRET, SIGNING_KEY, SESSION_SECRET, TOKEN_KEYS):
            assert secret not in text
        hidden = {f.name for f in fields(SelfhostSettings) if not f.repr}
        assert hidden == {
            "client_secret", "oauth_jwt_signing_key", "account_session_secret", "canvas_token_keys_raw",
        }

    def test_messages_never_contain_secret_values(self):
        problems = _problems(
            ENTRA_CLIENT_SECRET="tiny-secret", OAUTH_JWT_SIGNING_KEY="weak-signing-key",
            ACCOUNT_SESSION_SECRET="c2hvcnQ=", CANVAS_TOKEN_KEYS=None,
            ENTRA_TENANT_ID="common-secret-ish", PUBLIC_BASE_URL="http://user:hunter2@evil.test",
        )
        text = " ".join(problems)
        for leaked in ("tiny-secret", "weak-signing-key", "c2hvcnQ=", "hunter2", "common-secret-ish", "evil.test"):
            assert leaked not in text


class TestRedirectUris:
    def test_custom_list(self):
        settings = load_selfhost_settings(_env(
            OAUTH_ALLOWED_REDIRECT_URIS=" https://claude.ai/api/mcp/auth_callback , http://localhost/cb ,https://claude.ai/api/mcp/auth_callback"
        ))
        assert settings.allowed_client_redirect_uris == (
            "https://claude.ai/api/mcp/auth_callback", "http://localhost/cb",
        )

    @pytest.mark.parametrize("entry", [
        "https://*.example.com/cb",
        "https://example.com/*",
        "http://example.com/cb",
        "http://localhost:8080/cb",
        "http://127.0.0.1:53682/callback",
        "https://localhost/cb",
        "https://127.0.0.1/cb",
        "https://user@example.com/cb",
        "https://example.com/cb#frag",
        "https://example.com/cb?x=1",
        "https://example.com",
        "ftp://example.com/cb",
        "javascript:alert(1)",
    ])
    def test_unsafe_entries_rejected(self, entry):
        problems = _problems(OAUTH_ALLOWED_REDIRECT_URIS=f"https://claude.ai/api/mcp/auth_callback,{entry}")
        assert any("OAUTH_ALLOWED_REDIRECT_URIS" in p for p in problems)


class TestPaths:
    def test_relative_paths_rejected(self):
        assert any("SELFHOST_DATA_DIR" in p for p in _problems(SELFHOST_DATA_DIR="data"))
        assert any("FASTMCP_HOME" in p for p in _problems(FASTMCP_HOME="fastmcp"))

    def test_fastmcp_home_is_required(self):
        assert any("FASTMCP_HOME" in p for p in _problems(FASTMCP_HOME=None))


class TestAllProblemsAtOnce:
    def test_empty_environment_reports_every_required_variable(self):
        with pytest.raises(SelfhostConfigError) as info:
            load_selfhost_settings({})
        text = " ".join(info.value.problems)
        for name in (
            "PUBLIC_BASE_URL", "ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET",
            "OAUTH_JWT_SIGNING_KEY", "ACCOUNT_SESSION_SECRET", "CANVAS_TOKEN_KEYS", "FASTMCP_HOME",
        ):
            assert name in text
        assert len(info.value.problems) >= 8

    def test_several_malformed_values_are_reported_together(self):
        problems = _problems(
            PUBLIC_BASE_URL="http://x", ENTRA_TENANT_ID="nope", ENTRA_API_SCOPE="openid",
            ACCOUNT_SESSION_TTL_SECONDS="5",
        )
        assert len(problems) == 4
        assert str(SelfhostConfigError(problems)) == "; ".join(problems)


class TestAuthMode:
    @pytest.mark.parametrize("env", [{}, {AUTH_MODE_ENV: ""}, {AUTH_MODE_ENV: "legacy"}, {AUTH_MODE_ENV: "  "}])
    def test_legacy(self, env):
        assert auth_mode(env) == "legacy"

    def test_entra(self):
        assert auth_mode({AUTH_MODE_ENV: AUTH_MODE_ENTRA}) == "entra-oauth"

    @pytest.mark.parametrize("value", ["Entra-OAuth", "oauth2", "easyauth", "true", "LEGACY", "entra-id"])
    def test_anything_else_is_refused(self, value):
        with pytest.raises(SelfhostConfigError) as info:
            auth_mode({AUTH_MODE_ENV: value})
        assert AUTH_MODE_ENV in info.value.problems[0]
        assert value not in info.value.problems[0]

    def test_reads_the_process_environment_by_default(self, monkeypatch):
        monkeypatch.setenv(AUTH_MODE_ENV, AUTH_MODE_ENTRA)
        assert auth_mode() == "entra-oauth"
        monkeypatch.delenv(AUTH_MODE_ENV)
        assert auth_mode() == "legacy"
