"""Tests for the selfhost environment contract."""

import base64
from dataclasses import fields
from pathlib import Path

import pytest

from canvas_mcp.core.selfhost.db.migrations.provider_environment import (
    load_provider_environment,
)
from canvas_mcp.core.selfhost.settings import (
    AUTH_MODE_ENV,
    AUTH_MODE_SELFHOST,
    COURSE_STATE_ENV,
    DEFAULT_COURSE_STATE,
    DEFAULT_REDIRECT_URIS,
    SelfhostConfigError,
    SelfhostSettings,
    auth_mode,
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
        load_provider_environment(_env(**overrides))
    return info.value.problems


class TestValidEnvironment:
    def test_minimal_environment_loads_with_defaults(self):
        settings = load_provider_environment(_env())
        assert settings.public_base_url == "https://canvas.example.test"
        assert settings.public_host == "canvas.example.test"
        assert settings.tenant_id == TENANT
        assert settings.client_id == CLIENT
        assert settings.api_scope == "Canvas.Access"
        assert settings.required_role == "Canvas.User"
        assert settings.owner_role == "Canvas.Owner"
        assert settings.allowed_client_redirect_uris == DEFAULT_REDIRECT_URIS
        assert settings.account_session_ttl_seconds == 604800
        assert settings.account_session_secret == bytes(range(32))
        assert settings.data_dir == Path("/data")
        assert not hasattr(settings, "fastmcp_home")
        assert settings.mcp_url == "https://canvas.example.test/mcp"
        assert settings.account_url == "https://canvas.example.test/account"
        assert settings.token_db_path == Path("/data") / "canvas-mcp" / "tokens.sqlite3"
        assert SelfhostSettings.mcp_path == "/mcp"

    def test_guids_are_lower_cased(self):
        settings = load_provider_environment(
            _env(ENTRA_TENANT_ID=TENANT.upper(), ENTRA_CLIENT_ID=CLIENT.upper())
        )
        assert settings.tenant_id == TENANT
        assert settings.client_id == CLIENT

    def test_overrides_are_honoured(self):
        settings = load_provider_environment(
            _env(
                MCP_SCOPE="Mcp.Use",
                ENTRA_REQUIRED_ROLE="Reader",
                ENTRA_OWNER_ROLE="Boss",
                ACCOUNT_SESSION_TTL_SECONDS="120",
                SELFHOST_DATA_DIR="/srv/state",
            )
        )
        assert (settings.api_scope, settings.required_role, settings.owner_role) == (
            "Mcp.Use",
            "Reader",
            "Boss",
        )
        assert settings.account_session_ttl_seconds == 120
        assert (
            settings.token_db_path
            == Path("/srv/state") / "canvas-mcp" / "tokens.sqlite3"
        )

    def test_session_secret_accepts_urlsafe_base64_without_padding(self):
        raw = bytes(range(200, 232))
        encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        assert (
            load_provider_environment(
                _env(ACCOUNT_SESSION_SECRET=encoded)
            ).account_session_secret
            == raw
        )


class TestPublicBaseUrl:
    def test_trailing_slash_is_removed(self):
        assert (
            load_provider_environment(
                _env(PUBLIC_BASE_URL="https://canvas.example.test/")
            ).public_base_url
            == "https://canvas.example.test"
        )

    def test_host_is_lower_cased(self):
        settings = load_provider_environment(
            _env(PUBLIC_BASE_URL="https://Canvas.Example.TEST")
        )
        assert settings.public_host == "canvas.example.test"
        assert settings.public_base_url == "https://canvas.example.test"

    @pytest.mark.parametrize(
        "value",
        [
            "http://canvas.example.test",
            "canvas.example.test",
            "https://canvas.example.test/app",
            "https://user:pw@canvas.example.test",
            "https://canvas.example.test/?x=1",
            "https://canvas.example.test/#frag",
            "https://",
            "https://canvas.example.test:notaport",
        ],
    )
    def test_rejected(self, value):
        problems = _problems(PUBLIC_BASE_URL=value)
        assert any("PUBLIC_BASE_URL" in p for p in problems)

    def test_missing(self):
        assert any(
            "PUBLIC_BASE_URL is required" in p for p in _problems(PUBLIC_BASE_URL=None)
        )


class TestEntraIdentifiers:
    @pytest.mark.parametrize("name", ["ENTRA_TENANT_ID", "ENTRA_CLIENT_ID"])
    @pytest.mark.parametrize(
        "value", [None, "", "not-a-guid", TENANT + "0", TENANT[:-1]]
    )
    def test_guid_required(self, name, value):
        assert any(name in p for p in _problems(**{name: value}))

    @pytest.mark.parametrize(
        "value", ["common", "organizations", "consumers", "Common"]
    )
    def test_tenant_aliases_rejected(self, value):
        assert any("ENTRA_TENANT_ID" in p for p in _problems(ENTRA_TENANT_ID=value))

    def test_client_secret_required_and_long_enough(self):
        assert any(
            "ENTRA_CLIENT_SECRET" in p for p in _problems(ENTRA_CLIENT_SECRET=None)
        )
        assert any(
            "ENTRA_CLIENT_SECRET" in p for p in _problems(ENTRA_CLIENT_SECRET="short")
        )

    @pytest.mark.parametrize(
        "value",
        [
            "has space",
            "x" * 65,
            "bad/scope",
            "openid",
            "Profile",
            "offline_access",
            "email",
        ],
    )
    def test_api_scope_rejected(self, value):
        assert any("MCP_SCOPE" in p for p in _problems(MCP_SCOPE=value))

    def test_roles_validated_and_distinct(self):
        assert any(
            "ENTRA_REQUIRED_ROLE" in p
            for p in _problems(ENTRA_REQUIRED_ROLE="bad role")
        )
        assert any(
            "ENTRA_OWNER_ROLE" in p for p in _problems(ENTRA_OWNER_ROLE="x" * 121)
        )
        assert any(
            "different" in p
            for p in _problems(ENTRA_REQUIRED_ROLE="Same", ENTRA_OWNER_ROLE="Same")
        )


class TestSecrets:
    def test_jwt_keys_are_derived_without_a_separate_secret(self):
        assert not hasattr(load_provider_environment(_env()), "oauth_jwt_signing_key")
        assert any(
            "OAUTH_JWT_SIGNING_KEY" in p
            for p in _problems(OAUTH_JWT_SIGNING_KEY=SIGNING_KEY)
        )

    def test_session_secret_validated(self):
        short = base64.b64encode(bytes(31)).decode()
        assert any(
            "ACCOUNT_SESSION_SECRET" in p
            for p in _problems(ACCOUNT_SESSION_SECRET=short)
        )
        assert any(
            "ACCOUNT_SESSION_SECRET" in p
            for p in _problems(ACCOUNT_SESSION_SECRET="!!!not base64!!!")
        )
        assert any(
            "ACCOUNT_SESSION_SECRET" in p
            for p in _problems(ACCOUNT_SESSION_SECRET=None)
        )

    @pytest.mark.parametrize("value", ["59", "2592001", "abc", "-5"])
    def test_ttl_bounds(self, value):
        assert any(
            "ACCOUNT_SESSION_TTL_SECONDS" in p
            for p in _problems(ACCOUNT_SESSION_TTL_SECONDS=value)
        )

    def test_ttl_edges_accepted(self):
        assert (
            load_provider_environment(
                _env(ACCOUNT_SESSION_TTL_SECONDS="60")
            ).account_session_ttl_seconds
            == 60
        )
        assert (
            load_provider_environment(
                _env(ACCOUNT_SESSION_TTL_SECONDS="3600")
            ).account_session_ttl_seconds
            == 3600
        )

    def test_token_keys_required(self):
        assert any("CANVAS_TOKEN_KEYS" in p for p in _problems(CANVAS_TOKEN_KEYS=None))
        assert any("CANVAS_TOKEN_KEYS" in p for p in _problems(CANVAS_TOKEN_KEYS="  "))

    def test_secrets_are_not_in_repr(self):
        text = repr(load_provider_environment(_env()))
        for secret in (CLIENT_SECRET, SIGNING_KEY, SESSION_SECRET, TOKEN_KEYS):
            assert secret not in text
        hidden = {f.name for f in fields(SelfhostSettings) if not f.repr}
        assert hidden == {
            "client_secret",
            "account_session_secret",
            "canvas_token_keys_raw",
            "access_source",
        }

    def test_messages_never_contain_secret_values(self):
        problems = _problems(
            ENTRA_CLIENT_SECRET="tiny-secret",
            OAUTH_JWT_SIGNING_KEY="weak-signing-key",
            ACCOUNT_SESSION_SECRET="c2hvcnQ=",
            CANVAS_TOKEN_KEYS=None,
            ENTRA_TENANT_ID="common-secret-ish",
            PUBLIC_BASE_URL="http://user:hunter2@evil.test",
        )
        text = " ".join(problems)
        for leaked in (
            "tiny-secret",
            "weak-signing-key",
            "c2hvcnQ=",
            "hunter2",
            "common-secret-ish",
            "evil.test",
        ):
            assert leaked not in text


class TestRedirectUris:
    def test_custom_list(self):
        settings = load_provider_environment(
            _env(
                OAUTH_ALLOWED_REDIRECT_URIS=" https://claude.ai/api/mcp/auth_callback , http://localhost/cb ,https://claude.ai/api/mcp/auth_callback"
            )
        )
        assert settings.allowed_client_redirect_uris == (
            "https://claude.ai/api/mcp/auth_callback",
            "http://localhost/cb",
        )

    @pytest.mark.parametrize(
        "entry",
        [
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
        ],
    )
    def test_unsafe_entries_rejected(self, entry):
        problems = _problems(
            OAUTH_ALLOWED_REDIRECT_URIS=f"https://claude.ai/api/mcp/auth_callback,{entry}"
        )
        assert any("OAUTH_ALLOWED_REDIRECT_URIS" in p for p in problems)


class TestPaths:
    def test_relative_data_path_is_rejected(self):
        assert any(
            "SELFHOST_DATA_DIR" in p for p in _problems(SELFHOST_DATA_DIR="data")
        )

    def test_fastmcp_home_is_not_required_or_used(self):
        for value in (None, "fastmcp"):
            assert not hasattr(
                load_provider_environment(_env(FASTMCP_HOME=value)), "fastmcp_home"
            )


class TestAllProblemsAtOnce:
    def test_empty_environment_reports_every_required_variable(self):
        with pytest.raises(SelfhostConfigError) as info:
            load_provider_environment({})
        text = " ".join(info.value.problems)
        for name in (
            "PUBLIC_BASE_URL",
            "ENTRA_TENANT_ID",
            "ENTRA_CLIENT_ID",
            "ENTRA_CLIENT_SECRET",
            "ACCOUNT_SESSION_SECRET",
            "CANVAS_TOKEN_KEYS",
        ):
            assert name in text
        assert len(info.value.problems) >= 6

    def test_several_malformed_values_are_reported_together(self):
        problems = _problems(
            PUBLIC_BASE_URL="http://x",
            ENTRA_TENANT_ID="nope",
            MCP_SCOPE="openid",
            ACCOUNT_SESSION_TTL_SECONDS="5",
        )
        assert len(problems) == 4
        assert str(SelfhostConfigError(problems)) == "; ".join(problems)


class TestAuthMode:
    @pytest.mark.parametrize(
        "env",
        [{}, {AUTH_MODE_ENV: ""}, {AUTH_MODE_ENV: "legacy"}, {AUTH_MODE_ENV: "  "}],
    )
    def test_legacy(self, env):
        assert auth_mode(env) == "legacy"

    def test_entra(self):
        assert auth_mode({AUTH_MODE_ENV: AUTH_MODE_SELFHOST}) == "selfhost"

    @pytest.mark.parametrize(
        "value", ["Entra-OAuth", "oauth2", "easyauth", "true", "LEGACY", "entra-id"]
    )
    def test_anything_else_is_refused(self, value):
        with pytest.raises(SelfhostConfigError) as info:
            auth_mode({AUTH_MODE_ENV: value})
        assert AUTH_MODE_ENV in info.value.problems[0]
        assert value not in info.value.problems[0]

    def test_reads_the_process_environment_by_default(self, monkeypatch):
        monkeypatch.setenv(AUTH_MODE_ENV, AUTH_MODE_SELFHOST)
        assert auth_mode() == "selfhost"
        monkeypatch.delenv(AUTH_MODE_ENV)
        assert auth_mode() == "legacy"


class TestDatabaseOwnedSchools:
    def test_startup_settings_do_not_seed_school_policy(self):
        settings = load_provider_environment(_env())
        assert not hasattr(settings, "featured_schools")
        assert not hasattr(settings, "school_search")


class TestCourseState:
    def test_the_default_is_request_local(self):
        assert DEFAULT_COURSE_STATE == "request_local"
        assert load_provider_environment(_env()).course_state == "request_local"

    def test_the_variable_name(self):
        assert COURSE_STATE_ENV == "SELFHOST_COURSE_STATE"

    @pytest.mark.parametrize(
        "value", ["", "request_local", "REQUEST_LOCAL", " request_local "]
    )
    def test_request_local_spellings(self, value):
        assert (
            load_provider_environment(_env(SELFHOST_COURSE_STATE=value)).course_state
            == "request_local"
        )

    @pytest.mark.parametrize(
        "value", ["per_principal", "PER_PRINCIPAL", " per_principal "]
    )
    def test_per_principal_is_an_explicit_opt_in(self, value):
        assert (
            load_provider_environment(_env(SELFHOST_COURSE_STATE=value)).course_state
            == "per_principal"
        )

    @pytest.mark.parametrize(
        "value", ["per-principal", "principal", "true", "1", "global", "none"]
    )
    def test_anything_else_is_refused_without_echoing_the_value(self, value):
        problems = _problems(SELFHOST_COURSE_STATE=value)
        assert len(problems) == 1
        assert "SELFHOST_COURSE_STATE" in problems[0]
        assert "request_local" in problems[0] and "per_principal" in problems[0]
        assert value not in problems[0].replace("per_principal", "").replace(
            "request_local", ""
        )


class TestAccountUi:
    def test_react_has_one_mandatory_image_path(self):
        settings = load_provider_environment(_env())
        assert not hasattr(settings, "account_ui")
        assert settings.account_web_dist.as_posix() == "/app/web-dist"

    def test_the_directory_is_taken_as_given_and_must_be_absolute(self):
        settings = load_provider_environment(_env(ACCOUNT_WEB_DIST="/srv/web/dist"))
        assert settings.account_web_dist.as_posix() == "/srv/web/dist"
        for value in ("web/dist", "./dist", "dist", "~/dist"):
            assert _problems(ACCOUNT_WEB_DIST=value) == [
                "ACCOUNT_WEB_DIST must be an absolute path"
            ]


@pytest.mark.parametrize("raw", ["pilot", " PILOT "])
def test_pilot_profile_disables_all_file_download_tools(raw):
    settings = load_provider_environment(
        _env(SELFHOST_PROFILE=raw, SELFHOST_DISABLED_TOOLS="list_courses")
    )
    assert settings.profile == "pilot"
    assert set(settings.disabled_tools) == {
        "list_courses",
        "read_course_file",
        "read_course_file_text",
        "download_course_file",
    }


def test_unknown_profile_is_refused_without_echoing_its_value():
    problems = _problems(SELFHOST_PROFILE="secret-profile-value")
    assert any("SELFHOST_PROFILE" in p for p in problems)
    assert all("secret-profile-value" not in p for p in problems)
