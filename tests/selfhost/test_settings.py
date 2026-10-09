"""Tests for the entra-oauth environment contract."""

import base64
from dataclasses import fields
from pathlib import Path

import pytest

from canvas_mcp.core.selfhost.settings import (
    AUTH_MODE_ENTRA,
    AUTH_MODE_ENV,
    COURSE_STATE_ENV,
    DEFAULT_COURSE_STATE,
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


class TestFeaturedSchools:
    def test_defaults_are_empty_and_off(self):
        settings = load_selfhost_settings(_env())
        assert settings.featured_schools == ()
        assert settings.school_search is False

    def test_hosts_with_and_without_names(self):
        settings = load_selfhost_settings(_env(
            CANVAS_FEATURED_SCHOOLS="canvas.a.edu=A University, canvas.b.edu"
        ))
        assert [(s.host, s.name) for s in settings.featured_schools] == [
            ("canvas.a.edu", "A University"), ("canvas.b.edu", ""),
        ]

    def test_whitespace_case_and_blank_items(self):
        settings = load_selfhost_settings(_env(
            CANVAS_FEATURED_SCHOOLS="  Canvas.A.EDU = Name = With Equals ,, canvas.b.edu  ,"
        ))
        assert [(s.host, s.name) for s in settings.featured_schools] == [
            ("canvas.a.edu", "Name = With Equals"), ("canvas.b.edu", ""),
        ]

    @pytest.mark.parametrize("value", [
        "https://canvas.a.edu", "canvas.a.edu:8443", "canvas.a.edu/lms", "127.0.0.1",
        "localhost", "singlelabel", "user@canvas.a.edu", "=Name", "canvas.a.edu.",
    ])
    def test_bad_hosts_are_refused_without_echoing_the_value(self, value):
        problems = _problems(CANVAS_FEATURED_SCHOOLS=value)
        assert len(problems) == 1
        assert "CANVAS_FEATURED_SCHOOLS entry 1" in problems[0]
        assert value not in problems[0]

    def test_the_failing_entry_is_numbered(self):
        problems = _problems(CANVAS_FEATURED_SCHOOLS="canvas.a.edu,,https://x.edu,canvas.b.edu,y")
        assert [p.split(" must")[0] for p in problems] == [
            "CANVAS_FEATURED_SCHOOLS entry 2", "CANVAS_FEATURED_SCHOOLS entry 4",
        ]

    def test_duplicates_are_refused(self):
        problems = _problems(CANVAS_FEATURED_SCHOOLS="canvas.a.edu,CANVAS.A.EDU=Again")
        assert len(problems) == 1 and "repeats" in problems[0]

    def test_a_set_but_empty_list_is_refused(self):
        problems = _problems(CANVAS_FEATURED_SCHOOLS=" , ,")
        assert problems == ["CANVAS_FEATURED_SCHOOLS is set but lists no school"]

    def test_too_many_schools_are_refused(self):
        many = ",".join(f"canvas.s{i}.edu" for i in range(51))
        assert any("more than 50" in p for p in _problems(CANVAS_FEATURED_SCHOOLS=many))
        fifty = ",".join(f"canvas.s{i}.edu" for i in range(50))
        assert len(load_selfhost_settings(_env(CANVAS_FEATURED_SCHOOLS=fifty)).featured_schools) == 50

    def test_bad_display_names_are_refused(self):
        too_long = "canvas.a.edu=" + "n" * 81
        problems = _problems(CANVAS_FEATURED_SCHOOLS=too_long)
        assert len(problems) == 1 and "n" * 10 not in problems[0]
        control = "canvas.a.edu=Bad" + chr(7) + "Name"
        assert len(_problems(CANVAS_FEATURED_SCHOOLS=control)) == 1
        ok = "canvas.a.edu=" + "n" * 80
        assert load_selfhost_settings(_env(CANVAS_FEATURED_SCHOOLS=ok)).featured_schools[0].name == "n" * 80

    def test_reserved_names_are_not_judged_at_load_time(self):
        """Only syntax is checked here; blocked suffixes are refused at startup,
        where the (exempt) default host is known."""
        settings = load_selfhost_settings(_env(CANVAS_FEATURED_SCHOOLS="canvas.school.example"))
        assert settings.featured_schools[0].host == "canvas.school.example"

    def test_no_dns_lookup_at_load_time(self, monkeypatch):
        import socket

        def boom(*_a, **_k):
            raise AssertionError("settings must not resolve names")

        monkeypatch.setattr(socket, "getaddrinfo", boom)
        load_selfhost_settings(_env(CANVAS_FEATURED_SCHOOLS="canvas.a.edu", CANVAS_SCHOOL_SEARCH="true"))


class TestSchoolSearch:
    @pytest.mark.parametrize("value", ["true", "TRUE", "True", "1", "yes", " Yes "])
    def test_truthy(self, value):
        assert load_selfhost_settings(_env(CANVAS_SCHOOL_SEARCH=value)).school_search is True

    @pytest.mark.parametrize("value", ["", "false", "FALSE", "0", "no", "No"])
    def test_falsey(self, value):
        assert load_selfhost_settings(_env(CANVAS_SCHOOL_SEARCH=value)).school_search is False

    @pytest.mark.parametrize("value", ["maybe", "on", "2", "enabled", "tru"])
    def test_anything_else_is_refused(self, value):
        problems = _problems(CANVAS_SCHOOL_SEARCH=value)
        assert problems == ["CANVAS_SCHOOL_SEARCH must be true or false"]


class TestCourseState:
    def test_the_default_is_request_local(self):
        assert DEFAULT_COURSE_STATE == "request_local"
        assert load_selfhost_settings(_env()).course_state == "request_local"

    def test_the_variable_name(self):
        assert COURSE_STATE_ENV == "SELFHOST_COURSE_STATE"

    @pytest.mark.parametrize("value", ["", "request_local", "REQUEST_LOCAL", " request_local "])
    def test_request_local_spellings(self, value):
        assert load_selfhost_settings(_env(SELFHOST_COURSE_STATE=value)).course_state == "request_local"

    @pytest.mark.parametrize("value", ["per_principal", "PER_PRINCIPAL", " per_principal "])
    def test_per_principal_is_an_explicit_opt_in(self, value):
        assert load_selfhost_settings(_env(SELFHOST_COURSE_STATE=value)).course_state == "per_principal"

    @pytest.mark.parametrize("value", ["per-principal", "principal", "true", "1", "global", "none"])
    def test_anything_else_is_refused_without_echoing_the_value(self, value):
        problems = _problems(SELFHOST_COURSE_STATE=value)
        assert len(problems) == 1
        assert "SELFHOST_COURSE_STATE" in problems[0]
        assert "request_local" in problems[0] and "per_principal" in problems[0]
        assert value not in problems[0].replace("per_principal", "").replace("request_local", "")
