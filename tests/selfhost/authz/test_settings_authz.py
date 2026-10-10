"""SELFHOST_AUTH_MODE and the tunables of the local authorization server."""

from __future__ import annotations

import pytest

from canvas_mcp.core.selfhost.settings import (
    AuthzSettings,
    SelfhostConfigError,
    format_duration,
    load_selfhost_settings,
)

from ..test_settings import _env


def _load(**overrides: str | None):
    return load_selfhost_settings(_env(**overrides))


def _problems(**overrides: str | None) -> list[str]:
    with pytest.raises(SelfhostConfigError) as info:
        _load(**overrides)
    return info.value.problems


class TestMode:
    def test_the_default_is_the_oauth_proxy(self):
        settings = _load()
        assert settings.authz_mode == "entra_proxy"
        assert settings.authz == AuthzSettings()

    @pytest.mark.parametrize(
        ("raw", "mode"),
        [("entra_proxy", "entra_proxy"), ("local", "local"), ("LOCAL", "local"), ("", "entra_proxy")],
    )
    def test_accepted_values(self, raw, mode):
        assert _load(SELFHOST_AUTH_MODE=raw).authz_mode == mode

    @pytest.mark.parametrize("raw", ["proxy", "entra-oauth", "locall", "1", "on"])
    def test_anything_else_is_refused_without_echoing_it(self, raw):
        problems = _problems(SELFHOST_AUTH_MODE=raw)
        assert problems == ["SELFHOST_AUTH_MODE must be unset, 'entra_proxy' or 'local'"]


class TestDefaults:
    def test_the_documented_defaults(self):
        authz = _load().authz
        assert authz.access_token_ttl == 3600
        assert authz.refresh_absolute_ttl == 30 * 86400
        assert authz.refresh_reuse_grace_s == 30
        assert authz.grant_status_cache_s == 30
        assert authz.cimd_enabled is True
        assert authz.cimd_fetch_timeout_s == 3
        assert authz.cimd_stale_max == 7 * 86400
        assert authz.max_upstream_auth_age == 14 * 86400

    def test_hand_built_settings_get_the_same_defaults(self):
        assert AuthzSettings().access_token_ttl == 3600


class TestDurations:
    @pytest.mark.parametrize(
        ("raw", "seconds"),
        [("3600", 3600), ("3600s", 3600), ("30m", 1800), ("12h", 43200), ("1d", 86400), ("300", 300)],
    )
    def test_the_grammar(self, raw, seconds):
        assert _load(ACCESS_TOKEN_TTL=raw).authz.access_token_ttl == seconds

    def test_unset_and_empty_mean_the_default(self):
        assert _load(ACCESS_TOKEN_TTL="").authz.access_token_ttl == 3600
        assert _load(ACCESS_TOKEN_TTL=None).authz.access_token_ttl == 3600

    @pytest.mark.parametrize("raw", ["5x", "-5", "1.5q", "q", "9 9", "1e3", "0x10", "1000000000", "١٢٣"])
    def test_malformed_values_are_refused(self, raw):
        problems = _problems(ACCESS_TOKEN_TTL=raw)
        assert len(problems) == 1 and problems[0].startswith("ACCESS_TOKEN_TTL must be a duration")
        assert raw not in problems[0]

    @pytest.mark.parametrize(("raw", "seconds"), [("5m", 300), ("24h", 86400), ("86400", 86400)])
    def test_access_token_ttl_bounds_are_inclusive(self, raw, seconds):
        assert _load(ACCESS_TOKEN_TTL=raw).authz.access_token_ttl == seconds

    @pytest.mark.parametrize("raw", ["299", "4m", "25h", "86401"])
    def test_access_token_ttl_outside_the_bounds_is_refused(self, raw):
        assert any(p.startswith("ACCESS_TOKEN_TTL") for p in _problems(ACCESS_TOKEN_TTL=raw))

    @pytest.mark.parametrize(
        ("name", "ok", "bad"),
        [
            ("REFRESH_ABSOLUTE_TTL", ("1h", "90d"), ("59m", "91d")),
            ("MAX_UPSTREAM_AUTH_AGE", ("1h", "90d"), ("59m", "91d")),
            ("CIMD_STALE_MAX", ("0", "30d"), ("31d", "99999999999")),
        ],
    )
    def test_ranges(self, name, ok, bad):
        extra = {"ACCESS_TOKEN_TTL": "300"} if name == "REFRESH_ABSOLUTE_TTL" else {}
        for raw in ok:
            _load(**{name: raw}, **extra)
        for raw in bad:
            problems = _problems(**{name: raw}, **extra)
            assert any(p.startswith(name) for p in problems)
            assert all(raw not in p for p in problems)

    def test_the_refresh_cap_must_outlast_an_access_token(self):
        problems = _problems(ACCESS_TOKEN_TTL="24h", REFRESH_ABSOLUTE_TTL="2h")
        assert problems == ["REFRESH_ABSOLUTE_TTL must be longer than ACCESS_TOKEN_TTL"]
        assert _problems(ACCESS_TOKEN_TTL="2h", REFRESH_ABSOLUTE_TTL="2h")

    def test_format_duration(self):
        assert format_duration(86400) == "1d"
        assert format_duration(7200) == "2h"
        assert format_duration(90) == "90s"
        assert format_duration(0) == "0s"


class TestIntegersAndSwitches:
    @pytest.mark.parametrize(
        ("name", "low", "high"),
        [
            ("REFRESH_REUSE_GRACE_S", 0, 120),
            ("GRANT_STATUS_CACHE_S", 0, 60),
            ("CIMD_FETCH_TIMEOUT_S", 1, 5),
        ],
    )
    def test_integer_ranges(self, name, low, high):
        attr = name.lower()
        assert getattr(_load(**{name: str(low)}).authz, attr) == low
        assert getattr(_load(**{name: str(high)}).authz, attr) == high
        for raw in (str(low - 1), str(high + 1), "x", "1.5"):
            problems = _problems(**{name: raw})
            assert problems == [f"{name} must be an integer from {low} to {high}"]

    @pytest.mark.parametrize(("raw", "value"), [("true", True), ("false", False), ("0", False), ("1", True)])
    def test_cimd_switch(self, raw, value):
        assert _load(CIMD_ENABLED=raw).authz.cimd_enabled is value

    def test_cimd_switch_rejects_nonsense(self):
        assert _problems(CIMD_ENABLED="maybe") == ["CIMD_ENABLED must be true or false"]


class TestValidatedInBothModes:
    def test_a_typo_fails_closed_even_in_the_default_mode(self):
        assert _problems(SELFHOST_AUTH_MODE="entra_proxy", ACCESS_TOKEN_TTL="nope")

    def test_every_problem_is_collected_at_once(self):
        problems = _problems(
            SELFHOST_AUTH_MODE="x", ACCESS_TOKEN_TTL="x", CIMD_FETCH_TIMEOUT_S="99", ENTRA_CLIENT_ID="x"
        )
        assert len(problems) >= 4


class TestPublicBaseUrl:
    def test_the_default_port_is_refused_in_local_mode_only(self):
        assert _problems(SELFHOST_AUTH_MODE="local", PUBLIC_BASE_URL="https://canvas.example.test:443") == [
            "PUBLIC_BASE_URL must not include the default port when SELFHOST_AUTH_MODE=local"
        ]
        assert _load(PUBLIC_BASE_URL="https://canvas.example.test:443").public_base_url.endswith(":443")

    def test_other_ports_and_trailing_slash_are_fine_in_local_mode(self):
        settings = _load(SELFHOST_AUTH_MODE="local", PUBLIC_BASE_URL="https://Canvas.Example.test:8443/")
        assert settings.public_base_url == "https://canvas.example.test:8443"


class TestRedirectAllowlist:
    def test_a_port_less_ipv6_loopback_entry_is_accepted(self):
        settings = _load(OAUTH_ALLOWED_REDIRECT_URIS="https://claude.ai/api/mcp/auth_callback,http://[::1]/callback")
        assert "http://[::1]/callback" in settings.allowed_client_redirect_uris

    @pytest.mark.parametrize(
        "entry", ["http://[::1]:8080/callback", "https://[::1]/callback", "http://[::2]/callback"]
    )
    def test_ipv6_entries_follow_the_same_rules(self, entry):
        assert any(
            "OAUTH_ALLOWED_REDIRECT_URIS" in p
            for p in _problems(OAUTH_ALLOWED_REDIRECT_URIS=f"https://claude.ai/cb,{entry}")
        )

    def test_the_default_list_is_unchanged(self):
        assert _load().allowed_client_redirect_uris == (
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback",
            "http://localhost/callback",
            "http://127.0.0.1/callback",
        )
