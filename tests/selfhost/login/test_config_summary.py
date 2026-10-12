"""``--config`` lists the providers (never a secret) and stays byte-identical for Entra alone."""

from __future__ import annotations

from canvas_mcp.core.selfhost.db.migrations.provider_environment import (
    load_provider_environment,
)
from canvas_mcp.server import _selfhost_summary

from .test_provider_settings import (
    GITHUB_SECRET,
    GOOGLE_ID,
    GOOGLE_SECRET,
    ISSUER,
    OIDC_SECRET,
    env,
    github,
    google,
    oidc,
)


def test_entra_only_summary_has_no_provider_line() -> None:
    lines = _selfhost_summary(load_provider_environment(env(SELFHOST_AUTH_MODE=None)))
    assert not any("Sign-in providers" in line for line in lines)
    assert any(line.startswith("  Entra tenant: ") for line in lines)
    assert any(line.startswith("  Entra client: ") for line in lines)
    # Listing entra explicitly changes nothing.
    explicit = _selfhost_summary(
        load_provider_environment(
            env(SELFHOST_AUTH_MODE=None, SELFHOST_LOGIN_PROVIDERS="entra")
        )
    )
    assert explicit == lines


def test_entra_only_summary_includes_the_native_authorization_server() -> None:
    local = _selfhost_summary(load_provider_environment(env()))
    assert not any("Sign-in providers" in line for line in local)
    assert any(line.startswith("  Entra tenant: ") for line in local)
    assert any(line.startswith("  Roles: user=") for line in local)


def test_multi_provider_summary_names_providers_and_no_secret() -> None:
    settings = load_provider_environment(
        env(
            SELFHOST_LOGIN_PROVIDERS="google,entra,github,oidc:school",
            **google(),
            **github(),
            **oidc(),
        )
    )
    text = "\n".join(_selfhost_summary(settings))
    assert (
        "Sign-in providers: google (client " + GOOGLE_ID + "), entra, github (client "
        in text
    )
    assert f"oidc:school (issuer {ISSUER}, client canvas-mcp)" in text
    for secret in (GOOGLE_SECRET, GITHUB_SECRET, OIDC_SECRET):
        assert secret not in text


def test_without_entra_the_tenant_and_client_lines_are_omitted() -> None:
    settings = load_provider_environment(
        env(
            SELFHOST_LOGIN_PROVIDERS="google",
            ACCESS_RULES="google:domain:example.edu",
            SELFHOST_BOOTSTRAP_OWNER="token_admin",
            ENTRA_TENANT_ID=None,
            ENTRA_CLIENT_ID=None,
            ENTRA_CLIENT_SECRET=None,
            **google(),
        )
    )
    text = "\n".join(_selfhost_summary(settings))
    assert "Entra tenant" not in text and "Entra client" not in text
    assert "Roles:" not in text  # the Entra app roles mean nothing without Entra
    assert "Sign-in providers: google" in text
