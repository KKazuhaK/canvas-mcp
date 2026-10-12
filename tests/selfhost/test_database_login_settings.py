"""Only infrastructure comes from the environment; provider import is explicit."""

import base64

from canvas_mcp.core.selfhost.app import prepare_selfhost
from canvas_mcp.core.selfhost.db.migrations.provider_environment import (
    load_provider_environment,
)
from canvas_mcp.core.selfhost.settings import load_selfhost_settings


def infrastructure():
    return {
        "PUBLIC_BASE_URL": "https://mcp.example.com",
        "ACCOUNT_SESSION_SECRET": base64.b64encode(b"s" * 32).decode(),
        "CANVAS_TOKEN_KEYS": "k1:" + base64.b64encode(b"k" * 32).decode(),
    }


def test_startup_configuration_requires_no_login_provider_credentials():
    settings = load_selfhost_settings(infrastructure())
    assert settings.login_providers.order == ()
    assert settings.tenant_id == settings.client_id == settings.client_secret == ""


def test_stale_or_invalid_provider_environment_is_not_a_runtime_layer():
    values = infrastructure() | {
        "SELFHOST_LOGIN_PROVIDERS": "invalid-provider",
        "ENTRA_TENANT_ID": "not-a-tenant",
        "ENTRA_CLIENT_ID": "not-a-client",
        "ENTRA_CLIENT_SECRET": "stale-private-secret",
        "GOOGLE_CLIENT_SECRET": "another-private-secret",
    }
    settings = load_selfhost_settings(values)
    assert settings.login_providers.order == ()
    assert settings.client_secret == ""
    assert "private-secret" not in repr(settings)


def test_environment_import_requires_the_explicit_isolated_adapter():
    values = infrastructure() | {
        "ENTRA_TENANT_ID": "11111111-2222-3333-4444-555555555555",
        "ENTRA_CLIENT_ID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "ENTRA_CLIENT_SECRET": "old-client-secret-value",
    }
    assert load_selfhost_settings(values).login_providers.order == ()
    imported = load_provider_environment(values)
    assert imported.login_providers.order == ("entra",)
    assert imported.client_secret == "old-client-secret-value"
    assert "old-client-secret-value" not in repr(imported)


def test_unconfigured_native_runtime_opens_for_protected_setup(tmp_path):
    settings = load_selfhost_settings(
        infrastructure() | {"SELFHOST_DATA_DIR": str(tmp_path)}
    )
    runtime = prepare_selfhost(settings)
    try:
        assert runtime.settings.login_providers.order == ()
        assert (
            runtime.provider_store is not None
            and runtime.provider_store.setup_available()
        )
        assert runtime.installation is not None
        code = runtime.installation.issue()
        assert code is not None and runtime.installation.verify(code)
    finally:
        runtime.store.close()
