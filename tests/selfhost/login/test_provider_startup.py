"""Startup with and without Entra: the owner path, and what the settings keep out of reach."""

from __future__ import annotations

import pathlib

import pytest

from canvas_mcp.core.selfhost.app import prepare_selfhost
from canvas_mcp.core.selfhost.settings import (
    SelfhostConfigError,
    load_selfhost_settings,
)
from canvas_mcp.core.selfhost.token_store import OPERATOR

from ..authz.stack import default_env
from ..conftest import OID_A, make_account
from .test_provider_settings import GOOGLE_ID, GOOGLE_SECRET

NO_ENTRA = {
    "SELFHOST_LOGIN_PROVIDERS": "google",
    "GOOGLE_CLIENT_ID": GOOGLE_ID,
    "GOOGLE_CLIENT_SECRET": GOOGLE_SECRET,
    "ACCESS_RULES": "google:domain:example.edu",
    "ENTRA_TENANT_ID": "",
    "ENTRA_CLIENT_ID": "",
    "ENTRA_CLIENT_SECRET": "",
}


def settings_for(tmp_path: pathlib.Path, **env: str):  # type: ignore[no-untyped-def]
    return load_selfhost_settings(default_env(tmp_path, **{**NO_ENTRA, **env}))


def test_without_entra_and_without_an_owner_path_the_server_refuses_to_start(tmp_path: pathlib.Path) -> None:
    settings = settings_for(tmp_path)
    with pytest.raises(SelfhostConfigError) as info:
        prepare_selfhost(settings)
    (message,) = info.value.problems
    assert "no owner can be made" in message
    for needle in (
        "SELFHOST_LOGIN_PROVIDERS does not list entra", "SELFHOST_BOOTSTRAP_OWNER is unset",
        "the database has no active owner", "google:<subject>", "github:<numeric user id>",
        "oidc:<slug>:<subject>", "token_admin promote-owner ACCOUNT",
    ):
        assert needle in message, needle
    assert GOOGLE_SECRET not in message


@pytest.mark.parametrize("owner", ["google:1234567890", "token_admin"])
def test_a_named_bootstrap_owner_or_token_admin_is_an_owner_path(tmp_path: pathlib.Path, owner: str) -> None:
    runtime = prepare_selfhost(settings_for(tmp_path, SELFHOST_BOOTSTRAP_OWNER=owner))
    try:
        assert not runtime.settings.entra_enabled
        assert runtime.identity.claims_policy.tenant_id == ""
    finally:
        runtime.store.close()


def test_an_owner_already_in_the_database_is_an_owner_path(tmp_path: pathlib.Path) -> None:
    settings = settings_for(tmp_path, SELFHOST_BOOTSTRAP_OWNER="token_admin")
    first = prepare_selfhost(settings)
    key = make_account(first.store, OID_A)
    assert first.store.promote_owner(key, actor=OPERATOR)
    first.store.close()
    # Same database, no bootstrap setting any more: the existing owner is the path.
    again = prepare_selfhost(settings_for(tmp_path))
    assert again.store.count_active_owners() == 1
    again.store.close()


def test_an_owner_that_was_disabled_is_not_an_owner_path(tmp_path: pathlib.Path) -> None:
    settings = settings_for(tmp_path, SELFHOST_BOOTSTRAP_OWNER="token_admin")
    first = prepare_selfhost(settings)
    key = make_account(first.store, OID_A, role="owner")
    assert first.store.disable_principal(key, actor=OPERATOR, reason="operator_disabled", allow_last_owner=True)
    first.store.close()
    with pytest.raises(SelfhostConfigError):
        prepare_selfhost(settings_for(tmp_path))


def test_an_entra_deployment_needs_no_owner_path(tmp_path: pathlib.Path) -> None:
    runtime = prepare_selfhost(load_selfhost_settings(default_env(tmp_path)))
    runtime.store.close()


def test_other_providers_are_refused_under_entra_proxy(tmp_path: pathlib.Path) -> None:
    with pytest.raises(SelfhostConfigError) as info:
        load_selfhost_settings(
            default_env(
                tmp_path, SELFHOST_AUTH_MODE="entra_proxy", SELFHOST_LOGIN_PROVIDERS="entra,google",
                GOOGLE_CLIENT_ID=GOOGLE_ID, GOOGLE_CLIENT_SECRET=GOOGLE_SECRET,
            )
        )
    assert any("need SELFHOST_AUTH_MODE=local" in p for p in info.value.problems)
