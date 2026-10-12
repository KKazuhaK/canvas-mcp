"""Startup with and without Entra: the owner path, and what the settings keep out of reach."""

from __future__ import annotations

import pathlib

import pytest

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.accounts import ExternalClaims
from canvas_mcp.core.selfhost.app import prepare_selfhost
from canvas_mcp.core.selfhost.db.migrations.provider_environment import (
    load_provider_environment,
)
from canvas_mcp.core.selfhost.settings import (
    SelfhostConfigError,
)
from canvas_mcp.core.selfhost.token_store import OPERATOR

from ..authz.stack import default_env
from ..conftest import OID_A, acct_key, make_account, sign_in
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


def env_for(tmp_path: pathlib.Path, **env: str) -> dict[str, str]:
    """One environment for one database (on PostgreSQL, building it resets the shared schema)."""
    return default_env(tmp_path, **{**NO_ENTRA, **env})


def settings_for(tmp_path: pathlib.Path, **env: str):  # type: ignore[no-untyped-def]
    return load_provider_environment(env_for(tmp_path, **env))


def test_without_entra_and_without_an_owner_path_the_server_refuses_to_start(
    tmp_path: pathlib.Path,
) -> None:
    settings = settings_for(tmp_path)
    with pytest.raises(SelfhostConfigError) as info:
        prepare_selfhost(settings)
    (message,) = info.value.problems
    assert "no owner can be made" in message
    for needle in (
        "SELFHOST_LOGIN_PROVIDERS does not list entra",
        "SELFHOST_BOOTSTRAP_OWNER is unset",
        "the database has no active owner",
        "google:<subject>",
        "github:<numeric user id>",
        "oidc:<slug>:<subject>",
        "token_admin promote-owner ACCOUNT",
    ):
        assert needle in message, needle
    assert GOOGLE_SECRET not in message


@pytest.mark.parametrize("owner", ["google:1234567890", "token_admin"])
def test_a_named_bootstrap_owner_or_token_admin_is_an_owner_path(
    tmp_path: pathlib.Path, owner: str
) -> None:
    runtime = prepare_selfhost(settings_for(tmp_path, SELFHOST_BOOTSTRAP_OWNER=owner))
    try:
        assert not runtime.settings.entra_enabled
        assert runtime.identity.login_providers == frozenset({"google"})
    finally:
        runtime.store.close()


def google_owner(runtime, subject: str = "1234567890") -> str:  # type: ignore[no-untyped-def]
    """An active owner the operator made, whose only identity is a Google one."""
    return str(
        runtime.store.create_operator_account(
            provider_id="google",
            issuer=acc.GOOGLE_ISSUER,
            subject=subject,
            status="active",
            role="owner",
        )
    )


def test_an_owner_already_in_the_database_is_an_owner_path(
    tmp_path: pathlib.Path,
) -> None:
    env = env_for(tmp_path, SELFHOST_BOOTSTRAP_OWNER="token_admin")
    first = prepare_selfhost(load_provider_environment(env))
    google_owner(first)
    first.store.close()
    # Same database, no bootstrap setting any more: the existing owner is the path.
    again = prepare_selfhost(
        load_provider_environment({**env, "SELFHOST_BOOTSTRAP_OWNER": ""})
    )
    assert again.store.count_active_owners() == 1
    again.store.close()


def test_owners_who_can_no_longer_sign_in_are_not_an_owner_path(
    tmp_path: pathlib.Path,
) -> None:
    # A deployment that ran with Entra and drops it: its owner has only an Entra identity.
    env = env_for(tmp_path, SELFHOST_BOOTSTRAP_OWNER="token_admin")
    first = prepare_selfhost(load_provider_environment(env))
    key = make_account(first.store, OID_A, role="owner")
    assert first.store.count_active_owners() == 1
    first.store.close()
    with pytest.raises(SelfhostConfigError) as info:
        prepare_selfhost(
            load_provider_environment({**env, "SELFHOST_BOOTSTRAP_OWNER": ""})
        )
    (message,) = info.value.problems
    assert "no owner can sign in" in message and "promote-owner" in message
    assert "SELFHOST_BOOTSTRAP_OWNER" in message  # it names the other way out
    # The operator command is the way out, and token_admin as the bootstrap setting keeps the start.
    again = prepare_selfhost(load_provider_environment(env))
    google_owner(again, "99")
    again.store.close()
    ok = prepare_selfhost(
        load_provider_environment({**env, "SELFHOST_BOOTSTRAP_OWNER": ""})
    )
    assert ok.store.count_active_owners() == 2 and key
    ok.store.close()


def test_a_rules_owner_with_a_google_identity_is_not_an_owner_path(
    tmp_path: pathlib.Path,
) -> None:
    # Its role came from the Entra owner rule: no Google sign-in can give it an owner session.
    env = env_for(tmp_path, SELFHOST_BOOTSTRAP_OWNER="token_admin")
    first = prepare_selfhost(load_provider_environment(env))
    policy = acc.AccessPolicy(
        mode="rules",
        rules=(
            acc.AccessRule("entra", "role", "Canvas.User"),
            acc.AccessRule("google", "domain", "example.test"),
        ),
        owner_rules=(acc.AccessRule("entra", "role", "Canvas.Owner"),),
    )
    make_account(first.store, OID_A)
    sign_in(first.store, OID_A, owner=True, policy=policy)
    key = acct_key(OID_A)
    assert first.store.get_principal_status(key).role_source == "rules"
    ext = ExternalClaims(
        provider_id="google",
        issuer=acc.GOOGLE_ISSUER,
        subject="g-1",
        email="g@example.test",
        email_verified=True,
        hd="example.test",
    )
    assert first.store.link_identity(
        key,
        ext,
        acc.evaluate_admission(ext, policy),
        policy,
        expected_epoch=first.store.get_principal_status(key).session_epoch,
    ).ok
    assert first.store.count_usable_owners({"google"}) == 0
    first.store.close()
    with pytest.raises(SelfhostConfigError) as info:
        prepare_selfhost(
            load_provider_environment({**env, "SELFHOST_BOOTSTRAP_OWNER": ""})
        )
    assert "no owner can sign in" in info.value.problems[0]


def test_an_owner_that_was_disabled_is_not_an_owner_path(
    tmp_path: pathlib.Path,
) -> None:
    env = env_for(tmp_path, SELFHOST_BOOTSTRAP_OWNER="token_admin")
    first = prepare_selfhost(load_provider_environment(env))
    key = make_account(first.store, OID_A, role="owner")
    assert first.store.disable_principal(
        key, actor=OPERATOR, reason="operator_disabled", allow_last_owner=True
    )
    first.store.close()
    with pytest.raises(SelfhostConfigError):
        prepare_selfhost(
            load_provider_environment({**env, "SELFHOST_BOOTSTRAP_OWNER": ""})
        )


def test_an_entra_deployment_needs_no_owner_path(tmp_path: pathlib.Path) -> None:
    runtime = prepare_selfhost(load_provider_environment(default_env(tmp_path)))
    runtime.store.close()


def test_other_providers_are_refused_under_entra_proxy(tmp_path: pathlib.Path) -> None:
    with pytest.raises(SelfhostConfigError) as info:
        load_provider_environment(
            default_env(
                tmp_path,
                SELFHOST_AUTH_MODE="entra_proxy",
                SELFHOST_LOGIN_PROVIDERS="entra,google",
                GOOGLE_CLIENT_ID=GOOGLE_ID,
                GOOGLE_CLIENT_SECRET=GOOGLE_SECRET,
            )
        )
    assert any(
        p.startswith("SELFHOST_AUTH_MODE: removed in v1") for p in info.value.problems
    )


def test_a_named_bootstrap_owner_is_an_owner_path_beside_owners_nobody_can_use(
    tmp_path: pathlib.Path,
) -> None:
    # The bootstrap owner applies while there is no *usable* owner, so the start is allowed and
    # the first sign-in of that identity makes an owner (audited with the number it overrides).
    env = env_for(tmp_path, SELFHOST_BOOTSTRAP_OWNER="token_admin")
    first = prepare_selfhost(load_provider_environment(env))
    stranded = make_account(first.store, OID_A, role="owner")
    first.store.close()
    runtime = prepare_selfhost(
        load_provider_environment(
            {**env, "SELFHOST_BOOTSTRAP_OWNER": "google:1234567890"}
        )
    )
    try:
        assert runtime.store.count_active_owners() == 1
        assert (
            runtime.store.count_usable_owners(runtime.settings.login_providers.ids) == 0
        )
        ext = ExternalClaims(
            provider_id="google",
            issuer=acc.GOOGLE_ISSUER,
            subject="1234567890",
            email="b@example.edu",
            email_verified=True,
            hd="example.edu",
        )
        signed = runtime.identity.sign_in_external(ext)
        assert not isinstance(signed, acc.Denied) and signed.owner
        assert runtime.store.count_active_owners() == 2
        assert (
            runtime.store.count_usable_owners(runtime.settings.login_providers.ids) == 1
        )
        assert runtime.store.get_principal_status(stranded).is_owner
    finally:
        runtime.store.close()


def test_a_disabled_bootstrap_account_beside_unusable_owners_is_not_an_owner_path(
    tmp_path: pathlib.Path,
) -> None:
    # The bootstrap owner would make an owner at its next sign-in, but a disabled account is refused first.
    env = env_for(tmp_path, SELFHOST_BOOTSTRAP_OWNER="token_admin")
    first = prepare_selfhost(load_provider_environment(env))
    make_account(first.store, OID_A, role="owner")  # stranded: an Entra identity only
    boot = first.store.create_operator_account(
        provider_id="google",
        issuer=acc.GOOGLE_ISSUER,
        subject="1234567890",
        status="disabled",
        reason="operator_disabled",
    )
    first.store.close()
    named = {**env, "SELFHOST_BOOTSTRAP_OWNER": "google:1234567890"}
    with pytest.raises(SelfhostConfigError) as info:
        prepare_selfhost(load_provider_environment(named))
    (message,) = info.value.problems
    assert (
        "no owner can sign in" in message
        and "SELFHOST_BOOTSTRAP_OWNER is disabled" in message
    )
    assert "1234567890" not in message
    # Enabling the account restores the path.
    again = prepare_selfhost(load_provider_environment(env))
    assert again.store.enable_principal(boot, actor=OPERATOR)
    again.store.close()
    ok = prepare_selfhost(load_provider_environment(named))
    ok.store.close()
