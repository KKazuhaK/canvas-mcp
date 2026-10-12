"""Build protocol settings from a single decrypted database snapshot."""

from __future__ import annotations

from dataclasses import replace

from ..accounts import AccessRule
from ..settings import SelfhostSettings
from .config import GitHubConfig, GoogleConfig, LoginProvidersConfig, OidcConfig
from .provider_config import ProviderConfigurationError
from .provider_store import ProviderSnapshot


def settings_from_database(
    infrastructure: SelfhostSettings, snapshot: ProviderSnapshot
) -> SelfhostSettings:
    """Database values replace every provider credential from the input object."""
    google = None
    github = None
    oidc = []
    tenant = client = secret = ""
    required = "Canvas.User"
    owner = "Canvas.Owner"
    for provider in snapshot.providers:
        values = provider.config
        if provider.client_secret is None:
            raise ProviderConfigurationError("provider_configuration_unavailable")
        if provider.id == "entra":
            tenant = str(values["tenant_id"])
            client = str(values["client_id"])
            secret = provider.client_secret
            required = str(values["required_role"])
            owner = str(values["owner_role"])
        elif provider.id == "google":
            google = GoogleConfig(str(values["client_id"]), provider.client_secret)
        elif provider.id == "github":
            github = GitHubConfig(str(values["client_id"]), provider.client_secret)
        else:
            oidc.append(
                OidcConfig(
                    slug=provider.id.removeprefix("oidc:"),
                    issuer=str(values["issuer"]),
                    client_id=str(values["client_id"]),
                    client_secret=provider.client_secret,
                    scopes=tuple(values["scopes"]),
                    token_auth_method=values.get("token_auth_method"),
                    userinfo=values["userinfo"],
                )
            )
    policy = infrastructure.access_policy
    # Preserve custom admission rules. The default Entra role names follow the
    # database registration, rather than a stale environment credential object.
    rules = tuple(
        AccessRule("entra", "role", required)
        if rule == AccessRule("entra", "role", infrastructure.required_role)
        else rule
        for rule in policy.rules
    )
    owner_rules = tuple(
        AccessRule("entra", "role", owner)
        if rule == AccessRule("entra", "role", infrastructure.owner_role)
        else rule
        for rule in policy.owner_rules
    )
    return replace(
        infrastructure,
        tenant_id=tenant,
        client_id=client,
        client_secret=secret,
        required_role=required,
        owner_role=owner,
        access_policy=replace(policy, rules=rules, owner_rules=owner_rules),
        login_providers=LoginProvidersConfig(
            order=tuple(provider.id for provider in snapshot.providers),
            google=google,
            github=github,
            oidc=tuple(oidc),
        ),
    )
