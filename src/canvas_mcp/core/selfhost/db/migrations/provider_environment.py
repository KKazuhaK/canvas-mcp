"""Explicit pre-database provider configuration import, removable after adoption."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Mapping
from typing import TYPE_CHECKING

from ...login.config import ProviderSettingsInput, parse_login_providers
from ...settings import (
    DEFAULT_OWNER_ROLE,
    DEFAULT_REQUIRED_ROLE,
    SelfhostSettings,
    load_selfhost_settings,
)

MIN_CLIENT_SECRET_CHARS = 16
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_ROLE_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
_RESERVED_TENANTS = frozenset({"common", "organizations", "consumers"})


def _guid(name: str, raw: str, problems: list[str]) -> str:
    if not raw:
        problems.append(f"{name} is required (a GUID)")
        return ""
    if not _GUID_RE.match(raw):
        problems.append(
            f"{name} must be a GUID such as 00000000-0000-0000-0000-000000000000"
        )
        return ""
    return raw.lower()


if TYPE_CHECKING:
    from ...login.provider_store import ProviderConfigStore


def import_provider_settings(
    settings: SelfhostSettings, providers: ProviderConfigStore
) -> bool:
    """Atomic adoption of a deliberate old input; DB-owned rows always win."""
    from sqlalchemy import exists, select

    from .. import schema as s

    now = int(time.time())
    with providers.database.write() as conn:
        if conn.execute(
            select(
                exists(
                    select(s.login_providers.c.id).where(
                        s.login_providers.c.config_source == "db"
                    )
                )
            )
        ).scalar_one():
            return False
        if not settings.login_providers.order:
            return False
        providers.repos.providers.reconcile(
            conn, settings.login_providers.order, now=now
        )
        revision = int(
            conn.execute(select(s.server_state.c.settings_revision)).scalar_one()
        )
        for rank, identifier in enumerate(settings.login_providers.order):
            config: dict[str, object]
            if identifier == "entra":
                config = {
                    "tenant_id": settings.tenant_id,
                    "client_id": settings.client_id,
                    "required_role": settings.required_role,
                    "owner_role": settings.owner_role,
                }
                secret = settings.client_secret
            elif identifier == "google":
                value = settings.login_providers.google
                assert value is not None
                config = {"client_id": value.client_id}
                secret = value.client_secret
            elif identifier == "github":
                github = settings.login_providers.github
                assert github is not None
                config = {"client_id": github.client_id}
                secret = github.client_secret
            else:
                oidc = settings.login_providers.oidc_by_id()[identifier]
                config = {
                    "issuer": oidc.issuer,
                    "client_id": oidc.client_id,
                    "scopes": list(oidc.scopes),
                    "userinfo": oidc.userinfo,
                }
                if oidc.token_auth_method is not None:
                    config["token_auth_method"] = oidc.token_auth_method
                secret = oidc.client_secret
            revision = providers.save(
                identifier,
                config=config,
                client_secret=secret,
                enabled=True,
                rank=rank,
                revision=revision,
                actor=None,
                now=now,
                _connection=conn,
            )
        return True


def clear_unconfigured_metadata(providers: ProviderConfigStore) -> bool:
    """An old beta's empty startup metadata is not an installed login configuration."""
    from sqlalchemy import func, select, update

    from .. import schema as s

    with providers.database.write() as conn:
        rows = conn.execute(select(s.login_providers)).mappings().all()
        if not rows or any(
            row["config_source"] == "db"
            or row["config"] is not None
            or row["secret_ciphertext"] is not None
            for row in rows
        ):
            return False
        if any(
            conn.execute(select(func.count()).select_from(table)).scalar_one()
            for table in s.metadata.sorted_tables
            if table not in (s.server_state, s.login_providers)
        ):
            return False
        if not any(row["configured"] for row in rows):
            return False
        now = int(time.time())
        conn.execute(update(s.login_providers).values(configured=False, updated_at=now))
        conn.execute(
            update(s.server_state).values(
                settings_revision=s.server_state.c.settings_revision + 1, updated_at=now
            )
        )
        return True


def load_provider_environment(env: Mapping[str, str] | None = None) -> SelfhostSettings:
    """Validate a deliberate import; ordinary startup never reads these credentials."""
    source = os.environ if env is None else env

    def get(name: str) -> str:
        return (source.get(name) or "").strip()

    problems: list[str] = []
    login = parse_login_providers(source, problems)
    tenant = client = secret = ""
    required = get("ENTRA_REQUIRED_ROLE") or DEFAULT_REQUIRED_ROLE
    owner = get("ENTRA_OWNER_ROLE") or DEFAULT_OWNER_ROLE
    if login.entra_enabled:
        tenant_raw = get("ENTRA_TENANT_ID")
        if tenant_raw.lower() in _RESERVED_TENANTS:
            problems.append(
                "ENTRA_TENANT_ID must be the directory (tenant) GUID, not common, organizations or consumers"
            )
        else:
            tenant = _guid("ENTRA_TENANT_ID", tenant_raw, problems)
        client = _guid("ENTRA_CLIENT_ID", get("ENTRA_CLIENT_ID"), problems)
        secret = get("ENTRA_CLIENT_SECRET")
        if not secret:
            problems.append("ENTRA_CLIENT_SECRET is required")
        elif len(secret) < MIN_CLIENT_SECRET_CHARS:
            problems.append(
                f"ENTRA_CLIENT_SECRET must be at least {MIN_CLIENT_SECRET_CHARS} characters"
            )
        for name, value in (
            ("ENTRA_REQUIRED_ROLE", required),
            ("ENTRA_OWNER_ROLE", owner),
        ):
            if not _ROLE_RE.match(value):
                problems.append(
                    f"{name} must match [A-Za-z0-9._-] and be 1 to 120 characters"
                )
        if required == owner:
            problems.append(
                "ENTRA_REQUIRED_ROLE and ENTRA_OWNER_ROLE must be different roles"
            )
    return load_selfhost_settings(
        source,
        _provider_input=ProviderSettingsInput(
            login, tenant, client, secret, required, owner, tuple(problems)
        ),
    )
