"""Explicit pre-database provider configuration import, removable after adoption."""

from __future__ import annotations

import contextlib
import os
import re
import sys
import time
from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING

from ... import accounts as acc
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
    from ...token_store import TokenStore


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
        providers.validate_in(conn)
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


def _protected_provider_lists(store: TokenStore) -> tuple[frozenset[str], ...]:
    """Preserve an owner under each real list, not only their intersection.

    The recorded and operator lists can have different owners and no owner under their
    intersection. Each guard runs inside the mutation's writer transaction.
    """
    recorded = store.recorded_login_providers()
    if not (os.environ.get("SELFHOST_LOGIN_PROVIDERS") or "").strip():
        return (recorded,)
    from_env = _environment_providers()
    if from_env is None or from_env == recorded:
        return (recorded,)
    return (recorded, from_env)


def _listed_providers(store: TokenStore) -> frozenset[str] | None:
    """Use the database's configured provider inventory for owner governance.

    An unreadable or absent operator environment cannot invent providers. When
    an explicit environment differs, promotion recovery uses its intersection
    with the inventory, or the inventory if they are disjoint. Disable and
    unlink separately preserve an owner under each real list in their writer
    transaction. Startup reconciles the inventory before checking owner access.
    """
    from canvas_mcp.core.selfhost.login.config import LOGIN_PROVIDERS_ENV

    recorded = store.recorded_login_providers()
    named = bool((os.environ.get(LOGIN_PROVIDERS_ENV) or "").strip())
    if not named:
        return recorded
    from_env = _environment_providers()
    if from_env is None or from_env == recorded:
        return recorded
    both = recorded & from_env
    print(
        f"note: {LOGIN_PROVIDERS_ENV} differs from the configured providers in the database; "
        "disable and unlink preserve an owner under each list",
        file=sys.stderr,
    )
    return both or recorded


def _environment_providers() -> frozenset[str] | None:
    """The provider ids this environment's settings name; None when they cannot be read."""
    from canvas_mcp.core.selfhost.login.config import (
        LOGIN_PROVIDERS_ENV,
        parse_login_providers,
    )
    from canvas_mcp.core.selfhost.settings import (
        SelfhostConfigError,
    )

    try:
        with _quiet_login_config():
            return load_provider_environment().login_providers.ids
    except SelfhostConfigError:
        pass
    ignored: list[str] = []
    try:
        # authz_mode "local": the mode of the other settings is not known here, and this reads
        # the list alone.
        with _quiet_login_config():
            ids = parse_login_providers(os.environ, ignored).ids
    except Exception:  # noqa: BLE001 - an unreadable list is reported by the caller
        return None
    if ids and not any(p.startswith(LOGIN_PROVIDERS_ENV) for p in ignored):
        return ids
    return None


def _note_assumed_entra_only(store: TokenStore) -> None:
    """Tell the operator when Entra alone is assumed for a database that holds other providers."""
    others = sorted(
        {
            identity.provider_id
            for account in store.iter_accounts()
            for identity in account.identities
            if identity.provider_id != acc.PROVIDER_ENTRA
        }
    )
    if others:
        print(
            "note: the server has not recorded its SELFHOST_LOGIN_PROVIDERS and this environment "
            f"does not set it, so only entra is assumed to be listed, but the database holds "
            f"sign-in methods at {', '.join(others[:5])}; run this command with the server's "
            "environment (or start the server once) so the usable-owner check matches it",
            file=sys.stderr,
        )


@contextlib.contextmanager
def _quiet_login_config() -> Iterator[None]:
    """Keep the stray-provider-variable warnings of the settings parser out of this command.

    ``GOOGLE_CLIENT_ID`` and the like, set while ``SELFHOST_LOGIN_PROVIDERS`` is not, are ignored
    and logged as a warning where the server starts; here they would only add noise to a command
    whose output people and scripts read. Nothing else the logger says is touched.
    """
    import logging

    from canvas_mcp.core.selfhost.login import config as login_config

    class _Stray(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return not (
                record.levelno == logging.WARNING
                and "is unset: it is ignored" in record.getMessage()
            )

    stray = _Stray()
    login_config.logger.addFilter(stray)
    try:
        yield
    finally:
        login_config.logger.removeFilter(stray)
