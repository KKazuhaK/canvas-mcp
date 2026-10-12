"""Startup validation and wiring of the self-hosted authorization server."""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from fastmcp import FastMCP
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp

from ..config import Config
from ..logging import log_info
from ..token_health import set_token_health_monitor
from .accounts import STATUS_DISABLED, EntraClaimsPolicy, bootstrap_sign_in_gives_owner
from .identity import IdentityService
from .limits import RateLimiters, build_rate_limiters
from .settings import SelfhostConfigError, SelfhostSettings
from .token_health import TokenHealth
from .tool_gate import SelfhostCredentialGate
from .tool_prefs import ToolPrefsCache, WriteToolCatalog

if TYPE_CHECKING:
    from ..tool_policy import ToolPolicy
    from .authz.runtime import AuthzRuntime
    from .config_snapshot import ConfigSnapshots
    from .login.installation import InstallationAuthority
    from .login.provider_store import ProviderConfigStore
    from .token_store import TokenStore

HEALTH_PATH = "/healthz"

SSRF_TRUST_PROXY_ENV = "FASTMCP_SSRF_TRUST_PROXY"
_FALSE_WORDS = frozenset({"", "0", "false", "f", "no", "n", "off"})


@dataclass(frozen=True)
class SelfhostRuntime:
    """Runtime services and immutable environment settings.

    MCP standing comes from one request snapshot. Only versioned preferences
    and best-effort usage bookkeeping are cached.
    """

    settings: SelfhostSettings
    store: TokenStore
    identity: IdentityService
    health: TokenHealth
    tool_prefs: ToolPrefsCache
    authz: AuthzRuntime
    snapshots: ConfigSnapshots
    provider_store: ProviderConfigStore | None = None
    installation: InstallationAuthority | None = None
    limiters: RateLimiters = field(
        default_factory=lambda: build_rate_limiters("memory")
    )


def _writable_directory_problem(name: str, path: Path) -> str | None:
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        return f"{name} cannot be created"
    if not path.is_dir() or not os.access(path, os.W_OK):
        return f"{name} is not a writable directory"
    return None


def _ssrf_trust_proxy_enabled() -> bool:
    """True when FastMCP's SSRF checks are switched to "trust the outbound proxy".

    FastMCP fetches OAuth client metadata (CIMD) and the JWKS through its own
    SSRF guard, which resolves the name and refuses private, loopback and
    link-local addresses. ``FASTMCP_SSRF_TRUST_PROXY`` hands that job to an
    outbound proxy and turns the address checks off. Any value except an
    explicit false word counts as on, and the effective FastMCP setting is
    checked as well as the environment, so an unparsable or unusual spelling
    can never leave the guard disabled without the server noticing.
    """
    raw = os.environ.get(SSRF_TRUST_PROXY_ENV, "").strip().lower()
    if raw not in _FALSE_WORDS:
        return True
    from fastmcp import settings as fastmcp_settings

    return bool(getattr(fastmcp_settings, "ssrf_trust_proxy", False))


def validate_selfhost_startup(config: Config, settings: SelfhostSettings) -> list[str]:
    """Every reason the server must refuse to start in this mode (empty = fine).

    Messages name settings and never include their values.
    """
    problems: list[str] = []

    if config.canvas_api_token:
        problems.append(
            "CANVAS_API_TOKEN must NOT be set: every user brings their own Canvas "
            "token, and a server token could be used by mistake"
        )
    if config.mcp_access_keys:
        problems.append("MCP_ACCESS_KEYS must not be set in this mode")
    if config.entra_auth_enabled:
        problems.append(
            "ENTRA_AUTH_ENABLED must not be set: the Easy Auth header path is "
            "spoofable off Azure and is never consulted in this mode"
        )
    if config.mcp_allow_unauthenticated:
        problems.append("MCP_ALLOW_UNAUTHENTICATED must not be set in this mode")
    if config.access_request_enabled:
        problems.append("ACCESS_REQUEST_ENABLED must not be set in this mode")

    if _ssrf_trust_proxy_enabled():
        problems.append(
            f"{SSRF_TRUST_PROXY_ENV} must not be set in this mode: it turns off "
            "FastMCP's DNS and private-address checks on the OAuth client metadata "
            "and key fetches that unauthenticated clients can trigger, and leaves "
            "that protection to an outbound proxy this server cannot verify"
        )

    allowed = {
        part.strip().lower()
        for part in (config.allowed_write_tools or "").replace(",", " ").split()
        if part.strip()
    }
    if config.execute_typescript_enabled or "execute_typescript" in allowed:
        problems.append(
            "EXECUTE_TYPESCRIPT_ENABLED must be false and ALLOWED_WRITE_TOOLS must "
            "not name execute_typescript: code execution would run with users' "
            "tokens on the shared host"
        )

    if settings.profile == "pilot":
        if config.allowed_write_tools:
            problems.append(
                "SELFHOST_PROFILE=pilot requires ALLOWED_WRITE_TOOLS to be unset"
            )
        if settings.course_state != "request_local":
            problems.append(
                "SELFHOST_PROFILE=pilot requires SELFHOST_COURSE_STATE=request_local"
            )

    problem = _writable_directory_problem("SELFHOST_DATA_DIR", settings.data_dir)
    if problem:
        problems.append(problem)

    return problems


def _data_layer_problem(settings: SelfhostSettings) -> str | None:
    """A startup problem if the data layer's optional packages are not installed."""
    from .db.migrations import dependencies_available

    if not dependencies_available():
        return (
            "the self-hosted mode needs SQLAlchemy and Alembic: "
            "pip install 'canvas-mcp[selfhost]' (the container image includes them)"
        )
    if settings.database_target.kind == "postgresql":
        try:
            import psycopg  # noqa: F401
        except ImportError:
            return (
                "DATABASE_URL names PostgreSQL, which needs the psycopg driver: "
                "pip install 'canvas-mcp[postgres]' (the container image includes it)"
            )
    return None


def _provider_issuer_problems(
    settings: SelfhostSettings, store: TokenStore
) -> list[str]:
    """A provider id with enrolled identities cannot be rebound to another issuer.

    Owner guards deliberately operate on provider ids. Keep that id bound to its issuer
    so an old identity cannot count as reachable when the configured IdP cannot emit it.
    """
    from .login.config import env_prefix

    configured = settings.login_providers.issuers()
    if not configured:
        return []
    changed = {
        identity.provider_id
        for account in store.iter_accounts()
        for identity in account.identities
        if identity.provider_id in configured
        and identity.issuer != configured[identity.provider_id]
    }
    return [
        f"{env_prefix(provider.removeprefix('oidc:'))}ISSUER cannot change for a provider "
        "with stored identities; use a new slug, link it to an owner, and then delist the old one"
        for provider in sorted(changed)
    ]


def _owner_path_problem(settings: SelfhostSettings, store: TokenStore) -> str | None:
    """Without Entra nobody can become an owner through the identity provider's data.

    An owner then needs ``SELFHOST_BOOTSTRAP_OWNER`` (a provider identity, or ``token_admin`` to
    promote the first owner with the operator command) or a *usable owner* the database already
    holds: an active owner with an identity at a listed provider whose role the rules did not
    grant (a role from ``OWNER_RULES`` needs the Entra sign-in that carried it, so it is not
    usable while Entra is not listed). The bootstrap owner applies while there is no usable
    owner, so it also covers a database whose owners are all unusable. Otherwise the server
    would start and nobody could ever open ``/account/admin``.
    """
    if settings.entra_enabled:
        return None
    policy = settings.access_policy
    if policy.bootstrap_via_token_admin:
        return None
    if store.count_usable_owners(settings.login_providers.ids) > 0:
        return None
    boot = policy.bootstrap_owner
    if boot is not None:
        # The bootstrap identity makes an owner at its next sign-in, and that sign-in is asked
        # the same table the server uses (accounts.decide): a new or pending account becomes
        # the owner, an active one is admitted whatever the rules say and, when it is an owner
        # no sign-in could use, re-sourced to bootstrap. Only an account the table refuses
        # (a disabled one) leaves the server without an owner path.
        key = store.lookup_identity(boot.provider_id, boot.issuer, boot.subject)
        if key is None:
            return None
        status = store.get_principal_status(key)
        if bootstrap_sign_in_gives_owner(
            status.facts, policy, active_owner_count=store.count_active_owners()
        ):
            return None
        if status.status == STATUS_DISABLED:
            return (
                "no owner can sign in: the account of SELFHOST_BOOTSTRAP_OWNER is disabled and "
                "no other usable owner exists; enable it with: "
                "python -m canvas_mcp.core.selfhost.token_admin enable ACCOUNT, or make another "
                "account an owner with: python -m canvas_mcp.core.selfhost.token_admin "
                "promote-owner ACCOUNT"
            )
        return (
            "no owner can sign in: signing in as SELFHOST_BOOTSTRAP_OWNER would not give an owner "
            f"session (its account is {status.status}) and no other usable owner exists; make "
            "another account an owner with: python -m canvas_mcp.core.selfhost.token_admin "
            "promote-owner ACCOUNT"
        )
    stranded = store.count_active_owners()
    if stranded > 0:
        return (
            "no owner can sign in: SELFHOST_LOGIN_PROVIDERS does not list entra and every active "
            f"owner in the database ({stranded}) either has no identity at a listed provider or "
            "holds a role the Entra owner rule granted, which only an Entra sign-in can use; "
            "list entra again, set SELFHOST_BOOTSTRAP_OWNER to a listed provider's identity "
            "(it applies while no owner can sign in), or make another account an owner with: "
            "python -m canvas_mcp.core.selfhost.token_admin promote-owner ACCOUNT"
        )
    return (
        "no owner can be made: SELFHOST_LOGIN_PROVIDERS does not list entra, "
        "SELFHOST_BOOTSTRAP_OWNER is unset and the database has no active owner; set "
        "SELFHOST_BOOTSTRAP_OWNER to the first owner's identity (google:<subject>, "
        "github:<numeric user id> or oidc:<slug>:<subject>), or to token_admin and then run: "
        "python -m canvas_mcp.core.selfhost.token_admin promote-owner ACCOUNT"
    )


def prepare_selfhost(settings: SelfhostSettings) -> SelfhostRuntime:
    """Open the encrypted token store and build the identity service.

    Schema checks and upgrades are delegated to ``db.migrations``. Pre-v1
    databases are refused; pending v1 revisions require automatic migration or
    an explicit operator upgrade.

    Raises :class:`SelfhostConfigError` when the keyring or the store is
    unusable (a key id missing, a wrong key, an unreadable or newer database,
    a database without data next to a SQLite file that has data).
    """
    from .token_store import (
        Keyring,
        KeyringError,
        StoreUnavailable,
        TokenStore,
        TokenStoreError,
    )

    missing = _data_layer_problem(settings)
    if missing:
        raise SelfhostConfigError([missing])

    from .db.migrations.transfer import refuse_silent_switch

    try:
        keyring = Keyring.parse(settings.canvas_token_keys_raw)
        store = TokenStore.for_target(settings.database_target, keyring)
        refuse_silent_switch(store.database, settings.token_db_path)
        store.initialize(auto_migrate=settings.auto_migrate)
    except StoreUnavailable as exc:
        # A corrupt file, not a database, locked, a failing disk, or an unreachable
        # server. The driver's message is left out: it can quote paths, SQL or the URL.
        # ``kind`` is only a driver exception class name, safe for the operator's log.
        if exc.kind == "BackupFailed":
            # The automatic backup before a schema upgrade failed (disk full, directory
            # not writable): the upgrade was refused and nothing was changed.
            raise SelfhostConfigError(
                [
                    "the Canvas token database schema upgrade did not run and nothing was "
                    "changed: the automatic backup failed (check free disk space and that the "
                    "database directory is writable; token_admin db upgrade --dry-run shows "
                    "what would run)"
                ]
            ) from None
        detail = f" ({exc.kind})" if exc.kind else ""
        raise SelfhostConfigError(
            [
                f"the Canvas token database cannot be opened or is not a valid database{detail}"
            ]
        ) from None
    except (TokenStoreError, KeyringError) as exc:
        raise SelfhostConfigError([str(exc)]) from None
    except OSError:
        raise SelfhostConfigError(
            ["the Canvas token database cannot be opened"]
        ) from None

    # token_admin reads this to know which owners are usable (it often runs without the
    # server's variables). It is the configured list, so it is written before the owner-path
    # check: when that refuses the start, the operator's next step is a token_admin command,
    # and it must judge owners by the list that was refused, not by an older one. An
    # Entra-only server with no earlier record writes nothing.
    from .login.provider_config import ProviderConfigurationError

    try:
        issuer_problems = _provider_issuer_problems(settings, store)
        if issuer_problems:
            raise SelfhostConfigError(issuer_problems)
        from .db.migrations.provider_environment import (
            clear_unconfigured_metadata,
            import_provider_settings,
        )
        from .login.installation import InstallationAuthority
        from .login.provider_settings import settings_from_database
        from .login.provider_store import ProviderConfigStore

        provider_store = ProviderConfigStore(
            store.database,
            keyring,
            validate=partial(settings_from_database, settings),
        )
        if settings.login_providers.order:
            import_provider_settings(settings, provider_store)
        else:
            clear_unconfigured_metadata(provider_store)
        settings = settings_from_database(settings, provider_store.load_snapshot())
        from .config_snapshot import ConfigSnapshots

        snapshots = ConfigSnapshots(store.database, None)
        if settings.profile == "pilot":
            from .profile import PilotProfileViolation

            try:
                snapshots.enable_pilot()
            except PilotProfileViolation as exc:
                raise SelfhostConfigError([str(exc)]) from None
        installation = InstallationAuthority(provider_store, settings.data_dir)
        owner_problem = (
            None
            if provider_store.setup_available()
            else _owner_path_problem(settings, store)
        )
    except ProviderConfigurationError:
        store.close()
        raise SelfhostConfigError(
            [
                "database-managed login configuration cannot be loaded; restore its original keys or explicitly import the previous provider configuration"
            ]
        ) from None
    except StoreUnavailable:
        store.close()
        raise SelfhostConfigError(
            [
                "database-managed settings cannot be loaded; check stored values and featured-school DNS with token_admin"
            ]
        ) from None
    except BaseException:
        store.close()
        raise
    if owner_problem is not None:
        store.close()
        raise SelfhostConfigError([owner_problem])

    identity = IdentityService(
        store,
        EntraClaimsPolicy(tenant_id=settings.tenant_id, client_id=settings.client_id),
        settings.access_policy,
        login_providers=settings.login_providers.ids,
    )
    health = TokenHealth(store, account_url=settings.account_url)
    from .authz.runtime import build_authz_runtime

    authz = build_authz_runtime(settings, store, keyring)
    return SelfhostRuntime(
        settings=settings,
        store=store,
        identity=identity,
        health=health,
        tool_prefs=ToolPrefsCache(store),
        limiters=build_rate_limiters(settings.state_backend),
        authz=authz,
        snapshots=snapshots,
        provider_store=provider_store,
        installation=installation,
    )


async def apply_disabled_tools(mcp: FastMCP, names: Collection[str]) -> list[str]:
    """Remove the tools the operator named in ``SELFHOST_DISABLED_TOOLS``.

    Runs once at startup, after registration and ``apply_tool_policy``. It only
    removes: a name that is not registered (a tool of another role profile, or one
    ``ALLOWED_WRITE_TOOLS`` already removed) is skipped, and nothing is ever added.
    A removed tool is neither listed nor callable. Returns the removed names, sorted.
    """
    wanted = set(names)
    if not wanted:
        return []
    removed: list[str] = []
    for tool in await mcp.list_tools(run_middleware=False):
        if tool.name in wanted:
            mcp.local_provider.remove_tool(tool.name)
            removed.append(tool.name)
    return sorted(removed)


def load_account_spa(settings: SelfhostSettings) -> Any:
    """Load the required React bundle; a missing or invalid build refuses startup."""
    from .account_spa import SpaBundle, SpaBundleError

    try:
        return SpaBundle.load(settings.account_web_dist)
    except SpaBundleError as exc:
        raise SelfhostConfigError(
            [f"ACCOUNT_WEB_DIST must contain a valid built account UI ({exc.reason})"]
        ) from None


def install_selfhost(
    mcp: FastMCP,
    runtime: SelfhostRuntime,
    config: Config,
    *,
    tool_policy: ToolPolicy | None = None,
    **account_options: Any,
) -> Literal["react"]:
    """Add the credential gate, the /account pages and /healthz to the server.

    ``tool_policy`` is the operator's resolved ``ALLOWED_WRITE_TOOLS``: the server
    ceiling for the per-user write-tool switches. Without one (tests) the set of
    registered tools is the ceiling. ``account_options`` are passed to the account
    routes (tests inject the school directory, the host resolver and the HTTP
    client factory there).

    The required React bundle is loaded before any routes are registered.
    """
    from .account_core import AccountConfig, register_account_routes

    settings = runtime.settings
    spa = load_account_spa(settings)
    if runtime.installation is not None:
        code = runtime.installation.issue()
        if code is not None:
            print(f"Setup URL: {settings.public_base_url}/account/setup", flush=True)
            print(f"Installation code (expires in 30 minutes): {code}", flush=True)
    from .. import course_files

    course_files.ALLOW_OFF_CANVAS_DOWNLOADS = settings.profile != "pilot"
    from .login.registry import build_login_runtime

    login_transport = account_options.pop("login_transport", None)
    logins = build_login_runtime(
        settings,
        flow_store=runtime.authz.txns,
        clock=account_options.get("clock") or time.time,
        rate_limiters=runtime.limiters,
        transport=login_transport,
        snapshots=runtime.snapshots,
    )
    ceiling = (
        tool_policy.allowed
        if tool_policy is not None and tool_policy.enforced
        else None
    )

    async def registered_tool_names() -> list[str]:
        return [tool.name for tool in await mcp.list_tools(run_middleware=False)]

    mcp.add_middleware(
        SelfhostCredentialGate(
            account_url=settings.account_url,
            write_ceiling=ceiling,
        )
    )
    # The Canvas client confirms a suspected dead token through this service.
    set_token_health_monitor(runtime.health)

    register_account_routes(
        mcp,
        AccountConfig(
            public_base_url=settings.public_base_url,
            session_secret=settings.account_session_secret,
            session_ttl_seconds=settings.account_session_ttl_seconds,
        ),
        runtime.store,
        runtime.identity,
        health=runtime.health,
        write_tools=WriteToolCatalog(
            ceiling=ceiling, list_registered=registered_tool_names
        ),
        tool_prefs=runtime.tool_prefs,
        **{
            "rate_limiters": runtime.limiters,
            "spa": spa,
            "authz": runtime.authz,
            "logins": logins,
            "snapshots": runtime.snapshots,
            "provider_store": runtime.provider_store,
            "installation": runtime.installation,
            "infrastructure": settings,
            **account_options,
        },
    )

    @mcp.custom_route(HEALTH_PATH, methods=["GET"])
    async def healthz(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok", headers={"Cache-Control": "no-store"})

    log_info("Account UI: built single-page app", account_ui="react")
    return "react"


def build_selfhost_asgi_app(
    mcp: FastMCP,
    runtime: SelfhostRuntime,
    config: Config,
    *,
    clock: Callable[[], float] | None = None,
) -> ASGIApp:
    """The HTTP app: stateless MCP behind OAuth, plus host and origin protection.

    The request-context middleware runs inside FastMCP's authentication, so it
    sees the outcome of bearer verification in ``scope['user']``. Around all of
    it, :class:`SelfhostEdgeGuard` pins the request scheme to https, rate-limits
    the unauthenticated OAuth endpoints and cleans expired OAuth records.
    """
    settings = runtime.settings
    from .edge_guard import SelfhostEdgeGuard
    from .maintenance import MaintenanceRunner
    from .request_context import LocalClaimsResolver, SelfhostRequestContextMiddleware

    identity = LocalClaimsResolver(runtime.authz.issuer)
    app = mcp.http_app(
        stateless_http=True,
        middleware=[
            Middleware(
                SelfhostRequestContextMiddleware,
                mcp_path=settings.mcp_path,
                identity=identity,
                store=runtime.store,
                snapshots=runtime.snapshots,
                account_url=settings.account_url,
                health=runtime.health,
                tool_prefs=runtime.tool_prefs,
                touch_grant=runtime.authz.store.touch_grant,
                clock=runtime.authz.clock,
                course_state=settings.course_state,
            )
        ],
        host_origin_protection=True,
        allowed_hosts=[settings.public_host],
        allowed_origins=[settings.public_base_url],
    )

    runner = MaintenanceRunner(
        runtime.store.database,
        cimd_stale_max=settings.authz.cimd_stale_max,
        now=runtime.authz.clock,
    )

    async def maintenance() -> None:
        await runner.run()

    return SelfhostEdgeGuard(
        app,
        clock=clock or time.monotonic,
        maintenance=maintenance,
        rate_limiters=runtime.limiters,
    )
