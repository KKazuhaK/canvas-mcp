"""Startup validation and wiring of the self-hosted Entra OAuth mode."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from fastmcp import FastMCP
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp

from ..config import Config, validate_canvas_url_scheme
from ..token_health import set_token_health_monitor
from .edge_guard import SelfhostEdgeGuard
from .identity import ClaimsPolicy, authorize_id_token_claims
from .limits import RateLimiters, build_rate_limiters
from .oauth import cull_expired_oauth_state
from .principal_access import PrincipalAccessCache
from .request_context import SelfhostRequestContextMiddleware
from .schools import SchoolPolicy, is_blocked_hostname
from .settings import SelfhostConfigError, SelfhostSettings
from .token_health import TokenHealth
from .tool_gate import SelfhostCredentialGate
from .tool_prefs import ToolPrefsCache, WriteToolCatalog

if TYPE_CHECKING:
    from ..tool_policy import ToolPolicy
    from .token_store import TokenStore

HEALTH_PATH = "/healthz"

SSRF_TRUST_PROXY_ENV = "FASTMCP_SSRF_TRUST_PROXY"
_FALSE_WORDS = frozenset({"", "0", "false", "f", "no", "n", "off"})


@dataclass(frozen=True)
class SelfhostRuntime:
    """What the running server shares: settings, token store, claim policy, token health.

    ``tool_prefs`` caches each user's write-tool switches for the MCP side; the
    account page drops a user's entry when they change a switch. ``access`` caches
    whether each principal is allowed to use the server at all; the account page
    drops an entry when an owner disables or enables a user.
    """

    settings: SelfhostSettings
    store: TokenStore
    policy: ClaimsPolicy
    health: TokenHealth
    tool_prefs: ToolPrefsCache
    access: PrincipalAccessCache
    limiters: RateLimiters = field(default_factory=lambda: build_rate_limiters("memory"))


def _writable_directory_problem(name: str, path: Path) -> str | None:
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        return f"{name} cannot be created"
    if not path.is_dir() or not os.access(path, os.W_OK):
        return f"{name} is not a writable directory"
    return None


def selfhost_school_policy(settings: SelfhostSettings, config: Config) -> SchoolPolicy:
    """The schools this server offers: ``CANVAS_API_URL`` plus the featured list.

    Deterministic and free of I/O, so the account pages and the request
    middleware always agree.
    """
    return SchoolPolicy.build(
        getattr(config, "canvas_api_url", "") or "",
        settings.featured_schools,
        settings.school_search,
    )


def _school_problems(config: Config, settings: SelfhostSettings) -> list[str]:
    """Startup problems with the Canvas schools. Values are never included."""
    problems: list[str] = []
    default_host = ""
    if config.canvas_api_url:
        if not validate_canvas_url_scheme():
            problems.append("CANVAS_API_URL must use https")
        try:
            default_host = (urlsplit(config.canvas_api_url).hostname or "").lower()
        except ValueError:
            default_host = ""
        if not default_host:
            problems.append("CANVAS_API_URL must include a host name")
    elif not settings.featured_schools and not settings.school_search:
        problems.append(
            "CANVAS_API_URL is required unless CANVAS_FEATURED_SCHOOLS or "
            "CANVAS_SCHOOL_SEARCH=true is set"
        )
    for index, school in enumerate(settings.featured_schools, start=1):
        # The default school is the operator's own pin and keeps its exemption.
        if school.host != default_host and is_blocked_hostname(school.host):
            problems.append(
                f"CANVAS_FEATURED_SCHOOLS entry {index} is not a public address "
                "(local and internal names are refused)"
            )
    return problems


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

    problems.extend(_school_problems(config, settings))

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

    for name, path in (
        ("FASTMCP_HOME", settings.fastmcp_home),
        ("SELFHOST_DATA_DIR", settings.data_dir),
    ):
        problem = _writable_directory_problem(name, path)
        if problem:
            problems.append(problem)

    env_home = os.environ.get("FASTMCP_HOME", "")
    if not env_home or Path(env_home) != settings.fastmcp_home:
        problems.append("FASTMCP_HOME must be set in the process environment")
    else:
        from fastmcp import settings as fastmcp_settings

        if Path(str(fastmcp_settings.home)) != settings.fastmcp_home:
            problems.append(
                "FASTMCP_HOME was not in the process environment when FastMCP "
                "started (a .env file is read too late); set it in the "
                "environment so the OAuth state is stored under it"
            )

    return problems


def _data_layer_problem(settings: SelfhostSettings) -> str | None:
    """A startup problem if the data layer's optional packages are not installed."""
    try:
        import alembic  # noqa: F401
        import sqlalchemy  # noqa: F401
    except ImportError:
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


def prepare_selfhost(settings: SelfhostSettings) -> SelfhostRuntime:
    """Open the encrypted token store and build the claim policy.

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

    from .db.transfer import refuse_silent_switch

    try:
        keyring = Keyring.parse(settings.canvas_token_keys_raw)
        store = TokenStore.for_target(settings.database_target, keyring)
        refuse_silent_switch(store.database, settings.token_db_path)
        store.initialize(auto_migrate=settings.auto_migrate)
    except StoreUnavailable:
        # A corrupt file, not a database, locked, a failing disk, or an unreachable
        # server. The driver's message is left out: it can quote paths, SQL or the URL.
        raise SelfhostConfigError(
            ["the Canvas token database cannot be opened or is not a valid database"]
        ) from None
    except (TokenStoreError, KeyringError) as exc:
        raise SelfhostConfigError([str(exc)]) from None
    except OSError:
        raise SelfhostConfigError(["the Canvas token database cannot be opened"]) from None

    policy = ClaimsPolicy(
        tenant_id=settings.tenant_id,
        client_id=settings.client_id,
        required_role=settings.required_role,
        owner_role=settings.owner_role,
    )
    health = TokenHealth(store, account_url=settings.account_url)
    return SelfhostRuntime(
        settings=settings,
        store=store,
        policy=policy,
        health=health,
        tool_prefs=ToolPrefsCache(store),
        access=PrincipalAccessCache(store),
        limiters=build_rate_limiters(settings.state_backend),
    )


def install_selfhost(
    mcp: FastMCP,
    runtime: SelfhostRuntime,
    config: Config,
    *,
    tool_policy: ToolPolicy | None = None,
    **account_options: Any,
) -> None:
    """Add the credential gate, the /account pages and /healthz to the server.

    ``tool_policy`` is the operator's resolved ``ALLOWED_WRITE_TOOLS``: the server
    ceiling for the per-user write-tool switches. Without one (tests) the set of
    registered tools is the ceiling. ``account_options`` are passed to the account
    routes (tests inject the school directory, the host resolver and the HTTP
    client factory there).
    """
    from .account_web import AccountConfig, register_account_routes

    settings = runtime.settings
    ceiling = tool_policy.allowed if tool_policy is not None and tool_policy.enforced else None

    async def registered_tool_names() -> list[str]:
        return [tool.name for tool in await mcp.list_tools(run_middleware=False)]

    mcp.add_middleware(
        SelfhostCredentialGate(
            account_url=settings.account_url,
            write_ceiling=ceiling,
            access=runtime.access,
        )
    )
    # The Canvas client confirms a suspected dead token through this service.
    set_token_health_monitor(runtime.health)

    register_account_routes(
        mcp,
        AccountConfig(
            public_base_url=settings.public_base_url,
            tenant_id=settings.tenant_id,
            client_id=settings.client_id,
            client_secret=settings.client_secret,
            session_secret=settings.account_session_secret,
            schools=selfhost_school_policy(settings, config),
            session_ttl_seconds=settings.account_session_ttl_seconds,
        ),
        runtime.store,
        authorize_id_token_claims(runtime.policy),
        health=runtime.health,
        write_tools=WriteToolCatalog(ceiling=ceiling, list_registered=registered_tool_names),
        tool_prefs=runtime.tool_prefs,
        access=runtime.access,
        **{"rate_limiters": runtime.limiters, **account_options},
    )

    @mcp.custom_route(HEALTH_PATH, methods=["GET"])
    async def healthz(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok", headers={"Cache-Control": "no-store"})


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
    app = mcp.http_app(
        stateless_http=True,
        middleware=[
            Middleware(
                SelfhostRequestContextMiddleware,
                mcp_path=settings.mcp_path,
                policy=runtime.policy,
                store=runtime.store,
                schools=selfhost_school_policy(settings, config),
                account_url=settings.account_url,
                health=runtime.health,
                tool_prefs=runtime.tool_prefs,
                access=runtime.access,
                owners=runtime.store,
                course_state=settings.course_state,
            )
        ],
        host_origin_protection=True,
        allowed_hosts=[settings.public_host],
        allowed_origins=[settings.public_base_url],
    )

    provider = mcp.auth

    async def cull_oauth_state() -> None:
        await cull_expired_oauth_state(provider)

    return SelfhostEdgeGuard(
        app,
        clock=clock or time.monotonic,
        maintenance=cull_oauth_state,
        rate_limiters=runtime.limiters,
    )
