"""Startup validation and wiring of the self-hosted Entra OAuth mode."""

from __future__ import annotations

import os
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from fastmcp import FastMCP
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp

from ..config import Config, validate_canvas_url_scheme
from .edge_guard import SelfhostEdgeGuard
from .identity import ClaimsPolicy, authorize_id_token_claims
from .oauth import cull_expired_oauth_state
from .request_context import SelfhostRequestContextMiddleware
from .settings import SelfhostConfigError, SelfhostSettings
from .tool_gate import SelfhostCredentialGate

if TYPE_CHECKING:
    from .token_store import TokenStore

HEALTH_PATH = "/healthz"


@dataclass(frozen=True)
class SelfhostRuntime:
    """What the running server shares: validated settings, token store, claim policy."""

    settings: SelfhostSettings
    store: TokenStore
    policy: ClaimsPolicy


def _writable_directory_problem(name: str, path: Path) -> str | None:
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        return f"{name} cannot be created"
    if not path.is_dir() or not os.access(path, os.W_OK):
        return f"{name} is not a writable directory"
    return None


def validate_selfhost_startup(config: Config, settings: SelfhostSettings) -> list[str]:
    """Every reason the server must refuse to start in this mode (empty = fine).

    Messages name settings and never include their values.
    """
    problems: list[str] = []

    if not config.canvas_api_url:
        problems.append("CANVAS_API_URL is required (the Canvas API URL is server-pinned)")
    elif not validate_canvas_url_scheme():
        problems.append("CANVAS_API_URL must use https")

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


def prepare_selfhost(settings: SelfhostSettings) -> SelfhostRuntime:
    """Open the encrypted token store and build the claim policy.

    Raises :class:`SelfhostConfigError` when the keyring or the store is
    unusable (a key id missing, a wrong key, an unreadable database).
    """
    from .token_store import Keyring, KeyringError, TokenStore, TokenStoreError

    try:
        keyring = Keyring.parse(settings.canvas_token_keys_raw)
        store = TokenStore(settings.token_db_path, keyring)
        store.initialize()
    except (TokenStoreError, KeyringError) as exc:
        raise SelfhostConfigError([str(exc)]) from None
    except sqlite3.Error:
        # A corrupt file, not a database, locked, or a failing disk. The driver's
        # message is left out: it can quote paths.
        raise SelfhostConfigError(
            ["the Canvas token database cannot be opened or is not a valid database"]
        ) from None
    except OSError:
        raise SelfhostConfigError(["the Canvas token database cannot be opened"]) from None

    policy = ClaimsPolicy(
        tenant_id=settings.tenant_id,
        client_id=settings.client_id,
        required_role=settings.required_role,
        owner_role=settings.owner_role,
    )
    return SelfhostRuntime(settings=settings, store=store, policy=policy)


def install_selfhost(mcp: FastMCP, runtime: SelfhostRuntime, config: Config) -> None:
    """Add the credential gate, the /account pages and /healthz to the server."""
    from .account_web import AccountConfig, register_account_routes

    settings = runtime.settings
    mcp.add_middleware(SelfhostCredentialGate())

    register_account_routes(
        mcp,
        AccountConfig(
            public_base_url=settings.public_base_url,
            tenant_id=settings.tenant_id,
            client_id=settings.client_id,
            client_secret=settings.client_secret,
            session_secret=settings.account_session_secret,
            canvas_api_url=config.canvas_api_url,
            session_ttl_seconds=settings.account_session_ttl_seconds,
        ),
        runtime.store,
        authorize_id_token_claims(runtime.policy),
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
                canvas_api_url=config.canvas_api_url,
                account_url=settings.account_url,
            )
        ],
        host_origin_protection=True,
        allowed_hosts=[settings.public_host],
        allowed_origins=[settings.public_base_url],
    )

    provider = mcp.auth

    async def cull_oauth_state() -> None:
        await cull_expired_oauth_state(provider)

    return SelfhostEdgeGuard(app, clock=clock or time.monotonic, maintenance=cull_oauth_state)
