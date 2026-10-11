"""Native account/API fixture over the actual authorization and React runtime.

Only providers, Canvas, DNS and wall time are faked. No HTML routes, claim
verifier override, old key parser or production compatibility layer is used.
"""

from __future__ import annotations

import base64
import pathlib
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import UTC
from typing import Any

import httpx
import pytest

from canvas_mcp.core.selfhost import account_core
from canvas_mcp.core.selfhost.accounts import AccessPolicy, default_policy
from canvas_mcp.core.selfhost.config_store import ConfigStore
from canvas_mcp.core.selfhost.custody import (
    CUSTODY_NOTICE_VERSION,
    CustodyAcknowledgement,
)
from canvas_mcp.core.selfhost.schools import School, SchoolPolicy

from .authz.stack import BASE, CANVAS_HOST, Browser, User, local_stack
from .conftest import acct_key, make_account
from .login.test_entra_only_golden import account_app

OID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID_2 = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
OID_OWNER = "cccccccc-dddd-eeee-ffff-000000000000"
KEY = acct_key(OID)
KEY_2 = acct_key(OID_2)
KEY_OWNER = acct_key(OID_OWNER)
CANVAS_TOKEN = "7~" + "T" * 62
SESSION_SECRET = bytes(range(32))
POLICY = default_policy("Canvas.User", "Canvas.Owner")
_resources = ExitStack()


@contextmanager
def _managed_stack(*args: Any, **options: Any) -> Iterator[Any]:
    """Close database connections only after the application has shut down."""
    stack = None
    try:
        with local_stack(*args, **options) as stack:
            yield stack
    finally:
        if stack is not None:
            stack.store.close()


@pytest.fixture(autouse=True)
def _display_in_utc(monkeypatch: pytest.MonkeyPatch):
    """Keep API time rendering deterministic and close every test server."""
    monkeypatch.setattr(account_core, "_display_tz", lambda: UTC)
    try:
        yield
    finally:
        _resources.close()


@dataclass(frozen=True)
class FixtureConfig:
    public_base_url: str = BASE
    session_secret: bytes = SESSION_SECRET
    session_ttl_seconds: int = 900
    schools: SchoolPolicy = SchoolPolicy(
        (School(CANVAS_HOST, f"https://{CANVAS_HOST}/api/v1", "Canvas"),), False
    )


def make_cfg(**options: Any) -> FixtureConfig:
    return FixtureConfig(**options)


@dataclass
class Harness:
    client: Any = None
    store: Any = None
    identity: Any = None
    stack: Any = None
    core: Any = None
    now: float = 1_800_000_000.0
    whoami_calls: list[str] = field(default_factory=list)
    whoami_urls: list[str] = field(default_factory=list)
    whoami_result: account_core.CanvasIdentity | account_core.CanvasCheckError = field(
        default_factory=lambda: account_core.CanvasIdentity("42", "Ada Canvas")
    )

    def clock(self) -> float:
        return self.now


def build_harness(
    tmp_path: pathlib.Path,
    *,
    cfg: FixtureConfig | None = None,
    policy: AccessPolicy = POLICY,
    **options: Any,
) -> Harness:
    h = Harness()
    cfg = cfg or make_cfg()
    patch = _resources.enter_context(pytest.MonkeyPatch.context())

    async def public_host(_host: str) -> list[str]:
        return ["93.184.216.34"]

    options.setdefault("resolve_host", public_host)

    async def whoami(token: str, api_url: str) -> account_core.CanvasIdentity:
        h.whoami_calls.append(token)
        h.whoami_urls.append(api_url)
        if isinstance(h.whoami_result, account_core.CanvasCheckError):
            raise h.whoami_result
        return h.whoami_result

    env = {
        "PUBLIC_BASE_URL": cfg.public_base_url,
        "ACCOUNT_SESSION_SECRET": base64.b64encode(cfg.session_secret).decode(),
        "ACCOUNT_SESSION_TTL_SECONDS": str(cfg.session_ttl_seconds),
        "ACCESS_POLICY": policy.mode,
        "ACCESS_RULES": ",".join(map(str, policy.rules))
        if policy.mode == "rules"
        else "",
        "ACCESS_RULES_FALLBACK": policy.fallback,
        "OWNER_RULES": ",".join(map(str, policy.owner_rules)),
        "ACCESS_OPEN_ACKNOWLEDGE_PUBLIC": "true",
    }
    replacements = {
        k: options.pop(k)
        for k in ("health", "write_tools", "tool_prefs")
        if k in options
    }
    h.stack = _resources.enter_context(
        _managed_stack(
            tmp_path,
            patch,
            env=env,
            clock=h.clock,
            tools=False,
            account_options={"canvas_whoami": whoami, **options},
        )
    )
    h.client, h.store, h.identity = (
        h.stack.client,
        h.stack.store,
        h.stack.runtime.identity,
    )
    h.store._new_account_id = lambda ext: acct_key(ext.subject)
    h.core = account_app(h.stack)
    h.stack.runtime.snapshots.resolve_host = options["resolve_host"]
    for name, value in replacements.items():
        setattr(h.core, name, value)
    config = ConfigStore(h.stack.runtime.snapshots)
    revision = h.stack.runtime.snapshots.revision()
    revision, _ = config.schools(
        cfg.schools.featured + cfg.schools.private,
        revision=revision,
        actor=None,
        now=int(h.now),
        grant_private=bool(cfg.schools.private),
    )
    config.setting(
        "schools.directory_search",
        cfg.schools.search_enabled,
        revision=revision,
        actor=None,
        now=int(h.now),
    )
    calls = getattr(options["resolve_host"], "calls", None)
    if isinstance(calls, list):
        calls.clear()
    return h


def sign_in(
    h: Harness,
    *,
    oid: str = OID,
    name: str = "Ada Lovelace",
    upn: str = "ada@example.test",
    roles: tuple[str, ...] = ("Canvas.User",),
    **claims: Any,
) -> httpx.Response:
    return Browser(h.stack, client=h.client).sign_in(
        User(name, oid, roles),
        preferred_username=upn,
        **claims,
    )


def put_row(
    store: Any,
    oid: str,
    *,
    token: str,
    name: str,
    upn: str = "",
    display: str | None = None,
    canvas_user_id: str = "77",
    **options: Any,
) -> Any:
    key = make_account(
        store, oid, name=name if display is None else display, username=upn
    )
    options.setdefault("canvas_host", CANVAS_HOST)
    options.setdefault(
        "custody", CustodyAcknowledgement(CUSTODY_NOTICE_VERSION, store._now())
    )
    return store.put(
        principal_key=key,
        api_token=token,
        canvas_user_id=canvas_user_id,
        canvas_user_name=name,
        **options,
    )
