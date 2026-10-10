"""Builders shared by the store, race and flow tests."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from canvas_mcp.core.selfhost.authz import tokens as tk
from canvas_mcp.core.selfhost.authz.store import AuthzStore
from canvas_mcp.core.selfhost.settings import AuthzSettings
from canvas_mcp.core.selfhost.token_store import TokenStore

from ..conftest import OID_A, make_account

CLIENT = "33333333-3333-4333-8333-333333333333"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"
RESOURCE = "https://canvas.example.test/mcp"
SCOPE = "Canvas.Access"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


@dataclass
class Env:
    """A token store, an authz store over the same database, and one active account."""

    tokens: TokenStore
    authz: AuthzStore
    account_key: str
    clock: Any
    codes: list[str] = field(default_factory=list)

    @property
    def account_id(self) -> str:
        return self.account_key.removeprefix("acct:")

    def new_code(
        self,
        *,
        client_id: str = CLIENT,
        client_kind: str = "dcr",
        account_id: str | None = None,
        upstream_auth_at: int | None = None,
        redirect_uri: str = REDIRECT,
    ) -> str:
        """Create a code for an approved request and return the raw code."""
        raw = tk.new_auth_code()
        ok = self.authz.create_code(
            code_hash=tk.hash_secret(raw),
            client_id=client_id,
            client_kind=client_kind,
            client_name="Test app",
            client_host="claude.ai" if client_kind == "cimd" else None,
            account_id=account_id or self.account_id,
            redirect_uri=redirect_uri,
            redirect_uri_explicit=True,
            redirect_host="claude.ai",
            code_challenge=CHALLENGE,
            scopes=(SCOPE,),
            resource=RESOURCE,
            upstream_auth_at=int(self.clock()) if upstream_auth_at is None else upstream_auth_at,
        )
        assert ok
        self.codes.append(raw)
        return raw

    def exchange(self, raw_code: str, *, client_id: str = CLIENT, refresh: bool = True) -> tuple[Any, str | None, str]:
        """Redeem a raw code; returns (result, raw refresh token, grant id used)."""
        grant_id = str(uuid.uuid4())
        raw_refresh = tk.new_refresh_token() if refresh else None
        result = self.authz.exchange_code(
            code_hash=tk.hash_secret(raw_code),
            client_id=client_id,
            grant_id=grant_id,
            refresh_hash=None if raw_refresh is None else tk.hash_secret(raw_refresh),
        )
        return result, raw_refresh, grant_id

    def rotate(self, raw_refresh: str) -> tuple[Any, str]:
        new = tk.new_refresh_token()
        result = self.authz.rotate_refresh(
            token_hash=tk.hash_secret(raw_refresh), new_hash=tk.hash_secret(new)
        )
        return result, new

    def grant_with_token(self) -> tuple[Any, str]:
        """A live grant and its first raw refresh token."""
        result, refresh, _ = self.exchange(self.new_code())
        assert refresh is not None and result.grant is not None
        return result.grant, refresh


def make_env(tmp_path: Any, keyring: Any, clock: Any, *, settings: AuthzSettings | None = None) -> Env:
    from dbbackend import make_store

    tokens = make_store(tmp_path / "authz.sqlite3", keyring, clock=clock)
    tokens.initialize()
    authz = AuthzStore(tokens.database, clock=clock, settings=settings or AuthzSettings())
    account_key = make_account(tokens, OID_A)
    return Env(tokens, authz, account_key, clock)
