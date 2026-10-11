"""Plain records and closed vocabularies of the authorization server (no I/O)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

CLIENT_KIND_DCR = "dcr"
CLIENT_KIND_CIMD = "cimd"
CLIENT_KINDS = (CLIENT_KIND_DCR, CLIENT_KIND_CIMD)

# Why a grant was revoked: a closed set, enforced by a CHECK constraint.
REVOKE_USER = "user_revoked"
REVOKE_OWNER = "owner_revoked"
REVOKE_OPERATOR = "operator_revoked"
REVOKE_CLIENT = "client_revoked"
REVOKE_REFRESH_REUSE = "refresh_reuse"
REVOKE_CODE_REPLAY = "code_replay"
REVOKE_ACCOUNT_DISABLED = "account_disabled"
REVOKE_ADMISSION_LOST = "admission_lost"
REVOKE_REAUTH_REQUIRED = "reauth_required"
REVOKE_REASONS = frozenset(
    {
        REVOKE_USER,
        REVOKE_OWNER,
        REVOKE_OPERATOR,
        REVOKE_CLIENT,
        REVOKE_REFRESH_REUSE,
        REVOKE_CODE_REPLAY,
        REVOKE_ACCOUNT_DISABLED,
        REVOKE_ADMISSION_LOST,
        REVOKE_REAUTH_REQUIRED,
    }
)

#: Who revoked a grant when it is not an account.
BY_SYSTEM = "system"
BY_OPERATOR = "operator"

#: How many times one code, or one refresh token, may be replayed inside the grace window.
MAX_GRACE_REPLAYS = 2
#: An authorization code lives five minutes.
CODE_TTL_SECONDS = 300


def split_scopes(value: str) -> tuple[str, ...]:
    return tuple(part for part in value.split(" ") if part)


@dataclass(frozen=True)
class ClientRecord:
    client_id: str
    info: dict[str, Any]
    client_name: str
    created_at: int
    expires_at: int


@dataclass(frozen=True)
class CimdSnapshot:
    url: str
    doc: dict[str, Any]
    fetched_at: int
    fresh_until: int
    last_error_at: int | None
    last_error: str | None


@dataclass(frozen=True)
class GrantRecord:
    """One connection of an app to an account (a refresh family)."""

    id: str
    account_id: str
    client_id: str
    client_kind: str
    client_name: str
    client_host: str | None
    redirect_host: str
    scopes: tuple[str, ...]
    resource: str
    created_at: int
    last_used_at: int | None
    upstream_auth_at: int
    expires_at: int
    revoked_at: int | None
    revoked_reason: str | None
    revoked_by: str | None

    @property
    def account_key(self) -> str:
        return self.account_id

    def active(self, now: int) -> bool:
        return self.revoked_at is None and self.expires_at > now


@dataclass(frozen=True)
class CodeRecord:
    """An authorization code (by its hash); consumed codes stay as tombstones."""

    code_hash: str
    client_id: str
    account_id: str
    redirect_uri: str
    redirect_uri_explicit: bool
    code_challenge: str
    scopes: tuple[str, ...]
    resource: str
    client_kind: str
    client_name: str
    client_host: str | None
    redirect_host: str
    upstream_auth_at: int
    #: The ``session_epoch`` of the /account session that approved the code.
    session_epoch: int
    created_at: int
    expires_at: int
    consumed_at: int | None
    grant_id: str | None
    grace_replays: int


@dataclass(frozen=True)
class RefreshView:
    """A refresh token row together with the facts of its grant."""

    token_hash: str
    grant_id: str
    parent_hash: str | None
    created_at: int
    expires_at: int
    used_at: int | None
    replaced_by: str | None
    grace_replays: int
    client_id: str | None
    scopes: tuple[str, ...]
    resource: str
    account_id: str | None
    grant_revoked_at: int | None


@dataclass(frozen=True)
class GrantStatus:
    """The committed grant standing returned by its named database read."""

    found: bool
    account_id: str | None = None
    client_id: str | None = None
    revoked: bool = True
    expires_at: int = 0
    last_used_at: int | None = None
    account_status: str | None = None

    def usable(self, now: int) -> bool:
        return (
            self.found
            and not self.revoked
            and self.expires_at > now
            and self.account_status == "active"
        )


class ExchangeOutcome(Enum):
    """The result of redeeming an authorization code."""

    WON = "won"  # this call consumed the code and created the grant
    GRACE = "grace"  # a benign duplicate inside the grace window: a sibling was issued
    CAPPED = "capped"  # a duplicate inside the window, but too many already
    REPLAY_REVOKED = (
        "replay_revoked"  # a replay outside the window: the grant is revoked
    )
    DEAD = "dead"  # unknown, expired, or the grant is gone
    INACTIVE = "inactive"  # the account is not active
    REAUTH = "reauth"  # the user must sign in again (MAX_UPSTREAM_AUTH_AGE)


class RotateOutcome(Enum):
    """The result of presenting a refresh token."""

    ROTATED = "rotated"
    GRACE = "grace"  # a benign duplicate inside the grace window: a sibling was issued
    CAPPED = "capped"
    REUSE_REVOKED = "reuse_revoked"  # a reused token: the whole grant is revoked
    DEAD = "dead"  # unknown, expired, or the grant is revoked
    INACTIVE = "inactive"
    REAUTH = "reauth"


@dataclass(frozen=True)
class ExchangeResult:
    outcome: ExchangeOutcome
    grant: GrantRecord | None = None
    refresh_issued: bool = False
    jwt_epoch: int | None = None


@dataclass(frozen=True)
class RotateResult:
    outcome: RotateOutcome
    grant: GrantRecord | None = None
    refresh_issued: bool = False
    jwt_epoch: int | None = None
