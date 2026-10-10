"""Plain records and closed vocabularies of the authorization server (no I/O)."""

from __future__ import annotations

from collections.abc import Sequence
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
    info_json: str
    client_name: str
    created_at: int
    expires_at: int

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> ClientRecord:
        return cls(str(row[0]), str(row[1]), str(row[2]), int(row[3]), int(row[4]))


@dataclass(frozen=True)
class CimdSnapshot:
    url: str
    doc_json: str
    fetched_at: int
    fresh_until: int
    last_error_at: int | None
    last_error: str | None

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> CimdSnapshot:
        return cls(
            str(row[0]),
            str(row[1]),
            int(row[2]),
            int(row[3]),
            None if row[4] is None else int(row[4]),
            None if row[5] is None else str(row[5]),
        )


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

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> GrantRecord:
        return cls(
            id=str(row[0]),
            account_id=str(row[1]),
            client_id=str(row[2]),
            client_kind=str(row[3]),
            client_name=str(row[4]),
            client_host=None if row[5] is None else str(row[5]),
            redirect_host=str(row[6]),
            scopes=split_scopes(str(row[7])),
            resource=str(row[8]),
            created_at=int(row[9]),
            last_used_at=None if row[10] is None else int(row[10]),
            upstream_auth_at=int(row[11]),
            expires_at=int(row[12]),
            revoked_at=None if row[13] is None else int(row[13]),
            revoked_reason=None if row[14] is None else str(row[14]),
            revoked_by=None if row[15] is None else str(row[15]),
        )

    @property
    def account_key(self) -> str:
        return f"acct:{self.account_id}"

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
    created_at: int
    expires_at: int
    consumed_at: int | None
    grant_id: str | None
    grace_replays: int

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> CodeRecord:
        return cls(
            code_hash=str(row[0]),
            client_id=str(row[1]),
            account_id=str(row[2]),
            redirect_uri=str(row[3]),
            redirect_uri_explicit=bool(row[4]),
            code_challenge=str(row[5]),
            scopes=split_scopes(str(row[6])),
            resource=str(row[7]),
            client_kind=str(row[8]),
            client_name=str(row[9]),
            client_host=None if row[10] is None else str(row[10]),
            redirect_host=str(row[11]),
            upstream_auth_at=int(row[12]),
            created_at=int(row[13]),
            expires_at=int(row[14]),
            consumed_at=None if row[15] is None else int(row[15]),
            grant_id=None if row[16] is None else str(row[16]),
            grace_replays=int(row[17]),
        )


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

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> RefreshView:
        return cls(
            token_hash=str(row[0]),
            grant_id=str(row[1]),
            parent_hash=None if row[2] is None else str(row[2]),
            created_at=int(row[3]),
            expires_at=int(row[4]),
            used_at=None if row[5] is None else int(row[5]),
            replaced_by=None if row[6] is None else str(row[6]),
            grace_replays=int(row[7]),
            client_id=None if row[8] is None else str(row[8]),
            scopes=split_scopes("" if row[9] is None else str(row[9])),
            resource="" if row[10] is None else str(row[10]),
            account_id=None if row[11] is None else str(row[11]),
            grant_revoked_at=None if row[12] is None else int(row[12]),
        )


@dataclass(frozen=True)
class GrantStatus:
    """What the request path needs to know about a grant (cached for a few seconds)."""

    found: bool
    account_id: str | None = None
    client_id: str | None = None
    revoked: bool = True
    expires_at: int = 0
    last_used_at: int | None = None
    account_status: str | None = None

    @classmethod
    def from_row(cls, row: Sequence[Any] | None) -> GrantStatus:
        if row is None:
            return cls(found=False)
        return cls(
            found=True,
            account_id=str(row[0]),
            client_id=str(row[1]),
            revoked=row[2] is not None,
            expires_at=int(row[3]),
            last_used_at=None if row[4] is None else int(row[4]),
            account_status=None if row[5] is None else str(row[5]),
        )

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
    REPLAY_REVOKED = "replay_revoked"  # a replay outside the window: the grant is revoked
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


@dataclass(frozen=True)
class RotateResult:
    outcome: RotateOutcome
    grant: GrantRecord | None = None
    refresh_issued: bool = False
