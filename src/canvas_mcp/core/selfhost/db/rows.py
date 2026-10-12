"""Frozen, named repository results; SQLAlchemy rows stay inside repositories."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CanvasOAuthAppRow:
    """Reserved sealed Developer Key record; v1 does not configure or use it."""

    id: str
    canvas_host: str
    client_id: str
    scopes: str
    enabled: bool
    secret_key_id: str
    secret_nonce: bytes = field(repr=False)
    secret_ciphertext: bytes = field(repr=False)
    created_at: int
    updated_at: int
    updated_by: str | None


@dataclass(frozen=True)
class AccountRow:
    id: str
    status: str
    role: str
    role_source: str | None
    role_seen_at: int | None
    admitted_via: str
    display_name: str
    created_at: int
    updated_at: int
    approved_at: int | None
    approved_by: str | None
    disabled_at: int | None
    disabled_by: str | None
    disabled_reason: str | None
    last_login_at: int | None
    session_epoch: int
    credential_generation: int
    write_tools_version: int
    upn: str = ""
    upn_required: bool = False


@dataclass(frozen=True)
class IdentityRow:
    id: str
    account_id: str
    provider_id: str
    issuer: str
    subject: str
    username: str | None
    email: str | None
    email_verified: bool
    linked_at: int
    last_login_at: int | None


@dataclass(frozen=True)
class CredentialRow:
    id: str
    account_id: str
    canvas_host: str
    kind: str
    oauth_app_id: str | None
    is_primary: bool
    generation: int
    key_id: str
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    canvas_user_id: str
    canvas_user_name: str
    status: str
    invalid_reason: str | None
    invalid_since: int | None
    created_at: int
    updated_at: int
    last_used_at: int | None
    last_verified_at: int | None
    expires_hint_at: int | None
    access_expires_at: int | None
    scopes: str | None
    custody_notice_version: int
    custody_ack_at: int


@dataclass(frozen=True)
class AuthEventRow:
    id: int
    at: int
    account_id: str | None
    provider_id: str
    surface: str
    outcome: str
    reason: str
    ua_hash: bytes | None


@dataclass(frozen=True)
class AuditRow:
    id: int
    at: int
    actor_kind: str
    actor_id: str | None
    subject_account_id: str | None
    action: str
    target_kind: str | None
    target_id: str | None
    reason: str | None
    detail: dict[str, Any]


@dataclass(frozen=True)
class WriteToolRow:
    account_id: str
    tool_name: str
    enabled_at: int
    enabled_via: str
