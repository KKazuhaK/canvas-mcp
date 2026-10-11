"""Immutable database snapshots shared by authentication and request handlers."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.engine import Connection


@dataclass(frozen=True)
class McpSnapshot:
    status: str
    role: str
    session_epoch: int
    credential_generation: int
    write_tools_version: int
    revoked_at: int | None
    grant_expires_at: int
    grant_used_at: int | None
    credential_id: str | None
    canvas_host: str | None
    kind: str | None
    generation: int | None
    key_id: str | None
    nonce: bytes | None
    ciphertext: bytes | None
    credential_status: str | None
    credential_used_at: int | None
    last_verified_at: int | None
    canvas_user_id: str | None
    custody_notice_version: int | None
    jwt_epoch: int
    settings_revision: int


@dataclass(frozen=True)
class SessionSnapshot:
    status: str
    role: str
    session_epoch: int
    settings_revision: int


_MCP = text("""
SELECT a.status, a.role, a.session_epoch, a.credential_generation, a.write_tools_version,
       g.revoked_at, g.expires_at AS grant_expires_at, g.last_used_at AS grant_used_at,
       c.id AS credential_id, c.canvas_host, c.kind, c.generation, c.key_id, c.nonce, c.ciphertext,
       c.status AS credential_status, c.last_used_at AS credential_used_at, c.last_verified_at,
       c.canvas_user_id, c.custody_notice_version, s.jwt_epoch, s.settings_revision
FROM oauth_grants g
JOIN accounts a ON a.id = g.account_id
LEFT JOIN canvas_credentials c ON c.account_id = a.id AND c.is_primary
CROSS JOIN server_state s
WHERE g.id = :grant_id AND g.account_id = :account_id AND s.id = 1
""")
_SESSION = text("""
SELECT a.status, a.role, a.session_epoch, s.settings_revision
FROM accounts a CROSS JOIN server_state s
WHERE a.id = :account_id AND s.id = 1
""")


def mcp_snapshot(
    conn: Connection, account_id: str, grant_id: str
) -> McpSnapshot | None:
    """Read grant, account, primary credential and server epochs in one statement."""
    row = (
        conn.execute(_MCP, {"account_id": account_id, "grant_id": grant_id})
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    values = dict(row)
    if values["credential_id"] is not None:
        values["credential_id"] = str(values["credential_id"])
    return McpSnapshot(**values)


def session_snapshot(conn: Connection, account_id: str) -> SessionSnapshot | None:
    row = conn.execute(_SESSION, {"account_id": account_id}).mappings().one_or_none()
    return None if row is None else SessionSnapshot(**row)
