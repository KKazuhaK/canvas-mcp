"""The authenticated database read shared within one HTTP request."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .db.snapshots import McpSnapshot


@dataclass(frozen=True)
class McpRead:
    account_id: str
    grant_id: str
    snapshot: McpSnapshot


MCP_READ: ContextVar[McpRead | None] = ContextVar("selfhost_mcp_read", default=None)
MCP_UNAVAILABLE: ContextVar[bool] = ContextVar(
    "selfhost_mcp_unavailable", default=False
)
