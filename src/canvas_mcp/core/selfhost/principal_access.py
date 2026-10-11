"""Pure account-standing refusals shared by request handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .accounts import DENIAL_MESSAGES, DENY_ACCESS_DENIED, DENY_PENDING_APPROVAL
from .token_store import PrincipalStatus

if TYPE_CHECKING:
    from .mcp_state import McpRead


def access_disabled_message() -> str:
    """The refusal for a principal an administrator disabled (no way to fix it yourself)."""
    return (
        "Your access to this server was disabled by an administrator. "
        "Contact the server owner to have it restored."
    )


def access_unavailable_message() -> str:
    """The refusal when the access decision could not be read (fail closed)."""
    return "Your access could not be verified right now. Try again in a moment."


def access_pending_message() -> str:
    """The refusal for an account that waits for an owner's approval."""
    return DENIAL_MESSAGES[DENY_PENDING_APPROVAL]


def access_not_provisioned_message() -> str:
    """The refusal for a principal without an account (fail closed)."""
    return DENIAL_MESSAGES[DENY_ACCESS_DENIED]


def access_refusal_message(status: PrincipalStatus) -> str | None:
    """Why this account may not use the server, or None when it may."""
    if status.active:
        return None
    if status.disabled:
        return access_disabled_message()
    if status.pending:
        return access_pending_message()
    return access_not_provisioned_message()


def snapshot_status(read: McpRead) -> PrincipalStatus:
    row = read.snapshot
    return PrincipalStatus(
        principal_key=read.account_id,
        status=row.status,
        role=row.role,
        display_name=row.display_name,
        session_epoch=row.session_epoch,
        credential_generation=row.credential_generation,
        stored=True,
    )
