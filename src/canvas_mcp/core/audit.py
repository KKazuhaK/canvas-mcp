"""Structured audit logging for Canvas MCP Server.

Provides a structured audit trail that can support institutional privacy and
compliance processes for data access and code execution events.
Events are emitted as JSON lines to both stderr and a rotating log file.

Controlled by:
- LOG_ACCESS_EVENTS: Enable data access audit events (default: false)
- LOG_EXECUTION_EVENTS: Enable code execution audit events (default: false)
- AUDIT_LOG_DIR: Directory for audit log files (default: ~/.canvas-mcp/)
"""

import json
import logging
import re
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from .credentials import get_request_principal
from .redact import mask_named_segments, scrub_event, scrub_secrets, strip_query

# Separate logger for audit events (not the main application logger)
_audit_logger = logging.getLogger("canvas_mcp.audit")
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False  # Don't propagate to root/parent loggers

# Module-level flags (set by init_audit_logging)
_access_events_enabled = False
_execution_events_enabled = False
_initialized = False

# Regex to replace numeric path segments
_NUMERIC_PATH_RE = re.compile(r"/\d+")

# Audit log file settings
_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
_BACKUP_COUNT = 5
_AUDIT_FILENAME = "audit.jsonl"
# Free-form error text is cut to this length; a codes-only field never needs more.
_MAX_ERROR_CHARS = 300


def _sanitize_endpoint(endpoint: str) -> str:
    """Replace numeric IDs and named segments with '***' and drop the query string.

    Named segments (a page slug, a ``sis_user_id:`` value, a ``by_path`` folder
    path) can carry a person's name, so they are masked like numeric ids.

    Example: /courses/12345/pages/midterm-for-jane?access_token=x → /courses/***/pages/***
    """
    path = mask_named_segments(strip_query(scrub_secrets(endpoint)))
    return _NUMERIC_PATH_RE.sub("/***", path)


def init_audit_logging() -> None:
    """Initialize audit logging based on configuration.

    Sets up stderr and file handlers for the audit logger.
    Called once during server startup.
    """
    global _access_events_enabled, _execution_events_enabled, _initialized

    if _initialized:
        return

    from .config import get_config
    config = get_config()

    _access_events_enabled = config.log_access_events
    _execution_events_enabled = config.log_execution_events

    if not _access_events_enabled and not _execution_events_enabled:
        _initialized = True
        return

    # Stderr handler — JSON lines to stderr
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.INFO)
    stderr_handler.setFormatter(logging.Formatter("%(message)s"))
    _audit_logger.addHandler(stderr_handler)

    # File handler — rotating JSON lines file
    audit_dir_str = config.audit_log_dir
    if not audit_dir_str:
        audit_dir = Path.home() / ".canvas-mcp"
    else:
        audit_dir = Path(audit_dir_str)

    try:
        audit_dir.mkdir(parents=True, exist_ok=True)
        audit_file = audit_dir / _AUDIT_FILENAME
        file_handler = RotatingFileHandler(
            str(audit_file),
            maxBytes=_MAX_BYTES,
            backupCount=_BACKUP_COUNT,
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter("%(message)s"))
        _audit_logger.addHandler(file_handler)
    except OSError:
        # If we can't write to the audit dir, log to stderr only
        print(
            f"Warning: Could not create audit log directory {audit_dir}. "
            "Audit events will be written to stderr only.",
            file=sys.stderr,
        )

    _initialized = True


def _emit(event: dict[str, Any]) -> None:
    """Emit a structured JSON audit event."""
    event["timestamp"] = datetime.now(UTC).isoformat()
    # Attribute each event to the verified identity (GUIDs only: no names or
    # UPNs) in the self-hosted multi-user mode.
    # The identity only: current_principal_key() also carries the school.
    principal = get_request_principal()
    if principal is not None and principal.key.startswith(("acct:", "entra:")):
        # An event that names its own subject (an admin acting on someone else's
        # enrollment) keeps it.
        event.setdefault("principal", principal.key)
    # Last line of defence: no event may carry a credential, whatever text a
    # caller passed in (an exception message that quotes a URL, a header).
    scrubbed = scrub_event(event)
    if isinstance(scrubbed.get("error"), str):
        scrubbed["error"] = scrub_secrets(scrubbed["error"], emails=True)[:_MAX_ERROR_CHARS]
    _audit_logger.info(json.dumps(scrubbed, default=str))


def log_data_access(
    method: str,
    endpoint: str,
    status: str,
    error: str | None = None,
) -> None:
    """Log a data access audit event.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE)
        endpoint: Canvas API endpoint (will be sanitized)
        status: "success" or "error"
        error: Optional error message
    """
    if not _access_events_enabled:
        return

    event: dict[str, Any] = {
        "event_type": "data_access",
        "method": method.upper(),
        "endpoint": _sanitize_endpoint(endpoint),
        "status": status,
    }
    if error:
        event["error"] = error

    _emit(event)


def log_code_execution(
    code_hash: str,
    sandbox_mode: str,
    status: str,
    duration_sec: float | None = None,
    error: str | None = None,
) -> None:
    """Log a code execution audit event.

    Args:
        code_hash: SHA-256 hash prefix of the executed code (not the raw code)
        sandbox_mode: Sandbox mode used (disabled, local, container)
        status: "success", "error", or "timeout"
        duration_sec: Execution duration in seconds
        error: Optional error message
    """
    if not _execution_events_enabled:
        return

    event: dict[str, Any] = {
        "event_type": "code_execution",
        "code_hash": code_hash,
        "sandbox_mode": sandbox_mode,
        "status": status,
    }
    if duration_sec is not None:
        event["duration_sec"] = round(duration_sec, 3)
    if error:
        event["error"] = error

    _emit(event)


def log_access_change(
    action: str,
    oid: str,
    *,
    upn: str | None = None,
    source: str = "self-service",
) -> None:
    """Audit an authorization-allowlist change (grant/revoke/deny).

    Args:
        action: "grant", "revoke", or "deny".
        oid: The affected Entra object ID.
        upn: Optional user principal name (recorded in the audit log only).
        source: How the change was made (default the self-service email flow).
    """
    if not _access_events_enabled:
        return
    event: dict[str, Any] = {
        "event_type": "access_change",
        "action": action,
        "entra_oid": oid,
    }
    if upn:
        event["upn"] = upn
    event["source"] = source
    _emit(event)


def log_token_event(
    action: str,
    principal_key: str,
    *,
    reason: str | None = None,
    outcome: str | None = None,
    actor: str | None = None,
) -> None:
    """Audit a change in the health of a stored Canvas token.

    Records only the principal key (an opaque identity string, never a Canvas
    token, name or e-mail address) and short closed-set codes.

    Args:
        action: "invalidated", "recheck", "admin_marked_invalid",
            "identity_change_detected" or "identity_change_confirmed".
        principal_key: Whose token it is.
        reason: Why a token was invalidated (closed set).
        outcome: Result of a re-check ("restored", "still_rejected", "unavailable").
        actor: Principal key of the person who did it, when that is not the owner
            of the token (an administrator).
    """
    if not _access_events_enabled:
        return
    event: dict[str, Any] = {
        "event_type": "canvas_token",
        "action": action,
        "principal": principal_key,
    }
    if reason:
        event["reason"] = reason
    if outcome:
        event["outcome"] = outcome
    if actor:
        event["actor"] = actor
    _emit(event)


def log_principal_event(
    action: str,
    principal_key: str,
    *,
    actor: str | None = None,
    reason: str | None = None,
    outcome: str | None = None,
) -> None:
    """Audit a change to whether a principal may use the server.

    Records the principal key (an opaque identity string, never a name, e-mail
    address or token) and short closed-set codes. The same transitions are also kept
    in the token database (``principal_status_events``), which is the record that
    covers the operator CLI.

    Args:
        action: "disabled", "enabled", "owner_gained", "owner_lost" (state
            transitions), "refused" (an access change that was not made),
            "sign_in_refused", "enroll_refused" (a disabled principal tried),
            "self_disconnected" (a user deleted their own token) or
            "enrollment_removed" (an owner removed an enrollment row).
        principal_key: The subject.
        actor: Principal key of the owner who did it, or "operator" for the CLI.
        reason: Why (closed set, for example "admin_disabled").
        outcome: Why a change was refused ("last_owner", "self", "not_owner").
    """
    if not _access_events_enabled:
        return
    event: dict[str, Any] = {
        "event_type": "principal_status",
        "action": action,
        "principal": principal_key,
    }
    if actor:
        event["actor"] = actor
    if reason:
        event["reason"] = reason
    if outcome:
        event["outcome"] = outcome
    _emit(event)


def log_write_tools_event(
    action: str,
    principal_key: str,
    *,
    enabled: Iterable[str] = (),
    disabled: Iterable[str] = (),
    outcome: str | None = None,
) -> None:
    """Audit a change to the write tools a user switched on at /account.

    Records the principal key and tool names only (a fixed vocabulary), never a
    token, name or e-mail address.

    Args:
        action: "changed" (a switch was saved), "cleared" (the user turned every
            write tool off) or "refused" (a change was not saved).
        principal_key: Whose switches they are.
        enabled: Tool names switched on by this change.
        disabled: Tool names switched off by this change.
        outcome: Why a change was refused ("sign_in_too_old").
    """
    if not _access_events_enabled:
        return
    event: dict[str, Any] = {
        "event_type": "write_tools",
        "action": action,
        "principal": principal_key,
        "enabled": sorted(enabled),
        "disabled": sorted(disabled),
    }
    if outcome:
        event["outcome"] = outcome
    _emit(event)


def reset_audit_state() -> None:
    """Reset audit module state. For testing only.

    Handlers are closed, not just detached. The RotatingFileHandler holds
    audit.jsonl open; dropping it without close() leaks that descriptor, and on
    Windows, where an open file cannot be deleted or renamed, it leaves the
    audit log locked until the interpreter exits.
    """
    global _access_events_enabled, _execution_events_enabled, _initialized
    _access_events_enabled = False
    _execution_events_enabled = False
    _initialized = False
    for handler in list(_audit_logger.handlers):
        _audit_logger.removeHandler(handler)
        handler.close()
