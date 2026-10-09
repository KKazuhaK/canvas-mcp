"""Structured logging for Canvas MCP Server."""

import logging
import os
import re
import sys
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .redact import SecretScrubFilter, mask_named_segments

# Configure logger for Canvas MCP
logger = logging.getLogger("canvas_mcp")
logger.setLevel(logging.INFO)

# Create console handler with formatting
handler = logging.StreamHandler(sys.stderr)
handler.setLevel(logging.INFO)

# Create formatter
formatter = logging.Formatter(
    fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
handler.setFormatter(formatter)
# Exception messages quote URLs; an OAuth callback URL carries a code and state.
handler.addFilter(SecretScrubFilter())

# Add handler to logger
logger.addHandler(handler)

# Loggers of the libraries that serve the self-hosted OAuth flow. They keep their
# own handlers (``propagate`` is off for FastMCP and uvicorn), so records that name
# an OAuth transaction or quote an upstream error never pass the filter above.
_THIRD_PARTY_LOGGERS = ("fastmcp", "mcp", "uvicorn", "uvicorn.error", "uvicorn.access")


def scrub_third_party_logs() -> int:
    """Put :class:`SecretScrubFilter` on the handlers FastMCP, mcp and uvicorn log through.

    Returns how many handlers were changed. Idempotent. Call it after uvicorn has
    built its config (that is when it installs its handlers). A filter on a logger
    would not see records of its child loggers, so the filter goes on the handlers.
    """
    changed = 0
    for name in _THIRD_PARTY_LOGGERS:
        for third_party_handler in logging.getLogger(name).handlers:
            if not any(isinstance(f, SecretScrubFilter) for f in third_party_handler.filters):
                third_party_handler.addFilter(SecretScrubFilter())
                changed += 1
    return changed


# PII keys that should be fully redacted in log context
_PII_KEYS = frozenset({
    "user_id", "student_id", "email", "name", "login_id",
    "sis_user_id", "value",
})

# ID keys that should be truncated (show only last 4 chars)
_ID_KEYS = frozenset({
    "course_id", "topic_id", "assignment_id", "entry_id", "submission_id",
})

# Regex to replace numeric path segments in URLs
_NUMERIC_PATH_RE = re.compile(r"/\d+")


def _is_redaction_enabled() -> bool:
    """Check if PII redaction is enabled (default: true)."""
    return os.getenv("LOG_REDACT_PII", "true").strip().lower() == "true"


def _sanitize_context(context: dict[str, Any]) -> dict[str, Any]:
    """Sanitize context dict by redacting PII and truncating IDs.

    - Keys in _PII_KEYS are replaced with '[REDACTED]'
    - Keys in _ID_KEYS are truncated to show only last 4 characters
    - All other keys pass through unchanged
    """
    if not _is_redaction_enabled():
        return context

    sanitized: dict[str, Any] = {}
    for key, val in context.items():
        if key in _PII_KEYS:
            sanitized[key] = "[REDACTED]"
        elif key in _ID_KEYS:
            str_val = str(val)
            if len(str_val) > 4:
                sanitized[key] = f"***{str_val[-4:]}"
            else:
                sanitized[key] = str_val
        else:
            sanitized[key] = val
    return sanitized


def sanitize_url(url: str) -> str:
    """Remove URL credentials/query data and replace numeric and named path segments.

    Example: /courses/12345/users/678 → /courses/***/users/***
    """
    parsed = urlsplit(url)
    if parsed.scheme or parsed.netloc:
        safe_netloc = parsed.netloc.rsplit("@", 1)[-1]
        url = urlunsplit((parsed.scheme, safe_netloc, parsed.path, "", ""))
    else:
        url = url.split("?", 1)[0].split("#", 1)[0]
    return _NUMERIC_PATH_RE.sub("/***", mask_named_segments(url))


def log_error(message: str, exc: Exception | None = None, **context: Any) -> None:
    """Log an error with optional exception and context.

    Args:
        message: The error message
        exc: Optional exception that caused the error
        **context: Additional context information to log
    """
    if context:
        message = f"{message} | Context: {_sanitize_context(context)}"

    if exc:
        logger.error(message, exc_info=exc)
    else:
        logger.error(message)


def log_warning(message: str, **context: Any) -> None:
    """Log a warning with optional context.

    Args:
        message: The warning message
        **context: Additional context information to log
    """
    if context:
        message = f"{message} | Context: {_sanitize_context(context)}"

    logger.warning(message)


def log_info(message: str, **context: Any) -> None:
    """Log an informational message with optional context.

    Args:
        message: The info message
        **context: Additional context information to log
    """
    if context:
        message = f"{message} | Context: {_sanitize_context(context)}"

    logger.info(message)


def log_debug(message: str, **context: Any) -> None:
    """Log a debug message with optional context.

    Args:
        message: The debug message
        **context: Additional context information to log
    """
    if context:
        message = f"{message} | Context: {_sanitize_context(context)}"

    logger.debug(message)
