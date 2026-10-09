"""Remove credentials from text before it reaches a log.

Log lines and audit events carry exception messages and request paths that
nobody wrote with logging in mind: an httpx error quotes the full URL, an
OAuth callback carries ``code=`` and ``state=`` in its query string, and a
stack frame can show an ``Authorization`` header. :func:`scrub_secrets`
replaces the credential shapes this server handles with ``[redacted]``.

It works on shapes, not on knowledge of the actual secrets, so it is a
backstop behind the rule that code never logs a credential on purpose.
"""

from __future__ import annotations

import logging
import re
from typing import Any

REDACTED = "[redacted]"

_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]*)?")
# Canvas personal access tokens look like "<id>~<64 characters>".
_CANVAS_TOKEN_RE = re.compile(r"\b\d{1,8}~[A-Za-z0-9]{20,}\b")
# Entra refresh tokens are opaque and start with "0.A"; Fernet tokens (the
# FastMCP OAuth state store) start with "gAAAA".
_ENTRA_REFRESH_RE = re.compile(r"\b0\.A[A-Za-z0-9_.-]{40,}")
_FERNET_RE = re.compile(r"\bgAAAA[A-Za-z0-9_=-]{20,}")
_USERINFO_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@")
_SECRET_PARAM_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])"
    r"(code|state|access_token|refresh_token|id_token|token|client_secret|"
    r"client_assertion|assertion|code_verifier|password|passwd|secret|"
    r"session|sig|signature|api_key|apikey|authorization)"
    r"(=|%3D|\":\s*\"|':\s*')"
    r"([^&\s\"'<>]+)"
)
# "code" and "state" also appear as short, harmless values ("state=open").
_SHORT_OK_PARAMS = frozenset({"code", "state"})
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _param(match: re.Match[str]) -> str:
    name, joiner, value = match.group(1), match.group(2), match.group(3)
    if name.lower() in _SHORT_OK_PARAMS and len(value) < 8:
        return match.group(0)
    return f"{name}{joiner}{REDACTED}"


def scrub_secrets(text: str, *, emails: bool = False) -> str:
    """Replace credentials in ``text`` with ``[redacted]``.

    ``emails=True`` also replaces e-mail addresses, for free-form text that
    can echo what a user typed.
    """
    if not text:
        return text
    text = _USERINFO_RE.sub(lambda m: f"{m.group(1)}{REDACTED}@", text)
    text = _BEARER_RE.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    text = _JWT_RE.sub(REDACTED, text)
    text = _CANVAS_TOKEN_RE.sub(REDACTED, text)
    text = _ENTRA_REFRESH_RE.sub(REDACTED, text)
    text = _FERNET_RE.sub(REDACTED, text)
    text = _SECRET_PARAM_RE.sub(_param, text)
    if emails:
        text = _EMAIL_RE.sub(REDACTED, text)
    return text


def strip_query(target: str) -> str:
    """Drop the query string and fragment of a path or URL (``?code=...``)."""
    return target.split("?", 1)[0].split("#", 1)[0]


class SecretScrubFilter(logging.Filter):
    """A logging filter that scrubs the message and traceback of each record."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # a broken format string: leave the record alone
            return True
        record.msg = scrub_secrets(message)
        record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = scrub_secrets(record.exc_text)
        return True


def scrub_event(value: Any) -> Any:
    """Scrub every string inside an audit event (dicts, lists, strings)."""
    if isinstance(value, str):
        return scrub_secrets(value)
    if isinstance(value, dict):
        return {key: scrub_event(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [scrub_event(item) for item in value]
    return value
