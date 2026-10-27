"""Machine-readable codes for failed tool calls.

A failed tool call keeps its human message and gains a code, so a client that
aggregates this server (and cannot parse prose) can tell a dead credential from
a missing permission from a transient outage. The wire form is a JSON text block
``{"error": "<CODE>", "message": "<human text>"}`` with ``isError`` set; see
``CanvasToolResultMiddleware``.

The Canvas client records the code at the point of failure, where the HTTP
status is known, into a holder that the middleware opens around each tool call.
The holder is a plain list in a ContextVar, so tasks started by a tool (a
``gather`` of sub-requests) append to the same list.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

CREDENTIAL_INVALID = "CREDENTIAL_INVALID"
PERMISSION_DENIED = "PERMISSION_DENIED"
RATE_LIMITED = "RATE_LIMITED"
INVALID_ARGUMENT = "INVALID_ARGUMENT"
SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"

ERROR_CODES = frozenset(
    {CREDENTIAL_INVALID, PERMISSION_DENIED, RATE_LIMITED, INVALID_ARGUMENT, SOURCE_UNAVAILABLE}
)

# Canvas answers 403 "Rate Limit Exceeded" instead of 429 when a token's request
# budget is spent.
_RATE_LIMIT_TEXT = re.compile(r"rate.?limit", re.IGNORECASE)

_INVALID_STATUSES = frozenset({400, 404, 409, 410, 422})

_failures: ContextVar[list[str] | None] = ContextVar("tool_failure_codes", default=None)


def code_for_status(status: int, body: str = "") -> str:
    """The code for a Canvas HTTP failure.

    A 401 that was not confirmed as a dead token (see ``core.token_health``) is a
    permission problem, as is every 403.
    """
    if status == 429 or (status == 403 and _RATE_LIMIT_TEXT.search(body)):
        return RATE_LIMITED
    if status in (401, 403):
        return PERMISSION_DENIED
    if status in _INVALID_STATUSES:
        return INVALID_ARGUMENT
    return SOURCE_UNAVAILABLE


@contextmanager
def capture_failures() -> Iterator[list[str]]:
    """Collect the codes recorded while one tool call runs."""
    codes: list[str] = []
    token = _failures.set(codes)
    try:
        yield codes
    finally:
        _failures.reset(token)


def record_failure(code: str) -> None:
    """Note a failed Canvas call for the tool call in progress (no-op outside one)."""
    codes = _failures.get()
    if codes is not None:
        codes.append(code)


def summarize(codes: list[str]) -> str | None:
    """One code for a tool call that recorded several.

    A dead credential explains everything else that failed with it; otherwise the
    last failure is the one the tool reported.
    """
    if not codes:
        return None
    if CREDENTIAL_INVALID in codes:
        return CREDENTIAL_INVALID
    return codes[-1]


def refuse(code: str, message: str) -> str:
    """Return ``message`` as a tool's refusal and record ``code`` for it.

    For refusals decided locally, before or without a Canvas answer, where the
    reason is known at the source and wording should not have to be guessed.
    """
    record_failure(code)
    return message


# An unconfirmed "token is invalid": a 401 the probe did not confirm is a
# permission problem; only the confirmed token-health path says CREDENTIAL_INVALID.
_PERMISSION_TEXT = re.compile(
    r"do(es)? not have permission|don't have permission|not authori[sz]ed|unauthori[sz]ed|forbidden|access denied"
    r"|permission denied|check permissions|insufficient (scope|permission)|token is invalid|invalid (access )?token",
    re.IGNORECASE,
)
_UNAVAILABLE_TEXT = re.compile(
    r"request failed|timed out|timeout|connection (error|refused|reset)|max retries exceeded|upload failed"
    r"|service unavailable|bad gateway|storage upload failed|unexpected error",
    re.IGNORECASE,
)


_FENCED_BLOCK = re.compile(
    r"<<<UNTRUSTED\s+CANVAS\s+CONTENT.*?<<<END\s+UNTRUSTED\s+CANVAS\s+CONTENT>>>",
    re.IGNORECASE | re.DOTALL,
)
# Inline fenced content may itself contain newlines; bounded so a stray opening
# marker cannot swallow an arbitrarily long message (that case is the
# unterminated rule below).
_FENCED_INLINE = re.compile(r"<<<UNTRUSTED\s+CANVAS\s+CONTENT.{0,4000}?>>>", re.IGNORECASE | re.DOTALL)
_FENCE_OPEN = re.compile(r"<<<UNTRUSTED\s+CANVAS\s+CONTENT.*", re.IGNORECASE | re.DOTALL)


def without_untrusted_content(text: str) -> str:
    """``text`` with every fenced span of Canvas-authored content removed.

    Names, titles and bodies come from Canvas users, so wording inside the
    fences must never decide a code. An opening marker with no end (a truncated
    message) drops everything after it.
    """
    text = _FENCED_BLOCK.sub(" ", text)
    text = _FENCED_INLINE.sub(" ", text)
    return _FENCE_OPEN.sub(" ", text)


def code_for_text(text: str, default: str = INVALID_ARGUMENT) -> str:
    """Last resort when no code was recorded at the source.

    Never returns CREDENTIAL_INVALID: that needs the confirmed token-health
    path or an explicit ``refuse(CREDENTIAL_INVALID, ...)`` at the source.
    Fenced untrusted content is ignored.

    A local refusal (not found, bad value, a tool that only runs on a local
    server) is the caller's to fix, so ``default`` is INVALID_ARGUMENT; only
    wording that names a network or availability failure maps to
    SOURCE_UNAVAILABLE.
    """
    text = without_untrusted_content(text)
    if _RATE_LIMIT_TEXT.search(text):
        return RATE_LIMITED
    if _PERMISSION_TEXT.search(text):
        return PERMISSION_DENIED
    if _UNAVAILABLE_TEXT.search(text):
        return SOURCE_UNAVAILABLE
    return default
