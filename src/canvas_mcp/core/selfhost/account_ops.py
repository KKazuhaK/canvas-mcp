"""Outcome types of the account operations shared by the HTML pages and the JSON API.

The security-critical sequences of ``/account`` (enrolling or replacing a token,
re-checking it, saving the write-tool switches, the owner's access actions) are
written once, as methods of :class:`~.account_web._AccountApp`. They return the
types below instead of rendering anything. The legacy pages turn an outcome into
today's HTML message and status; :mod:`.account_api` turns the same outcome into a
JSON error code. A check can therefore not be dropped from one surface and kept in
the other.

A refusal carries a code from the closed API code set (``account_api.API_ERROR_CODES``)
and scalar parameters only. It never carries upstream text.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

from .token_store import ToolPrefs

#: The outcomes of a link ceremony that a browser lands on as ``?error=`` (a closed set; never
#: provider text).
LINK_ERROR_CODES = frozenset(
    {
        "identity_in_use",
        "provider_already_linked",
        "access_denied",
        "link_session_ended",
        "provider_error",
        "provider_unavailable",
        "state_invalid",
        "sign_in_unverified",
        "sign_in_incomplete",
        "token_store_unavailable",
        "reauth_required",
        "rate_limited",
    }
)


@dataclass(frozen=True)
class Refusal:
    """An operation that did not happen, and why (a closed code plus scalar parameters)."""

    code: str
    params: Mapping[str, str | int] = field(default_factory=dict)


@dataclass(frozen=True)
class Rechecked:
    """A completed "check again": the token was brought back, or nothing changed."""

    result: Literal["restored", "unchanged"]


@dataclass(frozen=True)
class WriteToolsSnapshot:
    """What the server offers and what the account has switched on, read together."""

    offered: frozenset[str]
    prefs: ToolPrefs | None

    @property
    def current(self) -> frozenset[str]:
        return self.prefs.enabled_write_tools if self.prefs is not None else frozenset()


@dataclass(frozen=True)
class WriteSaved:
    """The write-tool switches were saved, or the request changed nothing."""

    result: Literal["saved", "unchanged"]


@dataclass(frozen=True)
class LinkStarted:
    """A link ceremony was prepared: set the cookie, then send the browser to ``url``.

    The cookie (``cookie_name``) holds the sealed ceremony cookie of the provider; ``url`` is the
    provider's authorization URL. Starting a link never changes the account.
    """

    url: str
    provider_id: str
    cookie_name: str
    cookie_value: str
    max_age: int


@dataclass(frozen=True)
class Linked:
    """An identity of ``provider_id`` is now (or already was) linked to the account."""

    provider_id: str


@dataclass(frozen=True)
class Unlinked:
    """An identity was removed. Every session of the account ended with the epoch bump.

    ``session_cookie`` is a re-issued session cookie for the caller (the new epoch) when the
    caller signed in with another provider; otherwise ``signed_out`` is true and the caller's
    cookie must be cleared.
    """

    provider_id: str
    signed_out: bool
    session_cookie: str | None = None


@dataclass(frozen=True)
class IdentityView:
    """One linked identity as the sign-in methods screen shows it."""

    id: int
    provider_id: str
    username: str
    email: str | None
    email_verified: bool
    linked_at: int
    last_login_at: int | None
    #: The identity the caller's current session signed in with.
    current: bool
    #: False for the only identity the account has.
    can_unlink: bool
