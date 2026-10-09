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
