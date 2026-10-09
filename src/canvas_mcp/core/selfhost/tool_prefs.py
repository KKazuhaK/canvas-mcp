"""Per-user opt-in for write tools in the self-hosted multi-user mode.

Four layers decide whether a write tool can act for a user:

1. the operator's ``ALLOWED_WRITE_TOOLS`` (the server ceiling): a tool that is not
   allowed is not even registered, see :mod:`canvas_mcp.core.tool_policy`;
2. the user's own switch, kept in the token database and changed only from the
   signed-in ``/account`` page (this module);
3. the course policy (``agent_writes`` in the syllabus), checked at call time;
4. the preview and confirmation step of the tool itself.

The effective set is ``registered ∩ ALLOWED_WRITE_TOOLS ∩ user-enabled``, and the
course policy narrows it further at call time. The user layer can only narrow:
no stored value can bring back a tool the operator did not allow. By default a
user has nothing enabled, and a tool the operator adds to ``ALLOWED_WRITE_TOOLS``
later is not switched on for anyone; each user turns it on by name.

Anything that is not a read tool counts as a write tool (a name that
:data:`~canvas_mcp.core.tool_policy.TOOL_EFFECTS` does not know fails closed).
Code execution can never be switched on by a user.

No MCP tool reads or changes these preferences, so a prompt-injected model cannot
widen them. The credential gate enforces them on every call (the security
boundary) and hides tools that are switched off from the tool list (a convenience
for the model, not a boundary).
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Collection, Iterable
from enum import StrEnum
from typing import Protocol

from ..tool_policy import TOOL_EFFECTS, Effect
from .token_store import ToolPrefs

# How the write tools are grouped on /account. Tools outside these groups (for
# example the educator tools an operator may allow) are shown in a final group.
WRITE_TOOL_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "planner",
        (
            "create_planner_note",
            "update_planner_note",
            "delete_planner_note",
            "mark_planner_item_complete",
            "create_personal_calendar_event",
            "delete_personal_calendar_event",
        ),
    ),
    ("submissions", ("submit_assignment", "comment_on_my_submission")),
    ("modules", ("mark_module_item_done",)),
    ("inbox", ("send_message", "reply_to_conversation")),
)
OTHER_GROUP = "other"

DEFAULT_CACHE_SECONDS = 30.0
_MAX_CACHED_USERS = 2048
_MAX_TOOL_NAME_IN_MESSAGE = 64


class WriteDecision(StrEnum):
    """What the per-user layer says about one tool call."""

    ALLOWED = "allowed"
    NOT_OFFERED = "not_offered"
    NOT_ENABLED = "not_enabled"


def is_write_tool(name: str) -> bool:
    """True for every tool that is not classified as read-only (unknown names fail closed)."""
    return TOOL_EFFECTS.get(name) is not Effect.READ


def user_can_enable(name: str) -> bool:
    """Whether a user may ever switch this tool on: a write tool, but never code execution."""
    return is_write_tool(name) and TOOL_EFFECTS.get(name) is not Effect.CODE_EXEC


def offered_write_tools(
    registered: Iterable[str], ceiling: Collection[str] | None
) -> frozenset[str]:
    """The write tools users may switch on: registered, inside the server ceiling.

    ``ceiling`` is the operator's ``ALLOWED_WRITE_TOOLS`` set; None means the
    registry itself is the ceiling.
    """
    return frozenset(
        name
        for name in registered
        if user_can_enable(name) and (ceiling is None or name in ceiling)
    )


def effective_write_tools(offered: Collection[str], enabled: Collection[str]) -> frozenset[str]:
    """``offered ∩ enabled``: stored names the server does not offer are ignored."""
    return frozenset(name for name in enabled if name in offered)


def decide(
    name: str, *, enabled: Collection[str], ceiling: Collection[str] | None
) -> WriteDecision:
    """May this call go ahead as far as the server ceiling and the user's switches go?

    Read tools always may. The course policy and the confirmation step are
    separate checks that still follow.
    """
    if not is_write_tool(name):
        return WriteDecision.ALLOWED
    if not user_can_enable(name) or (ceiling is not None and name not in ceiling):
        return WriteDecision.NOT_OFFERED
    if name in enabled:
        return WriteDecision.ALLOWED
    return WriteDecision.NOT_ENABLED


def _printable_name(name: str) -> str:
    """A tool name that is safe to put into a message (the name comes from the client)."""
    if (
        1 <= len(name) <= _MAX_TOOL_NAME_IN_MESSAGE
        and name.isascii()
        and all(ch.isalnum() or ch == "_" for ch in name)
    ):
        return name
    return "this tool"


def write_tool_off_message(tool: str, account_url: str | None) -> str:
    """The refusal for a write tool the user has not switched on."""
    where = f"{account_url} (Write tools)" if account_url else "your account page (Write tools)"
    return (
        f"The write tool '{_printable_name(tool)}' is turned off for your account. "
        f"You can turn it on at {where}. "
        "(The server operator allows it; your course may still restrict it.)"
    )


def write_tool_not_offered_message(tool: str) -> str:
    """The refusal for a write tool the server does not offer at all."""
    return f"The write tool '{_printable_name(tool)}' is not offered on this server."


def prefs_unreadable_message() -> str:
    """The refusal when the user's preferences could not be read (writes stay off)."""
    return (
        "Your write-tool settings could not be read right now, so write tools are "
        "off. Try again in a moment."
    )


class ToolPrefsSource(Protocol):
    """The slice of the token store the cache reads."""

    def get_tool_prefs(self, principal_key: str) -> ToolPrefs | None: ...


class ToolPrefsCache:
    """Per-principal cache of the switched-on tool names, valid for a short time.

    ``enabled`` reads the database at most once per ``ttl_seconds`` per user, and
    :meth:`invalidate` drops a user at once when they change a switch. With several
    server processes a change reaches the other processes within the TTL.
    Failures are never cached and propagate, so the caller can fail closed.
    Synchronous and thread-safe; async callers use ``anyio.to_thread.run_sync``.
    """

    def __init__(
        self,
        source: ToolPrefsSource,
        *,
        ttl_seconds: float = DEFAULT_CACHE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = _MAX_CACHED_USERS,
    ) -> None:
        self._source = source
        self._ttl = ttl_seconds
        self._clock = clock
        self._max = max_entries
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, tuple[float, frozenset[str]]] = OrderedDict()
        # Bumped by every invalidation, so a read that started before one cannot
        # store its (possibly old) result afterwards.
        self._epoch = 0

    def enabled(self, principal_key: str) -> frozenset[str]:
        """The names this principal has switched on (empty if never saved)."""
        now = self._clock()
        with self._lock:
            entry = self._entries.get(principal_key)
            if entry is not None and entry[0] > now:
                return entry[1]
            epoch = self._epoch
        prefs = self._source.get_tool_prefs(principal_key)
        names = prefs.enabled_write_tools if prefs is not None else frozenset()
        with self._lock:
            if epoch == self._epoch:
                self._entries[principal_key] = (self._clock() + self._ttl, names)
                self._entries.move_to_end(principal_key)
                while len(self._entries) > self._max:
                    self._entries.popitem(last=False)
        return names

    def invalidate(self, principal_key: str | None = None) -> None:
        """Forget one principal (or everyone) so the next read goes to the database."""
        with self._lock:
            self._epoch += 1
            if principal_key is None:
                self._entries.clear()
            else:
                self._entries.pop(principal_key, None)


class WriteToolCatalog:
    """Which write tools this server offers: registered tools inside the server ceiling.

    ``list_registered`` is called each time (the registry is the source of truth),
    so the catalog never goes stale against what is really registered.
    """

    def __init__(
        self,
        *,
        ceiling: Collection[str] | None,
        list_registered: Callable[[], Awaitable[Iterable[str]]],
    ) -> None:
        self.ceiling: frozenset[str] | None = None if ceiling is None else frozenset(ceiling)
        self._list_registered = list_registered

    async def offered(self) -> frozenset[str]:
        return offered_write_tools(await self._list_registered(), self.ceiling)
