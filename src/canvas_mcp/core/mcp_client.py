"""Which MCP client is calling, for results whose wire shape depends on it.

``read_course_file`` returns the course file itself as an embedded resource
(``EmbeddedResource`` with ``BlobResourceContents``), which is the
spec-compliant way to hand a client a file. Some clients handle that badly, so
the tool needs to know who is asking.

The answer comes from the ``clientInfo`` the client sent in ``initialize`` (or,
on the 2026-07-28 protocol, in the request envelope). Names were read from the
clients themselves on 2026-10-02:

- Claude Code 2.1.286 builds its MCP client as ``{name: "claude-code"}``. It
  saves a non-image blob to ``tool-results/`` and tells the model the path, so
  the model opens it with Read exactly as it would an attached file.
- Claude Desktop 2.19675 (chat) and claude.ai connectors build theirs as
  ``{name: "claude-ai", version: "0.1.0"}``. They have no Read tool, and their
  handling of blob resources in tool results is broken (``-32602`` invalid
  ``tools/call`` result, blobs misread), so they get extracted text instead.

Clients are matched by exact name. A client that sends no name, or one not
listed, gets the spec-compliant file result: only clients known to break are
special-cased, so a new or fixed client is never silently downgraded.
"""

from fastmcp.server.dependencies import get_context

#: ``clientInfo.name`` values of clients known to mishandle embedded-resource
#: blobs in a tool result.
BLOB_INCAPABLE_CLIENTS = frozenset({"claude-ai"})


def current_client_name() -> str | None:
    """The calling client's ``clientInfo.name``, or None when it is unknown."""
    try:
        params = get_context().session.client_params
    except (RuntimeError, AttributeError, LookupError):
        return None
    info = getattr(params, "client_info", None)
    name = getattr(info, "name", None)
    return name if isinstance(name, str) else None


def client_mishandles_file_blobs() -> bool:
    """True only for a client known to break on a blob resource in a result."""
    return current_client_name() in BLOB_INCAPABLE_CLIENTS
