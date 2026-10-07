"""Which MCP client is calling, for results whose wire shape depends on it.

``read_course_file`` returns the course file itself as an embedded resource
(``EmbeddedResource`` with ``BlobResourceContents``), which is the
spec-compliant way to hand a client a file. Some clients handle that badly, so
the tool needs to know who is asking.

The first answer is the ``clientInfo`` the client sent. It is known when the
session keeps the ``initialize`` handshake (stdio, in-memory, stateful HTTP) or
when the request envelope carries it (2026-07-28 protocol, where it is still
optional). Names were read from the clients themselves on 2026-10-02:

- Claude Code 2.1.286 builds its MCP client as ``{name: "claude-code"}``. It
  saves a non-image blob to ``tool-results/`` and tells the model the path, so
  the model opens it with Read exactly as it would an attached file.
- Claude Desktop 2.19675 (chat) and claude.ai connectors build theirs as
  ``{name: "claude-ai", version: "0.1.0"}``. They have no Read tool, and their
  handling of blob resources in tool results is broken (``-32602`` invalid
  ``tools/call`` result, blobs misread), so they get extracted text instead.

The hosted server runs ``http_app(stateless_http=True)``: every request is
handled on a fresh connection, so on a handshake-era protocol (2024-11-05 to
2025-11-25) the ``initialize`` clientInfo is gone by the time a tool runs and
the client is unnamed for everybody, claude.ai connectors included. Over HTTP
an unnamed client is therefore judged by its ``User-Agent``: Claude Code's MCP
HTTP/SSE transports send ``claude-code/<version>`` (read from the 2.1.285
binary), and they get the file. Any other unnamed HTTP client gets text,
because the remote clients of a hosted server are mostly connectors, and text
always arrives while a blob can fail the whole call there.

A named client is matched by exact name, and a client not on the list gets
the spec-compliant file result, as does an unnamed client on a local (stdio)
server: only clients known to break are special-cased.

The result-size cap (``client_needs_result_cap``) uses the same two signals but
errs the other way for unnamed HTTP clients. claude.ai accepts only about 150k
characters per tool result, while Claude Code honours the larger
``anthropic/maxResultSizeChars``. Stateless HTTP leaves claude.ai unnamed on
handshake-era protocols, so unnamed non-Claude-Code HTTP clients are treated
like connectors and capped. A named client is capped only when it is on
``RESULT_CAPPED_CLIENTS``, and a call with no HTTP request (stdio, in-memory)
is never capped.
"""

from fastmcp.server.dependencies import get_context, get_http_request

#: ``clientInfo.name`` values of clients known to mishandle embedded-resource
#: blobs in a tool result.
BLOB_INCAPABLE_CLIENTS = frozenset({"claude-ai"})

#: ``clientInfo.name`` values of clients that reject tool results above about
#: 150k characters (claude.ai connectors and Claude Desktop chat).
RESULT_CAPPED_CLIENTS = frozenset({"claude-ai"})

#: Start of the ``User-Agent`` Claude Code's MCP HTTP and SSE transports send.
CLAUDE_CODE_USER_AGENT_PREFIX = "claude-code/"


def current_client_name() -> str | None:
    """The calling client's ``clientInfo.name``, or None when it is unknown."""
    try:
        params = get_context().session.client_params
    except (RuntimeError, AttributeError, LookupError):
        return None
    info = getattr(params, "client_info", None)
    name = getattr(info, "name", None)
    return name if isinstance(name, str) else None


def _http_user_agent() -> str | None:
    """The HTTP ``User-Agent`` ("" when absent), or None when not over HTTP."""
    try:
        request = get_http_request()
    except RuntimeError:
        return None
    return request.headers.get("user-agent", "")


def client_mishandles_file_blobs() -> bool:
    """True when a blob resource in a result should not be sent to this client.

    A named client is judged by name. An unnamed one is given the file on a
    local server, and over HTTP only when its User-Agent is Claude Code's.
    """
    name = current_client_name()
    if name is not None:
        return name in BLOB_INCAPABLE_CLIENTS
    user_agent = _http_user_agent()
    if user_agent is None:
        return False
    return not user_agent.lower().startswith(CLAUDE_CODE_USER_AGENT_PREFIX)


def client_needs_result_cap() -> bool:
    """True when a tool result's text should be cut to the claude.ai limit.

    A named client is judged by name. An unnamed one is never capped when there
    is no HTTP request (stdio, in-memory), and over HTTP is capped unless its
    User-Agent is Claude Code's.
    """
    name = current_client_name()
    if name is not None:
        return name in RESULT_CAPPED_CLIENTS
    user_agent = _http_user_agent()
    if user_agent is None:
        return False
    return not user_agent.lower().startswith(CLAUDE_CODE_USER_AGENT_PREFIX)
