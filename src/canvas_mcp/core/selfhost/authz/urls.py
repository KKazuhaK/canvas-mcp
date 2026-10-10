"""URL rules of the authorization server, as pure functions.

* The issuer and the audience are exact strings that several parties compare
  byte for byte, so they are built in one place (:func:`issuer_of`, :func:`audience_of`).
* A redirect URI is only ever matched by :func:`redirect_matches`: exact string
  equality, with the one RFC 8252 exception for loopback http redirects, whose port is
  chosen by the client at run time.
* A ``resource`` indicator (RFC 8707) is compared after :func:`normalize_resource`.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from pydantic import AnyHttpUrl

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
MAX_REDIRECT_URI_CHARS = 2048
_DEFAULT_PORTS = {"https": 443, "http": 80}
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f-\x9f\\]")


def issuer_of(base_url: str) -> str:
    """The issuer string: ``str(AnyHttpUrl(base))``, which has a trailing slash.

    Every place that names the issuer (the metadata ``issuer``, the protected-resource
    metadata, the ``iss`` claim, the RFC 9207 ``iss`` parameter) uses this one string.
    """
    return str(AnyHttpUrl(base_url))


def audience_of(base_url: str, mcp_path: str) -> str:
    """The audience of access tokens: the MCP endpoint URL, with no trailing slash."""
    return base_url.rstrip("/") + mcp_path


def is_canonical_base(base_url: str) -> bool:
    """True for ``scheme://host[:port]`` in lower case, no default port, path, query, fragment or userinfo."""
    try:
        parts = urlsplit(base_url)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme not in ("https", "http") or not parts.hostname:
        return False
    if parts.path or parts.query or parts.fragment or "@" in parts.netloc:
        return False
    if base_url != base_url.lower() or base_url.endswith("/"):
        return False
    return port is None or port != _DEFAULT_PORTS[parts.scheme]


def host_of(url: str) -> str:
    """The lower-case host of a URL (no brackets), or an empty string."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def is_loopback_host(host: str) -> bool:
    return host.lower() in LOOPBACK_HOSTS


def normalize_resource(value: str) -> str | None:
    """A resource indicator in comparable form, or None if it cannot be one.

    Lower-case scheme and host, the default port dropped, one trailing slash stripped.
    A fragment, a query or user information make it unusable (RFC 8707 forbids a
    fragment, and the audience of this server has none of the others).
    """
    if not isinstance(value, str) or not value or len(value) > MAX_REDIRECT_URI_CHARS:
        return None
    if _CONTROL_OR_SPACE.search(value) or "#" in value or "?" in value:
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("https", "http") or not host or "@" in parts.netloc:
        return None
    shown = f"[{host}]" if ":" in host else host
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        shown = f"{shown}:{port}"
    path = parts.path
    if path.endswith("/"):
        path = path[:-1]
    return f"{scheme}://{shown}{path}"


def _has_dot_segment(path: str) -> bool:
    for candidate in (path, unquote(path), unquote(unquote(path))):
        if any(segment in (".", "..") for segment in candidate.split("/")):
            return True
    return False


def redirect_uri_syntax_ok(uri: str) -> bool:
    """Whether ``uri`` may ever be a redirect URI of a client.

    ``https`` on a host that is not a loopback name, or ``http`` on ``localhost``,
    ``127.0.0.1`` or ``[::1]``. Never user information, a fragment, a wildcard, a
    backslash, whitespace or a dot segment (also percent-encoded), at most 2048
    characters, and the path starts with ``/``.
    """
    if not isinstance(uri, str) or not uri or len(uri) > MAX_REDIRECT_URI_CHARS:
        return False
    if _CONTROL_OR_SPACE.search(uri) or "*" in uri or "#" in uri:
        return False
    try:
        parts = urlsplit(uri)
        parts.port  # noqa: B018 - raises ValueError for a bad port
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    if not host or "@" in parts.netloc or not parts.path.startswith("/"):
        return False
    if _has_dot_segment(parts.path):
        return False
    scheme = parts.scheme.lower()
    if uri[: len(scheme)] != scheme:  # an upper-case scheme is not an exact match anywhere
        return False
    if scheme == "https":
        return host not in LOOPBACK_HOSTS and not host.endswith(".localhost")
    if scheme == "http":
        return host in LOOPBACK_HOSTS
    return False


def redirect_matches(candidate: str, registered: str) -> bool:
    """Exact string equality, except for loopback http redirects.

    RFC 8252 section 7.3: a native app picks a free port at run time, so a registered
    loopback ``http`` URI **without a port** matches the same URI with any port. Host,
    path and query must still be equal, ``localhost`` is never matched with
    ``127.0.0.1`` or ``::1`` and the other way round, and ``*`` is an ordinary
    character (there are no wildcards anywhere).
    """
    if candidate == registered:
        return True
    try:
        cand, reg = urlsplit(candidate), urlsplit(registered)
        cand_port, reg_port = cand.port, reg.port
    except ValueError:
        return False
    if cand.scheme != "http" or reg.scheme != "http" or reg_port is not None:
        return False
    cand_host, reg_host = (cand.hostname or "").lower(), (reg.hostname or "").lower()
    if cand_host != reg_host or reg_host not in LOOPBACK_HOSTS:
        return False
    if "@" in cand.netloc or cand.fragment or cand_port == 0:
        return False
    return cand.path == reg.path and cand.query == reg.query
