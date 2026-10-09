"""Which Canvas schools users of the self-hosted mode may enroll at.

Every user brings their own Canvas token *and* their own school. This module
is the single place that decides which hosts are acceptable and the only place
that turns a stored host into an API URL:

* syntax rules for a school host name (:func:`parse_hostname`);
* address rules for what that name resolves to (:func:`is_public_address`,
  :func:`check_public_host`), so a school can never point the server at a
  private or cloud-metadata address;
* a client for Instructure's public school directory, the same one the Canvas
  mobile app uses (:class:`SchoolDirectory`);
* the operator's :class:`SchoolPolicy`: a default school (``CANVAS_API_URL``),
  featured schools, and whether the directory search is enabled.

Nothing here performs I/O at import time or at settings load time.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Final, Literal, Protocol
from urllib.parse import urlsplit

import anyio
import anyio.to_thread
import httpx

INSTRUCTURE_DIRECTORY_URL: Final = "https://canvas.instructure.com"
DIRECTORY_SEARCH_PATH: Final = "/api/v1/accounts/search"

MIN_QUERY_CHARS: Final = 2
MAX_QUERY_CHARS: Final = 64
SEARCH_RESULTS: Final = 10
CONFIRM_RESULTS: Final = 50
MAX_SCHOOL_NAME: Final = 120
MAX_FEATURED: Final = 50

_MAX_HOST_CHARS = 253
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_FORBIDDEN_HOST_CHARS = frozenset(":/@?#[]\\%")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# Names that never belong to a public school: local, internal and reserved
# suffixes. "home.arpa" is matched by its last label ("arpa").
_BLOCKED_SUFFIXES = frozenset(
    {
        "localhost",
        "local",
        "internal",
        "lan",
        "home",
        "corp",
        "intranet",
        "localdomain",
        "arpa",
        "invalid",
        "test",
        "example",
        "onion",
    }
)

_METADATA_ADDRS = frozenset(
    {"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"}
)
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")

RESOLVE_TIMEOUT_SECONDS = 5.0


# -- host names ----------------------------------------------------------------


def parse_hostname(raw: str) -> str | None:
    """The lowercase host name for ``raw``, or None when it is not a plain DNS name.

    Syntax only (no lookups): ASCII, at least two valid labels, no scheme,
    port, path, user information, trailing dot or IP literal.
    """
    if not isinstance(raw, str):
        return None
    host = raw.strip().lower()
    if not host or len(host) > _MAX_HOST_CHARS or not host.isascii():
        return None
    for ch in host:
        if ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F or ch in _FORBIDDEN_HOST_CHARS:
            return None
    if host.endswith("."):
        return None
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(label) for label in labels):
        return None
    # A numeric top-level label is never a real TLD; this also blocks the
    # dotted-quad and short-hand IPv4 spellings such as 1.2.3.4 or 0x7f.1.
    if labels[-1].isdigit():
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    return None


def is_blocked_hostname(host: str) -> bool:
    """True for names that are local or internal by convention (localhost, *.local, ...)."""
    labels = host.strip().lower().split(".")
    if not labels or not labels[-1]:
        return True
    return labels[-1] in _BLOCKED_SUFFIXES


# -- addresses -----------------------------------------------------------------


def is_public_address(addr: str) -> bool:
    """True only for a globally routable unicast address.

    An IPv6 address that embeds an IPv4 address (IPv4-mapped, 6to4, NAT64) is
    judged by the IPv4 address inside it; Teredo is refused outright.
    """
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.teredo is not None:
            return False
        embedded = ip.ipv4_mapped
        if embedded is None:
            embedded = ip.sixtofour
        if embedded is None and ip in _NAT64_PREFIX:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if embedded is not None:
            return is_public_address(str(embedded))
    return not (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or str(ip) in _METADATA_ADDRS
    )


HostResolver = Callable[[str], Awaitable[Sequence[str]]]


async def system_resolve(host: str) -> Sequence[str]:
    """Resolve ``host`` with the system resolver (in a thread, bounded in time)."""
    with anyio.fail_after(RESOLVE_TIMEOUT_SECONDS):
        infos = await anyio.to_thread.run_sync(
            socket.getaddrinfo, host, 443, 0, socket.SOCK_STREAM
        )
    return sorted({str(info[4][0]) for info in infos})


async def check_public_host(
    host: str, resolve: HostResolver
) -> Literal["ok", "unresolvable", "blocked"]:
    """Resolve ``host``; refuse it if ANY address it resolves to is not public."""
    try:
        addresses = list(await resolve(host))
    except Exception:  # noqa: BLE001 - OSError, a timeout or a broken resolver all fail closed
        return "unresolvable"
    if not addresses:
        return "unresolvable"
    if not all(is_public_address(addr) for addr in addresses):
        return "blocked"
    return "ok"


# -- the directory -------------------------------------------------------------


class DirectoryError(Exception):
    """The school directory could not answer (network, status or format)."""


@dataclass(frozen=True)
class DirectoryEntry:
    name: str
    domain: str


class SchoolDirectoryLike(Protocol):
    async def search(self, term: str, *, limit: int = SEARCH_RESULTS) -> list[DirectoryEntry]: ...

    async def confirm(self, host: str) -> DirectoryEntry | None: ...


def _clean_name(raw: object, fallback: str) -> str:
    text = _CONTROL_RE.sub(" ", raw) if isinstance(raw, str) else ""
    text = " ".join(text.split())[:MAX_SCHOOL_NAME].strip()
    return text or fallback


class SchoolDirectory:
    """Instructure's public school directory (an undocumented, unauthenticated API)."""

    def __init__(
        self,
        client_factory: Callable[[], httpx.AsyncClient],
        base_url: str = INSTRUCTURE_DIRECTORY_URL,
        timeout: float = 8.0,
    ) -> None:
        self._client_factory = client_factory
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    async def search(self, term: str, *, limit: int = SEARCH_RESULTS) -> list[DirectoryEntry]:
        try:
            async with self._client_factory() as client:
                resp = await client.get(
                    self._base_url + DIRECTORY_SEARCH_PATH,
                    params={"search_term": term, "per_page": str(limit)},
                    headers={"Accept": "application/json"},
                    timeout=self._timeout,
                    follow_redirects=False,
                )
            if resp.status_code != 200:
                raise DirectoryError("directory returned an unexpected status")
            data = resp.json()
        except DirectoryError:
            raise
        except (httpx.HTTPError, ValueError):
            raise DirectoryError("directory request failed") from None
        if not isinstance(data, list):
            raise DirectoryError("directory returned an unexpected body")
        entries: list[DirectoryEntry] = []
        seen: set[str] = set()
        for item in data:
            if not isinstance(item, dict):
                continue
            domain_raw = item.get("domain")
            domain = parse_hostname(domain_raw) if isinstance(domain_raw, str) else None
            if domain is None or domain in seen:
                continue
            seen.add(domain)
            entries.append(DirectoryEntry(_clean_name(item.get("name"), domain), domain))
            if len(entries) >= limit:
                break
        return entries

    async def confirm(self, host: str) -> DirectoryEntry | None:
        """The directory entry whose domain is exactly ``host``, else None."""
        wanted = host.strip().lower()
        for entry in await self.search(wanted, limit=CONFIRM_RESULTS):
            if entry.domain == wanted:
                return entry
        return None


# -- the policy ------------------------------------------------------------------


@dataclass(frozen=True)
class FeaturedSchool:
    """An operator-listed school as written in ``CANVAS_FEATURED_SCHOOLS``."""

    host: str
    name: str = ""


@dataclass(frozen=True)
class School:
    host: str
    api_url: str
    name: str
    is_default: bool = False


@dataclass(frozen=True)
class SchoolPolicy:
    """Which schools this server offers and how a stored host maps to an API URL."""

    default: School | None
    featured: tuple[School, ...]
    search_enabled: bool

    @classmethod
    def build(
        cls,
        canvas_api_url: str,
        featured: Sequence[FeaturedSchool] = (),
        search: bool = False,
    ) -> SchoolPolicy:
        names = {item.host: item.name for item in featured if item.name}
        default: School | None = None
        schools: list[School] = []
        seen: set[str] = set()
        url = (canvas_api_url or "").strip()
        if url:
            try:
                host = (urlsplit(url).hostname or "").lower()
            except ValueError:
                host = ""
            if host:
                default = School(host, url, names.get(host) or host, is_default=True)
                schools.append(default)
                seen.add(host)
        for item in featured:
            if item.host in seen:
                continue
            seen.add(item.host)
            schools.append(
                School(item.host, f"https://{item.host}/api/v1", item.name or item.host)
            )
        return cls(default=default, featured=tuple(schools), search_enabled=bool(search))

    @classmethod
    def pinned(cls, url: str) -> SchoolPolicy:
        return cls.build(url, (), False)

    @property
    def picker_enabled(self) -> bool:
        return self.search_enabled or len(self.featured) > 1

    @property
    def sole_school(self) -> School | None:
        if self.picker_enabled or not self.featured:
            return None
        return self.featured[0]

    def featured_school(self, host: str) -> School | None:
        for school in self.featured:
            if school.host == host:
                return school
        return None

    def resolve_stored(self, host: str | None) -> School | None:
        """The school a stored row belongs to, or None when it is no longer allowed.

        ``None`` (a legacy row) belongs to the default school. Searched schools
        are honoured only while the search is enabled.
        """
        if host is None:
            return self.default
        if self.default is not None and host == self.default.host:
            return self.default
        school = self.featured_school(host)
        if school is not None:
            return school
        if (
            self.search_enabled
            and parse_hostname(host) == host
            and not is_blocked_hostname(host)
        ):
            return School(host, f"https://{host}/api/v1", host)
        return None
