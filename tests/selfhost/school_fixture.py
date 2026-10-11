"""Scripted school directory/DNS and explicit native database configuration."""

from collections.abc import Sequence
from urllib.parse import urlsplit

from canvas_mcp.core.selfhost.schools import (
    DirectoryEntry,
    DirectoryError,
    School,
    SchoolPolicy,
)

DEFAULT_URL = "https://canvas.default.edu/api/v1"
DEFAULT_HOST = "canvas.default.edu"
HOST_A = "canvas.school-a.edu"
HOST_B = "canvas.school-b.edu"
PUBLIC_IP = "93.184.216.34"


def school_policy(
    default_url: str, featured: Sequence[School], search: bool
) -> SchoolPolicy:
    """Explicit fixture schools, saved by ConfigStore; the application has no default host."""
    schools = list(featured)
    if default_url:
        host = urlsplit(default_url).hostname
        assert host
        if not any(school.host == host for school in schools):
            schools.insert(0, School(host, default_url, host))
    return SchoolPolicy(tuple(schools), search)


class FakeDirectory:
    def __init__(
        self, entries: Sequence[DirectoryEntry] = (), error: bool = False
    ) -> None:
        self.entries = list(entries)
        self.error = error
        self.searches: list[str] = []
        self.confirms: list[str] = []

    async def search(self, term: str, *, limit: int = 10) -> list[DirectoryEntry]:
        self.searches.append(term)
        if self.error:
            raise DirectoryError("down")
        return list(self.entries)[:limit]

    async def confirm(self, host: str) -> DirectoryEntry | None:
        self.confirms.append(host)
        if self.error:
            raise DirectoryError("down")
        return next((entry for entry in self.entries if entry.domain == host), None)

    @property
    def calls(self) -> int:
        return len(self.searches) + len(self.confirms)


class FakeResolver:
    def __init__(
        self, table: dict[str, Sequence[str] | BaseException] | None = None
    ) -> None:
        self.table = table or {}
        self.calls: list[str] = []

    async def __call__(self, host: str) -> Sequence[str]:
        self.calls.append(host)
        value = self.table.get(host, [PUBLIC_IP])
        if isinstance(value, BaseException):
            raise value
        return value
