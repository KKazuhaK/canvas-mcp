"""Validation of ``DATABASE_URL`` for the self-hosted mode.

Standard library only: ``settings.py`` imports this module, and the upstream
modes (stdio, X-Canvas-Token, access keys, Easy Auth) must never need
SQLAlchemy just because the settings module was imported.

Rules:

* Unset or empty: SQLite at ``<SELFHOST_DATA_DIR>/canvas-mcp/tokens.sqlite3``.
  Nothing changes for an existing deployment.
* ``postgresql+psycopg://user:password@host:port/dbname[?options]``: PostgreSQL
  through psycopg 3. Plain ``postgresql://`` and ``postgres://`` are refused
  (they would select another driver). The query accepts a fixed set of
  libpq parameters; ``options`` is not one of them, so the server-side
  timeouts the store sets cannot be overridden from the URL.
* ``sqlite:///...``: an absolute file path inside the data directory (outside
  only with ``DATABASE_ALLOW_SQLITE_OUTSIDE_DATA_DIR=true``); no memory
  databases, no query.
* ``redis://`` is reserved for later and refused as not implemented.

Problems name the variable and never the value: a URL carries a password.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import parse_qsl, urlsplit

DATABASE_URL_ENV = "DATABASE_URL"
ALLOW_OUTSIDE_ENV = "DATABASE_ALLOW_SQLITE_OUTSIDE_DATA_DIR"

POSTGRES_SCHEME = "postgresql+psycopg"
_SQLITE_SCHEMES = ("sqlite", "sqlite+pysqlite")
_SSL_MODES = frozenset({"disable", "allow", "prefer", "require", "verify-ca", "verify-full"})
_QUERY_KEYS = frozenset(
    {"sslmode", "sslrootcert", "sslcert", "sslkey", "connect_timeout", "application_name"}
)
_APP_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,63}$")
_DBNAME_RE = re.compile(r"^[^\x00-\x1f\x7f/?#]{1,63}$")
_MAX_URL_CHARS = 2048


@dataclass(frozen=True)
class DatabaseTarget:
    """Where the self-hosted state lives. ``url`` may hold a password and is never shown."""

    kind: Literal["sqlite", "postgresql"]
    url: str = field(repr=False)
    description: str
    sqlite_path: Path | None = None


def default_sqlite_path(data_dir: Path) -> Path:
    """The SQLite file of a deployment that sets no ``DATABASE_URL``."""
    return data_dir / "canvas-mcp" / "tokens.sqlite3"


def sqlite_target(path: Path) -> DatabaseTarget:
    """A SQLite target for a file path (the zero-configuration default)."""
    return DatabaseTarget("sqlite", "sqlite:///" + path.as_posix(), str(path), path)


def _is_absolute(value: str) -> bool:
    # A POSIX-style path such as /data counts as absolute on every platform: the
    # container image is Linux, and the tests run on Windows too.
    return PurePosixPath(value).is_absolute() or Path(value).is_absolute()


def _inside(path: Path, directory: Path) -> bool:
    try:
        norm = Path(os.path.normpath(path))
        base = Path(os.path.normpath(directory))
        return norm == base or norm.is_relative_to(base)
    except (ValueError, OSError):
        return False


def parse_database_url(
    raw: str,
    data_dir: Path,
    *,
    allow_external_sqlite: bool = False,
    problems: list[str] | None = None,
) -> DatabaseTarget:
    """The validated target for ``DATABASE_URL``; problems are appended to ``problems``.

    Without a ``problems`` list the first problem raises ``ValueError``. On a
    problem the default SQLite target is returned so the caller can keep
    collecting other problems.
    """
    collected: list[str] = problems if problems is not None else []
    before = len(collected)
    target = _parse(raw.strip(), data_dir, allow_external_sqlite, collected)
    if problems is None and len(collected) > before:
        raise ValueError(collected[before])
    return target


def _parse(
    raw: str, data_dir: Path, allow_external: bool, problems: list[str]
) -> DatabaseTarget:
    name = DATABASE_URL_ENV
    default = sqlite_target(default_sqlite_path(data_dir))
    if not raw:
        return default
    if len(raw) > _MAX_URL_CHARS or any(ch.isspace() or ord(ch) < 0x20 for ch in raw):
        problems.append(f"{name} must be a single URL without whitespace or control characters")
        return default
    scheme, sep, _ = raw.partition("://")
    scheme = scheme.lower()
    if not sep:
        problems.append(
            f"{name} must look like {POSTGRES_SCHEME}://user:password@host:5432/dbname "
            "(or be unset to use the SQLite file in the data directory)"
        )
        return default
    if scheme in _SQLITE_SCHEMES:
        return _parse_sqlite(raw, scheme, data_dir, allow_external, problems, default)
    if scheme == POSTGRES_SCHEME:
        return _parse_postgres(raw, problems, default)
    if scheme in ("postgresql", "postgres"):
        problems.append(
            f"{name} must use the {POSTGRES_SCHEME}:// scheme (psycopg 3); "
            f"plain {scheme}:// would select another driver"
        )
    elif scheme.startswith("redis"):
        problems.append(
            f"{name} cannot name Redis: Redis is reserved for later and not implemented; "
            "the database is SQLite or PostgreSQL"
        )
    else:
        problems.append(
            f"{name} has an unsupported scheme; use {POSTGRES_SCHEME}:// or sqlite:///, "
            "or leave it unset"
        )
    return default


def _parse_sqlite(
    raw: str,
    scheme: str,
    data_dir: Path,
    allow_external: bool,
    problems: list[str],
    default: DatabaseTarget,
) -> DatabaseTarget:
    name = DATABASE_URL_ENV
    rest = raw[len(scheme) + 3 :]
    if "?" in rest or "#" in rest:
        problems.append(
            f"{name} for SQLite must be a plain file path: no query (uri=true, mode=memory "
            "and similar are not allowed)"
        )
        return default
    if not rest.startswith("/"):
        problems.append(
            f"{name} for SQLite must look like sqlite:////absolute/path/tokens.sqlite3 "
            "(four slashes for a POSIX path)"
        )
        return default
    path_text = rest[1:]
    if not path_text or path_text.startswith(":memory:"):
        problems.append(f"{name} for SQLite must name a file; memory databases are not allowed")
        return default
    if not _is_absolute(path_text):
        problems.append(f"{name} for SQLite must be an absolute path")
        return default
    if ".." in PurePosixPath(path_text.replace("\\", "/")).parts:
        problems.append(f"{name} for SQLite must not contain '..'")
        return default
    path = Path(path_text)
    if not allow_external and not _inside(path, data_dir):
        problems.append(
            f"{name} for SQLite points outside SELFHOST_DATA_DIR; set "
            f"{ALLOW_OUTSIDE_ENV}=true if that is intended"
        )
        return default
    return sqlite_target(path)


def _parse_postgres(raw: str, problems: list[str], default: DatabaseTarget) -> DatabaseTarget:
    name = DATABASE_URL_ENV
    try:
        parts = urlsplit(raw)
        port = parts.port
        host = parts.hostname
    except ValueError:
        problems.append(f"{name} is not a valid URL")
        return default
    if parts.fragment:
        problems.append(f"{name} must not contain a fragment")
        return default
    if not host:
        problems.append(f"{name} must include a host name")
        return default
    userinfo, _, hostport = parts.netloc.rpartition("@")
    if "," in hostport:
        problems.append(f"{name} must name exactly one host")
        return default
    if "@" in userinfo:
        # SQLAlchemy would split at the first "@" and misread the host.
        problems.append(
            f"{name} has a user name or password with a raw '@'; percent-encode special "
            "characters (or use only letters and digits)"
        )
        return default
    dbname = parts.path[1:] if parts.path.startswith("/") else parts.path
    if not _DBNAME_RE.fullmatch(dbname):
        problems.append(f"{name} must include a database name (a path such as /canvas_mcp)")
        return default
    try:
        query = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=bool(parts.query))
    except ValueError:
        problems.append(f"{name} has a malformed query string")
        return default
    problem = _query_problem(query)
    if problem:
        problems.append(f"{name} {problem}")
        return default
    shown_host = f"[{host}]" if ":" in host else host
    shown = f"{POSTGRES_SCHEME}://{shown_host}:{port if port is not None else 5432}/{dbname}"
    return DatabaseTarget("postgresql", raw, shown)


def _query_problem(query: list[tuple[str, str]]) -> str | None:
    seen: set[str] = set()
    for key, value in query:
        if key not in _QUERY_KEYS:
            return "has a query parameter that is not allowed (allowed: " + ", ".join(
                sorted(_QUERY_KEYS)
            ) + ")"
        if key in seen:
            return f"repeats the query parameter {key}"
        seen.add(key)
        if key == "sslmode" and value not in _SSL_MODES:
            return "sslmode must be one of " + ", ".join(sorted(_SSL_MODES))
        if key == "connect_timeout" and not (value.isdigit() and 1 <= int(value) <= 60):
            return "connect_timeout must be an integer from 1 to 60"
        if key == "application_name" and not _APP_NAME_RE.fullmatch(value):
            return "application_name must match [A-Za-z0-9._-], 1 to 63 characters"
        if key in ("sslrootcert", "sslcert", "sslkey") and not value:
            return f"{key} must not be empty"
    return None
