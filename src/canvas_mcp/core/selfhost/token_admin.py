"""Operator CLI for the self-hosted Canvas token store.

Usage::

    python -m canvas_mcp.core.selfhost.token_admin check
    python -m canvas_mcp.core.selfhost.token_admin list
    python -m canvas_mcp.core.selfhost.token_admin revoke TENANT_ID OBJECT_ID
    python -m canvas_mcp.core.selfhost.token_admin rotate

``list`` prints one tab-separated line per user: tenant id, object id, Canvas
name, created, last used and the Canvas host (``-`` for a legacy row, which
belongs to the default school ``CANVAS_API_URL``).

Reads ``CANVAS_TOKEN_KEYS`` and ``SELFHOST_DATA_DIR`` (default ``/data``) from
the environment. Never prints a token, a key or any other secret.

Exit codes: 0 ok, 1 not found, 2 configuration or keyring error.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sqlite3
import sys
from datetime import UTC, datetime

from canvas_mcp.core.selfhost.token_store import (
    Keyring,
    TokenDecryptionError,
    TokenStore,
    TokenStoreError,
    token_db_path,
)

EXIT_OK = 0
EXIT_NOT_FOUND = 1
EXIT_CONFIG = 2

KEYS_ENV = "CANVAS_TOKEN_KEYS"
DATA_DIR_ENV = "SELFHOST_DATA_DIR"
DEFAULT_DATA_DIR = "/data"

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _iso(value: int | None) -> str:
    if value is None:
        return "-"
    try:
        return datetime.fromtimestamp(value, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return "-"


def _cell(value: str) -> str:
    """Keep one record on one line: control characters become a space."""
    return _CONTROL_RE.sub(" ", value).strip()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m canvas_mcp.core.selfhost.token_admin",
        description="Inspect and maintain the encrypted Canvas token store.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="open the store, print the row count and key ids")
    sub.add_parser("list", help="list enrollments with their Canvas host (tab-separated, no tokens)")
    revoke = sub.add_parser("revoke", help="delete one user's enrollment")
    revoke.add_argument("tenant_id")
    revoke.add_argument("object_id")
    sub.add_parser("rotate", help="re-encrypt rows under the active key")
    return parser


def _open_store() -> TokenStore:
    """Open and initialize the store; raises TokenStoreError/OSError/sqlite3.Error."""
    keyring = Keyring.parse(os.environ.get(KEYS_ENV, ""))
    data_dir = pathlib.Path(os.environ.get(DATA_DIR_ENV) or DEFAULT_DATA_DIR)
    store = TokenStore(token_db_path(data_dir), keyring)
    store.initialize()
    return store


def _run(args: argparse.Namespace, store: TokenStore) -> int:
    command: str = args.command
    if command == "check":
        rows = store.list_enrollments()
        kids = sorted({row.key_id for row in rows})
        print(f"rows: {len(rows)}")
        print("key ids in use: " + (", ".join(kids) if kids else "(none)"))
        schools = sorted({row.canvas_host for row in rows if row.canvas_host})
        legacy = sum(1 for row in rows if not row.canvas_host)
        print(f"schools in use: {len(schools)}" + (f" (+{legacy} legacy row(s))" if legacy else ""))
        return EXIT_OK
    if command == "list":
        for row in store.list_enrollments():
            print(
                "\t".join(
                    [
                        row.tenant_id,
                        row.object_id,
                        _cell(row.canvas_user_name),
                        _iso(row.created_at),
                        _iso(row.last_used_at),
                        _cell(row.canvas_host or "") or "-",
                    ]
                )
            )
        return EXIT_OK
    if command == "revoke":
        try:
            removed = store.delete(args.tenant_id, args.object_id)
        except ValueError:
            print("error: tenant id and object id must be GUIDs", file=sys.stderr)
            return EXIT_CONFIG
        if not removed:
            print("not found: no enrollment for that tenant id and object id")
            return EXIT_NOT_FOUND
        print("revoked 1 enrollment")
        return EXIT_OK
    if command == "rotate":
        changed = store.rotate()
        print(f"re-encrypted {changed} row(s)")
        return EXIT_OK
    raise AssertionError(command)  # pragma: no cover - argparse enforces choices


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        store = _open_store()
        return _run(args, store)
    except TokenDecryptionError:
        print("error: a stored token could not be decrypted", file=sys.stderr)
        return EXIT_CONFIG
    except TokenStoreError as exc:
        # Messages from the store carry key ids and counts only, never secrets.
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except (OSError, sqlite3.Error) as exc:
        print(f"error: cannot open the token store ({type(exc).__name__})", file=sys.stderr)
        return EXIT_CONFIG


if __name__ == "__main__":
    sys.exit(main())
