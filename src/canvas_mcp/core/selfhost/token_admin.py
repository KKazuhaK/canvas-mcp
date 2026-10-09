"""Operator CLI for the self-hosted Canvas token store.

Usage::

    python -m canvas_mcp.core.selfhost.token_admin check
    python -m canvas_mcp.core.selfhost.token_admin list
    python -m canvas_mcp.core.selfhost.token_admin disable TENANT_ID OBJECT_ID [--allow-last-owner]
    python -m canvas_mcp.core.selfhost.token_admin enable TENANT_ID OBJECT_ID
    python -m canvas_mcp.core.selfhost.token_admin access
    python -m canvas_mcp.core.selfhost.token_admin history [TENANT_ID OBJECT_ID]
    python -m canvas_mcp.core.selfhost.token_admin remove TENANT_ID OBJECT_ID
    python -m canvas_mcp.core.selfhost.token_admin rotate

``disable`` and ``enable`` are the authorization decision: a disabled user is refused
at ``/account`` and on every MCP request, cannot enroll, and stays disabled until
``enable`` (or an owner on the admin page). The running server notices a change made
here within a few seconds (its access cache), a request already running is not
interrupted, and a Canvas call already sent is not cancelled. ``remove`` (also
spelled ``revoke``, the old name) only deletes the stored Canvas token: the user can
enroll again, so it is not a way to cut someone off. Every disable and enable is
recorded in the token database (``history``). ``access`` lists the disabled users and
the owners the server has seen.

``list`` prints one tab-separated line per user: tenant id, object id, Canvas
name, created, last used and the Canvas host (``-`` for a legacy row, which
belongs to the default school ``CANVAS_API_URL``).

Reads ``CANVAS_TOKEN_KEYS`` and ``SELFHOST_DATA_DIR`` (default ``/data``) from
the environment. Never prints a token, a key or any other secret.

Exit codes: 0 ok, 1 not found, 2 configuration or keyring error, 3 refused (for
example disabling the last active owner).
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
    DISABLE_REASON_OPERATOR,
    OPERATOR,
    AccessActionRefused,
    Keyring,
    TokenDecryptionError,
    TokenStore,
    TokenStoreError,
    token_db_path,
)

EXIT_OK = 0
EXIT_NOT_FOUND = 1
EXIT_CONFIG = 2
EXIT_REFUSED = 3

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
    disable = sub.add_parser("disable", help="disable a user: refused everywhere until enabled")
    disable.add_argument("tenant_id")
    disable.add_argument("object_id")
    disable.add_argument(
        "--allow-last-owner",
        action="store_true",
        help="allow disabling the last active owner (break-glass)",
    )
    enable = sub.add_parser("enable", help="lift a disablement")
    enable.add_argument("tenant_id")
    enable.add_argument("object_id")
    sub.add_parser("access", help="list disabled users and known owners (tab-separated)")
    history = sub.add_parser("history", help="show the access history, newest first")
    history.add_argument("tenant_id", nargs="?")
    history.add_argument("object_id", nargs="?")
    history.add_argument("--limit", type=int, default=50)
    remove_help = (
        "delete one user's stored Canvas token only (the user can enroll again; "
        "use 'disable' to cut someone off)"
    )
    for remove in (
        sub.add_parser("remove", help=remove_help),
        sub.add_parser("revoke", help=remove_help + " [old name of 'remove']"),
    ):
        remove.add_argument("tenant_id")
        remove.add_argument("object_id")
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
        statuses = store.list_principal_statuses()
        print(f"disabled users: {sum(1 for st in statuses if st.disabled)}")
        print(
            f"active owners seen: {store.count_active_owners()}"
            " (as of each owner's last sign-in; see 'access' for owner_seen_at)"
        )
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
    if command in ("remove", "revoke"):
        try:
            removed = store.delete(args.tenant_id, args.object_id)
        except ValueError:
            print("error: tenant id and object id must be GUIDs", file=sys.stderr)
            return EXIT_CONFIG
        if not removed:
            print("not found: no enrollment for that tenant id and object id")
            return EXIT_NOT_FOUND
        print("revoked 1 enrollment" if command == "revoke" else "removed 1 enrollment")
        print(
            "note: this only deleted the stored Canvas token; the user can enroll again. "
            "Use 'disable' to cut a user off.",
            file=sys.stderr,
        )
        return EXIT_OK
    if command == "disable":
        try:
            changed = store.disable_principal(
                args.tenant_id,
                args.object_id,
                actor=OPERATOR,
                reason=DISABLE_REASON_OPERATOR,
                allow_last_owner=args.allow_last_owner,
            )
        except ValueError:
            print("error: tenant id and object id must be GUIDs", file=sys.stderr)
            return EXIT_CONFIG
        except AccessActionRefused as exc:
            if exc.code == AccessActionRefused.LAST_OWNER:
                print(
                    "refused: that user is the last active owner as far as the stored "
                    "owner flags show (a former owner who never signed in again still "
                    "counts; check 'access' for the owner_seen_at column). "
                    "Add another owner first, or pass --allow-last-owner",
                    file=sys.stderr,
                )
            else:
                print(f"refused: {exc.code}", file=sys.stderr)
            return EXIT_REFUSED
        print("disabled 1 user" if changed else "already disabled")
        return EXIT_OK
    if command == "enable":
        try:
            changed = store.enable_principal(args.tenant_id, args.object_id, actor=OPERATOR)
        except ValueError:
            print("error: tenant id and object id must be GUIDs", file=sys.stderr)
            return EXIT_CONFIG
        if not changed:
            print("not disabled: nothing to enable")
            return EXIT_NOT_FOUND
        print("enabled 1 user")
        return EXIT_OK
    if command == "access":
        for st in store.list_principal_statuses():
            print(
                "\t".join(
                    [
                        st.principal_key,
                        st.status,
                        "owner" if st.is_owner else "-",
                        _iso(st.disabled_at),
                        _cell(st.disabled_by or "") or "-",
                        _cell(st.disabled_reason or "") or "-",
                        str(st.session_epoch),
                        _iso(st.owner_seen_at) if st.is_owner else "-",
                    ]
                )
            )
        return EXIT_OK
    if command == "history":
        if (args.tenant_id is None) != (args.object_id is None):
            print("error: give both tenant id and object id, or neither", file=sys.stderr)
            return EXIT_CONFIG
        try:
            events = (
                store.list_status_events(limit=args.limit)
                if args.tenant_id is None
                else store.list_status_events(args.tenant_id, args.object_id, limit=args.limit)
            )
        except ValueError:
            print("error: tenant id and object id must be GUIDs", file=sys.stderr)
            return EXIT_CONFIG
        for event in events:
            print(
                "\t".join(
                    [
                        _iso(event.at),
                        event.principal_key,
                        event.action,
                        _cell(event.actor or "") or "-",
                        _cell(event.reason or "") or "-",
                        str(event.session_epoch),
                    ]
                )
            )
        return EXIT_OK
    if command == "rotate":
        rotated = store.rotate()
        print(f"re-encrypted {rotated} row(s)")
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
