"""Registration and execution of database upgrade CLI commands.

The operator CLI has one lazy delegation call; upgrade policy stays here.
"""

from __future__ import annotations

import argparse
import os
import pathlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..engine import Database


def register_subcommands(subparsers: argparse._SubParsersAction) -> None:
    db = subparsers.add_parser("db", help="inspect and upgrade the database schema")
    db_sub = db.add_subparsers(dest="db_command", required=True)
    db_sub.add_parser("current", help="show the schema state; exit 4 if it is behind")
    upgrade = db_sub.add_parser("upgrade", help="apply pending schema revisions")
    upgrade.add_argument(
        "--backup",
        metavar="PATH",
        help="SQLite only: copy the database to this new private file before upgrading",
    )
    upgrade.add_argument(
        "--dry-run",
        action="store_true",
        help="run the upgrade, print what it would do and roll everything back",
    )
    import_sqlite = db_sub.add_parser(
        "import-sqlite",
        help="copy a SQLite token database into an empty PostgreSQL database",
    )
    import_sqlite.add_argument(
        "path", help="the SQLite file to import (it is not modified)"
    )


def run(db: Database, args: argparse.Namespace) -> int:
    from . import runner as migrate

    command = args.db_command
    if command == "current":
        status = migrate.current(db)
        print(f"backend: {db.description}")
        print(f"alembic revision: {status.alembic_revision or '(none)'}")
        print(f"database id: {status.database_id or '(none)'}")
        print(
            f"compatibility floor: {status.compat_floor if status.compat_floor is not None else '(none)'}"
        )
        print(f"server schema epoch: {migrate.SCHEMA_EPOCH}")
        print(f"head revision: {status.head}")
        print(f"state: {status.state}")
        if status.state in (migrate.STATE_CURRENT, migrate.STATE_NEWER):
            return 0
        if status.state in (migrate.STATE_UNINITIALIZED, migrate.STATE_BEHIND):
            return 4
        return 2
    if command == "upgrade":
        backup = pathlib.Path(args.backup) if args.backup else None
        before, after = migrate.upgrade(db, backup_to=backup, dry_run=args.dry_run)
        if args.dry_run:
            print(
                f"dry run: {before.alembic_revision or '(none)'} -> {migrate.head_revision()}; nothing was changed"
            )
        elif before == after:
            print(f"already compatible at {after.alembic_revision}")
        else:
            print(
                f"upgraded: {before.alembic_revision or '(none)'} -> {after.alembic_revision}"
            )
        if backup is not None and not args.dry_run:
            print(f"backup written to {backup}")
        return 0
    if command == "import-sqlite":
        from canvas_mcp.core.selfhost.db.migrations.transfer import import_sqlite

        from ...token_store import Keyring

        keyring = Keyring.parse(os.environ.get("CANVAS_TOKEN_KEYS", ""))
        report_ = import_sqlite(
            db,
            pathlib.Path(args.path),
            keyring,
        )
        for table, count in report_.counts.items():
            print(f"{table}: {count} row(s)")
        print(f"sealed values checked: {report_.sealed_values_checked}")
        print(
            "imported at the current schema; every sealed value decrypts with CANVAS_TOKEN_KEYS"
        )
        return 0
    raise AssertionError(command)
