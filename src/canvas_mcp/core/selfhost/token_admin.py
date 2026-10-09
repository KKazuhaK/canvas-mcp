"""Operator CLI for the self-hosted accounts and the encrypted Canvas token store.

Usage::

    python -m canvas_mcp.core.selfhost.token_admin check
    python -m canvas_mcp.core.selfhost.token_admin list
    python -m canvas_mcp.core.selfhost.token_admin accounts
    python -m canvas_mcp.core.selfhost.token_admin approve PRINCIPAL
    python -m canvas_mcp.core.selfhost.token_admin promote-owner PRINCIPAL
    python -m canvas_mcp.core.selfhost.token_admin disable PRINCIPAL [--allow-last-owner]
    python -m canvas_mcp.core.selfhost.token_admin enable PRINCIPAL
    python -m canvas_mcp.core.selfhost.token_admin access
    python -m canvas_mcp.core.selfhost.token_admin history [PRINCIPAL] [--limit N]
    python -m canvas_mcp.core.selfhost.token_admin remove PRINCIPAL
    python -m canvas_mcp.core.selfhost.token_admin rotate
    python -m canvas_mcp.core.selfhost.token_admin db current
    python -m canvas_mcp.core.selfhost.token_admin db upgrade [--backup PATH] [--dry-run]
                                                              [--mark-undecryptable-invalid]
    python -m canvas_mcp.core.selfhost.token_admin db import-sqlite PATH

``PRINCIPAL`` names an account in any of these forms: ``acct:<uuid>`` (or the bare
uuid), ``entra:<tenant id>:<object id>`` (the key of the releases before the account
model, mapped through the account's Entra identity), or the old pair ``TENANT_ID
OBJECT_ID``.

``disable`` and ``enable`` are the authorization decision: a disabled user is refused
at ``/account`` and on every MCP request, cannot enroll, and stays disabled until
``enable`` (or an owner on the admin page). ``disable`` of an Entra user who has never
signed in creates a disabled account for them, so someone can be blocked before their
first sign-in. ``approve`` activates an account that waits for approval
(``ACCESS_POLICY=approval``). ``promote-owner`` makes an active account an owner (a role
the operator granted is not taken back by the rules): the emergency entrance when no
owner exists. The running server notices a change made here within a few seconds (its
access cache), a request already running is not interrupted, and a Canvas call already
sent is not cancelled. ``remove`` (also spelled ``revoke``, the old name) only deletes
the stored Canvas token: the user can enroll again, so it is not a way to cut someone
off. Every change is recorded in the token database (``history``). ``access`` lists the
accounts that are not active and the owners.

``list`` prints one tab-separated line per enrollment: tenant id, object id (``-`` for a
user who is not an Entra user), Canvas name, created, last used, the Canvas host (``-``
for a row that belongs to the default school ``CANVAS_API_URL``) and, last, the account
key. ``accounts`` prints one line per account: key, status, role, how it was admitted,
display name, sign-in name, provider, created, last sign-in and the legacy
``entra:<tid>:<oid>`` key (``-`` if none).

``db current`` prints the backend (without credentials), the Alembic revision, the
schema version marker and whether the database is current; it needs no keys and
changes nothing. ``db upgrade`` applies pending schema revisions. The upgrade to the
account model re-encrypts every stored Canvas token under its new account, so it needs
``CANVAS_TOKEN_KEYS`` whenever the database holds tokens; stop every server first. A
SQLite file is copied to ``<file>.pre-0002-accounts-<time>.bak`` before anything is
written (or use ``--backup PATH`` to choose the copy); back up PostgreSQL with
``pg_dump -Fc`` first. ``--dry-run`` does all of it inside a transaction, prints what
would happen and rolls everything back. A token that does not decrypt with the keys
stops the upgrade; ``--mark-undecryptable-invalid`` marks such rows invalid instead (the
user enrolls again). ``db import-sqlite PATH`` copies a SQLite token database into an
empty PostgreSQL database (``DATABASE_URL``) in one transaction and checks that every
token still decrypts; the source file is not modified.

Every command except ``db ...`` refuses to run (exit 2) on a database that holds no
rows while the default SQLite file in the data directory still has data: using it
would hide the disablements stored in that file. Import the file first.

Reads ``CANVAS_TOKEN_KEYS``, ``SELFHOST_DATA_DIR`` (default ``/data``) and
``DATABASE_URL`` (unset: the SQLite file in the data directory) from the
environment, like the server. Schema changes are applied before a command runs
unless ``DATABASE_AUTO_MIGRATE=false``. Never prints a token, a key, a database
password or any other secret.

Exit codes: 0 ok, 1 not found, 2 configuration, keyring or database error, 3
refused (for example disabling the last active owner), 4 ``db current`` found the
schema behind this build (run ``db upgrade``).
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.db.url import (
    ALLOW_OUTSIDE_ENV,
    DATABASE_URL_ENV,
    default_sqlite_path,
    parse_database_url,
)
from canvas_mcp.core.selfhost.settings import AUTO_MIGRATE_ENV, _parse_auto_migrate
from canvas_mcp.core.selfhost.token_store import (
    DISABLE_REASON_OPERATOR,
    OPERATOR,
    AccessActionRefused,
    AccountInfo,
    Keyring,
    TokenDecryptionError,
    TokenStore,
    TokenStoreError,
    entra_principal_key,
    split_entra_key,
)

if TYPE_CHECKING:
    from canvas_mcp.core.selfhost.db.engine import Database

EXIT_OK = 0
EXIT_NOT_FOUND = 1
EXIT_CONFIG = 2
EXIT_REFUSED = 3
EXIT_BEHIND = 4

KEYS_ENV = "CANVAS_TOKEN_KEYS"
DATA_DIR_ENV = "SELFHOST_DATA_DIR"
DEFAULT_DATA_DIR = "/data"

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


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
        description="Inspect and maintain the accounts and the encrypted Canvas token store.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def principal(p: argparse.ArgumentParser, *, optional: bool = False) -> None:
        nargs = "?" if optional else None
        p.add_argument(
            "principal",
            nargs=nargs,
            help="acct:<uuid>, a bare uuid, entra:<tenant id>:<object id>, or TENANT_ID with OBJECT_ID",
        )
        p.add_argument("object_id", nargs="?", help="the object id when PRINCIPAL is a tenant id")

    sub.add_parser("check", help="open the store, print the row counts and key ids")
    sub.add_parser("list", help="list enrollments with their Canvas host (tab-separated, no tokens)")
    sub.add_parser("accounts", help="list every account (tab-separated)")
    approve = sub.add_parser("approve", help="approve an account that waits for approval")
    principal(approve)
    promote = sub.add_parser("promote-owner", help="make an active account an owner (emergency)")
    principal(promote)
    disable = sub.add_parser("disable", help="disable a user: refused everywhere until enabled")
    principal(disable)
    disable.add_argument(
        "--allow-last-owner",
        action="store_true",
        help="allow disabling the last active owner (break-glass)",
    )
    enable = sub.add_parser("enable", help="lift a disablement")
    principal(enable)
    sub.add_parser("access", help="list accounts that are not active, and owners (tab-separated)")
    history = sub.add_parser("history", help="show the access history, newest first")
    principal(history, optional=True)
    history.add_argument("--limit", type=int, default=50)
    remove_help = (
        "delete one user's stored Canvas token only (the user can enroll again; "
        "use 'disable' to cut someone off)"
    )
    for remove in (
        sub.add_parser("remove", help=remove_help),
        sub.add_parser("revoke", help=remove_help + " [old name of 'remove']"),
    ):
        principal(remove)
    sub.add_parser("rotate", help="re-encrypt rows under the active key")
    db = sub.add_parser("db", help="inspect and upgrade the database schema")
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
    upgrade.add_argument(
        "--mark-undecryptable-invalid",
        action="store_true",
        help="mark tokens that do not decrypt invalid instead of stopping the upgrade",
    )
    import_sqlite = db_sub.add_parser(
        "import-sqlite", help="copy a SQLite token database into an empty PostgreSQL database"
    )
    import_sqlite.add_argument("path", help="the SQLite file to import (it is not modified)")
    return parser


def _data_dir() -> pathlib.Path:
    return pathlib.Path(os.environ.get(DATA_DIR_ENV) or DEFAULT_DATA_DIR)


def _database() -> Database:
    """The configured database (``DATABASE_URL`` or the SQLite file), not yet opened."""
    try:
        from canvas_mcp.core.selfhost.db.engine import Database
    except ImportError:
        raise TokenStoreError(
            "the self-hosted mode needs SQLAlchemy and Alembic: "
            "pip install 'canvas-mcp[selfhost]'"
        ) from None

    data_dir = _data_dir()
    problems: list[str] = []
    allow = (os.environ.get(ALLOW_OUTSIDE_ENV) or "").strip().lower() in ("true", "1", "yes")
    target = parse_database_url(
        (os.environ.get(DATABASE_URL_ENV) or "").strip(),
        data_dir,
        allow_external_sqlite=allow,
        problems=problems,
    )
    if problems:
        raise TokenStoreError("; ".join(problems))
    try:
        return Database(target)
    except ImportError:
        raise TokenStoreError(
            "DATABASE_URL names PostgreSQL, which needs the psycopg driver: "
            "pip install 'canvas-mcp[postgres]'"
        ) from None


def _auto_migrate() -> bool:
    problems: list[str] = []
    value = _parse_auto_migrate(os.environ.get(AUTO_MIGRATE_ENV) or "", problems)
    if problems:
        raise TokenStoreError("; ".join(problems))
    return value


def _open_store() -> TokenStore:
    """Open and initialize the store; raises TokenStoreError/OSError."""
    keyring = Keyring.parse(os.environ.get(KEYS_ENV, ""))
    database = _database()
    from canvas_mcp.core.selfhost.db.transfer import refuse_silent_switch

    # Before anything is created or written: a command that ran on an empty target
    # next to a SQLite file with data would lose that file's disablements.
    refuse_silent_switch(database, default_sqlite_path(_data_dir()))
    store = TokenStore(database, keyring)
    store.initialize(auto_migrate=_auto_migrate())
    return store


def _optional_keyring() -> Keyring | None:
    """The keyring if ``CANVAS_TOKEN_KEYS`` is set (the schema upgrade may need it)."""
    raw = os.environ.get(KEYS_ENV, "")
    return Keyring.parse(raw) if raw.strip() else None


def _run_db(args: argparse.Namespace) -> int:
    """The ``db`` subcommands. ``current`` needs no keys; ``upgrade`` needs them for tokens."""
    command: str = args.db_command
    db = _database()  # first: reports a missing extra before anything imports SQLAlchemy
    from canvas_mcp.core.selfhost.db import migrate

    if command == "current":
        status = migrate.current(db)
        print(f"backend: {db.description}")
        print(f"alembic revision: {status.alembic_revision or '(none)'}")
        print(f"schema version marker: {status.meta_version or '(none)'}")
        print(f"head revision: {status.head}")
        print(f"state: {status.state}")
        if status.state == migrate.STATE_CURRENT:
            return EXIT_OK
        if status.state in (migrate.STATE_NEWER, migrate.STATE_UNREADABLE):
            return EXIT_CONFIG
        return EXIT_BEHIND
    if command == "upgrade":
        backup = pathlib.Path(args.backup) if args.backup else None
        report = migrate.AccountMigrationReport()
        before, after = migrate.upgrade(
            db,
            backup_to=backup,
            keyring=_optional_keyring(),
            dry_run=args.dry_run,
            mark_undecryptable_invalid=args.mark_undecryptable_invalid,
            report=report,
        )
        if args.dry_run:
            if before.state == migrate.STATE_CURRENT:
                print(f"dry run: already current at {before.alembic_revision}; nothing to do")
            else:
                print("dry run: nothing was changed. The upgrade would:")
                for line in report.lines():
                    print(f"  {line}")
            return EXIT_OK
        if backup is not None:
            print(f"backup written to {backup}")
        elif report.backup_path:
            print(f"backup written to {report.backup_path}")
        if before.state == migrate.STATE_CURRENT:
            print(f"already current at {after.alembic_revision}")
        else:
            print(f"upgraded: {before.alembic_revision or '(none)'} -> {after.alembic_revision}")
            if report.ran:
                for line in report.lines():
                    print(f"  {line}")
        return EXIT_OK
    if command == "import-sqlite":
        from canvas_mcp.core.selfhost.db.transfer import import_sqlite

        keyring = Keyring.parse(os.environ.get(KEYS_ENV, ""))
        report_ = import_sqlite(db, pathlib.Path(args.path), keyring)
        for table, count in report_.counts.items():
            print(f"{table}: {count} row(s)")
        print("imported; every stored token decrypts with CANVAS_TOKEN_KEYS")
        return EXIT_OK
    raise AssertionError(command)  # pragma: no cover - argparse enforces choices


@dataclass(frozen=True)
class _Target:
    """A principal as the operator typed it."""

    account_key: str | None
    entra: tuple[str, str] | None  # (tenant id, object id)


class _BadPrincipal(ValueError):
    pass


def _parse_target(principal: str | None, object_id: str | None) -> _Target:
    if principal is None:
        raise _BadPrincipal
    text = principal.strip().lower()
    if object_id is not None:
        key = entra_principal_key(text, object_id)  # raises ValueError unless both are GUIDs
        parts = split_entra_key(key)
        assert parts is not None
        return _Target(None, parts)
    if _UUID_RE.match(text):
        return _Target(f"acct:{text}", None)
    if acc.valid_account_key(text):
        return _Target(text, None)
    parts = split_entra_key(text)
    if parts is not None:
        return _Target(None, parts)
    raise _BadPrincipal


def _lookup(store: TokenStore, target: _Target) -> str | None:
    """The account key a typed principal names, or None if there is no such account."""
    if target.account_key is not None:
        return target.account_key if store.get_principal_status(target.account_key).stored else None
    assert target.entra is not None
    return store.lookup_identity(
        acc.PROVIDER_ENTRA, acc.entra_issuer(target.entra[0]), target.entra[1]
    )


_BAD_PRINCIPAL = (
    "error: name the account as acct:<uuid>, entra:<tenant GUID>:<object GUID>, or give "
    "TENANT_ID and OBJECT_ID (both GUIDs)"
)


def _identity_columns(account: AccountInfo | None) -> tuple[str, str]:
    legacy = None if account is None else account.legacy_key
    parts = split_entra_key(legacy) if legacy else None
    return parts if parts is not None else ("-", "-")


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
        accounts = store.list_principal_statuses()
        by_status = {
            name: sum(1 for st in accounts if st.status == name) for name in acc.ACCOUNT_STATUSES
        }
        print(
            f"accounts: {len(accounts)} (active {by_status['active']}, "
            f"pending {by_status['pending']}, disabled {by_status['disabled']})"
        )
        known = {st.principal_key for st in accounts}
        orphans = sum(1 for row in rows if row.principal_key not in known)
        print(f"tokens of principals without an account: {orphans}")
        print(f"disabled users: {by_status['disabled']}")
        print(
            f"active owners seen: {store.count_active_owners()}"
            " (as of each owner's last sign-in; see 'access' for owner_seen_at)"
        )
        return EXIT_OK
    if command == "list":
        by_key = {a.principal_key: a for a in store.list_accounts()}
        for row in store.list_enrollments():
            tid, oid = _identity_columns(by_key.get(row.principal_key))
            print(
                "\t".join(
                    [
                        tid,
                        oid,
                        _cell(row.canvas_user_name),
                        _iso(row.created_at),
                        _iso(row.last_used_at),
                        _cell(row.canvas_host or "") or "-",
                        row.principal_key,
                    ]
                )
            )
        return EXIT_OK
    if command == "accounts":
        for account in store.list_accounts():
            st = account.status
            identity = account.identities[0] if account.identities else None
            print(
                "\t".join(
                    [
                        st.principal_key,
                        st.status,
                        st.role,
                        st.admitted_via,
                        _cell(st.display_name) or "-",
                        _cell(account.username) or "-",
                        identity.provider_id if identity is not None else "-",
                        _iso(st.created_at),
                        _iso(st.last_login_at),
                        account.legacy_key or "-",
                    ]
                )
            )
        return EXIT_OK
    if command == "rotate":
        rotated = store.rotate()
        print(f"re-encrypted {rotated} row(s)")
        return EXIT_OK

    # The remaining commands name an account.
    try:
        target = (
            None
            if command == "history" and args.principal is None and args.object_id is None
            else _parse_target(args.principal, args.object_id)
        )
    except (ValueError, _BadPrincipal):
        print(_BAD_PRINCIPAL, file=sys.stderr)
        return EXIT_CONFIG
    if command == "history":
        return _history(args, store, target)
    assert target is not None
    key = _lookup(store, target)

    if command in ("remove", "revoke"):
        removed = store.delete(key, actor=OPERATOR) if key is not None else False
        if not removed:
            print("not found: no enrollment for that account")
            return EXIT_NOT_FOUND
        print("revoked 1 enrollment" if command == "revoke" else "removed 1 enrollment")
        print(
            "note: this only deleted the stored Canvas token; the user can enroll again. "
            "Use 'disable' to cut a user off.",
            file=sys.stderr,
        )
        return EXIT_OK
    if command == "disable":
        if key is None:
            if target.entra is None:
                print("not found: no such account", file=sys.stderr)
                return EXIT_NOT_FOUND
            # Block someone before their first sign-in: a disabled account that their
            # identity will find.
            store.create_operator_account(
                provider_id=acc.PROVIDER_ENTRA,
                issuer=acc.entra_issuer(target.entra[0]),
                subject=target.entra[1],
                status="disabled",
                reason=DISABLE_REASON_OPERATOR,
            )
            print("disabled 1 user (a new account was created for them)")
            return EXIT_OK
        try:
            changed = store.disable_principal(
                key,
                actor=OPERATOR,
                reason=DISABLE_REASON_OPERATOR,
                allow_last_owner=args.allow_last_owner,
            )
        except AccessActionRefused as exc:
            if exc.code == AccessActionRefused.LAST_OWNER:
                print(
                    "refused: that user is the last active owner as far as the stored "
                    "owner roles show (a former owner who never signed in again still "
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
        changed = key is not None and store.enable_principal(key, actor=OPERATOR)
        if not changed:
            print("not disabled: nothing to enable")
            return EXIT_NOT_FOUND
        print("enabled 1 user")
        return EXIT_OK
    if command == "approve":
        changed = key is not None and store.approve_account(key, actor=OPERATOR)
        if not changed:
            print("not pending: nothing to approve")
            return EXIT_NOT_FOUND
        print("approved 1 account")
        return EXIT_OK
    if command == "promote-owner":
        changed = key is not None and store.promote_owner(key, actor=OPERATOR)
        if not changed:
            print("nothing to do: no such active account, or it is already an owner")
            return EXIT_NOT_FOUND
        print("promoted 1 account to owner")
        return EXIT_OK
    raise AssertionError(command)  # pragma: no cover - argparse enforces choices


def _history(args: argparse.Namespace, store: TokenStore, target: _Target | None) -> int:
    key: str | None = None
    if target is not None:
        key = _lookup(store, target)
        if key is None:
            print("not found: no such account", file=sys.stderr)
            return EXIT_NOT_FOUND
    by_key = {a.principal_key: a for a in store.list_accounts()}
    for event in store.list_status_events(key, limit=args.limit):
        account = by_key.get(event.principal_key)
        print(
            "\t".join(
                [
                    _iso(event.at),
                    event.principal_key,
                    event.action,
                    _cell(event.actor or "") or "-",
                    _cell(event.reason or "") or "-",
                    str(event.session_epoch),
                    (account.legacy_key if account is not None else None) or "-",
                ]
            )
        )
    return EXIT_OK


def _access(store: TokenStore) -> int:
    by_key = {a.principal_key: a for a in store.list_accounts()}
    for st in store.list_principal_statuses():
        if st.active and not st.is_owner:
            continue
        account = by_key.get(st.principal_key)
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
                    _iso(st.role_seen_at) if st.is_owner else "-",
                    (account.legacy_key if account is not None else None) or "-",
                ]
            )
        )
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "db":
            return _run_db(args)
        store = _open_store()
        if args.command == "access":
            return _access(store)
        return _run(args, store)
    except TokenDecryptionError:
        print("error: a stored token could not be decrypted", file=sys.stderr)
        return EXIT_CONFIG
    except TokenStoreError as exc:
        # Messages from the store carry key ids and counts only, never secrets.
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except OSError as exc:
        print(f"error: cannot open the token store ({type(exc).__name__})", file=sys.stderr)
        return EXIT_CONFIG


if __name__ == "__main__":
    sys.exit(main())
