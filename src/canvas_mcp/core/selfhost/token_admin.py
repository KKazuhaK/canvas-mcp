"""Operator commands for v1 accounts, credentials, grants and configuration.

Run ``python -m canvas_mcp.core.selfhost.token_admin --help`` for all commands.
Account targets are canonical bare UUIDs printed by ``accounts``; identity
operations use the identity UUID printed by ``identities``. Provider subjects,
Entra tenant/object pairs and pre-v1 principal-key forms are not account ids.

``check`` prints native aggregates and encryption key ids, never ciphertext.
``accounts``, ``list``, ``identities``, ``access`` and ``list-grants`` stream
bounded pages. ``history [UUID] --limit 1..200 [--cursor CURSOR]`` prints one
page and emits its next cursor on stderr, separate from tab-separated records.
``remove UUID`` deletes the primary credential; ``disable UUID`` cuts off the
account. Governance commands protect the last usable/active owner.

All schema creation, upgrades, backups and SQLite-to-PostgreSQL import live in
``db/migrations/``. ``db current`` only inspects schema state; ``db upgrade``
applies the reviewed v1 revision graph. Pre-v1 databases are refused. Import
snapshots a v1 SQLite source privately, verifies all sealed values and commits
the target atomically. It never modifies the source. Multi-instance operators
set ``DATABASE_AUTO_MIGRATE=false`` and upgrade before starting servers.

Reads ``CANVAS_TOKEN_KEYS``, ``SELFHOST_DATA_DIR`` and ``DATABASE_URL`` as the
server does. Never prints tokens, encryption keys or database passwords.
Exit codes: 0 success, 1 not found, 2 configuration/storage error, 3 protected
operation refused, 4 ``db current`` found a schema behind this build.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

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
        p.add_argument(
            "principal",
            nargs="?" if optional else None,
            help="canonical bare account UUID printed by 'accounts'",
        )

    sub.add_parser("check", help="open the store, print the row counts and key ids")
    identities = sub.add_parser(
        "identities", help="list linked sign-in methods (tab-separated, no secrets)"
    )
    principal(identities, optional=True)
    unlink = sub.add_parser(
        "unlink-identity",
        help="remove one sign-in method from an account (it keeps at least one)",
    )
    principal(unlink)
    unlink.add_argument("identity_id", help="the identity UUID printed by 'identities'")
    providers = sub.add_parser(
        "login-providers",
        help="show the configured sign-in providers and the redirect URIs to register",
    )
    providers.add_argument(
        "--check",
        action="store_true",
        help="also fetch each OpenID Connect provider's discovery document and keys (network)",
    )
    action = providers.add_mutually_exclusive_group()
    action.add_argument(
        "--revision",
        action="store_true",
        help="print the current configuration revision for operator recovery",
    )
    action.add_argument(
        "--import-env",
        action="store_true",
        help="explicitly adopt legacy environment credentials once",
    )
    action.add_argument(
        "--configure",
        metavar="PROVIDER",
        help="operator recovery: read provider configuration JSON from stdin",
    )
    sub.add_parser(
        "setup-code", help="print a private first-install code, renewing it if expired"
    )
    sub.add_parser(
        "list",
        help="list enrollments with their Canvas host (tab-separated, no tokens)",
    )
    accounts = sub.add_parser("accounts", help="list accounts or delete one account")
    actions = accounts.add_subparsers(dest="accounts_action")
    delete_account = actions.add_parser(
        "delete", help="delete an account and its bindings; retain audit history"
    )
    delete_account.add_argument("account_id", help="canonical bare account UUID")
    approve = sub.add_parser(
        "approve", help="approve an account that waits for approval"
    )
    principal(approve)
    promote = sub.add_parser(
        "promote-owner", help="make an active account an owner (emergency)"
    )
    principal(promote)
    disable = sub.add_parser(
        "disable", help="disable a user: refused everywhere until enabled"
    )
    principal(disable)
    disable.add_argument(
        "--allow-last-owner",
        action="store_true",
        help="allow disabling the last usable or last active owner (break-glass)",
    )
    enable = sub.add_parser("enable", help="lift a disablement")
    principal(enable)
    sub.add_parser(
        "access", help="list accounts that are not active, and owners (tab-separated)"
    )
    history = sub.add_parser("history", help="show the access history, newest first")
    principal(history, optional=True)
    history.add_argument("--limit", type=int, default=50)
    history.add_argument(
        "--cursor", help="opaque continuation from the previous history page"
    )
    remove_help = (
        "delete one user's stored Canvas token only (the user can enroll again; "
        "use 'disable' to cut someone off)"
    )
    principal(sub.add_parser("remove", help=remove_help))
    sub.add_parser("rotate", help="re-encrypt rows under the active key")
    list_grants = sub.add_parser(
        "list-grants",
        help="list connected apps (MCP_AUTH_MODE=selfhost; tab-separated, no secrets)",
    )
    principal(list_grants, optional=True)
    list_grants.add_argument(
        "--all", action="store_true", help="include ended and expired connections"
    )
    revoke_grant = sub.add_parser(
        "revoke-grant",
        help="end one connected app's connection, or all of one account's",
    )
    revoke_grant.add_argument(
        "grant_id", nargs="?", help="the grant id printed by list-grants"
    )
    revoke_grant.add_argument(
        "--account",
        metavar="PRINCIPAL",
        help="end every live connection of this account (acct:<uuid>, a bare uuid or entra:<tenant id>:<object id>)",
    )
    sub.add_parser(
        "rotate-jwt-key",
        help="invalidate every access token (apps refresh; grants stay)",
    )
    from .db.migrations.cli import register_subcommands

    register_subcommands(sub)
    from .config_cli import register

    register(sub)
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
    allow = (os.environ.get(ALLOW_OUTSIDE_ENV) or "").strip().lower() in (
        "true",
        "1",
        "yes",
    )
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
    from canvas_mcp.core.selfhost.db.migrations.transfer import refuse_silent_switch

    # Before anything is created or written: a command that ran on an empty target
    # next to a SQLite file with data would lose that file's disablements.
    refuse_silent_switch(database, default_sqlite_path(_data_dir()))
    store = TokenStore(database, keyring)
    store.initialize(auto_migrate=_auto_migrate())
    return store


def _run_db(args: argparse.Namespace) -> int:
    """Delegate every database upgrade command to the isolated migration package."""
    db = _database()
    from .db.migrations.cli import run

    try:
        return run(db, args)
    finally:
        db.dispose()


@dataclass(frozen=True)
class _Target:
    account_key: str


class _BadPrincipal(ValueError):
    """A typed target is not a canonical account UUID."""


def _parse_target(principal: str | None) -> _Target:
    if not isinstance(principal, str) or not _UUID_RE.fullmatch(principal):
        raise _BadPrincipal
    return _Target(principal)


def _lookup(store: TokenStore, target: _Target) -> str | None:
    return (
        target.account_key
        if store.get_principal_status(target.account_key).stored
        else None
    )


def _bad_principal(_exc: ValueError) -> str:
    return "error: name the account by its canonical bare UUID (see 'accounts')"


def _identity_columns(account: AccountInfo | None) -> tuple[str, str]:
    if account is not None:
        for identity in account.identities:
            if identity.provider_id == acc.PROVIDER_ENTRA:
                return identity.tenant_id or "-", identity.subject
    return "-", "-"


_GRANT_ID_RE = _UUID_RE


def _grant_state(grant: object, now: int) -> str:
    revoked_at = getattr(grant, "revoked_at", None)
    if revoked_at is not None:
        return f"revoked:{getattr(grant, 'revoked_reason', None) or '-'}"
    return "expired" if getattr(grant, "expires_at", 0) <= now else "active"


def _live_grants(store: TokenStore) -> str:
    """How many connected apps are live (``check``); "-" if the table cannot be read."""
    from canvas_mcp.core.selfhost.authz.store import AuthzStore

    try:
        count = AuthzStore(store.database).count_live_grants()
    except Exception:  # noqa: BLE001 - check must work on any readable store
        return "-"
    return str(count)


def _run_grants(args: argparse.Namespace, store: TokenStore) -> int:
    """The commands of the local authorization server (``list-grants`` and friends)."""
    import time

    from canvas_mcp.core.selfhost.authz.store import AuthzStore

    authz = AuthzStore(store.database)
    command: str = args.command
    if command == "list-grants":
        now = int(time.time())
        wanted: str | None = None
        if args.principal is not None:
            try:
                found = _lookup(store, _parse_target(args.principal))
            except ValueError as exc:
                print(_bad_principal(exc), file=sys.stderr)
                return EXIT_CONFIG
            if found is None:
                print("not found: no such account", file=sys.stderr)
                return EXIT_NOT_FOUND
            wanted = found
        for grant in authz.iter_grants(include_inactive=args.all, account_key=wanted):
            print(
                "	".join(
                    [
                        grant.id,
                        grant.account_key,
                        grant.client_kind,
                        _cell(grant.client_id),
                        _cell(grant.client_name) or "-",
                        _cell(grant.redirect_host) or "-",
                        _iso(grant.created_at),
                        _iso(grant.last_used_at),
                        _iso(grant.expires_at),
                        _grant_state(grant, now),
                    ]
                )
            )
        return EXIT_OK
    if command == "revoke-grant":
        if (args.grant_id is None) == (args.account is None):
            print(
                "error: give a GRANT_ID, or --account PRINCIPAL (not both)",
                file=sys.stderr,
            )
            return EXIT_CONFIG
        if args.account is not None:
            try:
                key = _lookup(store, _parse_target(args.account))
            except ValueError as exc:
                print(_bad_principal(exc), file=sys.stderr)
                return EXIT_CONFIG
            ended = 0
            if key is not None:
                for grant in authz.iter_grants(account_key=key):
                    ended += 1 if authz.operator_revoke_grant(grant.id) else 0
            if ended == 0:
                print("not found: no live connection for that account")
                return EXIT_NOT_FOUND
            print(f"revoked {ended} connection(s)")
            return EXIT_OK
        grant_id = str(args.grant_id).strip().lower()
        if not _GRANT_ID_RE.match(grant_id) or not authz.operator_revoke_grant(
            grant_id
        ):
            print("not found: no live connection with that id")
            return EXIT_NOT_FOUND
        print("revoked 1 connection")
        return EXIT_OK
    epoch = authz.bump_jwt_epoch()
    print(
        f"rotated to epoch {epoch}: existing access tokens are refused on their next request; "
        "refresh tokens and grants are kept"
    )
    return EXIT_OK


def _run(args: argparse.Namespace, store: TokenStore) -> int:
    command: str = args.command
    if command == "check":
        total, schools, kids = store.credential_inventory()
        print(f"rows: {total}")
        print("key ids in use: " + (", ".join(kids) if kids else "(none)"))
        print(f"schools in use: {schools}")
        by_status = store.account_counts()
        print(
            f"accounts: {by_status['total']} (active {by_status['active']}, "
            f"pending {by_status['pending']}, disabled {by_status['disabled']})"
        )
        print(f"live connected apps: {_live_grants(store)}")
        print(f"disabled users: {by_status['disabled']}")
        print(
            f"active owners seen: {store.count_active_owners()}"
            " (as of each owner's last sign-in; see 'access' for owner_seen_at)"
        )
        from .config_cli import summary

        for line in summary(store):
            print(line)
        return EXIT_OK
    if command == "list":
        cursor = None
        while True:
            page = store.enrollments_page(cursor=cursor, limit=200)
            by_key = store.enrollment_accounts(page.items)
            for row in page.items:
                tid, oid = _identity_columns(by_key.get(row.principal_key))
                print(
                    "\t".join(
                        [
                            tid,
                            oid,
                            _cell(row.canvas_user_name),
                            _iso(row.created_at),
                            _iso(row.last_used_at),
                            row.canvas_host or "-",
                            row.principal_key,
                        ]
                    )
                )
            if page.next_cursor is None:
                return EXIT_OK
            cursor = page.next_cursor
    if command == "accounts":
        if args.accounts_action == "delete":
            if not _UUID_RE.fullmatch(args.account_id):
                print("account id must be a canonical bare UUID", file=sys.stderr)
                return EXIT_CONFIG
            try:
                changed = store.delete_account(
                    args.account_id, listed_providers=_listed_providers(store)
                )
            except AccessActionRefused:
                print(
                    "refused: deletion would remove the last usable or active owner",
                    file=sys.stderr,
                )
                return EXIT_REFUSED
            print("deleted 1 account" if changed else "not found: no such account")
            return EXIT_OK if changed else EXIT_NOT_FOUND
        for account in store.iter_accounts():
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
                    ]
                )
            )
        return EXIT_OK
    if command == "identities":
        return _identities(args, store)
    if command == "rotate":
        rotated = store.rotate()
        print(f"re-encrypted {rotated} row(s)")
        return EXIT_OK
    if command in ("list-grants", "revoke-grant", "rotate-jwt-key"):
        return _run_grants(args, store)

    # The remaining commands name an account.
    try:
        target = (
            None
            if command == "history" and args.principal is None
            else _parse_target(args.principal)
        )
    except ValueError as exc:
        print(_bad_principal(exc), file=sys.stderr)
        return EXIT_CONFIG
    if command == "history":
        return _history(args, store, target)
    assert target is not None
    try:
        key = _lookup(store, target)
    except _BadPrincipal as exc:
        print(_bad_principal(exc), file=sys.stderr)
        return EXIT_CONFIG

    if command == "remove":
        removed = store.delete(key, actor=OPERATOR) if key is not None else False
        if not removed:
            print("not found: no enrollment for that account")
            return EXIT_NOT_FOUND
        print("removed 1 enrollment")
        print(
            "note: this only deleted the stored Canvas token; the user can enroll again. "
            "Use 'disable' to cut a user off.",
            file=sys.stderr,
        )
        return EXIT_OK
    if command == "disable":
        if key is None:
            print("not found: no such account", file=sys.stderr)
            return EXIT_NOT_FOUND
        try:
            changed = store.disable_principal(
                key,
                actor=OPERATOR,
                reason=DISABLE_REASON_OPERATOR,
                allow_last_owner=args.allow_last_owner,
                listed_providers=_listed_providers(store),
                additional_provider_lists=_protected_provider_lists(store),
            )
        except AccessActionRefused as exc:
            if exc.code == AccessActionRefused.LAST_LOCAL_OWNER:
                print(
                    "refused: keep at least one usable local administrator; create another local administrator first",
                    file=sys.stderr,
                )
                return EXIT_REFUSED
            if exc.code == AccessActionRefused.LAST_OWNER:
                print(
                    "refused: that user is the last usable owner (an active owner who can still "
                    "sign in as one under the listed sign-in providers) or the only active owner "
                    "as far as the stored owner roles show (a former owner who never signed in "
                    "again still counts; check 'access' for the owner_seen_at column). "
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
    if command == "unlink-identity":
        if key is None:
            print("not found: no such account", file=sys.stderr)
            return EXIT_NOT_FOUND
        result = store.unlink_identity(
            key,
            args.identity_id,
            actor=OPERATOR,
            listed_providers=_listed_providers(store),
            additional_provider_lists=_protected_provider_lists(store),
        )
        if result.ok:
            print(
                f"unlinked 1 sign-in method ({result.provider_id}); every browser session of the "
                "account ended, connected apps are unchanged"
            )
            return EXIT_OK
        if result.code == "last_identity":
            print(
                "refused: an account keeps at least one sign-in method (use 'disable' to cut "
                "someone off)",
                file=sys.stderr,
            )
            return EXIT_REFUSED
        if result.code == "last_local_owner":
            print(
                "refused: keep at least one usable local administrator; create another local administrator first",
                file=sys.stderr,
            )
            return EXIT_REFUSED
        if result.code == "last_owner":
            print(
                "refused: that would leave the server without a usable owner (an owner whose role "
                "comes from the Entra owner rule needs an Entra identity, any other owner an "
                "identity at a listed provider); promote or link another owner first",
                file=sys.stderr,
            )
            return EXIT_REFUSED
        print(
            "not found: that account has no sign-in method with that id",
            file=sys.stderr,
        )
        return EXIT_NOT_FOUND
    if command == "promote-owner":
        changed = key is not None and store.promote_owner(
            key, actor=OPERATOR, listed_providers=_listed_providers(store)
        )
        if not changed:
            print(
                "nothing to do: no such active account, it is already a usable owner, or it is "
                "an owner that cannot be made usable (it has no sign-in method at a listed "
                "provider: link one first, or list the provider it uses)"
            )
            return EXIT_NOT_FOUND
        print("promoted 1 account to owner")
        return EXIT_OK
    raise AssertionError(command)  # pragma: no cover - argparse enforces choices


def _history(
    args: argparse.Namespace, store: TokenStore, target: _Target | None
) -> int:
    # Retained audit history is readable after its account was deleted.
    key = target.account_key if target is not None else None
    try:
        page = store.audit_page(account_id=key, limit=args.limit, cursor=args.cursor)
    except ValueError:
        print("error: invalid history cursor or limit (1-200)", file=sys.stderr)
        return EXIT_CONFIG
    for event in page.items:
        print(
            "\t".join(
                [
                    _iso(event.at),
                    event.target or "-",
                    event.action,
                    _cell(event.actor or "") or "-",
                    _cell(event.reason or "") or "-",
                    str(event.detail.get("session_epoch", "-")),
                ]
            )
        )
    if page.next_cursor is not None:
        print("next_cursor: " + page.next_cursor, file=sys.stderr)
    return EXIT_OK


def _identities(args: argparse.Namespace, store: TokenStore) -> int:
    keys: Iterable[str]
    if args.principal is None:
        keys = (a.principal_key for a in store.iter_accounts())
    else:
        try:
            target = _parse_target(args.principal)
            found = _lookup(store, target)
        except ValueError as exc:
            print(_bad_principal(exc), file=sys.stderr)
            return EXIT_CONFIG
        if found is None:
            print("not found: no such account", file=sys.stderr)
            return EXIT_NOT_FOUND
        keys = [found]
    for key in keys:
        for identity in store.list_identities(key):
            print(
                "\t".join(
                    [
                        key,
                        str(identity.id),
                        _cell(identity.provider_id),
                        _cell(identity.issuer),
                        _cell(identity.subject),
                        _cell(identity.username) or "-",
                        _iso(identity.linked_at),
                        _iso(identity.last_login_at),
                    ]
                )
            )
    return EXIT_OK


def _redirect_uri(base: str, provider_id: str) -> str:
    from .routes import redirect_uri

    return redirect_uri(base, provider_id)


def _endpoint_hosts(meta: Any) -> str:
    """The host names of a provider's endpoints (never a path or a query)."""
    from urllib.parse import urlsplit

    hosts: list[str] = []
    for url in (
        meta.authorization_endpoint,
        meta.token_endpoint,
        meta.jwks_uri,
        meta.userinfo_endpoint,
    ):
        host = urlsplit(url).hostname if url else None
        if host and host not in hosts:
            hosts.append(host)
    return ",".join(hosts)


def _protected_provider_lists(store: TokenStore) -> tuple[frozenset[str], ...]:
    if store.database_managed_login_providers():
        return (store.recorded_login_providers(),)
    from .db.migrations.provider_environment import _protected_provider_lists as legacy

    return legacy(store)


def _listed_providers(store: TokenStore) -> frozenset[str] | None:
    if store.database_managed_login_providers():
        return store.recorded_login_providers()
    from .db.migrations.provider_environment import _listed_providers as legacy

    return legacy(store)


def _note_assumed_entra_only(store: TokenStore) -> None:
    if not store.database_managed_login_providers():
        from .db.migrations.provider_environment import (
            _note_assumed_entra_only as legacy,
        )

        legacy(store)


def _run_login_providers(args: argparse.Namespace) -> int:
    """``login-providers``: what is configured, and with ``--check`` whether the providers answer."""
    from canvas_mcp.core.selfhost.login.provider_config import (
        ProviderConfigurationError,
    )
    from canvas_mcp.core.selfhost.login.provider_settings import settings_from_database
    from canvas_mcp.core.selfhost.login.provider_store import ProviderConfigStore
    from canvas_mcp.core.selfhost.settings import (
        SelfhostConfigError,
        load_selfhost_settings,
    )

    try:
        settings = load_selfhost_settings()
        store = _open_store()
        try:
            if args.revision:
                from sqlalchemy import select

                from .db import schema

                with store.database.read() as conn:
                    print(
                        conn.execute(
                            select(schema.server_state.c.settings_revision)
                        ).scalar_one()
                    )
                return EXIT_OK
            providers = ProviderConfigStore(
                store.database,
                Keyring.parse(settings.canvas_token_keys_raw),
                validate=lambda snapshot: settings_from_database(settings, snapshot),
                icon_directory=settings.data_dir / "provider-icons",
            )
            if args.import_env:
                from .db.migrations.provider_environment import (
                    import_provider_settings,
                    load_provider_environment,
                )

                import_provider_settings(load_provider_environment(), providers)
            if args.configure:
                import json

                try:
                    raw = sys.stdin.read(8193)
                    body = json.loads(raw) if len(raw.encode("utf-8")) <= 8192 else None
                except (ValueError, UnicodeError):
                    body = None
                required = {"config", "enabled", "rank", "revision"}
                if (
                    not isinstance(body, dict)
                    or set(body) - required - {"client_secret"}
                    or not required <= set(body)
                    or type(body["revision"]) is not int
                    or body["revision"] < 0
                ):
                    print(
                        "error: Invalid provider configuration input", file=sys.stderr
                    )
                    return EXIT_CONFIG
                from .db.settings_repo import SettingsConflict

                try:
                    providers.save(
                        args.configure,
                        config=body["config"],
                        enabled=body["enabled"],
                        rank=body["rank"],
                        revision=body["revision"],
                        client_secret=body.get("client_secret"),
                        actor=None,
                        now=int(time.time()),
                    )
                except SettingsConflict:
                    print("error: Configuration revision changed", file=sys.stderr)
                    return EXIT_CONFIG
            settings = settings_from_database(settings, providers.load_snapshot())
        finally:
            store.close()
    except SelfhostConfigError as exc:
        for problem in exc.problems:
            print(f"error: {problem}", file=sys.stderr)
        return EXIT_CONFIG
    except ProviderConfigurationError:
        print("error: Stored login configuration is unavailable", file=sys.stderr)
        return EXIT_CONFIG
    login = settings.login_providers
    base = settings.public_base_url
    if not (args.check and login.public):
        for provider_id in login.order:
            print(f"{provider_id}	redirect_uri={_redirect_uri(base, provider_id)}")
        return EXIT_OK

    import asyncio

    from canvas_mcp.core.selfhost.login.registry import build_login_runtime
    from canvas_mcp.core.selfhost.login_state import InMemoryLoginStateStore

    runtime = build_login_runtime(settings, flow_store=InMemoryLoginStateStore())
    assert runtime is not None

    async def check() -> int:
        failed = 0
        for provider_id in login.order:
            line = f"{provider_id}	redirect_uri={_redirect_uri(base, provider_id)}"
            provider: Any = runtime.providers.get(provider_id)
            discovery = getattr(provider, "discovery", None)
            if provider_id == acc.PROVIDER_GITHUB and provider is not None:
                scopes = "user:email" + (
                    ",read:org" if provider.wants_membership else ""
                )
                print(
                    line
                    + f"	OK	scopes={scopes}	endpoints=github.com,api.github.com	pkce=S256"
                )
                continue
            if provider is None or discovery is None:
                print(line + "	OK	(nothing to discover)")
                continue
            try:
                await provider.prepare()
                meta = discovery.current()
                assert meta is not None
                await provider.jwks.ensure(meta.jwks_uri, None)
                print(
                    line
                    + f"	OK	issuer={meta.issuer}	hosts={_endpoint_hosts(meta)}	algs={','.join(meta.algs)}"
                    + f"	pkce={'listed' if meta.pkce_s256 else 'not listed'}"
                    + f"	iss_param={'yes' if meta.iss_param_supported else 'no'}"
                    + f"	token_auth={','.join(meta.token_auth_methods) or 'not listed'}"
                    + f"	jwks_keys={provider.jwks.key_count()}"
                )
            except Exception as exc:  # noqa: BLE001 - report the class only, never the response
                failed += 1
                print(line + f"	FAILED	{type(exc).__name__}")
        return failed

    return EXIT_NOT_FOUND if asyncio.run(check()) else EXIT_OK


def _access(store: TokenStore) -> int:
    for account in store.iter_accounts():
        st = account.status
        if st.active and not st.is_owner:
            continue
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
                ]
            )
        )
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from .runtime_secrets import with_saved_secrets

        os.environ.update(with_saved_secrets(os.environ))
        if args.command == "db":
            return _run_db(args)
        if args.command == "login-providers":
            return _run_login_providers(args)
        store = _open_store()
        try:
            if args.command == "setup-code":
                from .login.installation import InstallationAuthority
                from .login.provider_config import ProviderConfigurationError
                from .login.provider_store import ProviderConfigStore
                from .settings import load_selfhost_settings

                settings = load_selfhost_settings()
                authority = InstallationAuthority(
                    ProviderConfigStore(
                        store.database,
                        Keyring.parse(settings.canvas_token_keys_raw),
                        icon_directory=settings.data_dir / "provider-icons",
                    ),
                    settings.data_dir,
                )
                try:
                    code = authority.issue()
                except ProviderConfigurationError:
                    print(
                        "error: Installation authorization is unavailable",
                        file=sys.stderr,
                    )
                    return EXIT_CONFIG
                if code is None:
                    print("error: Installation is already configured", file=sys.stderr)
                    return EXIT_NOT_FOUND
                print(code)
                return EXIT_OK
            if args.command in {"schools", "providers", "settings"}:
                from .config_cli import refusal, run
                from .config_store import SchoolRemovalConfirmation
                from .db.settings_repo import SettingsConflict

                try:
                    return run(args, store)
                except (ValueError, SettingsConflict, SchoolRemovalConfirmation) as exc:
                    print("error: " + refusal(exc), file=sys.stderr)
                    return EXIT_CONFIG
            if args.command == "access":
                return _access(store)
            return _run(args, store)
        finally:
            store.close()
    except TokenDecryptionError:
        print("error: a stored token could not be decrypted", file=sys.stderr)
        return EXIT_CONFIG
    except TokenStoreError as exc:
        # Messages from the store carry key ids and counts only, never secrets.
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except OSError as exc:
        print(
            f"error: cannot open the token store ({type(exc).__name__})",
            file=sys.stderr,
        )
        return EXIT_CONFIG


if __name__ == "__main__":
    sys.exit(main())
