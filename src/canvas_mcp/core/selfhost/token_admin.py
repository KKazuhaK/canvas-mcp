"""Operator CLI for the self-hosted accounts and the encrypted Canvas token store.

Usage::

    python -m canvas_mcp.core.selfhost.token_admin check
    python -m canvas_mcp.core.selfhost.token_admin list
    python -m canvas_mcp.core.selfhost.token_admin accounts
    python -m canvas_mcp.core.selfhost.token_admin identities [PRINCIPAL]
    python -m canvas_mcp.core.selfhost.token_admin unlink-identity PRINCIPAL IDENTITY_ID
    python -m canvas_mcp.core.selfhost.token_admin login-providers [--check]
    python -m canvas_mcp.core.selfhost.token_admin approve PRINCIPAL
    python -m canvas_mcp.core.selfhost.token_admin promote-owner PRINCIPAL
    python -m canvas_mcp.core.selfhost.token_admin disable PRINCIPAL [--allow-last-owner]
    python -m canvas_mcp.core.selfhost.token_admin enable PRINCIPAL
    python -m canvas_mcp.core.selfhost.token_admin access
    python -m canvas_mcp.core.selfhost.token_admin history [PRINCIPAL] [--limit N]
    python -m canvas_mcp.core.selfhost.token_admin remove PRINCIPAL
    python -m canvas_mcp.core.selfhost.token_admin rotate
    python -m canvas_mcp.core.selfhost.token_admin list-grants [PRINCIPAL] [--all]
    python -m canvas_mcp.core.selfhost.token_admin revoke-grant GRANT_ID
    python -m canvas_mcp.core.selfhost.token_admin revoke-grant --account PRINCIPAL
    python -m canvas_mcp.core.selfhost.token_admin rotate-jwt-key
    python -m canvas_mcp.core.selfhost.token_admin db current
    python -m canvas_mcp.core.selfhost.token_admin db upgrade [--backup PATH] [--dry-run]
                                                              [--mark-undecryptable-invalid]
    python -m canvas_mcp.core.selfhost.token_admin db import-sqlite PATH
                                                              [--mark-undecryptable-invalid]

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

A PRINCIPAL may also name an account by one of its sign-in identities: ``google:<subject>``,
``github:<numeric user id>`` or ``oidc:<slug>:<subject>``. The issuer of an ``oidc`` identity
comes from ``OIDC_<SLUG>_ISSUER`` in the environment; without it the provider and subject must
match exactly one linked identity (otherwise exit 2 with a hint).

``identities`` prints one tab-separated line per linked sign-in method (every account, or
one): account key, identity id, provider, issuer, subject, sign-in name, linked, last sign-in.
It never prints an e-mail address. ``unlink-identity`` removes one by the id that line
shows: an account always keeps at least one (exit 3), every browser session of the account
ends, connected apps stay, and the audit log records it. ``login-providers`` prints the
configured sign-in providers with the redirect URI to register at each; ``--check`` also asks
every OpenID Connect provider for its discovery document and key set (the only command that
makes network calls; it never asks for a token) and prints the issuer, the hosts of its
endpoints, the signature algorithms, whether PKCE S256 and the RFC 9207 ``iss`` parameter are
advertised, and for GitHub the scopes a sign-in would request. It exits 1 if a provider is
unusable. It reads the server's environment, so it needs the same variables as the server.

``list-grants`` (``SELFHOST_AUTH_MODE=local``) prints one tab-separated line per connected
app: grant id, account key, client kind (``dcr`` or ``cimd``, which answers how a client
identifies itself), client id (the metadata URL for CIMD), the app's name for itself, the
return host, created, last used, expires, and the state (``active``, ``expired`` or
``revoked:<reason>``); ``--all`` includes the ended ones, ``PRINCIPAL`` keeps one account's
(exit 1 if there is no such account). It never prints a token, a code or a hash.
``revoke-grant`` ends one connection by its id, or all of one account's with ``--account``
(each one is audited; exit 1 if there is nothing to end); the running server notices within
``GRANT_STATUS_CACHE_S``. ``rotate-jwt-key`` invalidates every access token (apps simply
refresh; connections are untouched; running servers notice within 30 seconds). To rotate
the signing key itself, put a new key first in ``CANVAS_TOKEN_KEYS``. ``check`` also prints
how many connections are live.

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
empty PostgreSQL database (``DATABASE_URL``): a file from before the account model is
first migrated to the current schema in a private copy (it needs the keys and accepts
``--mark-undecryptable-invalid`` like ``db upgrade``), then the schema and every row are
created in one PostgreSQL transaction and every token is checked to still decrypt. The
flag marks tokens that fail to decrypt under a key the keyring has (the user enrolls
again, the credential generation is raised and the audit log records it); a stored key
id that ``CANVAS_TOKEN_KEYS`` lacks always stops the import, because the server would
refuse to start on it. The output counts the tokens marked invalid. On any failure
PostgreSQL is left as it was; the source file is never modified.

Every command except ``db ...`` refuses to run (exit 2) on a database that holds no
rows while the default SQLite file in the data directory still has data: using it
would hide the disablements stored in that file. Import the file first.

Reads ``CANVAS_TOKEN_KEYS``, ``SELFHOST_DATA_DIR`` (default ``/data``) and
``DATABASE_URL`` (unset: the SQLite file in the data directory) from the
environment, like the server. Schema changes are applied before a command runs
unless ``DATABASE_AUTO_MIGRATE=false``. Never prints a token, a key, a database
password or any other secret.

Exit codes: 0 ok, 1 not found, 2 configuration, keyring or database error, 3
refused (for example disabling the last usable owner), 4 ``db current`` found the
schema behind this build (run ``db upgrade``).
"""

from __future__ import annotations

import argparse
import contextlib
import os
import pathlib
import re
import sys
from collections.abc import Iterator
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
            help=(
                "acct:<uuid>, a bare uuid, entra:<tenant id>:<object id>, google:<subject>, "
                "github:<numeric user id>, oidc:<slug>:<subject>, or TENANT_ID with OBJECT_ID"
            ),
        )
        p.add_argument("object_id", nargs="?", help="the object id when PRINCIPAL is a tenant id")

    sub.add_parser("check", help="open the store, print the row counts and key ids")
    identities = sub.add_parser(
        "identities", help="list linked sign-in methods (tab-separated, no secrets)"
    )
    principal(identities, optional=True)
    unlink = sub.add_parser(
        "unlink-identity", help="remove one sign-in method from an account (it keeps at least one)"
    )
    unlink.add_argument(
        "principal",
        help=(
            "acct:<uuid>, a bare uuid, entra:<tenant id>:<object id>, google:<subject>, "
            "github:<numeric user id> or oidc:<slug>:<subject>"
        ),
    )
    unlink.add_argument("identity_id", type=int, help="the identity id printed by 'identities'")
    unlink.set_defaults(object_id=None)
    providers = sub.add_parser(
        "login-providers", help="show the configured sign-in providers and the redirect URIs to register"
    )
    providers.add_argument(
        "--check",
        action="store_true",
        help="also fetch each OpenID Connect provider's discovery document and keys (network)",
    )
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
        help="allow disabling the last usable or last active owner (break-glass)",
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
    list_grants = sub.add_parser(
        "list-grants", help="list connected apps (SELFHOST_AUTH_MODE=local; tab-separated, no secrets)"
    )
    principal(list_grants, optional=True)
    list_grants.add_argument("--all", action="store_true", help="include ended and expired connections")
    revoke_grant = sub.add_parser(
        "revoke-grant", help="end one connected app's connection, or all of one account's"
    )
    revoke_grant.add_argument("grant_id", nargs="?", help="the grant id printed by list-grants")
    revoke_grant.add_argument(
        "--account",
        metavar="PRINCIPAL",
        help="end every live connection of this account (acct:<uuid>, a bare uuid or entra:<tenant id>:<object id>)",
    )
    sub.add_parser("rotate-jwt-key", help="invalidate every access token (apps refresh; grants stay)")
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
    import_sqlite.add_argument(
        "--mark-undecryptable-invalid",
        action="store_true",
        help="mark tokens that do not decrypt invalid instead of refusing the import",
    )
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
        report_ = import_sqlite(
            db,
            pathlib.Path(args.path),
            keyring,
            mark_undecryptable_invalid=args.mark_undecryptable_invalid,
        )
        for table, count in report_.counts.items():
            print(f"{table}: {count} row(s)")
        if report_.migration.ran:
            print("migration of the private copy:")
            for line in report_.migration.lines():
                print(f"  {line}")
        print(f"tokens marked invalid during the import: {report_.total_marked_invalid}")
        print(
            "imported at the current schema; every stored token that is not marked invalid "
            "decrypts with CANVAS_TOKEN_KEYS"
        )
        return EXIT_OK
    raise AssertionError(command)  # pragma: no cover - argparse enforces choices


@dataclass(frozen=True)
class _Target:
    """A principal as the operator typed it."""

    account_key: str | None
    entra: tuple[str, str] | None  # (tenant id, object id)
    #: ``(provider id, subject, issuer or None)`` of a Google, GitHub or generic OIDC identity.
    external: tuple[str, str, str | None] | None = None


class _BadPrincipal(ValueError):
    """The typed principal is not a known form (``detail`` is a fixed text, never user input)."""

    detail: str | None = None


class _AmbiguousPrincipal(_BadPrincipal):
    """An OpenID Connect subject without its issuer matches more than one provider identity."""

    detail = (
        "error: that subject is linked to more than one account issuer; set "
        "OIDC_<SLUG>_ISSUER in the environment (the same variables as the server) so the "
        "identity is looked up by its issuer, or name the account as acct:<uuid>"
    )


_EXTERNAL_GOOGLE_RE = re.compile(r"^google:([A-Za-z0-9_-]{1,255})$")
_EXTERNAL_GITHUB_RE = re.compile(r"^github:([1-9][0-9]{0,19})$")
_EXTERNAL_OIDC_RE = re.compile(r"^oidc:([a-z](?:[a-z0-9-]{0,30}[a-z0-9])?):([\x21-\x7e]{1,255})$")


def _external_target(text: str) -> _Target | None:
    """``google:<sub>``, ``github:<numeric id>`` or ``oidc:<slug>:<sub>`` (subjects keep their case)."""
    if (match := _EXTERNAL_GOOGLE_RE.match(text)) is not None:
        return _Target(None, None, (acc.PROVIDER_GOOGLE, match.group(1), acc.GOOGLE_ISSUER))
    if (match := _EXTERNAL_GITHUB_RE.match(text)) is not None:
        return _Target(None, None, (acc.PROVIDER_GITHUB, match.group(1), acc.GITHUB_ISSUER))
    if (match := _EXTERNAL_OIDC_RE.match(text)) is not None and "," not in text:
        from canvas_mcp.core.selfhost.login.config import env_prefix

        provider_id = f"{acc.PROVIDER_OIDC_PREFIX}{match.group(1)}"
        configured = os.environ.get(env_prefix(match.group(1)) + "ISSUER", "").strip()
        return _Target(None, None, (provider_id, match.group(2), configured or None))
    return None


def _parse_target(principal: str | None, object_id: str | None) -> _Target:
    if principal is None:
        raise _BadPrincipal
    external = None if object_id is not None else _external_target(principal.strip())
    if external is not None:
        return external
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
    if target.external is not None:
        provider_id, subject, issuer = target.external
        if issuer is not None:
            return store.lookup_identity(provider_id, issuer, subject)
        # No issuer in the environment: a provider and subject that match exactly one identity name it.
        found = {
            account.principal_key
            for account in store.list_accounts()
            for identity in account.identities
            if identity.provider_id == provider_id and identity.subject == subject
        }
        if len(found) > 1:
            raise _AmbiguousPrincipal
        return next(iter(found), None)
    assert target.entra is not None
    return store.lookup_identity(
        acc.PROVIDER_ENTRA, acc.entra_issuer(target.entra[0]), target.entra[1]
    )


_BAD_PRINCIPAL = (
    "error: name the account as acct:<uuid>, entra:<tenant GUID>:<object GUID>, google:<subject>, "
    "github:<numeric user id>, oidc:<slug>:<subject>, or give TENANT_ID and OBJECT_ID (both GUIDs)"
)


def _bad_principal(exc: ValueError) -> str:
    """The message for a principal the operator typed wrongly (fixed text only)."""
    return (exc.detail if isinstance(exc, _BadPrincipal) else None) or _BAD_PRINCIPAL



def _identity_columns(account: AccountInfo | None) -> tuple[str, str]:
    legacy = None if account is None else account.legacy_key
    parts = split_entra_key(legacy) if legacy else None
    return parts if parts is not None else ("-", "-")


_GRANT_ID_RE = _UUID_RE
#: ``list-grants`` reads at most this many connections (the store's own ceiling).
_MAX_LISTED_GRANTS = 2000


def _grant_state(grant: object, now: int) -> str:
    revoked_at = getattr(grant, "revoked_at", None)
    if revoked_at is not None:
        return f"revoked:{getattr(grant, 'revoked_reason', None) or '-'}"
    return "expired" if getattr(grant, "expires_at", 0) <= now else "active"


def _live_grants(store: TokenStore) -> str:
    """How many connected apps are live (``check``); "-" if the table cannot be read."""
    from canvas_mcp.core.selfhost.authz.store import AuthzStore

    try:
        count = len(AuthzStore(store.database).list_all_grants(limit=_MAX_LISTED_GRANTS))
    except Exception:  # noqa: BLE001 - check must work on any readable store
        return "-"
    return f"{count}+" if count >= _MAX_LISTED_GRANTS else str(count)


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
                found = _lookup(store, _parse_target(args.principal, args.object_id))
            except ValueError as exc:
                print(_bad_principal(exc), file=sys.stderr)
                return EXIT_CONFIG
            if found is None:
                print("not found: no such account", file=sys.stderr)
                return EXIT_NOT_FOUND
            wanted = found
        for grant in authz.list_all_grants(
            include_inactive=args.all, limit=_MAX_LISTED_GRANTS, account_key=wanted
        ):
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
            print("error: give a GRANT_ID, or --account PRINCIPAL (not both)", file=sys.stderr)
            return EXIT_CONFIG
        if args.account is not None:
            try:
                key = _lookup(store, _parse_target(args.account, None))
            except ValueError as exc:
                print(_bad_principal(exc), file=sys.stderr)
                return EXIT_CONFIG
            ended = 0
            if key is not None:
                for grant in authz.list_grants(key):
                    ended += 1 if authz.operator_revoke_grant(grant.id) else 0
            if ended == 0:
                print("not found: no live connection for that account")
                return EXIT_NOT_FOUND
            print(f"revoked {ended} connection(s)")
            return EXIT_OK
        grant_id = str(args.grant_id).strip().lower()
        if not _GRANT_ID_RE.match(grant_id) or not authz.operator_revoke_grant(grant_id):
            print("not found: no live connection with that id")
            return EXIT_NOT_FOUND
        print("revoked 1 connection")
        return EXIT_OK
    epoch = authz.bump_jwt_epoch()
    print(
        f"rotated to epoch {epoch}: access tokens stop verifying within 30 s; "
        "refresh tokens and grants are kept"
    )
    return EXIT_OK


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
        print(f"live connected apps: {_live_grants(store)}")
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
            if command == "history" and args.principal is None and args.object_id is None
            else _parse_target(args.principal, args.object_id)
        )
    except ValueError as exc:
        print(_bad_principal(exc), file=sys.stderr)
        return EXIT_CONFIG
    if command == "history":
        return _history(args, store, target)
    assert target is not None
    try:
        key = _lookup(store, target)
    except _AmbiguousPrincipal as exc:
        print(_bad_principal(exc), file=sys.stderr)
        return EXIT_CONFIG

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
                listed_providers=_listed_providers(store),
            )
        except AccessActionRefused as exc:
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
            key, args.identity_id, actor=OPERATOR, listed_providers=_listed_providers(store)
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
        if result.code == "last_owner":
            print(
                "refused: that would leave the server without a usable owner (an owner whose role "
                "comes from the Entra owner rule needs an Entra identity, any other owner an "
                "identity at a listed provider); promote or link another owner first",
                file=sys.stderr,
            )
            return EXIT_REFUSED
        print("not found: that account has no sign-in method with that id", file=sys.stderr)
        return EXIT_NOT_FOUND
    if command == "promote-owner":
        changed = key is not None and store.promote_owner(
            key, actor=OPERATOR, listed_providers=_listed_providers(store)
        )
        if not changed:
            print("nothing to do: no such active account, or it is already an owner")
            return EXIT_NOT_FOUND
        print("promoted 1 account to owner")
        return EXIT_OK
    raise AssertionError(command)  # pragma: no cover - argparse enforces choices


def _history(args: argparse.Namespace, store: TokenStore, target: _Target | None) -> int:
    key: str | None = None
    if target is not None:
        try:
            key = _lookup(store, target)
        except _AmbiguousPrincipal as exc:
            print(_bad_principal(exc), file=sys.stderr)
            return EXIT_CONFIG
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


def _identities(args: argparse.Namespace, store: TokenStore) -> int:
    keys: list[str]
    if args.principal is None and args.object_id is None:
        keys = [st.principal_key for st in store.list_principal_statuses()]
    else:
        try:
            target = _parse_target(args.principal, args.object_id)
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
    if provider_id == acc.PROVIDER_ENTRA:
        return f"{base}/account/callback"
    if provider_id in (acc.PROVIDER_GOOGLE, acc.PROVIDER_GITHUB):
        return f"{base}/account/callback/{provider_id}"
    return f"{base}/account/callback/oidc/{provider_id.removeprefix('oidc:')}"


def _endpoint_hosts(meta: Any) -> str:
    """The host names of a provider's endpoints (never a path or a query)."""
    from urllib.parse import urlsplit

    hosts: list[str] = []
    for url in (meta.authorization_endpoint, meta.token_endpoint, meta.jwks_uri, meta.userinfo_endpoint):
        host = urlsplit(url).hostname if url else None
        if host and host not in hosts:
            hosts.append(host)
    return ",".join(hosts)


def _listed_providers(store: TokenStore) -> frozenset[str] | None:
    """The providers of ``SELFHOST_LOGIN_PROVIDERS`` the usable-owner checks use (None: all).

    They decide which owners are usable, so they must be the server's. In this order:

    1. the list the server recorded in the database at its last startup (``meta``): an operator
       shell often lacks the server's variables, and this does not depend on them;
    2. this environment: the full settings, else ``SELFHOST_LOGIN_PROVIDERS`` alone.

    A note on stderr says so when the answer had to be assumed: the list is unreadable (every
    provider is then counted as listed, which is more permissive than the server), or nothing
    names it (no record, no variable) while the database holds sign-in methods at providers other
    than Entra (Entra alone is then assumed). A deployment with Entra alone gets no note.
    """
    from canvas_mcp.core.selfhost.login.config import (
        LOGIN_PROVIDERS_ENV,
        parse_login_providers,
    )
    from canvas_mcp.core.selfhost.settings import (
        SelfhostConfigError,
        load_selfhost_settings,
    )

    recorded = store.recorded_login_providers()
    if recorded is not None:
        return recorded
    named = bool((os.environ.get(LOGIN_PROVIDERS_ENV) or "").strip())
    try:
        with _quiet_login_config():
            loaded = load_selfhost_settings().login_providers.ids
    except SelfhostConfigError:
        pass
    else:
        if not named:
            _note_assumed_entra_only(store)
        return loaded
    ignored: list[str] = []
    try:
        # authz_mode "local": the mode of the other settings is not known here, and this reads
        # the list alone.
        with _quiet_login_config():
            ids = parse_login_providers(os.environ, ignored, authz_mode="local").ids
    except Exception:  # noqa: BLE001 - an unreadable list falls back to "all listed"
        ids = frozenset()
    if ids and not any(p.startswith(LOGIN_PROVIDERS_ENV) for p in ignored):
        if not named:
            _note_assumed_entra_only(store)
        return ids
    print(
        "note: SELFHOST_LOGIN_PROVIDERS is not readable in this environment; every provider is "
        "assumed to be listed, so the usable-owner check is more permissive than the server's",
        file=sys.stderr,
    )
    return None


def _note_assumed_entra_only(store: TokenStore) -> None:
    """Tell the operator when Entra alone is assumed for a database that holds other providers."""
    others = sorted(
        {
            identity.provider_id
            for account in store.list_accounts()
            for identity in account.identities
            if identity.provider_id != acc.PROVIDER_ENTRA
        }
    )
    if others:
        print(
            "note: the server has not recorded its SELFHOST_LOGIN_PROVIDERS and this environment "
            f"does not set it, so only entra is assumed to be listed, but the database holds "
            f"sign-in methods at {', '.join(others[:5])}; run this command with the server's "
            "environment (or start the server once) so the usable-owner check matches it",
            file=sys.stderr,
        )


@contextlib.contextmanager
def _quiet_login_config() -> Iterator[None]:
    """Keep the stray-provider-variable warnings of the settings parser out of this command.

    ``GOOGLE_CLIENT_ID`` and the like, set while ``SELFHOST_LOGIN_PROVIDERS`` is not, are ignored
    and logged as a warning where the server starts; here they would only add noise to a command
    whose output people and scripts read. Nothing else the logger says is touched.
    """
    import logging

    from canvas_mcp.core.selfhost.login import config as login_config

    class _Stray(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return not (
                record.levelno == logging.WARNING
                and "is unset: it is ignored" in record.getMessage()
            )

    stray = _Stray()
    login_config.logger.addFilter(stray)
    try:
        yield
    finally:
        login_config.logger.removeFilter(stray)


def _run_login_providers(args: argparse.Namespace) -> int:
    """``login-providers``: what is configured, and with ``--check`` whether the providers answer."""
    from canvas_mcp.core.selfhost.settings import (
        SelfhostConfigError,
        load_selfhost_settings,
    )

    try:
        settings = load_selfhost_settings()
    except SelfhostConfigError as exc:
        for problem in exc.problems:
            print(f"error: {problem}", file=sys.stderr)
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
                scopes = "user:email" + (",read:org" if provider.wants_membership else "")
                print(line + f"	OK	scopes={scopes}	endpoints=github.com,api.github.com	pkce=S256")
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
        if args.command == "login-providers":
            return _run_login_providers(args)
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
