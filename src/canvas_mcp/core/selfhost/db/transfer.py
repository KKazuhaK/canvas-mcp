"""Moving an existing SQLite token database into PostgreSQL.

Switching ``DATABASE_URL`` to an empty database would silently drop
``accounts`` (the disablements) and re-activate disabled users, who could
then enroll again. The server and the operator CLI therefore refuse to run in that
situation (``refuse_silent_switch``: the target holds no rows while the default
SQLite file does; an empty schema does not count as data) and
``token_admin db import-sqlite`` is the way across.

The import is all or nothing: it ends in a PostgreSQL database at the current schema
with every row, or it leaves the target exactly as it was:

1. The SQLite file is copied to a private temporary file (the source is opened
   read-only and never modified) and that copy is migrated to the current schema
   with the keyring: a file from before the account model (schema 1 to 4) gets its
   accounts and identities, and every token is re-encrypted under its ``acct:<uuid>``
   principal, exactly as ``db upgrade`` would do it. PostgreSQL has not been touched yet.
2. In ONE PostgreSQL transaction (DDL is transactional there) the schema is created,
   the migrated rows are copied unchanged (the AAD does not depend on the backend),
   the identity sequences are moved past the copied ids, the row counts are compared
   and every stored token is decrypted with the keyring.

Any failure rolls the transaction back, schema included, so an empty database is
still "uninitialized" afterwards and the silent-switch guard keeps the server
refusing (it judges by data, never by schema). The temporary copy is deleted.
Messages carry counts and key ids only.
"""

from __future__ import annotations

import pathlib
import sqlite3
import tempfile
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, insert, select, text, update
from sqlalchemy.engine import Connection

from . import migrate, schema
from .accounts_v5 import AccountMigrationReport
from .engine import Database
from .errors import StoreUnavailable, TokenStoreError
from .repos import Repositories

#: Tables copied, in order. ``meta`` is not copied as a table: the target is created by
#: Alembic. The one value in it that matters, the access-token epoch (``rotate-jwt-key``),
#: is carried over on its own (``_carry_jwt_epoch``): the grants are copied as live, so an
#: import must not bring back tokens that a rotation had invalidated.
COPIED_TABLES = (
    "canvas_tokens",
    "user_tool_prefs",
    "accounts",
    "external_identities",
    "principal_status_events",
    "credential_generations",
    "auth_events",
    "audit_log",
    # The authorization server's long-lived state: registered clients, the client
    # metadata documents, the connections (grants) and their refresh tokens. Moving a
    # server to PostgreSQL must not sign every connected app out.
    "oauth_clients",
    "cimd_clients",
    "oauth_grants",
    "oauth_refresh_tokens",
)
#: Tables that are not copied: minutes-long state (authorization codes and the login
#: states of requests waiting for a sign-in). An import loses at most a connection
#: that was being approved at that moment; the app simply starts it again.
EPHEMERAL_TABLES = ("oauth_codes", "login_states")
#: The tables whose rows make a database "hold data" for the silent-switch guard.
#: (The sign-in history and the audit log only exist next to accounts.)
_DATA_TABLES = (
    "canvas_tokens",
    "user_tool_prefs",
    "accounts",
    "external_identities",
    "principal_status_events",
    "credential_generations",
)
#: Probed in a SQLite file of any release: the legacy ``principal_status`` is still
#: listed, because a file from before the account model keeps its disablements there.
_PROBE_TABLES = (
    "canvas_tokens",
    "principal_status",
    "principal_status_events",
    "user_tool_prefs",
    "accounts",
    "external_identities",
)
#: Tables with an identity column: the sequence is moved past the copied ids.
_IDENTITY_TABLES = ("principal_status_events", "external_identities", "auth_events", "audit_log")


@dataclass(frozen=True)
class ImportReport:
    """What an import did: rows copied, what the copy migration did, tokens marked invalid.

    ``tokens_marked_invalid`` counts the tokens the final check on PostgreSQL found
    unreadable and marked; the ones the migration of the copy marked are in
    ``migration.tokens_marked_invalid``. Both stay zero unless
    ``--mark-undecryptable-invalid`` was given.
    """

    counts: dict[str, int]
    migration: AccountMigrationReport
    tokens_marked_invalid: int = 0

    @property
    def total_marked_invalid(self) -> int:
        return self.migration.tokens_marked_invalid + self.tokens_marked_invalid


def legacy_sqlite_has_rows(path: pathlib.Path) -> bool:
    """True if the SQLite file at ``path`` exists and holds enrollments or access state.

    A file that exists but cannot be read counts as "has rows": the caller refuses
    rather than guess that nothing would be lost.
    """
    if not path.is_file():
        return False
    try:
        conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error:
        return True
    try:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        for table in _PROBE_TABLES:
            if table in names and conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                return True
        return False
    except sqlite3.Error:
        return True
    finally:
        conn.close()


def target_holds_rows(target: Database) -> bool:
    """True if any table that holds accounts, tokens or access state of ``target`` has a row.

    Judged by data, not by schema: a schema that a failed import, ``db upgrade`` or
    a read-only CLI command created is still an empty database.
    """
    from sqlalchemy import inspect

    with target.guard(), target.read() as conn:
        existing = set(inspect(conn).get_table_names())
        for name in _DATA_TABLES:
            if name in existing:
                table = schema.metadata.tables[name]
                if conn.execute(select(table).limit(1)).first() is not None:
                    return True
    return False


def refuse_silent_switch(target: Database, legacy_path: pathlib.Path) -> None:
    """Fail closed when ``target`` holds no data but the default SQLite file does.

    Starting on such a target would drop the disablements stored in the SQLite file,
    and a disabled user could enroll again. Does nothing when ``target`` is that
    SQLite file itself, when the file holds nothing, or when the target is a
    database this build refuses anyway (newer or unreadable: ``ensure_ready``
    reports that with its own message). Raises :class:`TokenStoreError`.
    """
    sqlite_path = target.sqlite_path
    if sqlite_path is not None:
        try:
            if sqlite_path.resolve() == legacy_path.resolve():
                return
        except OSError:
            if sqlite_path == legacy_path:
                return
    if not legacy_sqlite_has_rows(legacy_path):
        return
    state = migrate.current(target).state
    if state in (migrate.STATE_NEWER, migrate.STATE_UNREADABLE):
        return
    if state != migrate.STATE_UNINITIALIZED and target_holds_rows(target):
        return
    way_across = (
        "Import it with: python -m canvas_mcp.core.selfhost.token_admin db import-sqlite PATH, "
        "or move the SQLite file away if it is meant to be abandoned"
        if target.kind == "postgresql"
        else "Point DATABASE_URL back at it, or move the SQLite file away if it is meant "
        "to be abandoned"
    )
    raise TokenStoreError(
        "DATABASE_URL names a database that holds no data, but the SQLite token database "
        f"in the data directory still holds data (including access decisions). {way_across}"
    )


def _private_migrated_copy(
    source: pathlib.Path,
    workdir: pathlib.Path,
    keyring: Any,
    *,
    mark_undecryptable_invalid: bool,
    report: AccountMigrationReport,
) -> tuple[dict[str, list[Any]], int]:
    """Copy ``source`` into ``workdir``, migrate the copy to head, return its rows.

    Touches neither ``source`` nor PostgreSQL. What the migration did is collected
    in ``report`` (all zero for a file that is already current). Returns the rows of the
    copied tables and the access-token epoch. Raises :class:`StoreUnavailable` if the
    file cannot be read and :class:`TokenStoreError` (naming the migration, not the
    import) if the copy cannot be brought to the current schema.
    """
    copy = workdir / "source.sqlite3"
    try:
        src = sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True, timeout=5.0)
        try:
            dst = sqlite3.connect(str(copy))
            try:
                src.backup(dst)
            finally:
                dst.close()
        finally:
            src.close()
    except sqlite3.Error:
        raise StoreUnavailable("the SQLite file cannot be read", "sqlite3.Error") from None
    origin = Database.sqlite(copy)
    try:
        try:
            migrate.ensure_ready(
                origin,
                auto=True,
                keyring=keyring,
                options=migrate.MigrationOptions(
                    mark_undecryptable_invalid=mark_undecryptable_invalid
                ),
                report=report,
                auto_backup=False,
            )
        except TokenStoreError as exc:
            # Includes KeyringError. The detail is curated by the migration (counts and
            # key ids); what this adds is where it happened and what was left alone.
            raise TokenStoreError(
                "the SQLite file could not be migrated to the current schema in a "
                f"private copy: {exc}. Nothing was imported; the SQLite file and "
                "PostgreSQL were not changed"
            ) from None
        if migrate.current(origin).state != migrate.STATE_CURRENT:
            raise TokenStoreError(
                "the private copy of the SQLite file is not at the current schema after "
                "its migration. Nothing was imported"
            )
        with origin.read() as oconn:
            rows = {
                name: list(oconn.execute(select(schema.metadata.tables[name])).all())
                for name in COPIED_TABLES
            }
            epoch = Repositories(origin.kind).jwt_epoch.get(oconn)
            return rows, epoch
    finally:
        origin.dispose()


def _verify_tokens(conn: Connection, keyring: Any, *, mark_invalid: bool = False) -> int:
    """Check every stored token as the server would; return how many were marked invalid.

    A row whose key id is not in the keyring always fails the import, flag or not: the
    server refuses to start when a stored row (even an invalid one) names a key id the
    keyring lacks, so marking it would produce a database nobody can run.

    A row that fails to decrypt under a key id that is present fails the import too,
    unless ``mark_invalid`` (the operator passed ``--mark-undecryptable-invalid``): such
    row is then marked invalid with the reason ``decrypt_failed``, in this transaction
    and as the runtime ``TokenStore.mark_invalid`` and the account migration do: the
    credential generation is raised (reason ``invalidated``) and an audit entry is
    written. A row that was invalid for another reason is switched to ``decrypt_failed``
    too (as the account migration does): the server's key check skips only rows with
    that reason, so otherwise it would refuse to start on a token it cannot read.
    """
    from ..token_store import (
        AUDIT_TOKEN_MARKED_INVALID,
        GENERATION_INVALIDATED,
        KeyringError,
        TokenDecryptionError,
        _aad_for_principal,
        _json,
    )

    tokens = schema.canvas_tokens
    key_ids = set(keyring.key_ids)
    unreadable: list[tuple[str, bool]] = []
    for row in conn.execute(
        select(
            tokens.c.principal_key,
            tokens.c.canvas_host,
            tokens.c.key_id,
            tokens.c.nonce,
            tokens.c.ciphertext,
            tokens.c.status,
            tokens.c.invalid_reason,
        )
    ):
        if row.key_id not in key_ids:
            raise KeyringError(
                f"CANVAS_TOKEN_KEYS is missing key id {row.key_id}; nothing was imported "
                "(restore that key: --mark-undecryptable-invalid cannot help, because the "
                "server would refuse to start on a database that names it)"
            )
        if row.status == "invalid" and row.invalid_reason == "decrypt_failed":
            # Already known to be unreadable in the source: carried over as it was.
            continue
        try:
            aad = _aad_for_principal(row.principal_key, row.canvas_host, row.key_id)
            keyring.decrypt(row.key_id, bytes(row.nonce), bytes(row.ciphertext), aad)
        except (TokenDecryptionError, ValueError):
            if mark_invalid:
                unreadable.append((row.principal_key, row.status == "invalid"))
                continue
            raise TokenStoreError(
                "a stored token does not decrypt with CANVAS_TOKEN_KEYS after the copy; "
                "nothing was imported (repeat with --mark-undecryptable-invalid to mark "
                "such rows invalid)"
            ) from None
    repos = Repositories("postgresql")
    now = int(time.time())
    marked = 0
    for principal_key, was_invalid in unreadable:
        if was_invalid:
            conn.execute(
                update(tokens)
                .where(tokens.c.principal_key == principal_key)
                .values(invalid_reason="decrypt_failed")
            )
        else:
            repos.tokens.mark_invalid(
                conn,
                principal_key,
                reason="decrypt_failed",
                now=now,
                expected_updated_at=None,
                expected_generation=None,
            )
        marked += 1
        repos.generations.bump(conn, principal_key, GENERATION_INVALIDATED, now)
        repos.audit.append(
            conn,
            now=now,
            actor="system",
            action=AUDIT_TOKEN_MARKED_INVALID,
            target=principal_key,
            reason="decrypt_failed",
            detail=_json({"via": "import-sqlite"}),
        )
    return marked


def _copy_rows(conn: Connection, rows: dict[str, list[Any]]) -> dict[str, int]:
    """Insert ``rows`` into the empty tables of ``conn`` and move the identity sequences."""
    counts: dict[str, int] = {}
    for name in COPIED_TABLES:
        table = schema.metadata.tables[name]
        if conn.execute(select(func.count()).select_from(table)).scalar_one():
            raise TokenStoreError(
                "refusing to import into a PostgreSQL database that already holds data"
            )
    for name in COPIED_TABLES:
        table = schema.metadata.tables[name]
        data = [dict(row._mapping) for row in rows[name]]
        if data:
            conn.execute(insert(table), data)
        counts[name] = len(data)
    # Keep every identity column ahead of the ids just copied.
    for identity_table in _IDENTITY_TABLES:
        conn.execute(
            text(
                f"SELECT setval(pg_get_serial_sequence('{identity_table}', 'id'),"
                f" COALESCE((SELECT MAX(id) FROM {identity_table}), 1),"
                f" (SELECT MAX(id) IS NOT NULL FROM {identity_table}))"
            )
        )
    for name in COPIED_TABLES:
        stored = conn.execute(
            select(func.count()).select_from(schema.metadata.tables[name])
        ).scalar_one()
        if stored != counts[name]:
            raise TokenStoreError("row counts differ after the copy; nothing was imported")
    return counts


def import_sqlite(
    target: Database,
    source: pathlib.Path,
    keyring: Any,
    *,
    mark_undecryptable_invalid: bool = False,
) -> ImportReport:
    """Copy the SQLite file ``source`` into the empty PostgreSQL ``target``, all or nothing.

    See the module docstring for the two steps. ``source`` is never modified, and
    ``target`` is untouched until the private migrated copy is ready; from then on
    the schema and the data are created in one transaction.
    """
    if target.kind != "postgresql":
        raise TokenStoreError("import-sqlite writes to PostgreSQL; DATABASE_URL must name it")
    if not source.is_file():
        raise TokenStoreError("the SQLite file to import does not exist")
    if target_holds_rows(target):
        raise TokenStoreError(
            "refusing to import into a PostgreSQL database that already holds data"
        )

    migration = AccountMigrationReport()
    with tempfile.TemporaryDirectory(prefix="canvas-mcp-import-") as tmp:
        rows, jwt_epoch = _private_migrated_copy(
            source,
            pathlib.Path(tmp),
            keyring,
            mark_undecryptable_invalid=mark_undecryptable_invalid,
            report=migration,
        )

    counts: dict[str, int] = {}
    marked = [0]

    def populate(conn: Connection) -> None:
        counts.update(_copy_rows(conn, rows))
        Repositories("postgresql").jwt_epoch.set(conn, jwt_epoch)
        marked[0] = _verify_tokens(conn, keyring, mark_invalid=mark_undecryptable_invalid)

    migrate.ensure_ready(target, auto=True, populate=populate)
    return ImportReport(counts, migration, marked[0])
