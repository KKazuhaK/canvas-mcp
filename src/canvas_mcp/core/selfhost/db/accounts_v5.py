"""FROZEN: the body of revision ``0002_accounts`` (schema version 5, the account model).

Do not edit. A later schema change is a new revision. This module carries its own
copies of everything the migration depends on (the AAD layouts, the table
definitions), so it does not change when ``token_store.py`` or ``schema.py`` do.
Only the ``Keyring`` it is handed (``encrypt``, ``decrypt``, ``active_key_id``,
``key_ids``) is shared.

What it does, in one transaction (the caller's; a failure at any point leaves the
database exactly as it was):

1. Reads every row of the five tables that hold a principal key: ``canvas_tokens``,
   ``principal_status``, ``user_tool_prefs``, ``credential_generations`` and
   ``principal_status_events``.
2. Maps every ``entra:<tenant>:<object>`` key (as a primary key, an actor or a
   ``disabled_by``) to a fresh ``acct:<uuid>`` account, with one
   ``external_identities`` row: issuer ``https://login.microsoftonline.com/<tid>/v2.0``,
   subject = the object id. The status, epoch, owner flag and disablement of the old
   ``principal_status`` row move into ``accounts``; ``principal_status`` is dropped.
3. Re-encrypts every Canvas token under the new principal. The principal is bound
   into the AES-GCM associated data, so a plain re-key would make every token
   unreadable: each row is decrypted with its old associated data and encrypted
   again with the new one (the active key, a fresh nonce), then decrypted a second
   time and compared. Rows with a school keep the v2 layout with the new principal
   string; rows without one (legacy v1, bound to tenant and object) get layout v3,
   which binds the account and the key id and means "the default school".
4. Re-keys the preferences, the credential generations (their values are kept: the
   plaintext of every token is unchanged) and the status history in place.
5. Verifies the result and raises, rolling everything back, on the slightest
   difference.

Rows whose key is not an ``entra:`` key (and is not the operator) are carried over
unchanged and counted as unmapped: they stay unreachable, as they were.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

from .errors import TokenStoreError

SCHEMA_VERSION_V5 = 5

_AAD_PREFIX_V1 = b"canvas-mcp/canvas-token/v1\x1f"
_AAD_PREFIX_V2 = b"canvas-mcp/canvas-token/v2\x1f"
_AAD_PREFIX_V3 = b"canvas-mcp/canvas-token/v3\x1f"
_AAD_SEP = b"\x1f"

_GUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_ENTRA_KEY_RE = re.compile(rf"^entra:({_GUID}):({_GUID})$")
_ENTRA_ISSUER = "https://login.microsoftonline.com/{tid}/v2.0"

_OPAQUE_ACTORS = frozenset({"operator", "system"})


def aad_v1(tenant_id: str, object_id: str, key_id: str) -> bytes:
    """Legacy row without a school: bound to tenant and object ids."""
    return (
        _AAD_PREFIX_V1
        + tenant_id.encode()
        + _AAD_SEP
        + object_id.encode()
        + _AAD_SEP
        + key_id.encode()
    )


def aad_v2(principal_key: str, canvas_host: str, key_id: str) -> bytes:
    """Row with a school: bound to the principal string, the host and the key id."""
    return (
        _AAD_PREFIX_V2
        + principal_key.encode("utf-8", "surrogatepass")
        + _AAD_SEP
        + canvas_host.encode("utf-8", "surrogatepass")
        + _AAD_SEP
        + key_id.encode("utf-8", "surrogatepass")
    )


def aad_v3(principal_key: str, key_id: str) -> bytes:
    """Row without a school (the default school): bound to the account and the key id."""
    return (
        _AAD_PREFIX_V3
        + principal_key.encode("utf-8", "surrogatepass")
        + _AAD_SEP
        + key_id.encode("utf-8", "surrogatepass")
    )


@dataclass
class MigrationOptions:
    """How to run the data migration.

    ``dry_run``: do everything inside the transaction, report, then roll back.
    ``mark_undecryptable_invalid``: a token row that does not decrypt is marked
    invalid (``decrypt_failed``) instead of refusing the upgrade. Never applied by
    the automatic migration at server start: the operator asks for it.
    ``now``: a fixed clock for tests.
    """

    dry_run: bool = False
    mark_undecryptable_invalid: bool = False
    now: int | None = None


@dataclass
class AccountMigrationReport:
    """What the migration did (or, in a dry run, would do). Counts and key ids only."""

    dry_run: bool = False
    accounts: int = 0
    identities: int = 0
    tokens_reencrypted: int = 0
    tokens_carried_unreadable: int = 0
    tokens_marked_invalid: int = 0
    tokens_unmapped: int = 0
    rows_rekeyed: dict[str, int] = field(default_factory=dict)
    unmapped_keys: list[str] = field(default_factory=list)
    disabled_accounts: int = 0
    owner_accounts: int = 0
    backup_path: str | None = None
    ran: bool = False

    def lines(self) -> list[str]:
        out = [
            f"accounts to create: {self.accounts}",
            f"external identities to create: {self.identities}",
            f"Canvas tokens re-encrypted: {self.tokens_reencrypted}",
            f"unreadable tokens carried over (already marked decrypt_failed): "
            f"{self.tokens_carried_unreadable}",
            f"unreadable tokens that would be marked invalid: {self.tokens_marked_invalid}",
            f"tokens of non-Entra principals carried over unchanged: {self.tokens_unmapped}",
        ]
        for table in sorted(self.rows_rekeyed):
            out.append(f"rows re-keyed in {table}: {self.rows_rekeyed[table]}")
        out.append(f"disabled accounts: {self.disabled_accounts}")
        out.append(f"owner accounts: {self.owner_accounts}")
        out.append(f"non-Entra keys carried over unchanged: {len(self.unmapped_keys)}")
        return out


# -- table definitions (frozen copies) -----------------------------------------

_KEY = sa.Text().with_variant(sa.Text(collation="C"), "postgresql")
_INT = sa.BigInteger().with_variant(sqlite.INTEGER(), "sqlite")


def _table_specs() -> list[tuple[str, list[Any], dict[str, Any], list[tuple[str, list[str]]]]]:
    """``(name, columns and constraints, table kwargs, [(index name, columns)])``."""
    text = sa.Text()
    d_empty = sa.text("''")
    return [
        (
            "accounts",
            [
                sa.Column("id", _KEY, primary_key=True),
                sa.Column("status", text, nullable=False, server_default=sa.text("'active'")),
                sa.Column("role", text, nullable=False, server_default=sa.text("'user'")),
                sa.Column("role_source", text),
                sa.Column("role_seen_at", _INT),
                sa.Column("admitted_via", text, nullable=False),
                sa.Column("display_name", text, nullable=False, server_default=d_empty),
                sa.Column("contact_email", text),
                sa.Column("ui_locale", text),
                sa.Column("created_at", _INT, nullable=False),
                sa.Column("approved_at", _INT),
                sa.Column("approved_by", _KEY),
                sa.Column("disabled_reason", text),
                sa.Column("disabled_at", _INT),
                sa.Column("disabled_by", _KEY),
                sa.Column("last_login_at", _INT),
                sa.Column("session_epoch", _INT, nullable=False, server_default=sa.text("0")),
                sa.Column("updated_at", _INT, nullable=False),
                sa.CheckConstraint(
                    "status IN ('pending', 'active', 'disabled')", name="accounts_status_check"
                ),
                sa.CheckConstraint("role IN ('user', 'owner')", name="accounts_role_check"),
            ],
            {"sqlite_with_rowid": False},
            [("accounts_status_role", ["status", "role"])],
        ),
        (
            "external_identities",
            [
                sa.Column("id", _INT, sa.Identity(), primary_key=True, autoincrement=True),
                sa.Column("account_id", _KEY, nullable=False),
                sa.Column("provider_id", _KEY, nullable=False),
                sa.Column("issuer", _KEY, nullable=False),
                sa.Column("subject", _KEY, nullable=False),
                sa.Column("username", text),
                sa.Column("email", text),
                sa.Column("email_verified", _INT, nullable=False, server_default=sa.text("0")),
                sa.Column("linked_at", _INT, nullable=False),
                sa.Column("last_login_at", _INT),
                sa.UniqueConstraint(
                    "provider_id", "issuer", "subject", name="external_identities_key"
                ),
            ],
            {"sqlite_autoincrement": True},
            [("external_identities_account", ["account_id"])],
        ),
        (
            "auth_events",
            [
                sa.Column("id", _INT, sa.Identity(), primary_key=True, autoincrement=True),
                sa.Column("at", _INT, nullable=False),
                sa.Column("account_id", _KEY),
                sa.Column("provider_id", text, nullable=False),
                sa.Column("surface", text, nullable=False),
                sa.Column("outcome", text, nullable=False),
                sa.Column("reason", text, nullable=False),
                sa.Column("ip", text, nullable=False, server_default=sa.text("'unknown'")),
                sa.Column("ua_hash", text),
            ],
            {"sqlite_autoincrement": True},
            [("auth_events_account", ["account_id", "id"]), ("auth_events_at", ["at"])],
        ),
        (
            "audit_log",
            [
                sa.Column("id", _INT, sa.Identity(), primary_key=True, autoincrement=True),
                sa.Column("at", _INT, nullable=False),
                sa.Column("actor", _KEY, nullable=False),
                sa.Column("action", text, nullable=False),
                sa.Column("target", _KEY),
                sa.Column("reason", text),
                sa.Column("detail", text, nullable=False, server_default=sa.text("'{}'")),
            ],
            {"sqlite_autoincrement": True},
            [("audit_log_target", ["target", "id"])],
        ),
    ]


def _tokens_spec() -> tuple[str, list[Any], dict[str, Any]]:
    text = sa.Text()
    return (
        "canvas_tokens",
        [
            sa.Column("principal_key", _KEY, primary_key=True),
            sa.Column("key_id", _KEY, nullable=False),
            sa.Column("nonce", sa.LargeBinary(), nullable=False),
            sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
            sa.Column("canvas_user_id", text, nullable=False),
            sa.Column("canvas_user_name", text, nullable=False),
            sa.Column("created_at", _INT, nullable=False),
            sa.Column("updated_at", _INT, nullable=False),
            sa.Column("last_used_at", _INT),
            sa.Column("canvas_host", text),
            sa.Column("status", text, nullable=False, server_default=sa.text("'active'")),
            sa.Column("invalid_reason", text),
            sa.Column("invalid_since", _INT),
            sa.Column("last_verified_at", _INT),
            sa.Column("expires_hint_at", _INT),
        ],
        {"sqlite_with_rowid": False},
    )


def create_account_tables(op: Any) -> None:
    for name, parts, kwargs, indexes in _table_specs():
        op.create_table(name, *parts, **kwargs)
        for index_name, columns in indexes:
            op.create_index(index_name, name, columns)


def recreate_tokens_table(op: Any) -> None:
    """Drop the old ``canvas_tokens`` (primary key tenant + object) and create the new one."""
    op.drop_index("canvas_tokens_principal_key", table_name="canvas_tokens")
    op.drop_table("canvas_tokens")
    name, parts, kwargs = _tokens_spec()
    op.create_table(name, *parts, **kwargs)


# Lightweight table objects for the inserts and the reads.
_t_accounts = sa.table(
    "accounts",
    *[
        sa.column(c)
        for c in (
            "id status role role_source role_seen_at admitted_via display_name contact_email "
            "ui_locale created_at approved_at approved_by disabled_reason disabled_at "
            "disabled_by last_login_at session_epoch updated_at"
        ).split()
    ],
)
_t_identities = sa.table(
    "external_identities",
    *[
        sa.column(c)
        for c in (
            "account_id provider_id issuer subject username email email_verified linked_at "
            "last_login_at"
        ).split()
    ],
)
_t_tokens = sa.table(
    "canvas_tokens",
    sa.column("principal_key"),
    sa.column("key_id"),
    sa.column("nonce", sa.LargeBinary()),
    sa.column("ciphertext", sa.LargeBinary()),
    *[
        sa.column(c)
        for c in (
            "canvas_user_id canvas_user_name created_at updated_at last_used_at canvas_host "
            "status invalid_reason invalid_since last_verified_at expires_hint_at"
        ).split()
    ],
)
_t_audit = sa.table(
    "audit_log",
    *[sa.column(c) for c in "at actor action target reason detail".split()],
)


# -- reading the old state --------------------------------------------------------

_TOKEN_COLUMNS = (
    "tenant_id object_id key_id nonce ciphertext canvas_user_id canvas_user_name "
    "entra_display_name entra_upn created_at updated_at last_used_at canvas_host principal_key "
    "status invalid_reason invalid_since last_verified_at expires_hint_at"
).split()
_STATUS_COLUMNS = (
    "principal_key status disabled_reason disabled_at disabled_by display_name upn "
    "session_epoch is_owner owner_seen_at updated_at"
).split()
_PREFS_COLUMNS = "principal_key updated_at".split()
_GEN_COLUMNS = "principal_key generation reason updated_at".split()
_EVENT_COLUMNS = "id principal_key actor at".split()


def _fetch(bind: Any, table: str, columns: Sequence[str], order: str) -> list[dict[str, Any]]:
    rows = bind.execute(sa.text(f"SELECT {', '.join(columns)} FROM {table} ORDER BY {order}"))
    return [dict(zip(columns, row, strict=True)) for row in rows]


def _parse_entra_key(value: str) -> tuple[str, str] | None:
    match = _ENTRA_KEY_RE.match(value)
    return None if match is None else (match.group(1), match.group(2))


@dataclass
class _Plan:
    account_ids: dict[str, str] = field(default_factory=dict)  # entra key -> account uuid
    accounts: list[dict[str, Any]] = field(default_factory=list)
    identities: list[dict[str, Any]] = field(default_factory=list)
    tokens: list[dict[str, Any]] = field(default_factory=list)
    token_hashes: dict[str, tuple[str, bytes]] = field(default_factory=dict)
    generation_bumps: dict[str, tuple[int, str, int]] = field(default_factory=dict)
    old_active_owners: int = 0
    old_status: dict[str, dict[str, Any]] = field(default_factory=dict)


def _mapped(plan: _Plan, value: str | None) -> str | None:
    """The new form of a stored key or actor (unchanged for the operator and opaque keys)."""
    if value is None:
        return None
    account = plan.account_ids.get(value)
    return f"acct:{account}" if account is not None else value


def _classify(value: str | None, entra_keys: set[str], report: AccountMigrationReport) -> None:
    """Collect an ``entra:`` key; refuse a malformed one; count the others."""
    if value is None or value in _OPAQUE_ACTORS:
        return
    if value.startswith("entra:"):
        if _parse_entra_key(value) is None:
            raise TokenStoreError(
                "a stored key looks like an Entra principal but is malformed; nothing was migrated"
            )
        entra_keys.add(value)
    elif value not in report.unmapped_keys:
        report.unmapped_keys.append(value)


def upgrade_data(
    bind: Any,
    op: Any,
    keyring: Any,
    options: MigrationOptions,
    report: AccountMigrationReport,
) -> None:
    """Run the whole migration on ``bind`` (a connection inside the caller's transaction)."""
    now = options.now if options.now is not None else int(time.time())
    report.dry_run = options.dry_run
    tokens = _fetch(bind, "canvas_tokens", _TOKEN_COLUMNS, "tenant_id, object_id")
    statuses = _fetch(bind, "principal_status", _STATUS_COLUMNS, "principal_key")
    prefs = _fetch(bind, "user_tool_prefs", _PREFS_COLUMNS, "principal_key")
    generations = _fetch(bind, "credential_generations", _GEN_COLUMNS, "principal_key")
    events = _fetch(bind, "principal_status_events", _EVENT_COLUMNS, "id")

    # Pass 1: every key that must become an account.
    entra_keys: set[str] = set()
    for token in tokens:
        key = token["principal_key"]
        if key is None:
            key = f"entra:{token['tenant_id']}:{token['object_id']}" if token["tenant_id"] else None
            token["principal_key"] = key
        _classify(key, entra_keys, report)
    for status in statuses:
        if _parse_entra_key(status["principal_key"]) is None:
            # An access decision about a principal that is not an Entra user cannot be
            # carried into the account model; dropping it could re-admit someone.
            raise TokenStoreError(
                "principal_status holds a row for a principal that is not an Entra user; "
                "nothing was migrated"
            )
        _classify(status["principal_key"], entra_keys, report)
        _classify(status["disabled_by"], entra_keys, report)
    for pref in prefs:
        _classify(pref["principal_key"], entra_keys, report)
    for gen in generations:
        _classify(gen["principal_key"], entra_keys, report)
    for event in events:
        _classify(event["principal_key"], entra_keys, report)
        _classify(event["actor"], entra_keys, report)
    report.unmapped_keys.sort()

    needs_keys = any(
        t["principal_key"] in entra_keys for t in tokens
    )
    if needs_keys and keyring is None:
        raise TokenStoreError(
            "this upgrade re-encrypts stored Canvas tokens and needs CANVAS_TOKEN_KEYS"
        )
    if keyring is not None:
        unknown = sorted({t["key_id"] for t in tokens if t["principal_key"] in entra_keys} - set(keyring.key_ids))
        if unknown:
            from ..token_store import KeyringError

            raise KeyringError(
                "CANVAS_TOKEN_KEYS is missing key id(s): " + ", ".join(unknown)
                + "; nothing was migrated"
            )

    plan = _Plan()
    for key in sorted(entra_keys):
        plan.account_ids[key] = str(uuid.uuid4())

    _plan_accounts(plan, entra_keys, tokens, statuses, prefs, generations, events, now)
    plan.old_active_owners = sum(
        1 for s in statuses if s["is_owner"] and s["status"] != "disabled"
    )
    _plan_tokens(plan, tokens, generations, keyring, options, report, now)

    # DDL, then the data.
    create_account_tables(op)
    recreate_tokens_table(op)
    op.drop_table("principal_status")

    if plan.accounts:
        bind.execute(sa.insert(_t_accounts), plan.accounts)
        bind.execute(sa.insert(_t_identities), plan.identities)
    if plan.tokens:
        bind.execute(sa.insert(_t_tokens), plan.tokens)
    _rekey_in_place(bind, plan, report, generations)

    report.accounts = len(plan.accounts)
    report.identities = len(plan.identities)
    report.disabled_accounts = sum(1 for a in plan.accounts if a["status"] == "disabled")
    report.owner_accounts = sum(
        1 for a in plan.accounts if a["role"] == "owner" and a["status"] == "active"
    )
    if tokens or statuses or prefs or generations or events:
        # Only a database that held data gets this row: an empty database that merely
        # ran the upgrade must still look empty to the silent-switch guard.
        bind.execute(
            sa.insert(_t_audit),
            [
                {
                    "at": now,
                    "actor": "system",
                    "action": "schema_migrated",
                    "target": None,
                    "reason": None,
                    "detail": json.dumps(
                        {
                            "to_schema": SCHEMA_VERSION_V5,
                            "accounts": report.accounts,
                            "tokens_reencrypted": report.tokens_reencrypted,
                            "tokens_marked_invalid": report.tokens_marked_invalid,
                            "unmapped_keys": len(report.unmapped_keys),
                        },
                        sort_keys=True,
                    ),
                }
            ],
        )
    _after_inserts()
    _verify(bind, plan, tokens, statuses, prefs, generations, events, keyring)
    report.ran = True


def _after_inserts() -> None:
    """Hook point for the failure-injection tests (does nothing)."""


def _plan_accounts(
    plan: _Plan,
    entra_keys: set[str],
    tokens: list[dict[str, Any]],
    statuses: list[dict[str, Any]],
    prefs: list[dict[str, Any]],
    generations: list[dict[str, Any]],
    events: list[dict[str, Any]],
    now: int,
) -> None:
    by_status = {s["principal_key"]: s for s in statuses}
    by_token = {t["principal_key"]: t for t in tokens}
    stamps: dict[str, list[int]] = {}

    def stamp(key: str | None, value: Any) -> None:
        if key is not None and isinstance(value, int) and not isinstance(value, bool) and value > 0:
            stamps.setdefault(key, []).append(value)

    for t in tokens:
        stamp(t["principal_key"], t["created_at"])
    for s in statuses:
        stamp(s["principal_key"], s["updated_at"])
        stamp(s["principal_key"], s["disabled_at"])
        stamp(s["principal_key"], s["owner_seen_at"])
    for p in prefs:
        stamp(p["principal_key"], p["updated_at"])
    for g in generations:
        stamp(g["principal_key"], g["updated_at"])
    for e in events:
        stamp(e["principal_key"], e["at"])

    for key in sorted(entra_keys):
        tid, oid = _parse_entra_key(key) or ("", "")
        account = plan.account_ids[key]
        status = by_status.get(key)
        token = by_token.get(key)
        created = min(stamps[key]) if key in stamps else now
        disabled = status is not None and status["status"] == "disabled"
        owner = status is not None and bool(status["is_owner"])
        display = ""
        if token is not None and token["entra_display_name"]:
            display = token["entra_display_name"]
        elif status is not None and status["display_name"]:
            display = status["display_name"]
        username = ""
        if token is not None and token["entra_upn"]:
            username = token["entra_upn"]
        elif status is not None and status["upn"]:
            username = status["upn"]
        plan.accounts.append(
            {
                "id": account,
                "status": "disabled" if disabled else "active",
                "role": "owner" if owner else "user",
                "role_source": "rules" if owner else None,
                "role_seen_at": status["owner_seen_at"] if owner and status is not None else None,
                "admitted_via": "rules",
                "display_name": display[:200],
                "contact_email": None,
                "ui_locale": None,
                "created_at": created,
                "approved_at": None,
                "approved_by": None,
                "disabled_reason": status["disabled_reason"] if disabled and status else None,
                "disabled_at": status["disabled_at"] if disabled and status else None,
                "disabled_by": _mapped(plan, status["disabled_by"]) if disabled and status else None,
                "last_login_at": None,
                "session_epoch": int(status["session_epoch"]) if status is not None else 0,
                "updated_at": int(status["updated_at"]) if status is not None else created,
            }
        )
        plan.identities.append(
            {
                "account_id": account,
                "provider_id": "entra",
                "issuer": _ENTRA_ISSUER.format(tid=tid),
                "subject": oid,
                "username": username[:254] or None,
                "email": None,
                "email_verified": 0,
                "linked_at": created,
                "last_login_at": None,
            }
        )
        if status is not None:
            plan.old_status[key] = status


def _plan_tokens(
    plan: _Plan,
    tokens: list[dict[str, Any]],
    generations: list[dict[str, Any]],
    keyring: Any,
    options: MigrationOptions,
    report: AccountMigrationReport,
    now: int,
) -> None:
    gen_values = {g["principal_key"]: int(g["generation"]) for g in generations}
    for row in tokens:
        old_key = row["principal_key"]
        host = row["canvas_host"]
        new_row = {
            "principal_key": old_key,
            "key_id": row["key_id"],
            "nonce": bytes(row["nonce"]),
            "ciphertext": bytes(row["ciphertext"]),
            "canvas_user_id": row["canvas_user_id"],
            "canvas_user_name": row["canvas_user_name"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "last_used_at": row["last_used_at"],
            "canvas_host": host,
            "status": row["status"] or "active",
            "invalid_reason": row["invalid_reason"],
            "invalid_since": row["invalid_since"],
            "last_verified_at": row["last_verified_at"],
            "expires_hint_at": row["expires_hint_at"],
        }
        parts = _parse_entra_key(old_key) if old_key is not None else None
        if parts is None:
            # Not an Entra principal: carried unchanged (the v2 layout binds the
            # principal string, which does not change).
            report.tokens_unmapped += 1
            plan.tokens.append(new_row)
            continue
        account_key = f"acct:{plan.account_ids[old_key]}"
        kid = row["key_id"]
        # The old row was bound to its principal exactly as TokenStore.get built it.
        old_aad = aad_v2(old_key, host, kid) if host is not None else aad_v1(parts[0], parts[1], kid)
        try:
            plaintext = keyring.decrypt(kid, bytes(row["nonce"]), bytes(row["ciphertext"]), old_aad)
        except TokenStoreError:
            plaintext = None
        if plaintext is None:
            if row["status"] == "invalid" and row["invalid_reason"] == "decrypt_failed":
                # Unreadable before, unreadable now: the ciphertext is kept as it is so the
                # row keeps its history, and it stays invalid. No new layout can seal it.
                report.tokens_carried_unreadable += 1
                new_row["principal_key"] = account_key
                plan.tokens.append(new_row)
                continue
            if not options.mark_undecryptable_invalid:
                raise TokenStoreError(
                    "a stored token does not decrypt with CANVAS_TOKEN_KEYS; nothing was "
                    "migrated (restore the right keys, or run 'db upgrade "
                    "--mark-undecryptable-invalid' to mark such rows invalid)"
                )
            report.tokens_marked_invalid += 1
            new_row.update(
                {
                    "principal_key": account_key,
                    "status": "invalid",
                    "invalid_reason": "decrypt_failed",
                    "invalid_since": now,
                }
            )
            plan.generation_bumps[old_key] = (gen_values.get(old_key, 0) + 1, "invalidated", now)
            plan.tokens.append(new_row)
            continue
        active = keyring.active_key_id
        new_aad = aad_v2(account_key, host, active) if host is not None else aad_v3(account_key, active)
        new_kid, nonce, ciphertext = keyring.encrypt(plaintext, new_aad)
        assert new_kid == active
        check = keyring.decrypt(new_kid, nonce, ciphertext, new_aad)
        if hashlib.sha256(check).digest() != hashlib.sha256(plaintext).digest():
            raise TokenStoreError("re-encryption check failed; nothing was migrated")
        new_row.update(
            {
                "principal_key": account_key,
                "key_id": new_kid,
                "nonce": nonce,
                "ciphertext": ciphertext,
            }
        )
        plan.tokens.append(new_row)
        plan.token_hashes[account_key] = (host if host is not None else "", hashlib.sha256(plaintext).digest())
        report.tokens_reencrypted += 1


def _rekey_in_place(
    bind: Any, plan: _Plan, report: AccountMigrationReport, generations: list[dict[str, Any]]
) -> None:
    mapping = [
        {"old": old, "new": f"acct:{account}"} for old, account in sorted(plan.account_ids.items())
    ]
    counts: dict[str, int] = {}
    if mapping:
        for table, column in (
            ("user_tool_prefs", "principal_key"),
            ("credential_generations", "principal_key"),
            ("principal_status_events", "principal_key"),
            ("principal_status_events", "actor"),
        ):
            stmt = sa.text(f"UPDATE {table} SET {column} = :new WHERE {column} = :old")
            changed = 0
            for item in mapping:
                result = bind.execute(stmt, item)
                changed += max(0, int(result.rowcount or 0))
            counts[f"{table}.{column}"] = changed
    # A generation raised because a row was marked invalid (the explicit option).
    for old_key, (value, reason, stamp_at) in plan.generation_bumps.items():
        new_key = f"acct:{plan.account_ids[old_key]}"
        existing = bind.execute(
            sa.text("SELECT generation FROM credential_generations WHERE principal_key = :k"),
            {"k": new_key},
        ).first()
        if existing is None:
            bind.execute(
                sa.text(
                    "INSERT INTO credential_generations (principal_key, generation, reason, "
                    "updated_at) VALUES (:k, :g, :r, :u)"
                ),
                {"k": new_key, "g": value, "r": reason, "u": stamp_at},
            )
        else:
            bind.execute(
                sa.text(
                    "UPDATE credential_generations SET generation = :g, reason = :r, "
                    "updated_at = :u WHERE principal_key = :k"
                ),
                {"k": new_key, "g": value, "r": reason, "u": stamp_at},
            )
    report.rows_rekeyed = {
        "canvas_tokens": len(plan.tokens),
        "user_tool_prefs": counts.get("user_tool_prefs.principal_key", 0),
        "credential_generations": counts.get("credential_generations.principal_key", 0),
        "principal_status_events": counts.get("principal_status_events.principal_key", 0),
        "principal_status_events (actor)": counts.get("principal_status_events.actor", 0),
    }


def _scalar(bind: Any, sql: str, params: dict[str, Any] | None = None) -> int:
    return int(bind.execute(sa.text(sql), params or {}).scalar_one())


def _verify(
    bind: Any,
    plan: _Plan,
    tokens: list[dict[str, Any]],
    statuses: list[dict[str, Any]],
    prefs: list[dict[str, Any]],
    generations: list[dict[str, Any]],
    events: list[dict[str, Any]],
    keyring: Any,
) -> None:
    """Prove the result before the transaction may commit; any difference raises."""

    def fail(what: str) -> None:
        raise TokenStoreError(f"migration check failed ({what}); nothing was migrated")

    if _scalar(bind, "SELECT COUNT(*) FROM canvas_tokens") != len(tokens):
        fail("token count")
    if _scalar(bind, "SELECT COUNT(*) FROM user_tool_prefs") != len(prefs):
        fail("preferences count")
    if _scalar(bind, "SELECT COUNT(*) FROM principal_status_events") != len(events):
        fail("history count")
    if _scalar(bind, "SELECT COUNT(*) FROM credential_generations") < len(generations):
        fail("generations count")
    for table, column in (
        ("canvas_tokens", "principal_key"),
        ("user_tool_prefs", "principal_key"),
        ("credential_generations", "principal_key"),
        ("principal_status_events", "principal_key"),
        ("principal_status_events", "actor"),
        ("accounts", "disabled_by"),
        ("accounts", "approved_by"),
    ):
        if _scalar(bind, f"SELECT COUNT(*) FROM {table} WHERE {column} LIKE 'entra:%'") != 0:
            fail("a legacy key remains")
    if _scalar(bind, "SELECT COUNT(*) FROM accounts") != len(plan.accounts):
        fail("account count")
    if _scalar(bind, "SELECT COUNT(*) FROM external_identities") != len(plan.accounts):
        fail("identity count")
    if (
        _scalar(
            bind,
            "SELECT COUNT(*) FROM accounts a WHERE (SELECT COUNT(*) FROM external_identities i "
            "WHERE i.account_id = a.id) <> 1",
        )
        != 0
    ):
        fail("an account without exactly one identity")
    for key, account in sorted(plan.account_ids.items()):
        old = plan.old_status.get(key)
        if old is None:
            continue
        row = bind.execute(
            sa.text(
                "SELECT status, session_epoch, disabled_reason, disabled_at, disabled_by, role, "
                "role_seen_at FROM accounts WHERE id = :id"
            ),
            {"id": account},
        ).one()
        disabled = old["status"] == "disabled"
        expected = (
            "disabled" if disabled else "active",
            int(old["session_epoch"]),
            old["disabled_reason"] if disabled else None,
            old["disabled_at"] if disabled else None,
            _mapped(plan, old["disabled_by"]) if disabled else None,
            "owner" if old["is_owner"] else "user",
            old["owner_seen_at"] if old["is_owner"] else None,
        )
        if tuple(row) != expected:
            fail("an access status differs")
    now_owners = _scalar(
        bind, "SELECT COUNT(*) FROM accounts WHERE role = 'owner' AND status = 'active'"
    )
    if now_owners != plan.old_active_owners:
        fail("the number of active owners")
    if keyring is not None:
        for account_key, (host, digest) in plan.token_hashes.items():
            row = bind.execute(
                sa.text(
                    "SELECT key_id, nonce, ciphertext, canvas_host FROM canvas_tokens "
                    "WHERE principal_key = :k"
                ),
                {"k": account_key},
            ).first()
            if row is None:
                fail("a token row is missing")
                continue
            kid = row[0]
            aad = aad_v2(account_key, row[3], kid) if row[3] is not None else aad_v3(account_key, kid)
            try:
                plaintext = keyring.decrypt(kid, bytes(row[1]), bytes(row[2]), aad)
            except TokenStoreError:
                fail("a token does not decrypt under its new principal")
                continue
            if hashlib.sha256(plaintext).digest() != digest or (row[3] or "") != host:
                fail("a token differs after re-encryption")


def upgrade_offline_postgresql(op: Any) -> None:
    """The DDL for ``--sql`` output. The data step needs a live database.

    The guard makes the script refuse a database that holds rows: re-encrypting
    tokens cannot be expressed as SQL, so a populated database is upgraded online
    (``db upgrade`` or the server's automatic migration).
    """
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM canvas_tokens) OR EXISTS (SELECT 1 FROM "
        "principal_status) OR EXISTS (SELECT 1 FROM user_tool_prefs) OR EXISTS (SELECT 1 FROM "
        "credential_generations) OR EXISTS (SELECT 1 FROM principal_status_events) THEN "
        "RAISE EXCEPTION 'this database holds data; upgrade it online (token_admin db upgrade)'; "
        "END IF; END $$"
    )
    create_account_tables(op)
    recreate_tokens_table(op)
    op.drop_table("principal_status")
    op.execute("UPDATE meta SET value = '5' WHERE key = 'schema_version'")
