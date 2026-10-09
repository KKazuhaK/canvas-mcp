"""The tables of the self-hosted state, as SQLAlchemy Core metadata.

This is the shape the queries are written against and the shape Alembic's
``compare_metadata`` checks a migrated database against. It is schema version 5:
the account model (``accounts`` and ``external_identities``), the sign-in history
and audit tables, and ``canvas_tokens`` keyed by ``principal_key``
(``acct:<uuid>``). The tables are *created* by the Alembic revisions (frozen DDL,
so a revision never changes when this module does); nothing calls
``metadata.create_all``.

Portability notes:

* Key columns use collation ``C`` on PostgreSQL so ``ORDER BY`` sorts like
  SQLite's BINARY collation.
* Integers that can exceed 32 bits (timestamps up to 4_102_444_800 in
  ``expires_hint_at``, counters) are BIGINT on PostgreSQL. On SQLite they stay
  ``INTEGER`` (a 64-bit affinity there), which keeps ``INTEGER PRIMARY KEY``.
* Flags (``email_verified``) are integers 0/1 on both backends.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    Identity,
    Index,
    LargeBinary,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects import sqlite

#: Alembic's own version table. Named so it cannot collide with another
#: application that shares a PostgreSQL database.
VERSION_TABLE = "canvas_mcp_alembic_version"

metadata = MetaData()

_INT = BigInteger().with_variant(sqlite.INTEGER(), "sqlite")
_KEY = Text().with_variant(Text(collation="C"), "postgresql")

meta = Table(
    "meta",
    metadata,
    Column("key", Text, primary_key=True),
    Column("value", Text, nullable=False),
    sqlite_with_rowid=False,
)

accounts = Table(
    "accounts",
    metadata,
    # The bare canonical UUID; the principal key used everywhere else is ``acct:<id>``.
    Column("id", _KEY, primary_key=True),
    Column("status", Text, nullable=False, server_default=text("'active'")),
    Column("role", Text, nullable=False, server_default=text("'user'")),
    # rules | bootstrap | operator: who granted ``role``. Only ``rules`` is re-evaluated
    # by a sign-in.
    Column("role_source", Text),
    # The newest evidence of the role (a sign-in); a demotion needs newer evidence.
    Column("role_seen_at", _INT),
    # rules | open | approval | operator | bootstrap: how the account was admitted.
    Column("admitted_via", Text, nullable=False),
    Column("display_name", Text, nullable=False, server_default=text("''")),
    Column("contact_email", Text),
    Column("ui_locale", Text),
    Column("created_at", _INT, nullable=False),
    Column("approved_at", _INT),
    Column("approved_by", _KEY),
    Column("disabled_reason", Text),
    Column("disabled_at", _INT),
    Column("disabled_by", _KEY),
    Column("last_login_at", _INT),
    Column("session_epoch", _INT, nullable=False, server_default=text("0")),
    Column("updated_at", _INT, nullable=False),
    CheckConstraint("status IN ('pending', 'active', 'disabled')", name="accounts_status_check"),
    CheckConstraint("role IN ('user', 'owner')", name="accounts_role_check"),
    Index("accounts_status_role", "status", "role"),
    sqlite_with_rowid=False,
)

external_identities = Table(
    "external_identities",
    metadata,
    Column("id", _INT, Identity(), primary_key=True, autoincrement=True),
    Column("account_id", _KEY, nullable=False),
    Column("provider_id", _KEY, nullable=False),
    Column("issuer", _KEY, nullable=False),
    Column("subject", _KEY, nullable=False),
    Column("username", Text),
    Column("email", Text),
    Column("email_verified", _INT, nullable=False, server_default=text("0")),
    Column("linked_at", _INT, nullable=False),
    Column("last_login_at", _INT),
    UniqueConstraint("provider_id", "issuer", "subject", name="external_identities_key"),
    Index("external_identities_account", "account_id"),
    sqlite_autoincrement=True,
)

canvas_tokens = Table(
    "canvas_tokens",
    metadata,
    Column("principal_key", _KEY, primary_key=True),
    Column("key_id", _KEY, nullable=False),
    Column("nonce", LargeBinary, nullable=False),
    Column("ciphertext", LargeBinary, nullable=False),
    Column("canvas_user_id", Text, nullable=False),
    Column("canvas_user_name", Text, nullable=False),
    Column("created_at", _INT, nullable=False),
    Column("updated_at", _INT, nullable=False),
    Column("last_used_at", _INT),
    Column("canvas_host", Text),
    Column("status", Text, nullable=False, server_default=text("'active'")),
    Column("invalid_reason", Text),
    Column("invalid_since", _INT),
    Column("last_verified_at", _INT),
    Column("expires_hint_at", _INT),
    sqlite_with_rowid=False,
)

user_tool_prefs = Table(
    "user_tool_prefs",
    metadata,
    Column("principal_key", _KEY, primary_key=True),
    Column("enabled_write_tools", Text, nullable=False, server_default=text("'[]'")),
    Column("enabled_at", Text, nullable=False, server_default=text("'{}'")),
    Column("updated_at", _INT, nullable=False),
    Column("updated_via", Text, nullable=False, server_default=text("'account_web'")),
    sqlite_with_rowid=False,
)

principal_status_events = Table(
    "principal_status_events",
    metadata,
    Column("id", _INT, Identity(), primary_key=True, autoincrement=True),
    Column("principal_key", _KEY, nullable=False),
    Column("action", Text, nullable=False),
    Column("actor", Text),
    Column("reason", Text),
    Column("session_epoch", _INT, nullable=False),
    Column("at", _INT, nullable=False),
    Index("principal_status_events_principal", "principal_key", "id"),
    sqlite_autoincrement=True,
)

credential_generations = Table(
    "credential_generations",
    metadata,
    Column("principal_key", _KEY, primary_key=True),
    Column("generation", _INT, nullable=False),
    Column("reason", Text, nullable=False, server_default=text("''")),
    Column("updated_at", _INT, nullable=False),
    sqlite_with_rowid=False,
)

auth_events = Table(
    "auth_events",
    metadata,
    Column("id", _INT, Identity(), primary_key=True, autoincrement=True),
    Column("at", _INT, nullable=False),
    Column("account_id", _KEY),
    Column("provider_id", Text, nullable=False),
    # account (the /account sign-in) | mcp (a request that created or changed an account)
    Column("surface", Text, nullable=False),
    # success | pending | denied | error
    Column("outcome", Text, nullable=False),
    # A closed code set (see ``accounts.AUTH_REASONS``).
    Column("reason", Text, nullable=False),
    # ``unknown`` unless a trusted proxy is configured (not implemented yet).
    Column("ip", Text, nullable=False, server_default=text("'unknown'")),
    # 16 hex characters of an HMAC of the user agent; never the user agent itself.
    Column("ua_hash", Text),
    Index("auth_events_account", "account_id", "id"),
    Index("auth_events_at", "at"),
    sqlite_autoincrement=True,
)

audit_log = Table(
    "audit_log",
    metadata,
    Column("id", _INT, Identity(), primary_key=True, autoincrement=True),
    Column("at", _INT, nullable=False),
    # An account key, ``operator`` or ``system``.
    Column("actor", _KEY, nullable=False),
    # A closed set of action names (see ``token_store.AUDIT_ACTIONS``).
    Column("action", Text, nullable=False),
    Column("target", _KEY),
    Column("reason", Text),
    # JSON of fixed-vocabulary values only: never a token, key, address or free text.
    Column("detail", Text, nullable=False, server_default=text("'{}'")),
    Index("audit_log_target", "target", "id"),
    sqlite_autoincrement=True,
)

#: Every table the store owns, in dependency-free order (there are no foreign keys).
TABLE_NAMES = (
    "meta",
    "canvas_tokens",
    "user_tool_prefs",
    "accounts",
    "external_identities",
    "principal_status_events",
    "credential_generations",
    "auth_events",
    "audit_log",
)
