"""The tables of the self-hosted state, as SQLAlchemy Core metadata.

This is the shape the queries are written against and the shape Alembic's
``compare_metadata`` checks a migrated database against. It is schema version 5:
the account model (``accounts`` and ``external_identities``), the sign-in history
and audit tables, and ``canvas_tokens`` keyed by ``principal_key``
(``acct:<uuid>``). Revision 0003 adds, without changing the version marker, the tables
of the server's own authorization server (``oauth_*``, ``cimd_clients``,
``login_states``). The tables are *created* by the Alembic revisions (frozen DDL,
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

# -- the self-hosted authorization server (SELFHOST_AUTH_MODE=local) ---------------
#
# Revision ``0003_oauth_authz``. There are no foreign keys here either: ``oauth_*`` rows
# name an account by its bare id, a client by its id (a registration uuid or a CIMD URL)
# and a grant by its uuid, and the application keeps them consistent inside single
# transactions. Every ``*_hash`` column holds a lowercase 64-character SHA-256 hex digest:
# a code or a refresh token is never stored, only its hash.

oauth_clients = Table(
    "oauth_clients",
    metadata,
    # The client id handed out at registration (a uuid).
    Column("id", _KEY, primary_key=True),
    # The registered client record (public clients only: no secret), as JSON.
    Column("info_json", Text, nullable=False),
    Column("client_name", Text, nullable=False, server_default=text("''")),
    Column("created_at", _INT, nullable=False),
    Column("expires_at", _INT, nullable=False),
    Index("oauth_clients_expires", "expires_at"),
    sqlite_with_rowid=False,
)

cimd_clients = Table(
    "cimd_clients",
    metadata,
    # The client id, which is the URL of the client's metadata document.
    Column("url", _KEY, primary_key=True),
    # The last document that passed every check (the last known good one), as JSON.
    Column("doc_json", Text, nullable=False),
    Column("fetched_at", _INT, nullable=False),
    Column("fresh_until", _INT, nullable=False),
    Column("last_error_at", _INT),
    # A closed code (timeout, http_status, invalid_document, ssrf_blocked, budget,
    # client_id_mismatch, unsupported_auth_method, cimd_redirects_not_allowed).
    Column("last_error", Text),
    CheckConstraint("fresh_until >= fetched_at", name="cimd_clients_fresh_check"),
    Index("cimd_clients_fetched", "fetched_at"),
    sqlite_with_rowid=False,
)

oauth_grants = Table(
    "oauth_grants",
    metadata,
    # One grant is one refresh-token family; its id is the family id.
    Column("id", _KEY, primary_key=True),
    Column("account_id", _KEY, nullable=False),
    Column("client_id", _KEY, nullable=False),
    Column("client_kind", Text, nullable=False),
    Column("client_name", Text, nullable=False, server_default=text("''")),
    # The host of a CIMD client id (its verified name); null for a registered client.
    Column("client_host", Text),
    # Where the approval was delivered (the host of the redirect URI).
    Column("redirect_host", Text, nullable=False, server_default=text("''")),
    # Space-separated.
    Column("scopes", Text, nullable=False),
    Column("resource", Text, nullable=False),
    Column("created_at", _INT, nullable=False),
    Column("last_used_at", _INT),
    # When the user last signed in at /account for this grant (the ``iat`` of the session).
    Column("upstream_auth_at", _INT, nullable=False),
    # ``created_at`` plus the absolute lifetime; rotation never extends it.
    Column("expires_at", _INT, nullable=False),
    Column("revoked_at", _INT),
    Column("revoked_reason", Text),
    # An account key, ``operator`` or ``system``.
    Column("revoked_by", _KEY),
    CheckConstraint("client_kind IN ('dcr', 'cimd')", name="oauth_grants_kind_check"),
    CheckConstraint(
        "revoked_reason IS NULL OR revoked_reason IN ('user_revoked', 'owner_revoked', "
        "'operator_revoked', 'client_revoked', 'refresh_reuse', 'code_replay', "
        "'account_disabled', 'admission_lost', 'reauth_required')",
        name="oauth_grants_reason_check",
    ),
    Index("oauth_grants_account", "account_id", "revoked_at"),
    Index("oauth_grants_client", "client_id"),
    Index("oauth_grants_expires", "expires_at"),
    sqlite_with_rowid=False,
)

oauth_codes = Table(
    "oauth_codes",
    metadata,
    Column("code_hash", _KEY, primary_key=True),
    Column("client_id", _KEY, nullable=False),
    Column("account_id", _KEY, nullable=False),
    Column("redirect_uri", Text, nullable=False),
    Column("redirect_uri_explicit", _INT, nullable=False),
    Column("code_challenge", Text, nullable=False),
    Column("scopes", Text, nullable=False),
    Column("resource", Text, nullable=False),
    Column("client_kind", Text, nullable=False),
    Column("client_name", Text, nullable=False, server_default=text("''")),
    Column("client_host", Text),
    Column("redirect_host", Text, nullable=False, server_default=text("''")),
    Column("upstream_auth_at", _INT, nullable=False),
    # The ``session_epoch`` of the /account session that approved the code: it is redeemable
    # only while the account's current epoch is still this one (see ``AuthzStore``).
    Column("session_epoch", _INT, nullable=False),
    Column("created_at", _INT, nullable=False),
    Column("expires_at", _INT, nullable=False),
    # Set when the code is exchanged; the row then stays as a tombstone (with the grant it
    # produced) until it is culled, so a replay can be told from an unknown code.
    Column("consumed_at", _INT),
    Column("grant_id", _KEY),
    Column("grace_replays", _INT, nullable=False, server_default=text("0")),
    CheckConstraint("redirect_uri_explicit IN (0, 1)", name="oauth_codes_explicit_check"),
    CheckConstraint("client_kind IN ('dcr', 'cimd')", name="oauth_codes_kind_check"),
    Index("oauth_codes_expires", "expires_at"),
    sqlite_with_rowid=False,
)

oauth_refresh_tokens = Table(
    "oauth_refresh_tokens",
    metadata,
    Column("token_hash", _KEY, primary_key=True),
    Column("grant_id", _KEY, nullable=False),
    # The token this one replaced (null for the first token of a grant).
    Column("parent_hash", _KEY),
    Column("created_at", _INT, nullable=False),
    # Copied from the grant: the absolute cap.
    Column("expires_at", _INT, nullable=False),
    Column("used_at", _INT),
    Column("replaced_by", _KEY),
    Column("grace_replays", _INT, nullable=False, server_default=text("0")),
    CheckConstraint("grace_replays >= 0", name="oauth_refresh_grace_check"),
    Index("oauth_refresh_grant", "grant_id"),
    Index("oauth_refresh_parent", "parent_hash"),
    Index("oauth_refresh_expires", "expires_at"),
    sqlite_with_rowid=False,
)

login_states = Table(
    "login_states",
    metadata,
    # What the state is for (``mcp_txn``: an /authorize request waiting for sign-in and consent).
    Column("kind", _KEY, primary_key=True),
    # SHA-256 of the unguessable id handed to the browser.
    Column("id_hash", _KEY, primary_key=True),
    # SHA-256 of the cookie that ties the state to the browser that created it.
    Column("binding_hash", _KEY),
    # JSON, at most 4096 bytes.
    Column("payload", Text, nullable=False),
    Column("created_at", _INT, nullable=False),
    Column("expires_at", _INT, nullable=False),
    Index("login_states_expires", "expires_at"),
    sqlite_with_rowid=False,
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
    "oauth_clients",
    "cimd_clients",
    "oauth_grants",
    "oauth_codes",
    "oauth_refresh_tokens",
    "login_states",
)
