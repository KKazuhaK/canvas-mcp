"""Schema for the self-hosted authorization server (``SELFHOST_AUTH_MODE=local``).

Adds six tables and nothing else; no existing table or row is touched, so the upgrade
is the same on a database in either authorization mode and a fresh database gets the
tables whether or not the local mode is ever switched on:

* ``oauth_clients``: dynamically registered clients (public clients only).
* ``cimd_clients``: the last known good client metadata documents.
* ``oauth_grants``: one row per connection of an app to an account (a refresh family).
* ``oauth_codes``: authorization codes, kept as tombstones after use.
* ``oauth_refresh_tokens``: SHA-256 hashes of refresh tokens and their rotation chain.
* ``login_states``: one-time state that must survive between requests (an /authorize
  request waiting for the user to sign in and approve).

The marker stays at 5 (``COMPAT_SCHEMA_VERSION``): the change is additive, and an older
server already refuses this database because it does not know the revision.

The DDL is frozen here (it does not import ``db.schema``), so this revision never
changes when the module that queries the tables does. There is no downgrade: restore
the backup you took before upgrading and run the previous image.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import sqlite

revision = "0003_oauth_authz"
down_revision = "0002_accounts"
branch_labels = None
depends_on = None

#: Additive only: an older server refuses the database through the unknown revision.
COMPAT_SCHEMA_VERSION = 5

#: Nothing existing is rewritten, so no private copy of a SQLite file is needed.
BACKUP_BEFORE = False

_KEY = sa.Text().with_variant(sa.Text(collation="C"), "postgresql")
_INT = sa.BigInteger().with_variant(sqlite.INTEGER(), "sqlite")
_EMPTY = sa.text("''")
_ZERO = sa.text("0")


def upgrade() -> None:
    text = sa.Text()
    rowid = {"sqlite_with_rowid": False}

    op.create_table(
        "oauth_clients",
        sa.Column("id", _KEY, primary_key=True),
        sa.Column("info_json", text, nullable=False),
        sa.Column("client_name", text, nullable=False, server_default=_EMPTY),
        sa.Column("created_at", _INT, nullable=False),
        sa.Column("expires_at", _INT, nullable=False),
        **rowid,
    )
    op.create_index("oauth_clients_expires", "oauth_clients", ["expires_at"])

    op.create_table(
        "cimd_clients",
        sa.Column("url", _KEY, primary_key=True),
        sa.Column("doc_json", text, nullable=False),
        sa.Column("fetched_at", _INT, nullable=False),
        sa.Column("fresh_until", _INT, nullable=False),
        sa.Column("last_error_at", _INT),
        sa.Column("last_error", text),
        sa.CheckConstraint("fresh_until >= fetched_at", name="cimd_clients_fresh_check"),
        **rowid,
    )
    op.create_index("cimd_clients_fetched", "cimd_clients", ["fetched_at"])

    op.create_table(
        "oauth_grants",
        sa.Column("id", _KEY, primary_key=True),
        sa.Column("account_id", _KEY, nullable=False),
        sa.Column("client_id", _KEY, nullable=False),
        sa.Column("client_kind", text, nullable=False),
        sa.Column("client_name", text, nullable=False, server_default=_EMPTY),
        sa.Column("client_host", text),
        sa.Column("redirect_host", text, nullable=False, server_default=_EMPTY),
        sa.Column("scopes", text, nullable=False),
        sa.Column("resource", text, nullable=False),
        sa.Column("created_at", _INT, nullable=False),
        sa.Column("last_used_at", _INT),
        sa.Column("upstream_auth_at", _INT, nullable=False),
        sa.Column("expires_at", _INT, nullable=False),
        sa.Column("revoked_at", _INT),
        sa.Column("revoked_reason", text),
        sa.Column("revoked_by", _KEY),
        sa.CheckConstraint("client_kind IN ('dcr', 'cimd')", name="oauth_grants_kind_check"),
        sa.CheckConstraint(
            "revoked_reason IS NULL OR revoked_reason IN ('user_revoked', 'owner_revoked', "
            "'operator_revoked', 'client_revoked', 'refresh_reuse', 'code_replay', "
            "'account_disabled', 'admission_lost', 'reauth_required')",
            name="oauth_grants_reason_check",
        ),
        **rowid,
    )
    op.create_index("oauth_grants_account", "oauth_grants", ["account_id", "revoked_at"])
    op.create_index("oauth_grants_client", "oauth_grants", ["client_id"])
    op.create_index("oauth_grants_expires", "oauth_grants", ["expires_at"])

    op.create_table(
        "oauth_codes",
        sa.Column("code_hash", _KEY, primary_key=True),
        sa.Column("client_id", _KEY, nullable=False),
        sa.Column("account_id", _KEY, nullable=False),
        sa.Column("redirect_uri", text, nullable=False),
        sa.Column("redirect_uri_explicit", _INT, nullable=False),
        sa.Column("code_challenge", text, nullable=False),
        sa.Column("scopes", text, nullable=False),
        sa.Column("resource", text, nullable=False),
        sa.Column("client_kind", text, nullable=False),
        sa.Column("client_name", text, nullable=False, server_default=_EMPTY),
        sa.Column("client_host", text),
        sa.Column("redirect_host", text, nullable=False, server_default=_EMPTY),
        sa.Column("upstream_auth_at", _INT, nullable=False),
        sa.Column("created_at", _INT, nullable=False),
        sa.Column("expires_at", _INT, nullable=False),
        sa.Column("consumed_at", _INT),
        sa.Column("grant_id", _KEY),
        sa.Column("grace_replays", _INT, nullable=False, server_default=_ZERO),
        sa.CheckConstraint("redirect_uri_explicit IN (0, 1)", name="oauth_codes_explicit_check"),
        sa.CheckConstraint("client_kind IN ('dcr', 'cimd')", name="oauth_codes_kind_check"),
        **rowid,
    )
    op.create_index("oauth_codes_expires", "oauth_codes", ["expires_at"])

    op.create_table(
        "oauth_refresh_tokens",
        sa.Column("token_hash", _KEY, primary_key=True),
        sa.Column("grant_id", _KEY, nullable=False),
        sa.Column("parent_hash", _KEY),
        sa.Column("created_at", _INT, nullable=False),
        sa.Column("expires_at", _INT, nullable=False),
        sa.Column("used_at", _INT),
        sa.Column("replaced_by", _KEY),
        sa.Column("grace_replays", _INT, nullable=False, server_default=_ZERO),
        sa.CheckConstraint("grace_replays >= 0", name="oauth_refresh_grace_check"),
        **rowid,
    )
    op.create_index("oauth_refresh_grant", "oauth_refresh_tokens", ["grant_id"])
    op.create_index("oauth_refresh_parent", "oauth_refresh_tokens", ["parent_hash"])
    op.create_index("oauth_refresh_expires", "oauth_refresh_tokens", ["expires_at"])

    op.create_table(
        "login_states",
        sa.Column("kind", _KEY, primary_key=True),
        sa.Column("id_hash", _KEY, primary_key=True),
        sa.Column("binding_hash", _KEY),
        sa.Column("payload", text, nullable=False),
        sa.Column("created_at", _INT, nullable=False),
        sa.Column("expires_at", _INT, nullable=False),
        **rowid,
    )
    op.create_index("login_states_expires", "login_states", ["expires_at"])


def downgrade() -> None:
    raise NotImplementedError("restore the backup taken before upgrading")
