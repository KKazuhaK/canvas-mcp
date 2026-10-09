"""Baseline: schema version 4 of the self-hosted token database.

SQLite: the frozen, idempotent steps of the pre-Alembic releases (see
``baseline_v4``), so a fresh file is identical to one the old code created and an
existing file (schema versions 1 to 4) is adopted in place without touching any
row's ciphertext, nonce or key id.

PostgreSQL: the same tables, created with ``op.create_table``.

Revision ``0001_baseline_v4``. Upgrading is idempotent; there is no downgrade
(restore the backup taken before upgrading).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from canvas_mcp.core.selfhost.db import baseline_v4

revision = "0001_baseline_v4"
down_revision = None
branch_labels = None
depends_on = None

#: ``meta.schema_version`` an older server needs to see to open the database
#: after this revision. Every later revision that an older server would misread
#: must declare a higher value (a test checks the values never decrease).
COMPAT_SCHEMA_VERSION = 4

_KEY = sa.Text(collation="C")


def upgrade() -> None:
    if op.get_context().dialect.name == "sqlite":
        baseline_v4.ensure_sqlite_v4(op.get_bind())
        return
    _upgrade_postgresql()


def _upgrade_postgresql() -> None:
    op.create_table(
        "meta",
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "canvas_tokens",
        sa.Column("tenant_id", _KEY, nullable=False),
        sa.Column("object_id", _KEY, nullable=False),
        sa.Column("key_id", _KEY, nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("canvas_user_id", sa.Text(), nullable=False),
        sa.Column("canvas_user_name", sa.Text(), nullable=False),
        sa.Column("entra_display_name", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("entra_upn", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("last_used_at", sa.BigInteger()),
        sa.Column("canvas_host", sa.Text()),
        sa.Column("principal_key", _KEY),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'active'")),
        sa.Column("invalid_reason", sa.Text()),
        sa.Column("invalid_since", sa.BigInteger()),
        sa.Column("last_verified_at", sa.BigInteger()),
        sa.Column("expires_hint_at", sa.BigInteger()),
        sa.PrimaryKeyConstraint("tenant_id", "object_id"),
    )
    op.create_index("canvas_tokens_principal_key", "canvas_tokens", ["principal_key"], unique=True)
    op.create_table(
        "user_tool_prefs",
        sa.Column("principal_key", _KEY, nullable=False),
        sa.Column("enabled_write_tools", sa.Text(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("enabled_at", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column(
            "updated_via", sa.Text(), nullable=False, server_default=sa.text("'account_web'")
        ),
        sa.PrimaryKeyConstraint("principal_key"),
    )
    op.create_table(
        "principal_status",
        sa.Column("principal_key", _KEY, nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'active'")),
        sa.Column("disabled_reason", sa.Text()),
        sa.Column("disabled_at", sa.BigInteger()),
        sa.Column("disabled_by", sa.Text()),
        sa.Column("display_name", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("upn", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("session_epoch", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("is_owner", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("owner_seen_at", sa.BigInteger()),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("principal_key"),
    )
    op.create_table(
        "principal_status_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("principal_key", _KEY, nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("actor", sa.Text()),
        sa.Column("reason", sa.Text()),
        sa.Column("session_epoch", sa.BigInteger(), nullable=False),
        sa.Column("at", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "principal_status_events_principal",
        "principal_status_events",
        ["principal_key", "id"],
    )
    op.create_table(
        "credential_generations",
        sa.Column("principal_key", _KEY, nullable=False),
        sa.Column("generation", sa.BigInteger(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("principal_key"),
    )
    op.execute(
        "INSERT INTO meta (key, value) VALUES ('schema_version', '"
        + str(COMPAT_SCHEMA_VERSION)
        + "')"
    )


def downgrade() -> None:
    raise NotImplementedError("restore the backup taken before upgrading")
