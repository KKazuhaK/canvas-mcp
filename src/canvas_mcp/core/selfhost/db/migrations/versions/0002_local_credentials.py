"""Expand with local password credentials; preserve existing accounts and ciphertext."""

import sqlalchemy as sa
from alembic import op

revision = "0002_local_credentials"
down_revision = "0001_v1_baseline"
branch_labels = None
depends_on = None
CONTRACT = False
NON_TRANSACTIONAL = False


def upgrade() -> None:
    # Frozen types: do not import evolving application metadata into a revision.
    pg = op.get_context().dialect.name == "postgresql"
    op.create_table(
        "local_credentials",
        sa.Column(
            "account_id", sa.Uuid(as_uuid=False) if pg else sa.Text(), nullable=False
        ),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.BigInteger() if pg else sa.Integer(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.BigInteger() if pg else sa.Integer(), nullable=False
        ),
        sa.PrimaryKeyConstraint("account_id", name="pk_local_credentials"),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["accounts.id"],
            ondelete="CASCADE",
            name="fk_local_credentials_account_id_accounts",
        ),
        sa.UniqueConstraint("username", name="uq_local_credentials_username"),
        sa.CheckConstraint(
            "length(username) BETWEEN 3 AND 64 AND username = lower(username)",
            name="username",
        ),
        sa.CheckConstraint(
            "length(password_hash) BETWEEN 80 AND 256", name="password_hash"
        ),
        sqlite_strict=True,
        sqlite_with_rowid=False,
    )


def downgrade() -> None:
    raise RuntimeError("schema downgrades are not supported; restore a backup")
