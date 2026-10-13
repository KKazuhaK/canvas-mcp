"""Preserve manual dates while recording authoritative Canvas expiry metadata."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005_canvas_expiry"
down_revision = "0004_onboarding_and_icons"
branch_labels = None
depends_on = None
CONTRACT = False
NON_TRANSACTIONAL = False


def upgrade() -> None:
    op.add_column(
        "canvas_credentials",
        sa.Column(
            "expiry_source",
            sa.Text().with_variant(postgresql.TEXT(collation="C"), "postgresql"),
            nullable=False,
            server_default=sa.text("'manual'"),
        ),
    )


def downgrade() -> None:
    raise RuntimeError("schema downgrades are not supported; restore a backup")
