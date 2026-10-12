"""Expand provider presentation and finish legacy provisional account names."""

import sqlalchemy as sa
from alembic import op

revision = "0004_onboarding_and_icons"
down_revision = "0003_account_login_policy"
branch_labels = None
depends_on = None
CONTRACT = False
NON_TRANSACTIONAL = False


def upgrade() -> None:
    if op.get_context().as_sql:
        raise RuntimeError(
            "account-name backfill requires an online migration connection"
        )
    op.add_column("login_providers", sa.Column("icon_data", sa.Text(), nullable=True))
    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, upn FROM accounts ORDER BY id")).all()
    used = {row.upn for row in rows if row.upn}
    for row in rows:
        if row.upn:
            continue
        base = "account_" + str(row.id).replace("-", "")
        name, suffix = base, 1
        while name in used:
            suffix += 1
            name = f"{base}_{suffix}"
        used.add(name)
        conn.execute(
            sa.text(
                "UPDATE accounts SET upn = :name, upn_required = false WHERE id = :id"
            ),
            {"name": name, "id": row.id},
        )


def downgrade() -> None:
    raise RuntimeError("schema downgrades are not supported; restore a backup")
