"""Frozen nineteen-table v1 baseline. Restore a backup instead of downgrading."""

from __future__ import annotations

import time
from uuid import uuid4

from alembic import op

from canvas_mcp.core.selfhost.db.migrations import baseline_v1

revision = "0001_v1_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    context = op.get_context()
    if context.as_sql:
        for statement in baseline_v1.statements(context.dialect.name):
            op.execute(statement)
        op.execute(
            "INSERT INTO server_state (id,database_id,compat_floor,jwt_epoch,"
            "settings_revision,created_at,updated_at) "
            f"VALUES (1,'{uuid4()}',1,0,0,{int(time.time())},{int(time.time())})"
        )
    else:
        baseline_v1.create(op.get_bind(), now=int(time.time()))


def downgrade() -> None:
    raise RuntimeError("v1 schema downgrades are not supported; restore a backup")
