"""${message}

Revision ``${up_revision}``.

If an older server would misread the database after this revision, set
COMPAT_SCHEMA_VERSION above the previous revision's value: the server refuses
a database whose ``meta.schema_version`` is newer than it supports.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
${imports if imports else ""}

revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}

COMPAT_SCHEMA_VERSION = 4


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    raise NotImplementedError("restore the backup taken before upgrading")
