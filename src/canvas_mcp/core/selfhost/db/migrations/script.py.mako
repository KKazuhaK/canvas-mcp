"""${message}

Revision ``${up_revision}``.

Expand revisions leave server_state.compat_floor unchanged. Contract revisions
raise that floor only after a release stopped using the contracted shape.
Keep backups, rebuild helpers and upgrade-only code inside this package.
Never import current schema metadata into a frozen revision.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
${imports if imports else ""}

revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}

CONTRACT = False
NON_TRANSACTIONAL = False  # PostgreSQL concurrent DDL only; use policy.concurrent_index.


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    raise NotImplementedError("restore the backup taken before upgrading")
