"""Schema version 5: the account model.

Creates ``accounts``, ``external_identities``, ``auth_events`` and ``audit_log``,
replaces ``canvas_tokens`` (its primary key moves from tenant + object to the
principal key) and drops ``principal_status`` (its columns live in ``accounts``).
The data step (``db/accounts_v5.py``, frozen) maps every ``entra:<tenant>:<object>``
principal to an ``acct:<uuid>`` account, re-encrypts every stored Canvas token under
its new principal and re-keys the preferences, the credential generations and the
status history, all in the one transaction of this upgrade.

The data step needs ``CANVAS_TOKEN_KEYS`` (the keyring is passed in through
``config.attributes['keyring']``) and takes a private copy of a SQLite file first
(``BACKUP_BEFORE``). There is no downgrade: stop every server, restore the backup
(SQLite: the ``*.bak`` file next to the database; PostgreSQL: your ``pg_dump``) and
run the previous image.

Offline (``--sql``) output exists for PostgreSQL only and refuses a database that
holds data: re-encryption cannot be written as SQL.
"""

from __future__ import annotations

from alembic import context, op

from canvas_mcp.core.selfhost.db import accounts_v5

revision = "0002_accounts"
down_revision = "0001_baseline_v4"
branch_labels = None
depends_on = None

#: ``meta.schema_version`` an older server needs to see to open the database. A server
#: of the previous release reads ``principal_status`` and would serve a disabled user,
#: so it must refuse this database.
COMPAT_SCHEMA_VERSION = 5

#: Take a private copy of a populated SQLite file before this revision runs.
BACKUP_BEFORE = True


def upgrade() -> None:
    ctx = op.get_context()
    if ctx.as_sql:
        if ctx.dialect.name != "postgresql":
            raise NotImplementedError("offline SQL for this revision exists for PostgreSQL only")
        accounts_v5.upgrade_offline_postgresql(op)
        return
    attributes = context.config.attributes
    options = attributes.get("options") or accounts_v5.MigrationOptions()
    report = attributes.get("report")
    if report is None:
        report = accounts_v5.AccountMigrationReport()
    accounts_v5.upgrade_data(op.get_bind(), op, attributes.get("keyring"), options, report)


def downgrade() -> None:
    raise NotImplementedError("restore the backup taken before upgrading")
