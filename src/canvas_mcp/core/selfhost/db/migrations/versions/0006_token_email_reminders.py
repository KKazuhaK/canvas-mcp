"""Add sealed SMTP configuration, account opt-in and durable delivery claims."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import CheckConstraint, Column, ForeignKey, Index, Integer, Table, Text
from sqlalchemy.dialects import postgresql, sqlite

revision = "0006_token_email_reminders"
down_revision = "0005_canvas_expiry"
branch_labels = None
depends_on = None
CONTRACT = True
NON_TRANSACTIONAL = False

metadata = sa.MetaData(
    naming_convention={
        "pk": "pk_%(table_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    }
)
Key = sa.Text().with_variant(postgresql.TEXT(collation="C"), "postgresql")
Epoch = sa.BigInteger().with_variant(sqlite.INTEGER(), "sqlite")
Bytes = sa.LargeBinary()


def Uuid() -> sa.types.TypeEngine:
    return sa.Text().with_variant(postgresql.UUID(as_uuid=False), "postgresql")


def Flag() -> sa.types.TypeEngine:
    return sa.Integer().with_variant(sa.Boolean(), "postgresql")


def JsonDoc() -> sa.types.TypeEngine:
    return sa.Text().with_variant(postgresql.JSONB(), "postgresql")


# Referenced durable parents already exist in the preceding graph.
Table("accounts", metadata, Column("id", Uuid(), primary_key=True))
Table("canvas_credentials", metadata, Column("id", Uuid(), primary_key=True))

mail_settings = Table(
    "mail_settings",
    metadata,
    Column("id", Key, primary_key=True),
    Column("config", JsonDoc(), nullable=False),
    Column("key_id", Key),
    Column("nonce", Bytes),
    Column("ciphertext", Bytes),
    Column("updated_at", Epoch, nullable=False),
    CheckConstraint("id = 'smtp'", name="id"),
    CheckConstraint(
        "(key_id IS NULL) = (nonce IS NULL) AND (nonce IS NULL) = (ciphertext IS NULL)",
        name="secret",
    ),
    info={
        "lifecycle": "durable",
        "sealed": {
            "key_id": "key_id",
            "nonce": "nonce",
            "ciphertext": "ciphertext",
            "prefix": "canvas-mcp/mail-settings/v1",
            "fields": ("id", "key_id"),
        },
    },
    sqlite_strict=True,
    sqlite_with_rowid=False,
)

notification_preferences = Table(
    "notification_preferences",
    metadata,
    Column(
        "account_id",
        Uuid(),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("enabled", Flag(), nullable=False),
    Column("email", Text, nullable=False),
    Column("locale", Key, nullable=False),
    Column("updated_at", Epoch, nullable=False),
    CheckConstraint("length(email) BETWEEN 0 AND 254", name="email"),
    CheckConstraint("locale IN ('en','zh')", name="locale"),
    CheckConstraint("enabled IN (0,1)", name="enabled_boolean").ddl_if(
        dialect="sqlite"
    ),
    info={"lifecycle": "durable"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
)

notification_deliveries = Table(
    "notification_deliveries",
    metadata,
    Column("id", Key, primary_key=True),
    Column(
        "account_id",
        Uuid(),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column(
        "credential_id",
        Uuid(),
        ForeignKey("canvas_credentials.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("generation", Epoch, nullable=False),
    Column("expires_at", Epoch, nullable=False),
    Column("stage", Key, nullable=False),
    Column("status", Key, nullable=False),
    Column("attempts", Integer(), nullable=False),
    Column("lease_until", Epoch, nullable=False),
    Column("updated_at", Epoch, nullable=False),
    CheckConstraint("stage IN ('soon','expired')", name="stage"),
    CheckConstraint("status IN ('claimed','sent','failed')", name="status"),
    CheckConstraint("attempts BETWEEN 1 AND 3", name="attempts"),
    info={"lifecycle": "durable"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
)
Index("ix_notification_deliveries_account_id", notification_deliveries.c.account_id)
Index(
    "ix_notification_deliveries_credential_id", notification_deliveries.c.credential_id
)


def upgrade() -> None:
    connection = op.get_bind()
    for table in (mail_settings, notification_preferences, notification_deliveries):
        table.create(connection)
    # Older builds cannot verify or rotate the newly sealed SMTP secret.
    connection.execute(sa.text("UPDATE server_state SET compat_floor=3 WHERE id=1"))


def downgrade() -> None:
    raise RuntimeError("schema downgrades are not supported; restore a backup")
