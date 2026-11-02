"""Add browser-extension bindings, pairing codes and sealed Canvas snapshots."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import (
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    PrimaryKeyConstraint,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects import postgresql, sqlite

revision = "0007_browser_sync"
down_revision = "0006_token_email_reminders"
branch_labels = None
depends_on = None
CONTRACT = False
NON_TRANSACTIONAL = False

metadata = sa.MetaData(
    naming_convention={
        "pk": "pk_%(table_name)s",
        "uq": "uq_%(table_name)s_%(column_0_N_name)s",
        "ix": "ix_%(table_name)s_%(column_0_N_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    }
)
Key = sa.Text().with_variant(postgresql.TEXT(collation="C"), "postgresql")
Epoch = sa.BigInteger().with_variant(sqlite.INTEGER(), "sqlite")
Bytes = sa.LargeBinary()


def Uuid() -> sa.types.TypeEngine:
    return sa.Text().with_variant(postgresql.UUID(as_uuid=False), "postgresql")


# Referenced durable parent already exists in the preceding graph.
Table("accounts", metadata, Column("id", Uuid(), primary_key=True))

extension_bindings = Table(
    "extension_bindings",
    metadata,
    Column("id", Uuid(), primary_key=True),
    Column(
        "account_id",
        Uuid(),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("token_hash", Key, nullable=False),
    Column("canvas_host", Key),
    Column("canvas_user_id", Text),
    Column("created_at", Epoch, nullable=False),
    Column("last_upload_at", Epoch),
    Column("revoked_at", Epoch),
    UniqueConstraint("token_hash", name="uq_extension_bindings_token_hash"),
    CheckConstraint("length(id) = 36", name="id_uuid").ddl_if(dialect="sqlite"),
    CheckConstraint("length(account_id) = 36", name="account_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("length(token_hash) = 64", name="token_hash"),
    info={"lifecycle": "durable", "cull": "revoked_bindings"},
    sqlite_strict=True,
)

extension_pairing_codes = Table(
    "extension_pairing_codes",
    metadata,
    Column("code_hash", Key, primary_key=True),
    Column(
        "account_id",
        Uuid(),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("created_at", Epoch, nullable=False),
    Column("expires_at", Epoch, nullable=False),
    Column("claimed_at", Epoch),
    CheckConstraint("length(code_hash) = 64", name="code_hash"),
    CheckConstraint("length(account_id) = 36", name="account_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    info={"lifecycle": "durable", "cull": "extension_codes"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
)

browser_snapshots = Table(
    "browser_snapshots",
    metadata,
    Column(
        "binding_id",
        Uuid(),
        ForeignKey("extension_bindings.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("resource_key", Key, nullable=False),
    Column("captured_at", Epoch, nullable=False),
    Column("canvas_status", Integer(), nullable=False),
    Column("key_id", Key, nullable=False),
    Column("nonce", Bytes, nullable=False),
    Column("ciphertext", Bytes, nullable=False),
    PrimaryKeyConstraint("binding_id", "resource_key"),
    CheckConstraint("length(binding_id) = 36", name="binding_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("canvas_status BETWEEN 100 AND 599", name="canvas_status"),
    CheckConstraint("length(nonce) = 12", name="nonce"),
    CheckConstraint("length(ciphertext) >= 17", name="ciphertext"),
    info={"lifecycle": "durable", "cull": "browser_snapshots"},
    sqlite_strict=True,
)

Index(
    "uq_extension_bindings_active",
    extension_bindings.c.account_id,
    unique=True,
    postgresql_where=extension_bindings.c.revoked_at.is_(None),
    sqlite_where=extension_bindings.c.revoked_at.is_(None),
)
Index("ix_extension_pairing_codes_account_id", extension_pairing_codes.c.account_id)
Index("ix_extension_pairing_codes_expires_at", extension_pairing_codes.c.expires_at)
Index("ix_browser_snapshots_captured_at", browser_snapshots.c.captured_at)


def upgrade() -> None:
    connection = op.get_bind()
    for table in (extension_bindings, extension_pairing_codes, browser_snapshots):
        table.create(connection)


def downgrade() -> None:
    raise RuntimeError("schema downgrades are not supported; restore a backup")
