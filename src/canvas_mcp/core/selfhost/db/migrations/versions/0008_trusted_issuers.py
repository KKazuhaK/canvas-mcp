"""Add trusted external token issuers and one federated grant per account and issuer."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import CheckConstraint, Column, Table, Text, text, true
from sqlalchemy.dialects import postgresql, sqlite

revision = "0008_trusted_issuers"
down_revision = "0007_browser_sync"
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


class Flag(sa.types.TypeDecorator):
    """BOOLEAN on PostgreSQL, INTEGER on SQLite STRICT tables."""

    impl = sa.Boolean(create_constraint=False)
    cache_ok = True

    def load_dialect_impl(self, dialect: sa.engine.Dialect) -> sa.types.TypeEngine:
        return dialect.type_descriptor(
            sa.Integer() if dialect.name == "sqlite" else self.impl
        )


trusted_issuers = Table(
    "trusted_issuers",
    metadata,
    Column("issuer", Key, primary_key=True),
    Column("name", Text),
    Column("audience", Text),
    Column("jwks_url", Text),
    Column("algorithms", Text, nullable=False),
    Column("require_typ_at_jwt", Flag(), nullable=False, server_default=true()),
    Column("subject_claim", Text, nullable=False, server_default=text("'sub'")),
    Column("read_scope", Text),
    Column("write_scope", Text),
    Column("created_at", Epoch, nullable=False),
    Column("updated_at", Epoch, nullable=False),
    CheckConstraint("length(issuer) BETWEEN 1 AND 512", name="issuer"),
    CheckConstraint("name IS NULL OR length(name) BETWEEN 1 AND 40", name="name"),
    CheckConstraint(
        "audience IS NULL OR length(audience) BETWEEN 1 AND 512", name="audience"
    ),
    CheckConstraint(
        "jwks_url IS NULL OR length(jwks_url) BETWEEN 1 AND 2048", name="jwks_url"
    ),
    CheckConstraint("length(algorithms) BETWEEN 1 AND 80", name="algorithms"),
    CheckConstraint("length(subject_claim) BETWEEN 1 AND 64", name="subject_claim"),
    CheckConstraint(
        "require_typ_at_jwt IN (0,1)", name="require_typ_at_jwt_boolean"
    ).ddl_if(dialect="sqlite"),
    info={"lifecycle": "durable"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
)


def upgrade() -> None:
    connection = op.get_bind()
    trusted_issuers.create(connection)
    op.create_index(
        "uq_oauth_grants_federated",
        "oauth_grants",
        ["account_id", "client_id"],
        unique=True,
        postgresql_where=sa.text("client_id LIKE 'federated:%'"),
        sqlite_where=sa.text("client_id LIKE 'federated:%'"),
    )


def downgrade() -> None:
    raise RuntimeError("schema downgrades are not supported; restore a backup")
