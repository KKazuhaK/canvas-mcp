"""Canonical account names and provider-neutral identity ownership."""

import re

import sqlalchemy as sa
from alembic import op

from canvas_mcp.core.selfhost.db.migrations.policy import rebuild_sqlite_table

revision = "0003_account_login_policy"
down_revision = "0002_local_credentials"
branch_labels = None
depends_on = None
CONTRACT = True
NON_TRANSACTIONAL = False


def upgrade() -> None:
    if op.get_context().as_sql:
        raise RuntimeError(
            "account-name backfill requires an online migration connection"
        )
    conn = op.get_bind()
    pg = conn.dialect.name == "postgresql"
    uuid = sa.Uuid(as_uuid=False) if pg else sa.Text()
    flag = sa.Boolean() if pg else sa.Integer()
    op.add_column(
        "accounts", sa.Column("upn", sa.Text(), nullable=False, server_default="")
    )
    op.add_column(
        "accounts",
        sa.Column("upn_required", flag, nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "login_providers",
        sa.Column("auto_link_email", flag, nullable=False, server_default=sa.false()),
    )

    # Preserve local names first. Never merge existing accounts by their emails.
    names: dict[object, str] = dict(
        conn.execute(
            sa.text("SELECT account_id, username FROM local_credentials")
        ).all()
    )
    used = set(names.values())
    accounts = (
        conn.execute(sa.text("SELECT id FROM accounts ORDER BY id")).scalars().all()
    )
    for account_id in accounts:
        name = names.get(account_id)
        if name is None:
            emails = conn.execute(
                sa.text(
                    "SELECT email FROM external_identities WHERE account_id=:id AND email_verified=:verified AND provider_id<>'entra' ORDER BY linked_at, id"
                ),
                {"id": account_id, "verified": True},
            ).scalars()
            for email in emails:
                candidate = email.strip().lower() if isinstance(email, str) else ""
                if (
                    re.fullmatch(r"[a-z0-9][a-z0-9.@_+-]{2,253}", candidate)
                    and candidate.count("@") == 1
                    and not candidate.endswith("@")
                    and candidate not in used
                ):
                    name = candidate
                    break
        if name is None:
            name = "account_" + str(account_id).replace("-", "")
            while name in used:
                name += "_"
        used.add(name)
        conn.execute(
            sa.text("UPDATE accounts SET upn=:name WHERE id=:id"),
            {"name": name, "id": account_id},
        )

    check = "upn = '' OR (length(upn) BETWEEN 3 AND 254 AND upn = lower(upn))"
    if pg:
        op.create_check_constraint(op.f("ck_accounts_upn"), "accounts", check)
        op.drop_constraint(
            "uq_local_credentials_username", "local_credentials", type_="unique"
        )
        op.drop_constraint(
            op.f("ck_local_credentials_username"), "local_credentials", type_="check"
        )
        op.drop_column("local_credentials", "username")
    else:
        with rebuild_sqlite_table("accounts") as batch:
            batch.create_check_constraint(op.f("ck_accounts_upn"), check)
            batch.create_check_constraint(
                op.f("ck_accounts_upn_required_boolean"), "upn_required IN (0,1)"
            )
        with rebuild_sqlite_table("login_providers") as batch:
            batch.create_check_constraint(
                op.f("ck_login_providers_auto_link_email_boolean"),
                "auto_link_email IN (0,1)",
            )
        with rebuild_sqlite_table("local_credentials") as batch:
            batch.drop_constraint("uq_local_credentials_username", type_="unique")
            batch.drop_constraint(op.f("ck_local_credentials_username"), type_="check")
            batch.drop_column("username")
    op.create_index(
        "uq_accounts_upn",
        "accounts",
        ["upn"],
        unique=True,
        sqlite_where=sa.text("upn <> ''"),
        postgresql_where=sa.text("upn <> ''"),
    )
    conn.execute(
        sa.text(
            "UPDATE external_identities SET username=NULL WHERE provider_id='local'"
        )
    )

    op.create_table(
        "external_identity_owners",
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("account_id", uuid, nullable=False),
        sa.PrimaryKeyConstraint(
            "issuer", "subject", name="pk_external_identity_owners"
        ),
        sa.UniqueConstraint(
            "issuer",
            "subject",
            "account_id",
            name="uq_external_identity_owners_binding",
        ),
        sa.CheckConstraint("length(issuer) BETWEEN 1 AND 512", name="issuer"),
        sa.CheckConstraint("length(subject) BETWEEN 1 AND 255", name="subject"),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["accounts.id"],
            ondelete="CASCADE",
            name="fk_external_identity_owners_account_id_accounts",
        ),
        sqlite_strict=True,
        sqlite_with_rowid=False,
    )
    owners: dict[tuple[str, str], object] = {}
    for issuer, subject, account_id in conn.execute(
        sa.text("SELECT issuer, subject, account_id FROM external_identities")
    ):
        key = (issuer, subject)
        if key in owners and owners[key] != account_id:
            raise RuntimeError(
                "canonical external identity belongs to multiple accounts; resolve ownership before upgrading"
            )
        owners[key] = account_id
    for (issuer, subject), account_id in owners.items():
        conn.execute(
            sa.text(
                "INSERT INTO external_identity_owners (issuer, subject, account_id) VALUES (:issuer, :subject, :id)"
            ),
            {"issuer": issuer, "subject": subject, "id": account_id},
        )
    if pg:
        op.create_foreign_key(
            "fk_external_identities_owner",
            "external_identities",
            "external_identity_owners",
            ["issuer", "subject", "account_id"],
            ["issuer", "subject", "account_id"],
            ondelete="CASCADE",
        )
    else:
        with rebuild_sqlite_table("external_identities") as batch:
            batch.create_foreign_key(
                "fk_external_identities_owner",
                "external_identity_owners",
                ["issuer", "subject", "account_id"],
                ["issuer", "subject", "account_id"],
                ondelete="CASCADE",
            )
    op.create_index(
        "ix_external_identities_owner",
        "external_identities",
        ["issuer", "subject", "account_id"],
    )
    op.create_table(
        "account_login_policy",
        sa.Column("account_id", uuid, nullable=False),
        sa.Column("allow_multiple", flag),
        sa.Column(
            "restrict_providers", flag, nullable=False, server_default=sa.false()
        ),
        sa.Column("sso_lock_provider", sa.Text()),
        sa.Column("sso_lock_exempt", flag, nullable=False, server_default=sa.false()),
        sa.PrimaryKeyConstraint("account_id", name="pk_account_login_policy"),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["accounts.id"],
            ondelete="CASCADE",
            name="fk_account_login_policy_account_id_accounts",
        ),
        sa.ForeignKeyConstraint(
            ["sso_lock_provider"],
            ["login_providers.id"],
            ondelete="RESTRICT",
            name="fk_account_login_policy_sso_lock_provider_login_providers",
        ),
        *(
            []
            if pg
            else [
                sa.CheckConstraint(
                    "allow_multiple IS NULL OR allow_multiple IN (0,1)",
                    name="allow_multiple_boolean",
                ),
                sa.CheckConstraint(
                    "restrict_providers IN (0,1)", name="restrict_providers_boolean"
                ),
                sa.CheckConstraint(
                    "sso_lock_exempt IN (0,1)", name="sso_lock_exempt_boolean"
                ),
            ]
        ),
        sqlite_strict=True,
        sqlite_with_rowid=False,
    )
    op.create_table(
        "account_allowed_login_providers",
        sa.Column("account_id", uuid, nullable=False),
        sa.Column("provider_id", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint(
            "account_id", "provider_id", name="pk_account_allowed_login_providers"
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["account_login_policy.account_id"],
            ondelete="CASCADE",
            name="fk_account_allowed_login_providers_policy",
        ),
        sa.ForeignKeyConstraint(
            ["provider_id"],
            ["login_providers.id"],
            ondelete="RESTRICT",
            name="fk_account_allowed_login_providers_provider_id_login_providers",
        ),
        sqlite_strict=True,
        sqlite_with_rowid=False,
    )
    op.create_index(
        "ix_external_identity_owners_account_id",
        "external_identity_owners",
        ["account_id"],
    )
    op.create_index(
        "ix_account_login_policy_sso_lock_provider",
        "account_login_policy",
        ["sso_lock_provider"],
    )
    op.create_index(
        "ix_account_allowed_login_providers_provider_id",
        "account_allowed_login_providers",
        ["provider_id"],
    )
    conn.execute(sa.text("UPDATE server_state SET compat_floor=2 WHERE id=1"))


def downgrade() -> None:
    raise RuntimeError("schema downgrades are not supported; restore a backup")
