"""The reviewed v1 schema: one portable metadata definition, no legacy tables."""

from sqlalchemy import (
    CheckConstraint,
    Column,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    Table,
    Text,
    UniqueConstraint,
    false,
    text,
)

from .types import Bytes, Epoch, Flag, JsonDoc, Key, Uuid

VERSION_TABLE = "canvas_mcp_alembic_version"
SCHEMA_EPOCH = 2
metadata = MetaData(
    naming_convention={
        "pk": "pk_%(table_name)s",
        "uq": "uq_%(table_name)s_%(column_0_N_name)s",
        "ix": "ix_%(table_name)s_%(column_0_N_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    }
)

server_state = Table(
    "server_state",
    metadata,
    Column("id", Integer(), primary_key=True),
    Column("database_id", Uuid(), nullable=False),
    Column("compat_floor", Epoch, nullable=False),
    Column("jwt_epoch", Epoch, nullable=False, server_default=text("0")),
    Column("settings_revision", Epoch, nullable=False, server_default=text("0")),
    Column("created_at", Epoch, nullable=False),
    Column("updated_at", Epoch, nullable=False),
    CheckConstraint("id = 1", name="id"),
    CheckConstraint("length(database_id) = 36", name="database_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    info={"lifecycle": "state"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
)

settings = Table(
    "settings",
    metadata,
    Column("key", Key, primary_key=True),
    Column("value", JsonDoc(), nullable=False),
    Column("updated_at", Epoch, nullable=False),
    Column("updated_by", Uuid()),
    CheckConstraint("length(key) BETWEEN 1 AND 64", name="key"),
    CheckConstraint("length(updated_by) = 36", name="updated_by_uuid").ddl_if(
        dialect="sqlite"
    ),
    info={"lifecycle": "durable"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
)

login_providers = Table(
    "login_providers",
    metadata,
    Column("id", Key, primary_key=True),
    Column("protocol", Key, nullable=False),
    Column("display_name", Text),
    Column("sort_rank", Integer(), nullable=False, server_default=text("0")),
    Column("configured", Flag(), nullable=False, server_default=false()),
    Column("auto_link_email", Flag(), nullable=False, server_default=false()),
    Column("icon_data", Text),
    Column("configured_at", Epoch),
    Column("config_source", Key, nullable=False, server_default=text("'env'")),
    Column("config", JsonDoc()),
    Column("secret_key_id", Key),
    Column("secret_nonce", Bytes),
    Column("secret_ciphertext", Bytes),
    Column("created_at", Epoch, nullable=False),
    Column("updated_at", Epoch, nullable=False),
    Column("updated_by", Uuid()),
    CheckConstraint(
        " (secret_ciphertext IS NULL) = (secret_nonce IS NULL) AND (secret_nonce IS NULL) = (secret_key_id IS NULL)",
        name="secret_all_or_none",
    ),
    CheckConstraint(
        "display_name IS NULL OR length(display_name) BETWEEN 1 AND 40",
        name="display_name",
    ),
    CheckConstraint("configured IN (0,1)", name="configured_boolean").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("auto_link_email IN (0,1)", name="auto_link_email_boolean").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("config_source IN ('env','db')", name="config_source"),
    CheckConstraint(
        "secret_nonce IS NULL OR length(secret_nonce) = 12", name="secret_nonce"
    ),
    CheckConstraint("length(updated_by) = 36", name="updated_by_uuid").ddl_if(
        dialect="sqlite"
    ),
    info={
        "lifecycle": "durable",
        "sealed": {
            "key_id": "secret_key_id",
            "nonce": "secret_nonce",
            "ciphertext": "secret_ciphertext",
            "prefix": "canvas-mcp/provider-secret/v1",
            "fields": ("id", "secret_key_id"),
        },
    },
    sqlite_strict=True,
)

canvas_schools = Table(
    "canvas_schools",
    metadata,
    Column("host", Key, primary_key=True),
    Column("display_name", Text, nullable=False, server_default=text("''")),
    Column("featured_rank", Integer()),
    Column("origin", Key, nullable=False),
    Column("allow_private", Flag(), nullable=False, server_default=false()),
    Column("created_at", Epoch, nullable=False),
    Column("created_by", Uuid()),
    Column("updated_at", Epoch, nullable=False),
    Column("updated_by", Uuid()),
    CheckConstraint(
        "host = lower(host) AND length(host) BETWEEN 1 AND 253", name="host"
    ),
    CheckConstraint("length(display_name) <= 120", name="display_name"),
    CheckConstraint(
        "featured_rank IS NULL OR featured_rank >= 1", name="featured_rank"
    ),
    CheckConstraint("allow_private IN (0,1)", name="allow_private_boolean").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("length(created_by) = 36", name="created_by_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("length(updated_by) = 36", name="updated_by_uuid").ddl_if(
        dialect="sqlite"
    ),
    info={"lifecycle": "durable", "cull": "orphan_schools"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
)

accounts = Table(
    "accounts",
    metadata,
    Column("id", Uuid(), primary_key=True),
    Column("status", Key, nullable=False),
    Column("role", Key, nullable=False, server_default=text("'user'")),
    Column("role_source", Key),
    Column("role_seen_at", Epoch),
    Column("admitted_via", Key, nullable=False),
    Column("display_name", Text, nullable=False, server_default=text("''")),
    Column("upn", Key, nullable=False, server_default=text("''")),
    Column("upn_required", Flag(), nullable=False, server_default=false()),
    Column("created_at", Epoch, nullable=False),
    Column("updated_at", Epoch, nullable=False),
    Column("approved_at", Epoch),
    Column("approved_by", Uuid()),
    Column("disabled_at", Epoch),
    Column("disabled_by", Uuid()),
    Column("disabled_reason", Key),
    Column("last_login_at", Epoch),
    Column("session_epoch", Epoch, nullable=False, server_default=text("0")),
    Column("credential_generation", Epoch, nullable=False, server_default=text("0")),
    Column("write_tools_version", Epoch, nullable=False, server_default=text("0")),
    CheckConstraint(
        "(status = 'disabled') = (disabled_at IS NOT NULL)", name="disabled_consistent"
    ),
    CheckConstraint("length(id) = 36", name="id_uuid").ddl_if(dialect="sqlite"),
    CheckConstraint("status IN ('pending','active','disabled')", name="status"),
    CheckConstraint("role IN ('user','owner')", name="role"),
    CheckConstraint("length(display_name) <= 200", name="display_name"),
    CheckConstraint("upn_required IN (0,1)", name="upn_required_boolean").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint(
        "upn = '' OR (length(upn) BETWEEN 3 AND 254 AND upn = lower(upn))", name="upn"
    ),
    CheckConstraint("length(approved_by) = 36", name="approved_by_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("length(disabled_by) = 36", name="disabled_by_uuid").ddl_if(
        dialect="sqlite"
    ),
    info={"lifecycle": "durable", "cull": "pending"},
    sqlite_strict=True,
    postgresql_with={"fillfactor": 90},
)

local_credentials = Table(
    "local_credentials",
    metadata,
    Column(
        "account_id",
        Uuid(),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("password_hash", Text, nullable=False),
    Column("created_at", Epoch, nullable=False),
    Column("updated_at", Epoch, nullable=False),
    CheckConstraint("length(password_hash) BETWEEN 80 AND 256", name="password_hash"),
    info={"lifecycle": "durable"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
)

external_identities = Table(
    "external_identities",
    metadata,
    Column("id", Uuid(), primary_key=True),
    Column(
        "account_id",
        Uuid(),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column(
        "provider_id",
        Key,
        ForeignKey("login_providers.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("issuer", Key, nullable=False),
    Column("subject", Key, nullable=False),
    Column("username", Text),
    Column("email", Text),
    Column("email_verified", Flag(), nullable=False, server_default=false()),
    Column("linked_at", Epoch, nullable=False),
    Column("last_login_at", Epoch),
    UniqueConstraint(
        "provider_id", "issuer", "subject", name="uq_external_identities_subject"
    ),
    UniqueConstraint(
        "account_id", "provider_id", name="uq_external_identities_account_provider"
    ),
    ForeignKeyConstraint(
        ["issuer", "subject", "account_id"],
        [
            "external_identity_owners.issuer",
            "external_identity_owners.subject",
            "external_identity_owners.account_id",
        ],
        name="fk_external_identities_owner",
        ondelete="CASCADE",
    ),
    CheckConstraint("length(id) = 36", name="id_uuid").ddl_if(dialect="sqlite"),
    CheckConstraint("length(account_id) = 36", name="account_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("length(issuer) BETWEEN 1 AND 512", name="issuer"),
    CheckConstraint("length(subject) BETWEEN 1 AND 255", name="subject"),
    CheckConstraint("username IS NULL OR length(username) <= 254", name="username"),
    CheckConstraint("email IS NULL OR length(email) <= 320", name="email"),
    CheckConstraint("email_verified IN (0,1)", name="email_verified_boolean").ddl_if(
        dialect="sqlite"
    ),
    info={"lifecycle": "durable"},
    sqlite_strict=True,
)

external_identity_owners = Table(
    "external_identity_owners",
    metadata,
    Column("issuer", Key, primary_key=True),
    Column("subject", Key, primary_key=True),
    Column(
        "account_id",
        Uuid(),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
    ),
    UniqueConstraint(
        "issuer", "subject", "account_id", name="uq_external_identity_owners_binding"
    ),
    CheckConstraint("length(issuer) BETWEEN 1 AND 512", name="issuer"),
    CheckConstraint("length(subject) BETWEEN 1 AND 255", name="subject"),
    info={"lifecycle": "durable"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
)

account_login_policy = Table(
    "account_login_policy",
    metadata,
    Column(
        "account_id",
        Uuid(),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("allow_multiple", Flag()),
    Column("restrict_providers", Flag(), nullable=False, server_default=false()),
    Column(
        "sso_lock_provider", Key, ForeignKey("login_providers.id", ondelete="RESTRICT")
    ),
    Column("sso_lock_exempt", Flag(), nullable=False, server_default=false()),
    CheckConstraint(
        "allow_multiple IS NULL OR allow_multiple IN (0,1)",
        name="allow_multiple_boolean",
    ).ddl_if(dialect="sqlite"),
    CheckConstraint(
        "restrict_providers IN (0,1)", name="restrict_providers_boolean"
    ).ddl_if(dialect="sqlite"),
    CheckConstraint("sso_lock_exempt IN (0,1)", name="sso_lock_exempt_boolean").ddl_if(
        dialect="sqlite"
    ),
    info={"lifecycle": "durable"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
)

account_allowed_login_providers = Table(
    "account_allowed_login_providers",
    metadata,
    Column(
        "account_id",
        Uuid(),
        ForeignKey(
            "account_login_policy.account_id",
            ondelete="CASCADE",
            name="fk_account_allowed_login_providers_policy",
        ),
        primary_key=True,
    ),
    Column(
        "provider_id",
        Key,
        ForeignKey("login_providers.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    info={"lifecycle": "durable"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
)

account_write_tools = Table(
    "account_write_tools",
    metadata,
    Column(
        "account_id",
        Uuid(),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("tool_name", Key, nullable=False),
    Column("enabled_at", Epoch, nullable=False),
    Column("enabled_via", Key, nullable=False),
    PrimaryKeyConstraint("account_id", "tool_name"),
    CheckConstraint("length(account_id) = 36", name="account_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("length(tool_name) BETWEEN 1 AND 128", name="tool_name"),
    info={"lifecycle": "durable"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
)

canvas_oauth_apps = Table(
    "canvas_oauth_apps",
    metadata,
    Column("id", Uuid(), primary_key=True),
    Column(
        "canvas_host",
        Key,
        ForeignKey("canvas_schools.host", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("client_id", Text, nullable=False),
    Column("scopes", Text, nullable=False, server_default=text("''")),
    Column("enabled", Flag(), nullable=False, server_default=false()),
    Column("secret_key_id", Key, nullable=False),
    Column("secret_nonce", Bytes, nullable=False),
    Column("secret_ciphertext", Bytes, nullable=False),
    Column("created_at", Epoch, nullable=False),
    Column("updated_at", Epoch, nullable=False),
    Column("updated_by", Uuid()),
    UniqueConstraint("canvas_host", name="uq_canvas_oauth_apps_canvas_host"),
    CheckConstraint("length(id) = 36", name="id_uuid").ddl_if(dialect="sqlite"),
    CheckConstraint("enabled IN (0,1)", name="enabled_boolean").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("length(secret_nonce) = 12", name="secret_nonce"),
    CheckConstraint("length(secret_ciphertext) >= 17", name="secret_ciphertext"),
    CheckConstraint("length(updated_by) = 36", name="updated_by_uuid").ddl_if(
        dialect="sqlite"
    ),
    info={
        "lifecycle": "reserved",
        "sealed": {
            "key_id": "secret_key_id",
            "nonce": "secret_nonce",
            "ciphertext": "secret_ciphertext",
            "prefix": "canvas-mcp/canvas-oauth-app/v1",
            "fields": ("canvas_host", "client_id", "secret_key_id"),
        },
    },
    sqlite_strict=True,
)

canvas_credentials = Table(
    "canvas_credentials",
    metadata,
    Column("id", Uuid(), primary_key=True),
    Column(
        "account_id",
        Uuid(),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column(
        "canvas_host",
        Key,
        ForeignKey("canvas_schools.host", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("kind", Key, nullable=False),
    Column(
        "oauth_app_id", Uuid(), ForeignKey("canvas_oauth_apps.id", ondelete="RESTRICT")
    ),
    Column("is_primary", Flag(), nullable=False),
    Column("generation", Epoch, nullable=False),
    Column("key_id", Key, nullable=False),
    Column("nonce", Bytes, nullable=False),
    Column("ciphertext", Bytes, nullable=False),
    Column("canvas_user_id", Text, nullable=False),
    Column("canvas_user_name", Text, nullable=False),
    Column("status", Key, nullable=False, server_default=text("'active'")),
    Column("invalid_reason", Key),
    Column("invalid_since", Epoch),
    Column("created_at", Epoch, nullable=False),
    Column("updated_at", Epoch, nullable=False),
    Column("last_used_at", Epoch),
    Column("last_verified_at", Epoch),
    Column("expires_hint_at", Epoch),
    Column("access_expires_at", Epoch),
    Column("scopes", Text),
    Column("custody_notice_version", Integer(), nullable=False),
    Column("custody_ack_at", Epoch, nullable=False),
    UniqueConstraint(
        "account_id", "canvas_host", name="uq_canvas_credentials_account_host"
    ),
    CheckConstraint("custody_notice_version >= 1", name="custody_notice_version"),
    CheckConstraint("(kind = 'oauth') = (oauth_app_id IS NOT NULL)", name="oauth_app"),
    CheckConstraint(
        "(status = 'invalid') = (invalid_since IS NOT NULL)", name="invalid_since"
    ),
    CheckConstraint("length(id) = 36", name="id_uuid").ddl_if(dialect="sqlite"),
    CheckConstraint("length(account_id) = 36", name="account_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("kind IN ('pat','oauth')", name="kind"),
    CheckConstraint("length(oauth_app_id) = 36", name="oauth_app_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("is_primary IN (0,1)", name="is_primary_boolean").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("length(nonce) = 12", name="nonce"),
    CheckConstraint("length(ciphertext) >= 17", name="ciphertext"),
    CheckConstraint("status IN ('active','invalid')", name="status"),
    info={
        "lifecycle": "durable",
        "sealed": {
            "key_id": "key_id",
            "nonce": "nonce",
            "ciphertext": "ciphertext",
            "prefix": "canvas-mcp/canvas-credential/v1",
            "fields": ("account_id", "canvas_host", "kind", "key_id"),
        },
    },
    sqlite_strict=True,
    postgresql_with={"fillfactor": 90},
)

oauth_clients = Table(
    "oauth_clients",
    metadata,
    Column("id", Key, primary_key=True),
    Column("info", JsonDoc(), nullable=False),
    Column("client_name", Text, nullable=False, server_default=text("''")),
    Column("created_at", Epoch, nullable=False),
    Column("expires_at", Epoch, nullable=False),
    info={"lifecycle": "durable", "cull": "clients"},
    sqlite_strict=True,
)

cimd_clients = Table(
    "cimd_clients",
    metadata,
    Column("url", Key, primary_key=True),
    Column("doc", JsonDoc(), nullable=False),
    Column("fetched_at", Epoch, nullable=False),
    Column("fresh_until", Epoch, nullable=False),
    Column("last_error_at", Epoch),
    Column("last_error", Text),
    CheckConstraint("fresh_until >= fetched_at", name="fresh"),
    info={"lifecycle": "durable", "cull": "cimd"},
    sqlite_strict=True,
)

oauth_grants = Table(
    "oauth_grants",
    metadata,
    Column("id", Uuid(), primary_key=True),
    Column(
        "account_id",
        Uuid(),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("client_id", Key, nullable=False),
    Column("client_kind", Key, nullable=False),
    Column("client_name", Text, nullable=False, server_default=text("''")),
    Column("client_host", Text),
    Column("redirect_host", Text, nullable=False, server_default=text("''")),
    Column("scopes", Text, nullable=False),
    Column("resource", Text, nullable=False),
    Column("created_at", Epoch, nullable=False),
    Column("last_used_at", Epoch),
    Column("upstream_auth_at", Epoch, nullable=False),
    Column("expires_at", Epoch, nullable=False),
    Column("revoked_at", Epoch),
    Column("revoked_reason", Key),
    Column("revoked_by", Uuid()),
    CheckConstraint("(revoked_at IS NULL) = (revoked_reason IS NULL)", name="revoked"),
    CheckConstraint("length(id) = 36", name="id_uuid").ddl_if(dialect="sqlite"),
    CheckConstraint("length(account_id) = 36", name="account_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("client_kind IN ('dcr','cimd')", name="client_kind"),
    CheckConstraint(
        "revoked_reason IS NULL OR length(revoked_reason) <= 64", name="revoked_reason"
    ),
    CheckConstraint("length(revoked_by) = 36", name="revoked_by_uuid").ddl_if(
        dialect="sqlite"
    ),
    info={"lifecycle": "durable", "cull": "grants"},
    sqlite_strict=True,
    postgresql_with={"fillfactor": 90},
)

oauth_codes = Table(
    "oauth_codes",
    metadata,
    Column("code_hash", Bytes, primary_key=True),
    Column("client_id", Key, nullable=False),
    Column(
        "account_id",
        Uuid(),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("redirect_uri", Text, nullable=False),
    Column("redirect_uri_explicit", Flag(), nullable=False),
    Column("code_challenge", Text, nullable=False),
    Column("scopes", Text, nullable=False),
    Column("resource", Text, nullable=False),
    Column("client_kind", Key, nullable=False),
    Column("client_name", Text, nullable=False, server_default=text("''")),
    Column("client_host", Text),
    Column("redirect_host", Text, nullable=False, server_default=text("''")),
    Column("upstream_auth_at", Epoch, nullable=False),
    Column("session_epoch", Epoch, nullable=False),
    Column("created_at", Epoch, nullable=False),
    Column("expires_at", Epoch, nullable=False),
    Column("consumed_at", Epoch),
    Column("grant_id", Uuid()),
    Column("grace_replays", Integer(), nullable=False, server_default=text("0")),
    CheckConstraint("length(code_hash) = 32", name="code_hash"),
    CheckConstraint("length(account_id) = 36", name="account_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint(
        "redirect_uri_explicit IN (0,1)", name="redirect_uri_explicit_boolean"
    ).ddl_if(dialect="sqlite"),
    CheckConstraint("client_kind IN ('dcr','cimd')", name="client_kind"),
    CheckConstraint("length(grant_id) = 36", name="grant_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("grace_replays >= 0", name="grace_replays"),
    info={"lifecycle": "ephemeral", "cull": "codes"},
    sqlite_strict=True,
    postgresql_with={"autovacuum_vacuum_scale_factor": 0.05},
)

oauth_refresh_tokens = Table(
    "oauth_refresh_tokens",
    metadata,
    Column("token_hash", Bytes, primary_key=True),
    Column(
        "grant_id",
        Uuid(),
        ForeignKey("oauth_grants.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("parent_hash", Bytes),
    Column("created_at", Epoch, nullable=False),
    Column("used_at", Epoch),
    Column("replaced_by", Bytes),
    Column("grace_replays", Integer(), nullable=False, server_default=text("0")),
    CheckConstraint("length(token_hash) = 32", name="token_hash"),
    CheckConstraint("length(grant_id) = 36", name="grant_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint(
        "parent_hash IS NULL OR length(parent_hash) = 32", name="parent_hash"
    ),
    CheckConstraint(
        "replaced_by IS NULL OR length(replaced_by) = 32", name="replaced_by"
    ),
    CheckConstraint("grace_replays >= 0", name="grace_replays"),
    info={"lifecycle": "durable"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
    postgresql_with={"autovacuum_vacuum_scale_factor": 0.05},
)

login_states = Table(
    "login_states",
    metadata,
    Column("kind", Key, nullable=False),
    Column("id_hash", Bytes, nullable=False),
    Column("binding_hash", Bytes),
    Column("payload", Bytes, nullable=False),
    Column("created_at", Epoch, nullable=False),
    Column("expires_at", Epoch, nullable=False),
    PrimaryKeyConstraint("kind", "id_hash"),
    CheckConstraint("length(kind) <= 32", name="kind"),
    CheckConstraint("length(id_hash) = 32", name="id_hash"),
    CheckConstraint(
        "binding_hash IS NULL OR length(binding_hash) = 32", name="binding_hash"
    ),
    CheckConstraint("length(payload) <= 4096", name="payload"),
    info={"lifecycle": "ephemeral", "cull": "login_states"},
    sqlite_strict=True,
    postgresql_with={"autovacuum_vacuum_scale_factor": 0.05},
)

auth_events = Table(
    "auth_events",
    metadata,
    Column("id", Epoch, Identity(always=False), primary_key=True),
    Column("at", Epoch, nullable=False),
    Column("account_id", Uuid()),
    Column("provider_id", Key, nullable=False),
    Column("surface", Key, nullable=False),
    Column("outcome", Key, nullable=False),
    Column("reason", Key, nullable=False),
    Column("ua_hash", Bytes),
    CheckConstraint("length(account_id) = 36", name="account_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("length(surface) <= 16", name="surface"),
    CheckConstraint(
        "outcome IN ('success','pending','denied','error')", name="outcome"
    ),
    CheckConstraint("length(reason) <= 64", name="reason"),
    CheckConstraint("ua_hash IS NULL OR length(ua_hash) = 8", name="ua_hash"),
    info={"lifecycle": "history", "cull": "auth_events"},
    sqlite_strict=True,
    sqlite_autoincrement=True,
)

audit_log = Table(
    "audit_log",
    metadata,
    Column("id", Epoch, Identity(always=False), primary_key=True),
    Column("at", Epoch, nullable=False),
    Column("actor_kind", Key, nullable=False),
    Column("actor_id", Uuid()),
    Column("subject_account_id", Uuid()),
    Column("action", Key, nullable=False),
    Column("target_kind", Key),
    Column("target_id", Key),
    Column("reason", Text),
    Column("detail", JsonDoc(), nullable=False, server_default=text("'{}'")),
    CheckConstraint("(actor_kind = 'account') = (actor_id IS NOT NULL)", name="actor"),
    CheckConstraint("(target_kind IS NULL) = (target_id IS NULL)", name="target"),
    CheckConstraint("actor_kind IN ('account','operator','system')", name="actor_kind"),
    CheckConstraint("length(actor_id) = 36", name="actor_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint(
        "length(subject_account_id) = 36", name="subject_account_id_uuid"
    ).ddl_if(dialect="sqlite"),
    CheckConstraint("length(action) <= 64", name="action"),
    info={"lifecycle": "history", "cull": "audit"},
    sqlite_strict=True,
    sqlite_autoincrement=True,
)

web_sessions = Table(
    "web_sessions",
    metadata,
    Column("id_hash", Bytes, primary_key=True),
    Column(
        "account_id",
        Uuid(),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("session_epoch", Epoch, nullable=False),
    Column("provider_id", Key, nullable=False),
    Column("issued_at", Epoch, nullable=False),
    Column("last_seen_at", Epoch, nullable=False),
    Column("expires_at", Epoch, nullable=False),
    Column("revoked_at", Epoch),
    Column("ua_hash", Bytes),
    CheckConstraint("length(id_hash) = 32", name="id_hash"),
    CheckConstraint("length(account_id) = 36", name="account_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("ua_hash IS NULL OR length(ua_hash) = 8", name="ua_hash"),
    info={"lifecycle": "reserved"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
)

account_quotas = Table(
    "account_quotas",
    metadata,
    Column(
        "account_id",
        Uuid(),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("quota_key", Key, nullable=False),
    Column("limit_value", Epoch, nullable=False),
    Column("window_seconds", Integer()),
    Column("updated_at", Epoch, nullable=False),
    Column("updated_by", Uuid()),
    PrimaryKeyConstraint("account_id", "quota_key"),
    CheckConstraint("length(account_id) = 36", name="account_id_uuid").ddl_if(
        dialect="sqlite"
    ),
    CheckConstraint("length(quota_key) <= 64", name="quota_key"),
    CheckConstraint("limit_value >= 0", name="limit_value"),
    CheckConstraint("length(updated_by) = 36", name="updated_by_uuid").ddl_if(
        dialect="sqlite"
    ),
    info={"lifecycle": "reserved"},
    sqlite_strict=True,
    sqlite_with_rowid=False,
)

Index("ix_accounts_status_role", accounts.c.status, accounts.c.role)
Index(
    "uq_accounts_upn",
    accounts.c.upn,
    unique=True,
    sqlite_where=text("upn <> ''"),
    postgresql_where=text("upn <> ''"),
)
Index(
    "uq_canvas_credentials_primary",
    canvas_credentials.c.account_id,
    unique=True,
    postgresql_where=canvas_credentials.c.is_primary,
    sqlite_where=canvas_credentials.c.is_primary == 1,
)
Index("ix_canvas_credentials_canvas_host", canvas_credentials.c.canvas_host)
Index(
    "ix_canvas_credentials_oauth_app_id",
    canvas_credentials.c.oauth_app_id,
    postgresql_where=canvas_credentials.c.oauth_app_id.is_not(None),
    sqlite_where=canvas_credentials.c.oauth_app_id.is_not(None),
)
Index("ix_oauth_clients_expires_at", oauth_clients.c.expires_at)
Index("ix_cimd_clients_fetched_at", cimd_clients.c.fetched_at)
Index("ix_oauth_grants_account_id_id", oauth_grants.c.account_id, oauth_grants.c.id)
Index("ix_oauth_grants_expires_at", oauth_grants.c.expires_at)
Index(
    "ix_oauth_grants_revoked_at",
    oauth_grants.c.revoked_at,
    postgresql_where=oauth_grants.c.revoked_at.is_not(None),
    sqlite_where=oauth_grants.c.revoked_at.is_not(None),
)
Index("ix_oauth_codes_account_id", oauth_codes.c.account_id)
Index("ix_oauth_codes_expires_at", oauth_codes.c.expires_at)
Index(
    "ix_oauth_refresh_tokens_grant_id_parent_hash",
    oauth_refresh_tokens.c.grant_id,
    oauth_refresh_tokens.c.parent_hash,
)
Index("ix_login_states_expires_at", login_states.c.expires_at)
Index(
    "ix_auth_events_account_id_id",
    auth_events.c.account_id,
    auth_events.c.id,
    postgresql_where=auth_events.c.account_id.is_not(None),
    sqlite_where=auth_events.c.account_id.is_not(None),
)
Index(
    "ix_audit_log_subject",
    audit_log.c.subject_account_id,
    audit_log.c.id,
    postgresql_where=audit_log.c.subject_account_id.is_not(None),
    sqlite_where=audit_log.c.subject_account_id.is_not(None),
)
Index(
    "ix_audit_log_target",
    audit_log.c.target_kind,
    audit_log.c.target_id,
    audit_log.c.id,
    postgresql_where=audit_log.c.target_id.is_not(None),
    sqlite_where=audit_log.c.target_id.is_not(None),
)
Index("ix_web_sessions_account_id", web_sessions.c.account_id)
Index("ix_web_sessions_expires_at", web_sessions.c.expires_at)
Index(
    "ix_external_identities_owner",
    external_identities.c.issuer,
    external_identities.c.subject,
    external_identities.c.account_id,
)
Index("ix_external_identity_owners_account_id", external_identity_owners.c.account_id)
Index(
    "ix_account_login_policy_sso_lock_provider",
    account_login_policy.c.sso_lock_provider,
)
Index(
    "ix_account_allowed_login_providers_provider_id",
    account_allowed_login_providers.c.provider_id,
)
