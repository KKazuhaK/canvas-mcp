CREATE TABLE accounts (
	id TEXT NOT NULL, 
	status TEXT NOT NULL, 
	role TEXT DEFAULT 'user' NOT NULL, 
	role_source TEXT, 
	role_seen_at INTEGER, 
	admitted_via TEXT NOT NULL, 
	display_name TEXT DEFAULT '' NOT NULL, 
	created_at INTEGER NOT NULL, 
	updated_at INTEGER NOT NULL, 
	approved_at INTEGER, 
	approved_by TEXT, 
	disabled_at INTEGER, 
	disabled_by TEXT, 
	disabled_reason TEXT, 
	last_login_at INTEGER, 
	session_epoch INTEGER DEFAULT 0 NOT NULL, 
	credential_generation INTEGER DEFAULT 0 NOT NULL, 
	write_tools_version INTEGER DEFAULT 0 NOT NULL, 
	CONSTRAINT pk_accounts PRIMARY KEY (id), 
	CONSTRAINT ck_accounts_disabled_consistent CHECK ((status = 'disabled') = (disabled_at IS NOT NULL)), 
	CONSTRAINT ck_accounts_id_uuid CHECK (length(id) = 36), 
	CONSTRAINT ck_accounts_status CHECK (status IN ('pending','active','disabled')), 
	CONSTRAINT ck_accounts_role CHECK (role IN ('user','owner')), 
	CONSTRAINT ck_accounts_display_name CHECK (length(display_name) <= 200), 
	CONSTRAINT ck_accounts_approved_by_uuid CHECK (length(approved_by) = 36), 
	CONSTRAINT ck_accounts_disabled_by_uuid CHECK (length(disabled_by) = 36)
)
 STRICT;

CREATE TABLE audit_log (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
	at INTEGER NOT NULL, 
	actor_kind TEXT NOT NULL, 
	actor_id TEXT, 
	subject_account_id TEXT, 
	action TEXT NOT NULL, 
	target_kind TEXT, 
	target_id TEXT, 
	reason TEXT, 
	detail TEXT DEFAULT '{}' NOT NULL, 
	CONSTRAINT ck_audit_log_actor CHECK ((actor_kind = 'account') = (actor_id IS NOT NULL)), 
	CONSTRAINT ck_audit_log_target CHECK ((target_kind IS NULL) = (target_id IS NULL)), 
	CONSTRAINT ck_audit_log_actor_kind CHECK (actor_kind IN ('account','operator','system')), 
	CONSTRAINT ck_audit_log_actor_id_uuid CHECK (length(actor_id) = 36), 
	CONSTRAINT ck_audit_log_subject_account_id_uuid CHECK (length(subject_account_id) = 36), 
	CONSTRAINT ck_audit_log_action CHECK (length(action) <= 64)
)
 STRICT;

CREATE TABLE auth_events (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
	at INTEGER NOT NULL, 
	account_id TEXT, 
	provider_id TEXT NOT NULL, 
	surface TEXT NOT NULL, 
	outcome TEXT NOT NULL, 
	reason TEXT NOT NULL, 
	ua_hash BLOB, 
	CONSTRAINT ck_auth_events_account_id_uuid CHECK (length(account_id) = 36), 
	CONSTRAINT ck_auth_events_surface CHECK (length(surface) <= 16), 
	CONSTRAINT ck_auth_events_outcome CHECK (outcome IN ('success','pending','denied','error')), 
	CONSTRAINT ck_auth_events_reason CHECK (length(reason) <= 64), 
	CONSTRAINT ck_auth_events_ua_hash CHECK (ua_hash IS NULL OR length(ua_hash) = 8)
)
 STRICT;

CREATE TABLE canvas_schools (
	host TEXT NOT NULL, 
	display_name TEXT DEFAULT '' NOT NULL, 
	featured_rank INTEGER, 
	origin TEXT NOT NULL, 
	allow_private INTEGER DEFAULT 0 NOT NULL, 
	created_at INTEGER NOT NULL, 
	created_by TEXT, 
	updated_at INTEGER NOT NULL, 
	updated_by TEXT, 
	CONSTRAINT pk_canvas_schools PRIMARY KEY (host), 
	CONSTRAINT ck_canvas_schools_host CHECK (host = lower(host) AND length(host) BETWEEN 1 AND 253), 
	CONSTRAINT ck_canvas_schools_display_name CHECK (length(display_name) <= 120), 
	CONSTRAINT ck_canvas_schools_featured_rank CHECK (featured_rank IS NULL OR featured_rank >= 1), 
	CONSTRAINT ck_canvas_schools_allow_private_boolean CHECK (allow_private IN (0,1)), 
	CONSTRAINT ck_canvas_schools_created_by_uuid CHECK (length(created_by) = 36), 
	CONSTRAINT ck_canvas_schools_updated_by_uuid CHECK (length(updated_by) = 36)
)
 WITHOUT ROWID,
 STRICT;

CREATE TABLE cimd_clients (
	url TEXT NOT NULL, 
	doc TEXT NOT NULL, 
	fetched_at INTEGER NOT NULL, 
	fresh_until INTEGER NOT NULL, 
	last_error_at INTEGER, 
	last_error TEXT, 
	CONSTRAINT pk_cimd_clients PRIMARY KEY (url), 
	CONSTRAINT ck_cimd_clients_fresh CHECK (fresh_until >= fetched_at)
)
 STRICT;

CREATE TABLE login_providers (
	id TEXT NOT NULL, 
	protocol TEXT NOT NULL, 
	display_name TEXT, 
	sort_rank INTEGER DEFAULT 0 NOT NULL, 
	configured INTEGER DEFAULT 0 NOT NULL, 
	configured_at INTEGER, 
	config_source TEXT DEFAULT 'env' NOT NULL, 
	config TEXT, 
	secret_key_id TEXT, 
	secret_nonce BLOB, 
	secret_ciphertext BLOB, 
	created_at INTEGER NOT NULL, 
	updated_at INTEGER NOT NULL, 
	updated_by TEXT, 
	CONSTRAINT pk_login_providers PRIMARY KEY (id), 
	CONSTRAINT ck_login_providers_secret_all_or_none CHECK ( (secret_ciphertext IS NULL) = (secret_nonce IS NULL) AND (secret_nonce IS NULL) = (secret_key_id IS NULL)), 
	CONSTRAINT ck_login_providers_display_name CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 40), 
	CONSTRAINT ck_login_providers_configured_boolean CHECK (configured IN (0,1)), 
	CONSTRAINT ck_login_providers_config_source CHECK (config_source IN ('env','db')), 
	CONSTRAINT ck_login_providers_secret_nonce CHECK (secret_nonce IS NULL OR length(secret_nonce) = 12), 
	CONSTRAINT ck_login_providers_updated_by_uuid CHECK (length(updated_by) = 36)
)
 STRICT;

CREATE TABLE login_states (
	kind TEXT NOT NULL, 
	id_hash BLOB NOT NULL, 
	binding_hash BLOB, 
	payload BLOB NOT NULL, 
	created_at INTEGER NOT NULL, 
	expires_at INTEGER NOT NULL, 
	CONSTRAINT pk_login_states PRIMARY KEY (kind, id_hash), 
	CONSTRAINT ck_login_states_kind CHECK (length(kind) <= 32), 
	CONSTRAINT ck_login_states_id_hash CHECK (length(id_hash) = 32), 
	CONSTRAINT ck_login_states_binding_hash CHECK (binding_hash IS NULL OR length(binding_hash) = 32), 
	CONSTRAINT ck_login_states_payload CHECK (length(payload) <= 4096)
)
 STRICT;

CREATE TABLE oauth_clients (
	id TEXT NOT NULL, 
	info TEXT NOT NULL, 
	client_name TEXT DEFAULT '' NOT NULL, 
	created_at INTEGER NOT NULL, 
	expires_at INTEGER NOT NULL, 
	CONSTRAINT pk_oauth_clients PRIMARY KEY (id)
)
 STRICT;

CREATE TABLE server_state (
	id INTEGER NOT NULL, 
	database_id TEXT NOT NULL, 
	compat_floor INTEGER NOT NULL, 
	jwt_epoch INTEGER DEFAULT 0 NOT NULL, 
	settings_revision INTEGER DEFAULT 0 NOT NULL, 
	created_at INTEGER NOT NULL, 
	updated_at INTEGER NOT NULL, 
	CONSTRAINT pk_server_state PRIMARY KEY (id), 
	CONSTRAINT ck_server_state_id CHECK (id = 1), 
	CONSTRAINT ck_server_state_database_id_uuid CHECK (length(database_id) = 36)
)
 WITHOUT ROWID,
 STRICT;

CREATE TABLE settings (
	"key" TEXT NOT NULL, 
	value TEXT NOT NULL, 
	updated_at INTEGER NOT NULL, 
	updated_by TEXT, 
	CONSTRAINT pk_settings PRIMARY KEY ("key"), 
	CONSTRAINT ck_settings_key CHECK (length(key) BETWEEN 1 AND 64), 
	CONSTRAINT ck_settings_updated_by_uuid CHECK (length(updated_by) = 36)
)
 WITHOUT ROWID,
 STRICT;

CREATE TABLE account_quotas (
	account_id TEXT NOT NULL, 
	quota_key TEXT NOT NULL, 
	limit_value INTEGER NOT NULL, 
	window_seconds INTEGER, 
	updated_at INTEGER NOT NULL, 
	updated_by TEXT, 
	CONSTRAINT pk_account_quotas PRIMARY KEY (account_id, quota_key), 
	CONSTRAINT ck_account_quotas_account_id_uuid CHECK (length(account_id) = 36), 
	CONSTRAINT ck_account_quotas_quota_key CHECK (length(quota_key) <= 64), 
	CONSTRAINT ck_account_quotas_limit_value CHECK (limit_value >= 0), 
	CONSTRAINT ck_account_quotas_updated_by_uuid CHECK (length(updated_by) = 36), 
	CONSTRAINT fk_account_quotas_account_id_accounts FOREIGN KEY(account_id) REFERENCES accounts (id) ON DELETE CASCADE
)
 WITHOUT ROWID,
 STRICT;

CREATE TABLE account_write_tools (
	account_id TEXT NOT NULL, 
	tool_name TEXT NOT NULL, 
	enabled_at INTEGER NOT NULL, 
	enabled_via TEXT NOT NULL, 
	CONSTRAINT pk_account_write_tools PRIMARY KEY (account_id, tool_name), 
	CONSTRAINT ck_account_write_tools_account_id_uuid CHECK (length(account_id) = 36), 
	CONSTRAINT ck_account_write_tools_tool_name CHECK (length(tool_name) BETWEEN 1 AND 128), 
	CONSTRAINT fk_account_write_tools_account_id_accounts FOREIGN KEY(account_id) REFERENCES accounts (id) ON DELETE CASCADE
)
 WITHOUT ROWID,
 STRICT;

CREATE TABLE canvas_oauth_apps (
	id TEXT NOT NULL, 
	canvas_host TEXT NOT NULL, 
	client_id TEXT NOT NULL, 
	scopes TEXT DEFAULT '' NOT NULL, 
	enabled INTEGER DEFAULT 0 NOT NULL, 
	secret_key_id TEXT NOT NULL, 
	secret_nonce BLOB NOT NULL, 
	secret_ciphertext BLOB NOT NULL, 
	created_at INTEGER NOT NULL, 
	updated_at INTEGER NOT NULL, 
	updated_by TEXT, 
	CONSTRAINT pk_canvas_oauth_apps PRIMARY KEY (id), 
	CONSTRAINT uq_canvas_oauth_apps_canvas_host UNIQUE (canvas_host), 
	CONSTRAINT ck_canvas_oauth_apps_id_uuid CHECK (length(id) = 36), 
	CONSTRAINT ck_canvas_oauth_apps_enabled_boolean CHECK (enabled IN (0,1)), 
	CONSTRAINT ck_canvas_oauth_apps_secret_nonce CHECK (length(secret_nonce) = 12), 
	CONSTRAINT ck_canvas_oauth_apps_secret_ciphertext CHECK (length(secret_ciphertext) >= 17), 
	CONSTRAINT ck_canvas_oauth_apps_updated_by_uuid CHECK (length(updated_by) = 36), 
	CONSTRAINT fk_canvas_oauth_apps_canvas_host_canvas_schools FOREIGN KEY(canvas_host) REFERENCES canvas_schools (host) ON DELETE RESTRICT
)
 STRICT;

CREATE TABLE external_identities (
	id TEXT NOT NULL, 
	account_id TEXT NOT NULL, 
	provider_id TEXT NOT NULL, 
	issuer TEXT NOT NULL, 
	subject TEXT NOT NULL, 
	username TEXT, 
	email TEXT, 
	email_verified INTEGER DEFAULT 0 NOT NULL, 
	linked_at INTEGER NOT NULL, 
	last_login_at INTEGER, 
	CONSTRAINT pk_external_identities PRIMARY KEY (id), 
	CONSTRAINT uq_external_identities_subject UNIQUE (provider_id, issuer, subject), 
	CONSTRAINT uq_external_identities_account_provider UNIQUE (account_id, provider_id), 
	CONSTRAINT ck_external_identities_id_uuid CHECK (length(id) = 36), 
	CONSTRAINT ck_external_identities_account_id_uuid CHECK (length(account_id) = 36), 
	CONSTRAINT ck_external_identities_issuer CHECK (length(issuer) BETWEEN 1 AND 512), 
	CONSTRAINT ck_external_identities_subject CHECK (length(subject) BETWEEN 1 AND 255), 
	CONSTRAINT ck_external_identities_username CHECK (username IS NULL OR length(username) <= 254), 
	CONSTRAINT ck_external_identities_email CHECK (email IS NULL OR length(email) <= 320), 
	CONSTRAINT ck_external_identities_email_verified_boolean CHECK (email_verified IN (0,1)), 
	CONSTRAINT fk_external_identities_account_id_accounts FOREIGN KEY(account_id) REFERENCES accounts (id) ON DELETE CASCADE, 
	CONSTRAINT fk_external_identities_provider_id_login_providers FOREIGN KEY(provider_id) REFERENCES login_providers (id) ON DELETE RESTRICT
)
 STRICT;

CREATE TABLE oauth_codes (
	code_hash BLOB NOT NULL, 
	client_id TEXT NOT NULL, 
	account_id TEXT NOT NULL, 
	redirect_uri TEXT NOT NULL, 
	redirect_uri_explicit INTEGER NOT NULL, 
	code_challenge TEXT NOT NULL, 
	scopes TEXT NOT NULL, 
	resource TEXT NOT NULL, 
	client_kind TEXT NOT NULL, 
	client_name TEXT DEFAULT '' NOT NULL, 
	client_host TEXT, 
	redirect_host TEXT DEFAULT '' NOT NULL, 
	upstream_auth_at INTEGER NOT NULL, 
	session_epoch INTEGER NOT NULL, 
	created_at INTEGER NOT NULL, 
	expires_at INTEGER NOT NULL, 
	consumed_at INTEGER, 
	grant_id TEXT, 
	grace_replays INTEGER DEFAULT 0 NOT NULL, 
	CONSTRAINT pk_oauth_codes PRIMARY KEY (code_hash), 
	CONSTRAINT ck_oauth_codes_code_hash CHECK (length(code_hash) = 32), 
	CONSTRAINT ck_oauth_codes_account_id_uuid CHECK (length(account_id) = 36), 
	CONSTRAINT ck_oauth_codes_redirect_uri_explicit_boolean CHECK (redirect_uri_explicit IN (0,1)), 
	CONSTRAINT ck_oauth_codes_client_kind CHECK (client_kind IN ('dcr','cimd')), 
	CONSTRAINT ck_oauth_codes_grant_id_uuid CHECK (length(grant_id) = 36), 
	CONSTRAINT ck_oauth_codes_grace_replays CHECK (grace_replays >= 0), 
	CONSTRAINT fk_oauth_codes_account_id_accounts FOREIGN KEY(account_id) REFERENCES accounts (id) ON DELETE CASCADE
)
 STRICT;

CREATE TABLE oauth_grants (
	id TEXT NOT NULL, 
	account_id TEXT NOT NULL, 
	client_id TEXT NOT NULL, 
	client_kind TEXT NOT NULL, 
	client_name TEXT DEFAULT '' NOT NULL, 
	client_host TEXT, 
	redirect_host TEXT DEFAULT '' NOT NULL, 
	scopes TEXT NOT NULL, 
	resource TEXT NOT NULL, 
	created_at INTEGER NOT NULL, 
	last_used_at INTEGER, 
	upstream_auth_at INTEGER NOT NULL, 
	expires_at INTEGER NOT NULL, 
	revoked_at INTEGER, 
	revoked_reason TEXT, 
	revoked_by TEXT, 
	CONSTRAINT pk_oauth_grants PRIMARY KEY (id), 
	CONSTRAINT ck_oauth_grants_revoked CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL)), 
	CONSTRAINT ck_oauth_grants_id_uuid CHECK (length(id) = 36), 
	CONSTRAINT ck_oauth_grants_account_id_uuid CHECK (length(account_id) = 36), 
	CONSTRAINT ck_oauth_grants_client_kind CHECK (client_kind IN ('dcr','cimd')), 
	CONSTRAINT ck_oauth_grants_revoked_reason CHECK (revoked_reason IS NULL OR length(revoked_reason) <= 64), 
	CONSTRAINT ck_oauth_grants_revoked_by_uuid CHECK (length(revoked_by) = 36), 
	CONSTRAINT fk_oauth_grants_account_id_accounts FOREIGN KEY(account_id) REFERENCES accounts (id) ON DELETE CASCADE
)
 STRICT;

CREATE TABLE web_sessions (
	id_hash BLOB NOT NULL, 
	account_id TEXT NOT NULL, 
	session_epoch INTEGER NOT NULL, 
	provider_id TEXT NOT NULL, 
	issued_at INTEGER NOT NULL, 
	last_seen_at INTEGER NOT NULL, 
	expires_at INTEGER NOT NULL, 
	revoked_at INTEGER, 
	ua_hash BLOB, 
	CONSTRAINT pk_web_sessions PRIMARY KEY (id_hash), 
	CONSTRAINT ck_web_sessions_id_hash CHECK (length(id_hash) = 32), 
	CONSTRAINT ck_web_sessions_account_id_uuid CHECK (length(account_id) = 36), 
	CONSTRAINT ck_web_sessions_ua_hash CHECK (ua_hash IS NULL OR length(ua_hash) = 8), 
	CONSTRAINT fk_web_sessions_account_id_accounts FOREIGN KEY(account_id) REFERENCES accounts (id) ON DELETE CASCADE
)
 WITHOUT ROWID,
 STRICT;

CREATE TABLE canvas_credentials (
	id TEXT NOT NULL, 
	account_id TEXT NOT NULL, 
	canvas_host TEXT NOT NULL, 
	kind TEXT NOT NULL, 
	oauth_app_id TEXT, 
	is_primary INTEGER NOT NULL, 
	generation INTEGER NOT NULL, 
	key_id TEXT NOT NULL, 
	nonce BLOB NOT NULL, 
	ciphertext BLOB NOT NULL, 
	canvas_user_id TEXT NOT NULL, 
	canvas_user_name TEXT NOT NULL, 
	status TEXT DEFAULT 'active' NOT NULL, 
	invalid_reason TEXT, 
	invalid_since INTEGER, 
	created_at INTEGER NOT NULL, 
	updated_at INTEGER NOT NULL, 
	last_used_at INTEGER, 
	last_verified_at INTEGER, 
	expires_hint_at INTEGER, 
	access_expires_at INTEGER, 
	scopes TEXT, 
	custody_notice_version INTEGER NOT NULL, 
	custody_ack_at INTEGER NOT NULL, 
	CONSTRAINT pk_canvas_credentials PRIMARY KEY (id), 
	CONSTRAINT uq_canvas_credentials_account_host UNIQUE (account_id, canvas_host), 
	CONSTRAINT ck_canvas_credentials_custody_notice_version CHECK (custody_notice_version >= 1), 
	CONSTRAINT ck_canvas_credentials_oauth_app CHECK ((kind = 'oauth') = (oauth_app_id IS NOT NULL)), 
	CONSTRAINT ck_canvas_credentials_invalid_since CHECK ((status = 'invalid') = (invalid_since IS NOT NULL)), 
	CONSTRAINT ck_canvas_credentials_id_uuid CHECK (length(id) = 36), 
	CONSTRAINT ck_canvas_credentials_account_id_uuid CHECK (length(account_id) = 36), 
	CONSTRAINT ck_canvas_credentials_kind CHECK (kind IN ('pat','oauth')), 
	CONSTRAINT ck_canvas_credentials_oauth_app_id_uuid CHECK (length(oauth_app_id) = 36), 
	CONSTRAINT ck_canvas_credentials_is_primary_boolean CHECK (is_primary IN (0,1)), 
	CONSTRAINT ck_canvas_credentials_nonce CHECK (length(nonce) = 12), 
	CONSTRAINT ck_canvas_credentials_ciphertext CHECK (length(ciphertext) >= 17), 
	CONSTRAINT ck_canvas_credentials_status CHECK (status IN ('active','invalid')), 
	CONSTRAINT fk_canvas_credentials_account_id_accounts FOREIGN KEY(account_id) REFERENCES accounts (id) ON DELETE CASCADE, 
	CONSTRAINT fk_canvas_credentials_canvas_host_canvas_schools FOREIGN KEY(canvas_host) REFERENCES canvas_schools (host) ON DELETE RESTRICT, 
	CONSTRAINT fk_canvas_credentials_oauth_app_id_canvas_oauth_apps FOREIGN KEY(oauth_app_id) REFERENCES canvas_oauth_apps (id) ON DELETE RESTRICT
)
 STRICT;

CREATE TABLE oauth_refresh_tokens (
	token_hash BLOB NOT NULL, 
	grant_id TEXT NOT NULL, 
	parent_hash BLOB, 
	created_at INTEGER NOT NULL, 
	used_at INTEGER, 
	replaced_by BLOB, 
	grace_replays INTEGER DEFAULT 0 NOT NULL, 
	CONSTRAINT pk_oauth_refresh_tokens PRIMARY KEY (token_hash), 
	CONSTRAINT ck_oauth_refresh_tokens_token_hash CHECK (length(token_hash) = 32), 
	CONSTRAINT ck_oauth_refresh_tokens_grant_id_uuid CHECK (length(grant_id) = 36), 
	CONSTRAINT ck_oauth_refresh_tokens_parent_hash CHECK (parent_hash IS NULL OR length(parent_hash) = 32), 
	CONSTRAINT ck_oauth_refresh_tokens_replaced_by CHECK (replaced_by IS NULL OR length(replaced_by) = 32), 
	CONSTRAINT ck_oauth_refresh_tokens_grace_replays CHECK (grace_replays >= 0), 
	CONSTRAINT fk_oauth_refresh_tokens_grant_id_oauth_grants FOREIGN KEY(grant_id) REFERENCES oauth_grants (id) ON DELETE CASCADE
)
 WITHOUT ROWID,
 STRICT;

CREATE INDEX ix_accounts_status_role ON accounts (status, role);

CREATE INDEX ix_audit_log_subject ON audit_log (subject_account_id, id) WHERE subject_account_id IS NOT NULL;

CREATE INDEX ix_audit_log_target ON audit_log (target_kind, target_id, id) WHERE target_id IS NOT NULL;

CREATE INDEX ix_auth_events_account_id_id ON auth_events (account_id, id) WHERE account_id IS NOT NULL;

CREATE INDEX ix_cimd_clients_fetched_at ON cimd_clients (fetched_at);

CREATE INDEX ix_login_states_expires_at ON login_states (expires_at);

CREATE INDEX ix_oauth_clients_expires_at ON oauth_clients (expires_at);

CREATE INDEX ix_oauth_codes_account_id ON oauth_codes (account_id);

CREATE INDEX ix_oauth_codes_expires_at ON oauth_codes (expires_at);

CREATE INDEX ix_oauth_grants_account_id_id ON oauth_grants (account_id, id);

CREATE INDEX ix_oauth_grants_expires_at ON oauth_grants (expires_at);

CREATE INDEX ix_oauth_grants_revoked_at ON oauth_grants (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE INDEX ix_web_sessions_account_id ON web_sessions (account_id);

CREATE INDEX ix_web_sessions_expires_at ON web_sessions (expires_at);

CREATE INDEX ix_canvas_credentials_canvas_host ON canvas_credentials (canvas_host);

CREATE INDEX ix_canvas_credentials_oauth_app_id ON canvas_credentials (oauth_app_id) WHERE oauth_app_id IS NOT NULL;

CREATE UNIQUE INDEX uq_canvas_credentials_primary ON canvas_credentials (account_id) WHERE is_primary = 1;

CREATE INDEX ix_oauth_refresh_tokens_grant_id_parent_hash ON oauth_refresh_tokens (grant_id, parent_hash);
