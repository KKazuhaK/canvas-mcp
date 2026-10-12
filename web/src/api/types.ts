// Wire types for the same-origin JSON API under /api/v1, as the Python server
// (src/canvas_mcp/core/selfhost/account_api.py) answers it. Every response is
// no-store and every failure is { error: { code, params? } } with a code from the
// closed ApiErrorCode set; the UI never shows server, IdP or Canvas free text.
//
// Timestamps are ISO-8601 UTC strings or null. An account id is the bare lower-case
// UUID (safe in a path); `key` is the same id.

/** Codes the JSON API answers with (HTTP status in the comment). */
export type ApiOnlyErrorCode =
  // session and transport
  | 'not_authenticated' // 401
  | 'csrf_invalid' // 403
  | 'origin_not_allowed' // 403
  | 'reauth_required' // 403, params: { max_age_s }
  | 'forbidden' // 403
  | 'pending_approval' // 403
  | 'access_disabled' // 403 (also a sign-in error)
  | 'method_not_allowed' // 405
  | 'unsupported_media_type' // 415
  | 'payload_too_large' // 413
  | 'malformed_request' // 400
  | 'validation_failed' // 422, params: { field[, min, max] }
  | 'not_found' // 404
  | 'rate_limited' // 429, params: { retry_after_s }
  | 'token_store_unavailable' // 503 (also a sign-in error)
  | 'internal_error' // 500
  // Canvas token
  | 'token_invalid_format' // 422
  | 'token_rejected' // 422
  | 'token_unreadable' // 422
  | 'canvas_unavailable' // 503
  | 'identity_change_required' // 409, params: { enrolled_user_name, new_user_name, confirmation }
  | 'recheck_not_allowed' // 409
  | 'custody_ack_required' // 422
  | 'custody_notice_outdated' // 409, params: { notice_version }
  | 'not_enrolled' // 404
  // schools
  | 'school_required' // 422
  | 'school_invalid' // 422
  | 'school_not_offered' // 422
  | 'school_not_in_directory' // 422
  | 'school_unresolvable' // 422
  | 'school_address_blocked' // 422
  | 'school_selection_unverified' // 422
  | 'directory_unavailable' // 503
  // write tools
  | 'write_tool_not_allowed' // 422, params: { tool }
  | 'write_tools_unavailable' // 503
  // admin
  | 'settings_conflict' // 409
  | 'pilot_profile_restricted' // 409
  | 'confirmation_required' // 409, params: { affected: { host: count } }
  | 'last_owner' // 409
  | 'cannot_disable_self' // 409
  // linked sign-in methods
  | 'identity_in_use' // 409 (also the result of a link)
  | 'provider_already_linked' // 409
  | 'last_identity' // 409
  | 'link_session_ended' // 409 (also the result of a link)
  | 'provider_unavailable' // 503 (also the result of a link)
  // an app's authorization request (the server's own authorization server)
  | 'authorization_invalid' // 400 (also a sign-in error)
  | 'client_unavailable' // 409
  | 'invalid_provider_configuration'
  | 'provider_secret_required'
  | 'provider_identity_binding_changed'
  | 'too_many_providers'
  | 'installation_already_initialized'
  | 'installation_code_invalid'
  | 'provider_configuration_unavailable'
  | 'installation_authority_unavailable'
  | 'invalid_local_credentials'
  | 'local_username_taken'
  | 'local_login_failed'

export interface LoginProviderConfiguration {
  id: string
  protocol: 'entra' | 'google' | 'github' | 'oidc' | 'local'
  enabled: boolean
  rank: number
  config: Record<string, string | string[] | boolean>
  secret_present: boolean
  callback_uri: string
}
export interface LoginProviderSave {
  revision: number
  config: LoginProviderConfiguration['config']
  enabled: boolean
  rank: number
  client_secret?: string
}
export interface LoginProviderSettings {
  revision: number
  public_base_url: string
  providers: LoginProviderConfiguration[]
}
export interface SetupStatus {
  initialized: boolean
  revision: number
  callback_uri: string
}
export interface SetupRequest {
  revision: number
  code: string
  local_account: { username: string; password: string }
  provider_id?: string
  config?: LoginProviderConfiguration['config']
  client_secret?: string
}

/** Codes that only ever arrive as ?error= on /account/sign-in, never as JSON. */
export type SignInErrorCode =
  | 'state_invalid'
  | 'provider_error'
  | 'sign_in_incomplete'
  | 'sign_in_unverified'
  | 'wrong_tenant'
  | 'bad_subject'
  | 'bad_roles'
  | 'access_denied'
  | 'access_disabled'
  | 'signups_paused'
  | 'token_store_unavailable'
  | 'rate_limited'
  // An app (MCP client) was waiting for this sign-in, but its request is gone: it
  // expired, was started in another browser, or was already used.
  | 'authorization_invalid'

export type ApiErrorCode = ApiOnlyErrorCode | SignInErrorCode

export type ErrorParams = Record<string, string | number | Record<string, number>>

export interface ApiErrorBody {
  error: { code: ApiErrorCode; params?: ErrorParams }
}

// ---- providers ---------------------------------------------------------------

export type ProviderIcon = 'microsoft' | 'google' | 'github' | 'key'
export interface Provider {
  id: string
  kind: 'oidc' | 'oauth2' | 'local'
  name: string
  icon: ProviderIcon
  /** The server-side redirect that starts the sign-in (a full-page navigation). */
  start_url: string
}
export interface ProvidersResponse {
  providers: Provider[]
  mcp_url: string
  setup_required?: boolean
}

// ---- Canvas token --------------------------------------------------------------

export type CanvasTokenState = 'none' | 'active' | 'invalid'
export type InvalidReason = 'canvas_token_rejected' | 'decrypt_failed' | 'revoked_by_admin'
export type ExpiryNotice = 'none' | 'soon' | 'passed'

export interface SchoolRef {
  host: string
  name: string
  /** False when the server no longer offers this school. */
  offered: boolean
}

export interface CanvasTokenStatus {
  custody: {
    notice_version: number
    acknowledged_version: number | null
    acknowledged_at: string | null
    current: boolean
  }
  state: CanvasTokenState
  /** Canvas user ids are strings, as stored. */
  canvas_user_id: string | null
  canvas_user_name: string | null
  school: SchoolRef | null
  invalid_reason: InvalidReason | null
  invalid_since: string | null
  /** True when the token is invalid and the reason is not revoked_by_admin. */
  recheck_allowed: boolean
  /** The date the person noted when enrolling (YYYY-MM-DD). */
  expires_on: string | null
  expiry_notice: ExpiryNotice
  /** https link to the school's own Canvas settings page, or null. */
  settings_url: string | null
  enrolled_at: string | null
  updated_at: string | null
  last_used_at: string | null
  last_verified_at: string | null
}

export interface CanvasTokenRequest {
  custody: { acknowledged: true; notice_version: number }
  canvas_token: string
  school?: string | null
  school_sig?: string | null
  expires_on?: string | null
  confirm_identity_change?: string | null
}

export type RecheckResult = 'restored' | 'unchanged'
export interface RecheckResponse {
  result: RecheckResult
  canvas: CanvasTokenStatus
}

// ---- schools ---------------------------------------------------------------------

export type SchoolMode = 'picker' | 'sole' | 'none'
export interface SchoolChoice {
  host: string
  name: string
  source: 'featured' | 'enrolled'
}
export interface SchoolsResponse {
  mode: SchoolMode
  choices: SchoolChoice[]
  selected: string | null
  sole: { host: string; name: string } | null
  search_enabled: boolean
}
export interface SchoolSearchResult {
  host: string
  name: string
  /** Proof (HMAC) that this host came out of this session's own search. */
  sig: string
}
export interface SchoolSearchResponse {
  results: SchoolSearchResult[]
}

// ---- me ----------------------------------------------------------------------------

export type AccountRole = 'owner' | 'user'
/** A disabled account is signed out by the server, so /me only ever shows these two. */
export type SelfStatus = 'active' | 'pending'
export type UiLocale = 'en' | 'zh'

export interface Account {
  id: string
  key: string
  display_name: string
  username: string
  provider_id: string
  role: AccountRole
  status: SelfStatus
}

export interface SessionInfo {
  issued_at: string | null
  expires_at: string | null
  fresh_until: string | null
  fresh: boolean
  fresh_window_s: number
}

export interface Features {
  school_picker: boolean
  school_search: boolean
  write_tools: boolean
  admin: boolean
  // Two or more sign-in providers: the Sign-in methods screen.
  identities: boolean
  // The server's own authorization server (SELFHOST_AUTH_MODE=local) only.


  logout_everywhere: boolean
  role_management: boolean
}

export interface MeResponse {
  custody_ack_required: boolean
  account: Account
  csrf_token: string
  session: SessionInfo
  /** null while the account is pending. */
  canvas: CanvasTokenStatus | null
  /** null while pending or when the server has no write-tool catalog. */
  write_tools: { offered: number; enabled: number } | null
  features: Features
  ui_locale: UiLocale | null
  server: { mcp_url: string; display_timezone: string }
}

// ---- write tools ----------------------------------------------------------------------

export type WriteToolGroupId = 'planner' | 'submissions' | 'modules' | 'inbox' | 'other'
export type WriteToolEffect = 'canvas_write' | 'local_write'
export interface WriteTool {
  name: string
  offered: boolean
  enabled: boolean
  enabled_at: string | null
  effect: WriteToolEffect
}
export interface WriteToolGroup {
  id: WriteToolGroupId
  tools: WriteTool[]
}
export interface WriteToolsResponse {
  groups: WriteToolGroup[]
  /** Names that are on but that this server no longer offers. */
  kept_not_offered: string[]
  offered_any: boolean
  editable: boolean
}
export type WriteToolsSaveResult = 'saved' | 'unchanged'
export type WriteToolsSavedResponse = WriteToolsResponse & { result: WriteToolsSaveResult }

// ---- login history ---------------------------------------------------------------------

export type LoginOutcome = 'success' | 'pending' | 'refused'
export type LoginReason =
  | 'account_created'
  | 'activated'
  | 'access_disabled'
  | 'signups_paused'
  | 'pending_approval'
  | 'identity_linked'
export interface PageQuery { cursor?: string; limit?: number }
export interface PageResponse { next_cursor: string | null }

export interface LoginEvent {
  id: number
  at: string | null
  provider_id: string
  outcome: LoginOutcome
  reason: LoginReason | null
}
export interface LoginHistoryResponse extends PageResponse {
  events: LoginEvent[]
}

// ---- sign-in methods (two or more providers) ----------------------------------------------

/** One linked sign-in method. `id` is a decimal string (an unlink names it). */
export interface Identity {
  id: string
  provider_id: string
  username: string
  email: string | null
  /** True only for an address the provider verified; display only, never a key. */
  email_verified: boolean
  linked_at: string | null
  last_login_at: string | null
  /** The method this session signed in with. */
  current: boolean
  /** False for the only method the account has. */
  can_unlink: boolean
}
export interface IdentitiesResponse {
  identities: Identity[]
  /** Provider ids that can still be linked. */
  linkable: string[]
  fresh: boolean
  fresh_window_s: number
}
export interface LinkStartResponse {
  /** The provider's authorization page; navigate to it as it is (https only). */
  redirect_to: string
}
export interface UnlinkResponse {
  /** True when the method just removed was the one this session used. */
  signed_out: boolean
}

// ---- apps: consent and connected apps (SELFHOST_AUTH_MODE=local) ---------------------------

export type ClientKind = 'dcr' | 'cimd'

/**
 * Who an app is. `verified` is true only for an app that identifies itself with a
 * metadata document at a domain: then `label` and `host` are that domain. Otherwise
 * `label` is the name the app registered for itself, which anyone can choose.
 */
export interface AppClient {
  kind: ClientKind
  label: string
  name: string
  host: string | null
  verified: boolean
}

export interface ConsentScope {
  name: string
}

export interface ConsentResponse {
  client: AppClient
  /** Where the answer is sent; `loopback` means an app on the person's own computer. */
  redirect: { host: string; loopback: boolean }
  scopes: ConsentScope[]
  account: { display_name: string; username: string }
  /** False for an account that waits for approval: it can only cancel. */
  can_approve: boolean
  expires_at: string | null
}

export type ConsentDecision = 'approve' | 'deny'
export interface ConsentDecisionResponse {
  /** The app's own return address, with the code or the error. Open it as it is. */
  redirect_to: string
}

export interface Grant {
  id: string
  client: AppClient
  redirect_host: string
  created_at: string | null
  last_used_at: string | null
  expires_at: string | null
}
export interface GrantsResponse extends PageResponse {
  grants: Grant[]
}
export interface GrantRevokeResponse {
  changed: boolean
}

// ---- owner admin ------------------------------------------------------------------------

export type AdminAccountStatus = 'active' | 'pending' | 'disabled' | 'missing'
export type DisabledReason = 'admin_disabled' | 'operator_disabled' | 'approval_denied'
export type AdminAction =
  | 'approve'
  | 'deny'
  | 'disable'
  | 'enable'
  | 'mark_invalid'
  | 'remove_enrollment'

export interface AdminEnrollment {
  id: string
  is_primary: boolean
  custody_notice_version: number
  custody_ack_at: string | null
  custody_current: boolean
  canvas_user_name: string
  canvas_user_id: string
  school: SchoolRef | null
  state: 'active' | 'invalid'
  invalid_reason: InvalidReason | null
  invalid_since: string | null
  last_verified_at: string | null
  last_used_at: string | null
  created_at: string | null
  updated_at: string | null
}

/** One sign-in method of an account, as an owner sees it (present with two or more providers). */
export interface AdminIdentity {
  id: string
  provider_id: string
  username: string
  subject: string
  issuer: string
  linked_at: string | null
  last_login_at: string | null
  can_unlink: boolean
}

export interface AdminAccount {
  id: string
  key: string
  display_name: string
  username: string
  role: AccountRole
  status: AdminAccountStatus
  disabled_reason: DisabledReason | null
  disabled_at: string | null
  created_at: string | null
  approved_at: string | null
  last_login_at: string | null
  is_self: boolean
  identity: { provider_id: string; tenant_id: string; subject: string } | null
  enrollment: AdminEnrollment | null
  /** Every sign-in method; absent when Entra is the only provider. */
  identities?: AdminIdentity[]
  /** What the caller may do to this row; the UI offers exactly these. */
  actions: AdminAction[]
}

export type AdminStatusFilter = 'active' | 'pending' | 'disabled'
export interface AdminAccountsResponse extends PageResponse {
  accounts: AdminAccount[]
  counts: { total: number; active: number; pending: number; disabled: number; owners: number }
}

export type AdminEnrollmentFilter = 'all' | 'needs_reenroll'
export interface AdminEnrollmentsResponse extends PageResponse {
  rows: AdminAccount[]
  counts: { needing: number; total_enrollments: number; disabled: number; pending: number }
}

export interface AdminActionResponse {
  changed: boolean
  account: AdminAccount
}

export type AuditDetailValue = string | number | boolean | string[]
export type AuditActorKind = 'account' | 'operator' | 'system'
export interface AuditEntry {
  id: number
  at: string | null
  action: string
  actor: { kind: AuditActorKind; key: string | null; name: string | null }
  target: { key: string; name: string | null } | null
  reason: string | null
  detail: Record<string, AuditDetailValue>
}
export interface AdminAuditResponse {
  entries: AuditEntry[]
  /** Pass as `cursor` to get the next (older) page, or null at the end. */
  next_cursor: string | null
}

export interface AdminSchool {
  host: string
  display_name: string
  rank: number
  enrollments: number
  allow_private: boolean
}
export interface AdminSettingsResponse {
  revision: number
  sign_in_methods: {
    id: string; protocol: string; icon: ProviderIcon; configured: boolean
    default_name: string; display_name: string | null; effective_name: string
  }[]
  schools: { directory_search: boolean; featured: AdminSchool[]; warnings: string[] }
  retention: { auth_events_days: number; audit_days: number }
  affected_enrollments?: Record<string, number>
}
export interface FeaturedSchoolsRequest {
  revision: number
  featured: { host: string; display_name: string }[]
  confirm_affected: string[]
}
export interface SchoolCheckResponse {
  valid: boolean; reason?: ApiErrorCode; suggested_name: string | null; in_directory: boolean | null
}
