// Wire types for the same-origin JSON API under /account/api, as the Python server
// (src/canvas_mcp/core/selfhost/account_api.py) answers it. Every response is
// no-store and every failure is { error: { code, params? } } with a code from the
// closed ApiErrorCode set; the UI never shows server, IdP or Canvas free text.
//
// Timestamps are ISO-8601 UTC strings or null. An account id is the bare lower-case
// UUID (safe in a path); `key` is the same id with the "acct:" prefix.

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
  | 'last_owner' // 409
  | 'cannot_disable_self' // 409

/** Codes that only ever arrive as ?error= on /account/sign-in, never as JSON. */
export type SignInErrorCode =
  | 'state_invalid'
  | 'provider_error'
  | 'sign_in_incomplete'
  | 'sign_in_unverified'
  | 'wrong_tenant'
  | 'wrong_client'
  | 'bad_subject'
  | 'bad_roles'
  | 'access_denied'
  | 'access_disabled'
  | 'signups_paused'
  | 'token_store_unavailable'

export type ApiErrorCode = ApiOnlyErrorCode | SignInErrorCode

export type ErrorParams = Record<string, string | number>

export interface ApiErrorBody {
  error: { code: ApiErrorCode; params?: ErrorParams }
}

// ---- providers ---------------------------------------------------------------

export type ProviderIcon = 'microsoft'
export interface Provider {
  id: string
  kind: 'oidc'
  name: string
  icon: ProviderIcon
  /** The server-side redirect that starts the sign-in (a full-page navigation). */
  start_url: string
}
export interface ProvidersResponse {
  providers: Provider[]
  mcp_url: string
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

export type SchoolMode = 'picker' | 'sole' | 'fixed'
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
  // Not built yet (identities, connected apps, consent, ...): always false today.
  identities: boolean
  connected_apps: boolean
  consent: boolean
  logout_everywhere: boolean
  role_management: boolean
}

export interface MeResponse {
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
export interface LoginEvent {
  at: string | null
  provider_id: string
  outcome: LoginOutcome
  reason: LoginReason | null
}
export interface LoginHistoryResponse {
  events: LoginEvent[]
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
  canvas_user_name: string
  canvas_user_id: string
  school: (SchoolRef & { is_default: boolean }) | null
  state: 'active' | 'invalid'
  invalid_reason: InvalidReason | null
  invalid_since: string | null
  last_verified_at: string | null
  last_used_at: string | null
  created_at: string | null
  updated_at: string | null
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
  /** What the caller may do to this row; the UI offers exactly these. */
  actions: AdminAction[]
}

export type AdminStatusFilter = 'active' | 'pending' | 'disabled'
export interface AdminAccountsResponse {
  accounts: AdminAccount[]
  counts: { total: number; active: number; pending: number; disabled: number; owners: number }
}

export type AdminEnrollmentFilter = 'all' | 'needs_reenroll'
export interface AdminEnrollmentsResponse {
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
  /** Pass as `before` to get the next (older) page, or null at the end. */
  next_cursor: string | null
}
