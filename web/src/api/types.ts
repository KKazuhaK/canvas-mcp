// Wire types for the same-origin JSON API under /account/api. Every response is
// no-store and every failure is { error: { code, params? } } with a code from the
// closed ApiErrorCode set; the UI never shows server or IdP free text.

export type ApiErrorCode =
  // Login / identity set
  | 'access_denied'
  | 'not_provisioned'
  | 'pending_approval'
  | 'identity_in_use'
  | 'provider_error'
  | 'signups_paused'
  | 'state_invalid'
  // Generic API set
  | 'not_authenticated' // 401, no/expired session
  | 'forbidden' // 403, e.g. not owner / account disabled
  | 'csrf_invalid' // 403
  | 'origin_not_allowed' // 403
  | 'not_found' // 404
  | 'validation_failed' // 422, params: { field }
  | 'rate_limited' // 429, params: { retry_after_s }
  | 'token_invalid_format' // 422, token fails the shape check
  | 'token_rejected' // 422, Canvas answered 401 to the token
  | 'canvas_unavailable' // 502/503, could not reach Canvas to verify
  | 'token_store_unavailable' // 503
  | 'last_identity' // 409, cannot unlink the only identity
  | 'link_requires_recent_login' // 403, session older than 10 minutes
  | 'consent_expired' // 410
  | 'grant_revoked' // 409/410
  | 'write_tool_not_allowed' // 403
  | 'internal_error' // 500

export type ErrorParams = Record<string, string | number>

export interface ApiErrorBody {
  error: { code: ApiErrorCode; params?: ErrorParams }
}

export type ProviderKind = 'oidc' | 'github_oauth2'
export type ProviderIcon = 'microsoft' | 'google' | 'github' | 'key'
export interface Provider {
  id: string
  kind: ProviderKind
  name: string
  icon: ProviderIcon
}
export type LoginMode = 'open' | 'invite_only' | 'closed'
export interface ProvidersResponse {
  providers: Provider[]
  login_mode: LoginMode
  signups_paused: boolean
  mcp_url: string
}

export type AccountStatus = 'active' | 'pending' | 'disabled'
export type AccountRole = 'owner' | 'user'
export interface Account {
  id: string
  display_name: string
  email: string | null
  role: AccountRole
  status: AccountStatus
  created_at: string
}

export type CanvasTokenState = 'none' | 'valid' | 'invalid' | 'unknown'
export interface CanvasTokenStatus {
  state: CanvasTokenState
  canvas_user_id: number | null
  canvas_user_name: string | null
  enrolled_at: string | null
  updated_at: string | null
  last_used_at: string | null
  last_checked_at: string | null
  invalid_since: string | null
}

export interface MeResponse {
  account: Account
  csrf_token: string
  session_issued_at: string
  canvas: CanvasTokenStatus
  write_tools_enabled_count: number
}

export type WriteToolGroup = 'planner_calendar' | 'submissions' | 'modules' | 'messages'
export type RiskLevel = 'low' | 'medium' | 'high'
export interface WriteTool {
  name: string
  group: WriteToolGroup
  risk: RiskLevel
  server_allowed: boolean
  enabled: boolean
}
export interface WriteToolsResponse {
  server_enabled: boolean
  tools: WriteTool[]
}

export interface Identity {
  id: string
  provider_id: string
  provider_name: string
  display: string
  email: string | null
  email_verified: boolean
  linked_at: string
  last_login_at: string | null
  is_current_session: boolean
}
export interface IdentitiesResponse {
  identities: Identity[]
  linkable_providers: Provider[]
}

export interface Grant {
  id: string
  client_name: string
  client_id: string
  created_at: string
  last_used_at: string | null
  revoked_at: string | null
}
export interface GrantsResponse {
  grants: Grant[]
}

export type LoginOutcome = 'success' | 'denied' | 'error'
export interface LoginEvent {
  at: string
  provider_id: string
  outcome: LoginOutcome
  reason: ApiErrorCode | null
  ip: string | null
  user_agent: string | null
}
export interface LoginHistoryResponse {
  events: LoginEvent[]
}

export interface ConsentInfo {
  txn: string
  client_name: string
  client_uri: string | null
  redirect_host: string
  scopes: string[]
  account_display_name: string
  expires_at: string
}
export type ConsentDecision = 'allow' | 'deny'
export interface ConsentResult {
  redirect_url: string
}

export type EnrollmentTokenState = CanvasTokenState

export interface AdminAccount {
  id: string
  display_name: string
  email: string | null
  role: AccountRole
  status: AccountStatus
  providers: string[]
  created_at: string
  last_login_at: string | null
  canvas_state: CanvasTokenState
  grants_count: number
}
export interface AdminAccountsResponse {
  accounts: AdminAccount[]
  next_cursor: string | null
}
export type AdminAccountActionName =
  | 'approve'
  | 'disable'
  | 'enable'
  | 'set_role'
  | 'unlink_identity'
  | 'revoke_grants'
export interface AdminAccountActionBody {
  action: AdminAccountActionName
  role?: AccountRole
  identity_id?: string
}
export interface AdminEnrollment {
  account_id: string
  display_name: string
  canvas_user_name: string | null
  canvas_user_id: number | null
  state: EnrollmentTokenState
  enrolled_at: string
  updated_at: string
  last_used_at: string | null
  invalid_since: string | null
}
export interface AdminEnrollmentsResponse {
  enrollments: AdminEnrollment[]
}

export type AuditAction =
  | 'approve'
  | 'disable'
  | 'enable'
  | 'set_role'
  | 'link'
  | 'unlink'
  | 'write_tool_toggle'
  | 'token_enroll'
  | 'token_delete'
  | 'grant_revoke'
  | 'enrollment_revoke'
  | 'login'
export interface AuditEntry {
  id: string
  at: string
  actor_account_id: string | null
  actor_name: string | null
  action: AuditAction
  target_account_id: string | null
  target_name: string | null
  detail: Record<string, string | number | boolean> | null
}
export interface AdminAuditResponse {
  entries: AuditEntry[]
  next_cursor: string | null
}
