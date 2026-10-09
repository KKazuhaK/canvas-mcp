import { API_BASE_URL, http, setCsrfToken } from './client'
import type {
  AdminAccountActionBody,
  AdminAccount,
  AdminAccountsResponse,
  AdminAuditResponse,
  AdminEnrollmentsResponse,
  AccountStatus,
  AuditAction,
  CanvasTokenStatus,
  ConsentDecision,
  ConsentInfo,
  ConsentResult,
  GrantsResponse,
  IdentitiesResponse,
  LoginHistoryResponse,
  MeResponse,
  ProvidersResponse,
  WriteToolsResponse,
} from './types'

// One typed function per route. Paths are relative to API_BASE_URL.

const enc = encodeURIComponent

export async function getProviders(): Promise<ProvidersResponse> {
  return (await http.get<ProvidersResponse>('/providers')).data
}

export async function getMe(): Promise<MeResponse> {
  const { data } = await http.get<MeResponse>('/me')
  // Kept in memory only; the request interceptor reads it for mutating verbs.
  setCsrfToken(data.csrf_token)
  return data
}

export async function getCanvasToken(): Promise<CanvasTokenStatus> {
  return (await http.get<CanvasTokenStatus>('/me/canvas-token')).data
}

/** The token is write-only: it goes out in this one request body and nowhere else. */
export async function putCanvasToken(canvasToken: string): Promise<CanvasTokenStatus> {
  return (await http.put<CanvasTokenStatus>('/me/canvas-token', { canvas_token: canvasToken })).data
}

export async function deleteCanvasToken(): Promise<void> {
  await http.delete('/me/canvas-token')
}

export async function verifyCanvasToken(): Promise<CanvasTokenStatus> {
  return (await http.post<CanvasTokenStatus>('/me/canvas-token/verify')).data
}

export async function getWriteTools(): Promise<WriteToolsResponse> {
  return (await http.get<WriteToolsResponse>('/me/write-tools')).data
}

export async function putWriteTools(enabled: string[]): Promise<WriteToolsResponse> {
  return (await http.put<WriteToolsResponse>('/me/write-tools', { enabled })).data
}

export async function getIdentities(): Promise<IdentitiesResponse> {
  return (await http.get<IdentitiesResponse>('/me/identities')).data
}

/** Ask the server for the IdP hand-off URL; the caller navigates to it. */
export async function startLinkUrl(providerId: string): Promise<{ redirect_url: string }> {
  return (await http.post<{ redirect_url: string }>(`/me/identities/link/${enc(providerId)}`)).data
}

export async function deleteIdentity(id: string): Promise<void> {
  await http.delete(`/me/identities/${enc(id)}`)
}

export async function getGrants(): Promise<GrantsResponse> {
  return (await http.get<GrantsResponse>('/me/grants')).data
}

export async function deleteGrant(id: string): Promise<void> {
  await http.delete(`/me/grants/${enc(id)}`)
}

export async function getLoginHistory(): Promise<LoginHistoryResponse> {
  return (await http.get<LoginHistoryResponse>('/me/login-history')).data
}

export async function logout(all = false): Promise<void> {
  await http.post('/session/logout', undefined, all ? { params: { all: 1 } } : undefined)
}

export async function getConsent(txn: string): Promise<ConsentInfo> {
  return (await http.get<ConsentInfo>(`/consent/${enc(txn)}`)).data
}

export async function postConsent(txn: string, decision: ConsentDecision): Promise<ConsentResult> {
  return (await http.post<ConsentResult>(`/consent/${enc(txn)}`, { decision })).data
}

export interface AdminAccountFilters {
  status: AccountStatus | ''
  q: string
}

export async function adminListAccounts(
  filters: AdminAccountFilters,
  cursor?: string | null,
): Promise<AdminAccountsResponse> {
  const params: Record<string, string> = {}
  if (filters.status) params.status = filters.status
  if (filters.q) params.q = filters.q
  if (cursor) params.cursor = cursor
  return (await http.get<AdminAccountsResponse>('/admin/accounts', { params })).data
}

export async function adminAccountAction(
  id: string,
  body: AdminAccountActionBody,
): Promise<AdminAccount> {
  return (await http.post<AdminAccount>(`/admin/accounts/${enc(id)}/action`, body)).data
}

export async function adminListEnrollments(): Promise<AdminEnrollmentsResponse> {
  return (await http.get<AdminEnrollmentsResponse>('/admin/enrollments')).data
}

export async function adminRevokeEnrollment(accountId: string): Promise<void> {
  await http.delete(`/admin/enrollments/${enc(accountId)}`)
}

export interface AdminAuditFilters {
  action: AuditAction | ''
  actor: string
}

export async function adminAudit(
  filters: AdminAuditFilters,
  cursor?: string | null,
): Promise<AdminAuditResponse> {
  const params: Record<string, string> = {}
  if (filters.action) params.action = filters.action
  if (filters.actor) params.actor = filters.actor
  if (cursor) params.cursor = cursor
  return (await http.get<AdminAuditResponse>('/admin/audit', { params })).data
}

/**
 * URL of the full-page navigation that starts a sign-in. The SPA never calls the
 * callback route. `txn` and `returnTo` must already be validated (utils/returnTo).
 */
export function loginStartUrl(
  providerId: string,
  opts: { txn?: string | null; returnTo?: string | null } = {},
): string {
  const query = new URLSearchParams()
  if (opts.txn) query.set('txn', opts.txn)
  if (opts.returnTo) query.set('return_to', opts.returnTo)
  const qs = query.toString()
  return `${API_BASE_URL}/login/${enc(providerId)}/start${qs ? `?${qs}` : ''}`
}

