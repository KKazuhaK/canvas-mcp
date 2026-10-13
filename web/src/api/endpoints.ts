import { http, setCsrfToken } from './client'
import {
  splitRoute,
  type BodyOf,
  type QueryOf,
  type ResponseOf,
  type RouteKey,
} from './contract'
import type {
  LoginProviderSave,
  SetupRequest,
  AdminAction,
  PageQuery,
  FeaturedSchoolsRequest,
  AdminEnrollmentFilter,
  AdminStatusFilter,
  CanvasTokenRequest,
  ConsentDecision,
  UiLocale,
} from './types'

// One typed function per route. The method, path, query, body and response of each
// come from the Contract table (contract.ts), so a call cannot name a route the
// server does not have.

const enc = encodeURIComponent

export const getLoginPolicy = () => call('GET /admin/settings/login-policy')
export const saveLoginPolicy = (body: BodyOf<'PUT /admin/settings/login-policy'>) => call('PUT /admin/settings/login-policy', { body })
export const getAccountLoginPolicy = (id: string) => call('GET /admin/accounts/{id}/login-policy', { id })
export const saveAccountLoginPolicy = (id: string, body: BodyOf<'PUT /admin/accounts/{id}/login-policy'>) => call('PUT /admin/accounts/{id}/login-policy', { id, body })
export const unlockAccountSso = (id: string, revision: number) => call('POST /admin/accounts/{id}/unlock-sso', { id, body: { revision } })

interface CallOptions<K extends RouteKey> {
  /** Replaces `{id}` in the path (percent-encoded). */
  id?: string
  query?: QueryOf<K>
  body?: BodyOf<K>
}

async function call<K extends RouteKey>(key: K, options: CallOptions<K> = {}): Promise<ResponseOf<K>> {
  const { method, path } = splitRoute(key)
  const url = options.id === undefined ? path : path.replace('{id}', enc(options.id))
  const response = await http.request<ResponseOf<K>>({
    method,
    url,
    params: options.query,
    data: options.body,
  })
  return response.data
}

// ---- public ---------------------------------------------------------------------

export const loginLocal = (body: BodyOf<'POST /login/local'>) => call('POST /login/local', { body })
export const saveAccountUpn = (id: string, upn: string, revision: number) => call('PUT /admin/accounts/{id}/upn', { id, body: { upn, revision } })
export const addLocalPassword = (password: string) => call('POST /me/local-password', { body: { password } })
export const changeLocalPassword = (body: BodyOf<'PUT /me/password'>) => call('PUT /me/password', { body })
export const createLocalAccount = (body: BodyOf<'POST /admin/local-accounts'>) => call('POST /admin/local-accounts', { body })
export const getProviders = () => call('GET /providers')
export const getSetupStatus = () => call('GET /setup')
export const initializeLogin = (body: SetupRequest) => call('POST /setup', { body })
export const getLoginProviderSettings = () => call('GET /admin/login-providers')
export const saveLoginProvider = (id: string, body: LoginProviderSave) => call('PUT /admin/login-providers/{id}', { id, body })

// ---- self -----------------------------------------------------------------------

export async function getMe() {
  const data = await call('GET /me')
  // Kept in memory only; the request interceptor reads it for mutating verbs.
  setCsrfToken(data.csrf_token)
  return data
}

export const getCanvasToken = () => call('GET /me/canvas-token')

/** The token is write-only: it goes out in this one request body and nowhere else. */
export const putCanvasToken = (body: CanvasTokenRequest) => call('PUT /me/canvas-token', { body })

export async function deleteCanvasToken(): Promise<void> {
  await call('DELETE /me/canvas-token')
}

export const recheckCanvasToken = () => call('POST /me/canvas-token/recheck')
export const acknowledgeCanvasToken = (notice_version: number) => call('POST /me/canvas-token/acknowledge', { body: { notice_version } })

export const getSchools = () => call('GET /me/schools')

export const searchSchools = (q: string) => call('GET /me/schools/search', { query: { q } })

export const getWriteTools = () => call('GET /me/write-tools')

export const putWriteTools = (enabled: string[]) =>
  call('PUT /me/write-tools', { body: { enabled } })

/** "Turn all off": needs no fresh sign-in. */
export const deleteWriteTools = () => call('DELETE /me/write-tools')

export const getLoginHistory = (query: PageQuery = {}) => call('GET /me/login-history', { query })

// ---- sign-in methods (two or more providers) ------------------------------------------

export const getIdentities = () => call('GET /me/identities')

/** Starts a link: the answer is the provider's page (https), to be navigated to as it is. */
export const startLink = (provider: string) =>
  call('POST /me/identities/link', { body: { provider } })

export const unlinkIdentity = (id: string) => call('DELETE /me/identities/{id}', { id })

export const adminUnlinkIdentity = (id: string) => call('DELETE /admin/identities/{id}', { id })

export async function putUiLocale(locale: UiLocale): Promise<void> {
  await call('PUT /me/ui-locale', { body: { locale } })
}

export async function logout(): Promise<void> {
  await call('POST /session/logout')
}

// ---- owner ------------------------------------------------------------------------

export const adminListAccounts = (status?: AdminStatusFilter, query: PageQuery = {}) =>
  call('GET /admin/accounts', { query: { ...query, ...(status ? { status } : {}) } })

export const adminListEnrollments = (filter: AdminEnrollmentFilter = 'all', query: PageQuery = {}) =>
  call('GET /admin/enrollments', { query: { ...query, filter } })

/** The row actions that go through POST /admin/accounts/{id}/<action>. */
export type AdminAccessAction = Extract<AdminAction, 'approve' | 'deny' | 'disable' | 'enable'>

export function adminAccessAction(id: string, action: AdminAccessAction) {
  switch (action) {
    case 'approve':
      return call('POST /admin/accounts/{id}/approve', { id })
    case 'deny':
      return call('POST /admin/accounts/{id}/deny', { id })
    case 'disable':
      return call('POST /admin/accounts/{id}/disable', { id })
    case 'enable':
      return call('POST /admin/accounts/{id}/enable', { id })
  }
}

export const adminMarkInvalid = (id: string) =>
  call('POST /admin/enrollments/{id}/mark-invalid', { id })

export const adminRemoveEnrollment = (id: string) => call('DELETE /admin/enrollments/{id}', { id })

export const adminAudit = (cursor?: string | null) =>
  call('GET /admin/audit', { query: cursor ? { cursor } : {} })

// ---- apps (the server's own authorization server) --------------------------------

/** What an app asks for, to show before the person decides. `txn` is the request id from the URL. */
export const getConsent = (txn: string) => call('GET /consent', { query: { txn } })

/** The one decision on a request; the answer says where to send the browser next. */
export const decideConsent = (txn: string, decision: ConsentDecision) =>
  call('POST /consent', { body: { txn, decision } })

export const getGrants = (query: PageQuery = {}) => call('GET /me/grants', { query })

export async function revokeGrant(id: string): Promise<void> {
  await call('DELETE /me/grants/{id}', { id })
}

export const adminGrants = (accountId: string, query: PageQuery = {}) =>
  call('GET /admin/accounts/{id}/grants', { id: accountId, query })

export const adminRevokeGrant = (id: string) => call('DELETE /admin/grants/{id}', { id })

// ---- sign-in ------------------------------------------------------------------------

/** The server-side OIDC start (a full-page navigation, never an XHR). */
export const LOGIN_PATH = '/auth/login'

export interface SignInUrlOptions {
  /** A validated same-site return address (utils/returnTo). */
  returnTo?: string | null
  /** A waiting app's request id (utils/appRedirect TXN_PATTERN); the server checks it again. */
  txn?: string | null
  /** "Use a different account": force the provider to ask again. */
  reauth?: boolean
}

/**
 * Where the SPA sends a person to sign in: the server-side redirect (`start_url` from
 * GET /providers). It is a full-page navigation, never an XHR. A bare string is a
 * `returnTo`, which must already be validated (utils/returnTo); the server validates it
 * again, and a request id only counts for a request started in this browser.
 */
export function signInUrl(
  startUrl: string,
  options?: SignInUrlOptions | string | null,
): string {
  const opts: SignInUrlOptions =
    typeof options === 'string' ? { returnTo: options } : (options ?? {})
  const query = new URLSearchParams()
  if (opts.txn) query.set('txn', opts.txn)
  if (opts.reauth) query.set('reauth', '1')
  if (opts.returnTo) query.set('return_to', opts.returnTo)
  const text = query.toString()
  return text ? `${startUrl}?${text}` : startUrl
}

export const getAdminSettings = () => call('GET /admin/settings')
export const saveSiteAddress = (revision: number, public_base_url: string) => call('PUT /admin/settings/site', { body: { revision, public_base_url, confirm: true } })
export const saveProviderNames = (revision: number, names: Record<string, string | null>) => call('PUT /admin/settings/sign-in-methods', { body: { revision, names } })
export const saveFeaturedSchools = (body: FeaturedSchoolsRequest) => call('PUT /admin/settings/schools', { body })
export const checkSchool = (host: string) => call('POST /admin/settings/schools/check', { body: { host } })
export const saveBrowserSession = (revision: number, ttl_seconds: number) => call('PUT /admin/settings/browser-session', { body: { revision, ttl_seconds } })
export const saveDirectorySearch = (revision: number, enabled: boolean) => call('PUT /admin/settings/directory-search', { body: { revision, enabled } })

export const getNotificationPreferences = () => call('GET /notifications')
export const saveNotificationPreferences = (body: BodyOf<'PUT /notifications'>) => call('PUT /notifications', { body })
export const getMailSettings = () => call('GET /admin/settings/mail')
export const saveMailSettings = (body: BodyOf<'PUT /admin/settings/mail'>) => call('PUT /admin/settings/mail', { body })

export const testMailSettings = () => call('POST /admin/settings/mail/test')
