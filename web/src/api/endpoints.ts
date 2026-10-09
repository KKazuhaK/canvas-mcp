import { http, setCsrfToken } from './client'
import {
  splitRoute,
  type BodyOf,
  type QueryOf,
  type ResponseOf,
  type RouteKey,
} from './contract'
import type {
  AdminAction,
  AdminEnrollmentFilter,
  AdminStatusFilter,
  CanvasTokenRequest,
  UiLocale,
} from './types'

// One typed function per route. The method, path, query, body and response of each
// come from the Contract table (contract.ts), so a call cannot name a route the
// server does not have.

const enc = encodeURIComponent

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

export const getProviders = () => call('GET /providers')

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

export const getSchools = () => call('GET /me/schools')

export const searchSchools = (q: string) => call('GET /me/schools/search', { query: { q } })

export const getWriteTools = () => call('GET /me/write-tools')

export const putWriteTools = (enabled: string[]) =>
  call('PUT /me/write-tools', { body: { enabled } })

/** "Turn all off": needs no fresh sign-in. */
export const deleteWriteTools = () => call('DELETE /me/write-tools')

export const getLoginHistory = () => call('GET /me/login-history')

export async function putUiLocale(locale: UiLocale): Promise<void> {
  await call('PUT /me/ui-locale', { body: { locale } })
}

export async function logout(): Promise<void> {
  await call('POST /session/logout')
}

// ---- owner ------------------------------------------------------------------------

export const adminListAccounts = (status?: AdminStatusFilter) =>
  call('GET /admin/accounts', { query: status ? { status } : {} })

export const adminListEnrollments = (filter: AdminEnrollmentFilter = 'all') =>
  call('GET /admin/enrollments', { query: { filter } })

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

export const adminAudit = (before?: string | null) =>
  call('GET /admin/audit', { query: before ? { before } : {} })

// ---- sign-in ------------------------------------------------------------------------

/** The server-side OIDC start (a full-page navigation, never an XHR). */
export const LOGIN_PATH = '/account/login'

/**
 * Where the SPA sends a person to sign in: the server-side OIDC redirect
 * (`start_url` from GET /providers, /account/login). It is a full-page
 * navigation, never an XHR. `returnTo` must already be validated (utils/returnTo);
 * the server validates it again.
 */
export function signInUrl(startUrl: string, returnTo?: string | null): string {
  if (!returnTo) return startUrl
  return `${startUrl}?${new URLSearchParams({ return_to: returnTo }).toString()}`
}
