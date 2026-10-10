import axios, { type InternalAxiosRequestConfig } from 'axios'
import { toApiError } from './errors'

/**
 * The only HTTP client in the app. Same-origin, cookie session, JSON.
 *
 * - No Authorization header, no token refresh, nothing in localStorage: the
 *   session lives in an HttpOnly cookie the page cannot read.
 * - Mutating verbs (and the school search GET) carry X-CSRF-Token, taken from the
 *   in-memory result of GET /me. The value is never persisted anywhere.
 * - Every failure is rethrown as an ApiError, which holds only status, a closed
 *   code and numeric/short params. The axios error (and its `config.data`, which
 *   may carry a Canvas token) is dropped.
 */
export const API_BASE_URL = '/account/api'

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

/**
 * GET routes that still need the CSRF header: the school search makes outbound
 * calls and spends the per-account search budget, so the server treats it like a
 * mutation.
 */
const CSRF_GET_PATHS = new Set(['/me/schools/search'])

let csrfToken: string | null = null

export function setCsrfToken(token: string | null): void {
  csrfToken = token
}

export function clearCsrfToken(): void {
  csrfToken = null
}

export function hasCsrfToken(): boolean {
  return csrfToken !== null
}

export interface ClientHandlers {
  /** A request other than the /me probe answered 401 not_authenticated. */
  onUnauthorized?: () => void
  /** A mutation answered 403 csrf_invalid: refetch /me once so the token is fresh. */
  onCsrfInvalid?: () => void
}

let handlers: ClientHandlers = {}

export function configureClient(next: ClientHandlers): void {
  handlers = next
}

export const http = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
  timeout: 30_000,
  headers: { Accept: 'application/json' },
})

http.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const method = (config.method ?? 'get').toUpperCase()
  const needsCsrf =
    MUTATING_METHODS.has(method) || (method === 'GET' && CSRF_GET_PATHS.has(config.url ?? ''))
  if (needsCsrf && csrfToken !== null) {
    config.headers.set('X-CSRF-Token', csrfToken)
  }
  return config
})

/**
 * Requests whose 401 is an answer, not a session loss: the signed-out probe, and the
 * consent screen, which sends a signed-out person to the sign-in of the app's request
 * itself (a plain navigation that keeps the request id) instead of the generic sign-in page.
 */
function isMeProbe(url: string | undefined): boolean {
  return url === '/me' || url === '/providers' || url === '/consent'
}

http.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    const apiError = toApiError(error)
    const url = axios.isAxiosError(error) ? error.config?.url : undefined
    if (apiError.status === 401 && apiError.code === 'not_authenticated' && !isMeProbe(url)) {
      clearCsrfToken()
      handlers.onUnauthorized?.()
    } else if (apiError.code === 'csrf_invalid') {
      handlers.onCsrfInvalid?.()
    }
    return Promise.reject(apiError)
  },
)
