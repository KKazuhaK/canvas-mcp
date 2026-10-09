import { AxiosError } from 'axios'
import type { ApiErrorCode, ErrorParams } from './types'

// Exhaustive by construction: adding a code to ApiErrorCode without listing it
// here fails the typecheck, and errors.test.ts then checks both locales.
const CODE_SET: Record<ApiErrorCode, true> = {
  access_denied: true,
  not_provisioned: true,
  pending_approval: true,
  identity_in_use: true,
  provider_error: true,
  signups_paused: true,
  state_invalid: true,
  not_authenticated: true,
  forbidden: true,
  csrf_invalid: true,
  origin_not_allowed: true,
  not_found: true,
  validation_failed: true,
  rate_limited: true,
  token_invalid_format: true,
  token_rejected: true,
  canvas_unavailable: true,
  token_store_unavailable: true,
  last_identity: true,
  link_requires_recent_login: true,
  consent_expired: true,
  grant_revoked: true,
  write_tool_not_allowed: true,
  internal_error: true,
}

export const API_ERROR_CODES = Object.keys(CODE_SET) as ApiErrorCode[]

/** Codes that never come from the server: the request produced no answer. */
export type ClientErrorCode = 'network_error' | 'timeout'
export const CLIENT_ERROR_CODES: ClientErrorCode[] = ['network_error', 'timeout']

/** Everything the errors namespace must be able to render. */
export type DisplayErrorCode = ApiErrorCode | ClientErrorCode

export function isApiErrorCode(value: unknown): value is ApiErrorCode {
  return typeof value === 'string' && Object.hasOwn(CODE_SET, value)
}

/** Map any value (e.g. a ?error= query string) to a code we can render. */
export function displayCode(value: unknown): DisplayErrorCode {
  return isApiErrorCode(value) ? value : 'internal_error'
}

export class ApiError extends Error {
  readonly status: number
  readonly code: DisplayErrorCode
  readonly params: ErrorParams

  constructor(status: number, code: DisplayErrorCode, params: ErrorParams = {}) {
    // The message is the code only: never server text, never request data.
    super(code)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.params = params
  }

  get isNetwork(): boolean {
    return this.code === 'network_error' || this.code === 'timeout'
  }
}

function cleanParams(value: unknown): ErrorParams {
  if (typeof value !== 'object' || value === null) return {}
  const out: ErrorParams = {}
  for (const [k, v] of Object.entries(value)) {
    if (typeof v === 'string' || typeof v === 'number') out[k] = v
  }
  return out
}

/**
 * Normalise anything thrown by the HTTP layer into an ApiError. The result holds
 * no reference to the axios request, so `config.data` (which can carry a Canvas
 * token) is not retained anywhere.
 */
export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error
  if (error instanceof AxiosError) {
    const response = error.response
    if (!response) {
      return new ApiError(0, error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT' ? 'timeout' : 'network_error')
    }
    const body: unknown = response.data
    if (typeof body === 'object' && body !== null && 'error' in body) {
      const inner = (body as { error: unknown }).error
      if (typeof inner === 'object' && inner !== null) {
        const { code, params } = inner as { code?: unknown; params?: unknown }
        if (isApiErrorCode(code)) return new ApiError(response.status, code, cleanParams(params))
      }
    }
    return new ApiError(response.status, 'internal_error')
  }
  return new ApiError(0, 'internal_error')
}

export function isUnauthenticated(error: unknown): boolean {
  return error instanceof ApiError && error.status === 401 && error.code === 'not_authenticated'
}
