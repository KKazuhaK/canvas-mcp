import { AxiosError } from 'axios'
import type { ApiErrorCode, ErrorParams } from './types'

// Exhaustive by construction: adding a code to ApiErrorCode without listing it
// here fails the typecheck, and errors.test.ts then checks both locales. The Python
// test tests/selfhost/test_account_api_contract.py compares this table with the
// server's own code lists.
const CODE_SET: Record<ApiErrorCode, true> = {
  not_authenticated: true,
  csrf_invalid: true,
  origin_not_allowed: true,
  reauth_required: true,
  forbidden: true,
  pending_approval: true,
  access_disabled: true,
  method_not_allowed: true,
  unsupported_media_type: true,
  payload_too_large: true,
  malformed_request: true,
  validation_failed: true,
  not_found: true,
  rate_limited: true,
  token_store_unavailable: true,
  internal_error: true,
  token_invalid_format: true,
  token_rejected: true,
  token_unreadable: true,
  canvas_unavailable: true,
  identity_change_required: true,
  recheck_not_allowed: true,
  school_required: true,
  school_invalid: true,
  school_not_offered: true,
  school_not_in_directory: true,
  school_unresolvable: true,
  school_address_blocked: true,
  school_selection_unverified: true,
  directory_unavailable: true,
  write_tool_not_allowed: true,
  write_tools_unavailable: true,
  last_owner: true,
  cannot_disable_self: true,
  state_invalid: true,
  provider_error: true,
  sign_in_incomplete: true,
  sign_in_unverified: true,
  wrong_tenant: true,
  wrong_client: true,
  bad_subject: true,
  bad_roles: true,
  access_denied: true,
  signups_paused: true,
  authorization_invalid: true,
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

/** The session is too old for this action (the 10-minute fresh-sign-in rule). */
export function isReauthRequired(error: unknown): boolean {
  return error instanceof ApiError && error.code === 'reauth_required'
}
