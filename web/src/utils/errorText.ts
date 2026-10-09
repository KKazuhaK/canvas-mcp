import type { TFunction } from 'i18next'
import { ApiError, displayCode, type DisplayErrorCode } from '@/api/errors'

/** Code to show for any thrown value: ApiError code, or the generic one. */
export function codeOf(error: unknown): DisplayErrorCode {
  return error instanceof ApiError ? error.code : 'internal_error'
}

/**
 * The ONLY source of user-facing error text: the closed code -> i18n map. Server
 * messages, IdP text and query-string values never reach the screen.
 */
export function errorText(t: TFunction, error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === 'rate_limited' && typeof error.params.retry_after_s === 'number') {
      return t('errors:rate_limited_wait', { retry_after_s: error.params.retry_after_s })
    }
    return t(`errors:${error.code}`)
  }
  return t('errors:internal_error')
}

/** Text for a bare code, e.g. the ?error= value from the login redirect. */
export function codeText(t: TFunction, raw: unknown): string {
  return t(`errors:${displayCode(raw)}`)
}
