import { beforeAll, describe, expect, it } from 'vitest'
import i18next from 'i18next'
import { API_ERROR_CODES, CLIENT_ERROR_CODES, ApiError, displayCode, isApiErrorCode } from './errors'
import { initI18n } from '@/i18n'
import { resources } from '@/i18n/options'
import { codeText, errorText } from '@/utils/errorText'

describe('closed error code set', () => {
  it('has the 24 server codes from the contract', () => {
    expect([...API_ERROR_CODES].sort()).toEqual(
      [
        'access_denied',
        'canvas_unavailable',
        'consent_expired',
        'csrf_invalid',
        'forbidden',
        'grant_revoked',
        'identity_in_use',
        'internal_error',
        'last_identity',
        'link_requires_recent_login',
        'not_authenticated',
        'not_found',
        'not_provisioned',
        'origin_not_allowed',
        'pending_approval',
        'provider_error',
        'rate_limited',
        'signups_paused',
        'state_invalid',
        'token_invalid_format',
        'token_rejected',
        'token_store_unavailable',
        'validation_failed',
        'write_tool_not_allowed',
      ].sort(),
    )
  })

  it('accepts only members of the set', () => {
    expect(isApiErrorCode('token_rejected')).toBe(true)
    expect(isApiErrorCode('nope')).toBe(false)
    expect(isApiErrorCode('toString')).toBe(false)
    expect(isApiErrorCode('__proto__')).toBe(false)
    expect(isApiErrorCode(undefined)).toBe(false)
    expect(isApiErrorCode(42)).toBe(false)
  })

  it('maps anything else to internal_error for display', () => {
    expect(displayCode('access_denied')).toBe('access_denied')
    expect(displayCode('<script>alert(1)</script>')).toBe('internal_error')
    expect(displayCode(null)).toBe('internal_error')
  })

  describe.each(['en', 'zh'] as const)('locale %s', (lang) => {
    it('has a non-empty string for every server code and client code', () => {
      const errors = resources[lang].errors as Record<string, unknown>
      for (const code of [...API_ERROR_CODES, ...CLIENT_ERROR_CODES]) {
        expect(typeof errors[code], `${lang}: ${code}`).toBe('string')
        expect((errors[code] as string).trim().length, `${lang}: ${code}`).toBeGreaterThan(0)
      }
    })
  })
})

describe('error text', () => {
  beforeAll(async () => {
    await initI18n('en')
    await i18next.changeLanguage('en')
  })

  it('comes only from the code map', () => {
    const t = i18next.t.bind(i18next)
    const error = new ApiError(422, 'token_rejected')
    expect(errorText(t, error)).toBe(resources.en.errors.token_rejected)
    expect(errorText(t, new Error('server said: leak'))).toBe(resources.en.errors.internal_error)
    expect(errorText(t, 'string')).toBe(resources.en.errors.internal_error)
  })

  it('shows the retry-after seconds for rate_limited when the server gave them', () => {
    const t = i18next.t.bind(i18next)
    expect(errorText(t, new ApiError(429, 'rate_limited', { retry_after_s: 12 }))).toContain('12')
    expect(errorText(t, new ApiError(429, 'rate_limited'))).toBe(resources.en.errors.rate_limited)
  })

  it('never prints a raw query value', () => {
    const t = i18next.t.bind(i18next)
    const text = codeText(t, '<img src=x onerror=alert(1)>')
    expect(text).toBe(resources.en.errors.internal_error)
    expect(text).not.toContain('<img')
  })
})
