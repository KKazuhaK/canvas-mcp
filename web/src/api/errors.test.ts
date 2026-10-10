import { beforeAll, describe, expect, it } from 'vitest'
import i18next from 'i18next'
import { API_ERROR_CODES, CLIENT_ERROR_CODES, ApiError, displayCode, isApiErrorCode } from './errors'
import { initI18n } from '@/i18n'
import { resources } from '@/i18n/options'
import { codeText, errorText } from '@/utils/errorText'

describe('closed error code set', () => {
  it('has the server codes of the API plus the sign-in page codes', () => {
    expect([...API_ERROR_CODES].sort()).toEqual(
      [
        // session and transport
        'not_authenticated',
        'csrf_invalid',
        'origin_not_allowed',
        'reauth_required',
        'forbidden',
        'pending_approval',
        'access_disabled',
        'method_not_allowed',
        'unsupported_media_type',
        'payload_too_large',
        'malformed_request',
        'validation_failed',
        'not_found',
        'rate_limited',
        'token_store_unavailable',
        'internal_error',
        // Canvas token
        'token_invalid_format',
        'token_rejected',
        'token_unreadable',
        'canvas_unavailable',
        'identity_change_required',
        'recheck_not_allowed',
        // schools
        'school_required',
        'school_invalid',
        'school_not_offered',
        'school_not_in_directory',
        'school_unresolvable',
        'school_address_blocked',
        'school_selection_unverified',
        'directory_unavailable',
        // write tools
        'write_tool_not_allowed',
        'write_tools_unavailable',
        // admin
        'last_owner',
        'cannot_disable_self',
        // only on the sign-in page
        'state_invalid',
        'provider_error',
        'sign_in_incomplete',
        'sign_in_unverified',
        'wrong_tenant',
        'wrong_client',
        'bad_subject',
        'bad_roles',
        'access_denied',
        'signups_paused',
        'authorization_invalid',
      ].sort(),
    )
  })

  it('no longer knows the codes of features that are not built (identities, grants, consent)', () => {
    for (const gone of ['not_provisioned', 'identity_in_use', 'last_identity', 'link_requires_recent_login', 'consent_expired', 'grant_revoked']) {
      expect(isApiErrorCode(gone), gone).toBe(false)
    }
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
    expect(displayCode('wrong_tenant')).toBe('wrong_tenant')
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

  it('says minutes, not hundreds of seconds, from a minute up (rounded up)', () => {
    const t = i18next.t.bind(i18next)
    const wait = (seconds: number) => errorText(t, new ApiError(429, 'rate_limited', { retry_after_s: seconds }))
    expect(wait(600)).toBe('Too many requests. Try again in 10 minutes.')
    expect(wait(60)).toBe('Too many requests. Try again in 1 minute.')
    expect(wait(61)).toBe('Too many requests. Try again in 2 minutes.')
    expect(wait(59)).toBe('Too many requests. Try again in 59 seconds.')
    expect(wait(600)).not.toContain('600')
  })

  it('has the minutes text in Chinese as well', () => {
    const zh = resources.zh.errors as Record<string, string>
    expect(zh.rate_limited_wait_minutes_one).toContain('{{count}}')
    expect(zh.rate_limited_wait_minutes_other).toContain('{{count}}')
  })

  it('never prints a raw query value', () => {
    const t = i18next.t.bind(i18next)
    const text = codeText(t, '<img src=x onerror=alert(1)>')
    expect(text).toBe(resources.en.errors.internal_error)
    expect(text).not.toContain('<img')
  })
})
