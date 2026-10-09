import { describe, expect, it } from 'vitest'
import { loginPathFor, safeHttpsUrl, safeRedirectTarget, sanitizeReturnTo, sanitizeTxn } from './returnTo'

describe('sanitizeReturnTo', () => {
  it.each([
    '/account',
    '/account/',
    '/account/token',
    '/account/consent/t_9f2',
    '/account/admin/audit?action=login',
    '/account/activity#top',
  ])('accepts %s', (value) => {
    expect(sanitizeReturnTo(value)).toBe(value)
  })

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['empty', ''],
    ['scheme-relative', '//evil.example'],
    ['scheme-relative deeper', '//evil.example/account'],
    ['absolute https', 'https://evil.example/account'],
    ['absolute http', 'http://evil.example'],
    ['javascript url', 'javascript:alert(1)'],
    ['data url', 'data:text/html,<script>alert(1)</script>'],
    ['backslash host', '/\\evil.example'],
    ['backslash in path', '/account\\..\\evil'],
    ['tab trick', '/\t/evil.example'],
    ['newline', '/account\n/evil'],
    ['null byte', '/account\u0000'],
    ['encoded double slash', '/%2fevil.example'],
    ['encoded backslash', '/%5cevil.example'],
    ['bad percent encoding', '/account/%zz'],
    ['relative', 'account/token'],
    ['outside the SPA', '/'],
    ['outside the SPA (other path)', '/admin'],
    ['look-alike prefix', '/account-evil/token'],
    ['the API', '/account/api/me'],
    ['the API root', '/account/api'],
    ['dot segments', '/account/../admin'],
    ['too long', `/account/${'a'.repeat(2000)}`],
  ])('rejects %s', (_label, value) => {
    expect(sanitizeReturnTo(value as string | null | undefined)).toBeNull()
  })
})

describe('sanitizeTxn', () => {
  it('accepts opaque ids and rejects anything else', () => {
    expect(sanitizeTxn('t_9f2')).toBe('t_9f2')
    expect(sanitizeTxn('A-b_C-1')).toBe('A-b_C-1')
    expect(sanitizeTxn('')).toBeNull()
    expect(sanitizeTxn('a/b')).toBeNull()
    expect(sanitizeTxn('a b')).toBeNull()
    expect(sanitizeTxn('x'.repeat(129))).toBeNull()
    expect(sanitizeTxn(null)).toBeNull()
  })
})

describe('safeRedirectTarget (server-provided destinations)', () => {
  it('accepts https, http and same-site paths', () => {
    expect(safeRedirectTarget('https://claude.ai/api/mcp/auth_callback?code=1&state=2')).toBe(
      'https://claude.ai/api/mcp/auth_callback?code=1&state=2',
    )
    expect(safeRedirectTarget('http://127.0.0.1:8123/callback?code=1')).toContain('127.0.0.1:8123')
    expect(safeRedirectTarget('/account/consent/x')).toBe(`${window.location.origin}/account/consent/x`)
  })

  it.each(['javascript:alert(1)', 'data:text/html,x', 'vbscript:x', 'file:///etc/passwd', '', 42, null])(
    'rejects %s',
    (value) => {
      expect(safeRedirectTarget(value)).toBeNull()
    },
  )
})

describe('safeHttpsUrl', () => {
  it('only passes https', () => {
    expect(safeHttpsUrl('https://claude.ai')).toBe('https://claude.ai/')
    expect(safeHttpsUrl('http://claude.ai')).toBeNull()
    expect(safeHttpsUrl('javascript:alert(1)')).toBeNull()
    expect(safeHttpsUrl('not a url')).toBeNull()
    expect(safeHttpsUrl(null)).toBeNull()
  })
})

describe('loginPathFor', () => {
  it('keeps the current page and txn as validated query values', () => {
    expect(loginPathFor('/token')).toBe('/login?return_to=%2Faccount%2Ftoken')
    expect(loginPathFor('/consent/t_1', 't_1')).toBe('/login?txn=t_1&return_to=%2Faccount%2Fconsent%2Ft_1')
    expect(loginPathFor('/')).toBe('/login')
    expect(loginPathFor('/x\\y')).toBe('/login')
    expect(loginPathFor('/x', 'bad txn!')).toBe('/login?return_to=%2Faccount%2Fx')
  })
})
