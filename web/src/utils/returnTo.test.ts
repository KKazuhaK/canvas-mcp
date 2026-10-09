import { afterEach, describe, expect, it } from 'vitest'
import { currentReturnTo, loginPathFor, safeHttpsUrl, sanitizeReturnTo } from './returnTo'

describe('sanitizeReturnTo', () => {
  it.each([
    '/account',
    '/account/',
    '/account/token',
    '/account/write-tools',
    '/account/admin/audit?action=login',
    '/account/activity#top',
    '/account/sign-in',
  ])('accepts %s', (value) => {
    expect(sanitizeReturnTo(value)).toBe(value)
  })

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['empty', ''],
    ['scheme-relative', '//evil.example'],
    ['scheme-relative deeper', '//evil.example/account'],
    ['double slash later in the path', '/account//x'],
    ['double slash in the query', '/account/token?next=//evil.example'],
    ['absolute https', 'https://evil.example/account'],
    ['absolute http', 'http://evil.example'],
    ['javascript url', 'javascript:alert(1)'],
    ['data url', 'data:text/html,<script>alert(1)</script>'],
    ['backslash host', '/\\evil.example'],
    ['backslash in path', '/account\\..\\evil'],
    ['tab trick', '/\t/evil.example'],
    ['newline', '/account\n/evil'],
    ['null byte', '/account\u0000'],
    ['non-ASCII', '/account/café'],
    ['encoded double slash', '/%2fevil.example'],
    ['encoded backslash', '/%5cevil.example'],
    ['encoded slash after /account', '/account/%2F%2Fevil.example'],
    ['double-encoded slash', '/account/%252F%252Fevil.example'],
    ['bad percent encoding', '/account/%zz'],
    ['relative', 'account/token'],
    ['outside the app', '/'],
    ['outside the app (other path)', '/admin'],
    ['look-alike prefix', '/account-evil/token'],
    ['the API', '/account/api/me'],
    ['the API root', '/account/api'],
    ['the API, upper case', '/account/API/me'],
    ['the login redirect', '/account/login'],
    ['the login redirect with a query', '/account/login?return_to=/account/token'],
    ['the callback', '/account/callback?code=1'],
    ['an encoded API path', '/account/%61pi/me'],
    ['dot segments', '/account/../admin'],
    ['encoded dot segments', '/account/%2e%2e/admin'],
    ['single dot segment', '/account/./token'],
    ['too long (513 characters)', `/account/${'a'.repeat(513 - 9)}`],
  ])('rejects %s', (_label, value) => {
    expect(sanitizeReturnTo(value as string | null | undefined)).toBeNull()
  })

  it('allows exactly 512 characters', () => {
    const value = `/account/${'a'.repeat(512 - 9)}`
    expect(value).toHaveLength(512)
    expect(sanitizeReturnTo(value)).toBe(value)
  })
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
  it('keeps the current page as a validated return_to on the app sign-in page', () => {
    expect(loginPathFor('/token')).toBe('/sign-in?return_to=%2Faccount%2Ftoken')
    expect(loginPathFor('/admin?x=1')).toBe('/sign-in?return_to=%2Faccount%2Fadmin%3Fx%3D1')
    expect(loginPathFor('/')).toBe('/sign-in')
    expect(loginPathFor('/x\\y')).toBe('/sign-in')
  })

  it('never returns to the sign-in page itself', () => {
    expect(loginPathFor('/sign-in')).toBe('/sign-in')
    expect(loginPathFor('/sign-in?error=provider_error')).toBe('/sign-in')
  })
})

describe('currentReturnTo', () => {
  afterEach(() => {
    window.history.replaceState({}, '', '/')
  })

  it('is the browser location when it is a page of the app, else null', () => {
    window.history.replaceState({}, '', '/account/write-tools?tab=1')
    expect(currentReturnTo()).toBe('/account/write-tools?tab=1')
    window.history.replaceState({}, '', '/account/sign-in?error=provider_error')
    expect(currentReturnTo()).toBeNull()
    window.history.replaceState({}, '', '/elsewhere')
    expect(currentReturnTo()).toBeNull()
  })
})
