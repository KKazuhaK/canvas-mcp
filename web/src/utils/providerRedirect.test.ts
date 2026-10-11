import { describe, expect, it } from 'vitest'
import { safeProviderRedirect } from './providerRedirect'

describe('safeProviderRedirect', () => {
  it.each([
    'https://accounts.google.com/o/oauth2/v2/auth?client_id=x&state=y',
    'https://github.com/login/oauth/authorize?client_id=x',
    'https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?x=1#frag',
    'https://idp.example.edu:8443/realms/a/protocol/openid-connect/auth',
  ])('lets %s through unchanged', (url) => {
    expect(safeProviderRedirect(url)).toBe(url)
  })

  it.each([
    ['http://idp.example.test/auth'],
    ['javascript:alert(1)'],
    ['data:text/html,<script>alert(1)</script>'],
    ['//idp.example.test/auth'],
    ['/account/login/google'],
    ['https://user@idp.example.test/auth'],
    ['https://user:pass@idp.example.test/auth'],
    ['https://idp.example.test/a b'],
    ['https://idp.example.test/a\tb'],
    ['https://idp.example.test/a\nb'],
    ['https://idp.example.test\\@evil.example/'],
    ['https://idp.example.test/a\u0085b'],
    ['https://'],
    ['not a url'],
    [''],
    ['https://idp.example.test/' + 'a'.repeat(5000)],
  ])('refuses %j', (url) => {
    expect(safeProviderRedirect(url)).toBeNull()
  })

  it('refuses a value that is not text', () => {
    expect(safeProviderRedirect(null)).toBeNull()
    expect(safeProviderRedirect(undefined)).toBeNull()
  })
})
