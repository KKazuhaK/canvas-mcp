import { describe, expect, it } from 'vitest'
import { TXN_PATTERN, consentLoginPath, safeAppRedirect } from './appRedirect'

describe('safeAppRedirect', () => {
  it.each([
    'https://claude.ai/api/mcp/auth_callback?code=abc&state=s&iss=https%3A%2F%2Fmcp.example.test%2F',
    'https://app.example.test/cb',
    'http://localhost:53682/callback?code=x',
    'http://127.0.0.1:39211/callback?code=x',
    'http://[::1]:5000/callback?code=x',
  ])('lets %s through unchanged', (url) => {
    expect(safeAppRedirect(url)).toBe(url)
  })

  it.each([
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    'data:text/html,<script>1</script>',
    'blob:https://claude.ai/x',
    'file:///etc/passwd',
    'ftp://app.test/cb',
    'claude://callback?code=x',
    'http://evil.test/cb',
    'http://localhost.evil.test/cb',
    'http://127.0.0.1.evil.test/cb',
    'https://user@app.test/cb',
    'https://user:password@app.test/cb',
    '//claude.ai/cb',
    '/relative/path',
    'https:\\\\claude.ai\\cb',
    'https://claude.ai/cb\n',
    'https://claude.ai/cb\tx',
    'https://claude.ai/ cb',
    'https://claude.ai/cb\u0000',
    'not a url',
    '',
    'https://claude.ai/' + 'a'.repeat(5000),
  ])('refuses %j', (url) => {
    expect(safeAppRedirect(url)).toBeNull()
  })

  it('refuses anything that is not a string', () => {
    expect(safeAppRedirect(null)).toBeNull()
    expect(safeAppRedirect(undefined)).toBeNull()
  })
})

describe('the request id and its sign-in link', () => {
  it('accepts exactly the shape the server issues', () => {
    expect(TXN_PATTERN.test('A'.repeat(43))).toBe(true)
    expect(TXN_PATTERN.test('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO_-')).toBe(true)
    for (const bad of ['', 'A'.repeat(42), 'A'.repeat(44), `${'A'.repeat(42)}=`, `${'A'.repeat(42)}/`, `${'A'.repeat(42)}\n`]) {
      expect(TXN_PATTERN.test(bad), JSON.stringify(bad)).toBe(false)
    }
  })

  it('builds the server-side sign-in path, with the request id as a query value', () => {
    expect(consentLoginPath('A'.repeat(43))).toBe(`/account/login?txn=${'A'.repeat(43)}`)
    expect(consentLoginPath('A'.repeat(43), { reauth: true })).toBe(`/account/login?txn=${'A'.repeat(43)}&reauth=1`)
  })
})
