import { beforeEach, describe, expect, it } from 'vitest'
import { clearCsrfToken, configureClient, setCsrfToken } from './client'
import {
  LOGIN_PATH,
  adminAccessAction,
  adminAudit,
  adminGrants,
  adminListAccounts,
  adminListEnrollments,
  adminMarkInvalid,
  adminRemoveEnrollment,
  adminRevokeGrant,
  decideConsent,
  deleteCanvasToken,
  deleteWriteTools,
  getCanvasToken,
  getConsent,
  getGrants,
  getLoginHistory,
  getMe,
  getProviders,
  getSchools,
  getWriteTools,
  logout,
  putCanvasToken,
  putUiLocale,
  putWriteTools,
  recheckCanvasToken,
  revokeGrant,
  searchSchools,
  signInUrl,
} from './endpoints'
import { meFixture, scriptAdapter } from '@/test/fixtures'

const ID = '00000000-0000-4000-8000-000000000002'
const TXN = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO_-'

beforeEach(() => {
  clearCsrfToken()
  configureClient({})
})

describe('the wire shape of every endpoint', () => {
  it.each([
    ['getProviders', () => getProviders(), 'GET', '/providers'],
    ['getCanvasToken', () => getCanvasToken(), 'GET', '/me/canvas-token'],
    ['deleteCanvasToken', () => deleteCanvasToken(), 'DELETE', '/me/canvas-token'],
    ['recheckCanvasToken', () => recheckCanvasToken(), 'POST', '/me/canvas-token/recheck'],
    ['getSchools', () => getSchools(), 'GET', '/me/schools'],
    ['getWriteTools', () => getWriteTools(), 'GET', '/me/write-tools'],
    ['deleteWriteTools', () => deleteWriteTools(), 'DELETE', '/me/write-tools'],
    ['getLoginHistory', () => getLoginHistory(), 'GET', '/me/login-history'],
    ['logout', () => logout(), 'POST', '/session/logout'],
    ['getGrants', () => getGrants(), 'GET', '/me/grants'],
    ['revokeGrant', () => revokeGrant(ID), 'DELETE', `/me/grants/${ID}`],
    ['adminGrants', () => adminGrants(ID), 'GET', `/admin/accounts/${ID}/grants`],
    ['adminRevokeGrant', () => adminRevokeGrant(ID), 'DELETE', `/admin/grants/${ID}`],
    ['getConsent', () => getConsent(TXN), 'GET', `/consent/${TXN}`],
    ['adminMarkInvalid', () => adminMarkInvalid(ID), 'POST', `/admin/enrollments/${ID}/mark-invalid`],
    ['adminRemoveEnrollment', () => adminRemoveEnrollment(ID), 'DELETE', `/admin/enrollments/${ID}`],
    ['approve', () => adminAccessAction(ID, 'approve'), 'POST', `/admin/accounts/${ID}/approve`],
    ['deny', () => adminAccessAction(ID, 'deny'), 'POST', `/admin/accounts/${ID}/deny`],
    ['disable', () => adminAccessAction(ID, 'disable'), 'POST', `/admin/accounts/${ID}/disable`],
    ['enable', () => adminAccessAction(ID, 'enable'), 'POST', `/admin/accounts/${ID}/enable`],
  ])('%s is %s %s with no body', async (_name, run, method, url) => {
    const seen = scriptAdapter(() => ({ status: 200, data: {} }))
    await run()
    expect(seen).toHaveLength(1)
    expect(seen[0].method).toBe(method)
    expect(seen[0].url).toBe(url)
    expect(seen[0].data).toBeUndefined()
  })

  it('GET /me stores the CSRF token for the calls after it', async () => {
    const seen = scriptAdapter((r) =>
      r.url === '/me' ? { status: 200, data: meFixture() } : { status: 204 },
    )
    await getMe()
    await logout()
    expect(seen[1].headers['x-csrf-token']).toBe('test-csrf-token')
  })

  it('PUT /me/canvas-token sends exactly the fields it was given', async () => {
    const seen = scriptAdapter(() => ({ status: 200, data: {} }))
    setCsrfToken('c')
    await putCanvasToken({
      canvas_token: 'tok',
      school: 'canvas.example.edu',
      school_sig: 'sig',
      expires_on: '2027-01-31',
      confirm_identity_change: 'conf',
    })
    expect(seen[0].method).toBe('PUT')
    expect(seen[0].url).toBe('/me/canvas-token')
    expect(JSON.parse(seen[0].data as string)).toEqual({
      canvas_token: 'tok',
      school: 'canvas.example.edu',
      school_sig: 'sig',
      expires_on: '2027-01-31',
      confirm_identity_change: 'conf',
    })
    expect(seen[0].headers['x-csrf-token']).toBe('c')
    expect(seen[0].headers['content-type']).toContain('application/json')
  })

  it('the school search is a GET with the query in params and the CSRF header', async () => {
    const seen = scriptAdapter(() => ({ status: 200, data: { results: [] } }))
    setCsrfToken('c')
    await searchSchools('state univ')
    expect(seen[0]).toMatchObject({ method: 'GET', url: '/me/schools/search', params: { q: 'state univ' } })
    expect(seen[0].headers['x-csrf-token']).toBe('c')
  })

  it('POST /consent/{id} sends exactly {decision} with the CSRF header', async () => {
    const seen = scriptAdapter(() => ({ status: 200, data: { redirect_to: 'https://app.test/cb' } }))
    setCsrfToken('c')
    await decideConsent(TXN, 'approve')
    expect(seen[0]).toMatchObject({ method: 'POST', url: `/consent/${TXN}` })
    expect(JSON.parse(seen[0].data as string)).toEqual({ decision: 'approve' })
    expect(seen[0].headers['x-csrf-token']).toBe('c')
  })

  it('the revoke calls carry the CSRF header and no body', async () => {
    const seen = scriptAdapter(() => ({ status: 200, data: { changed: true } }))
    setCsrfToken('c')
    await revokeGrant(ID)
    await adminRevokeGrant(ID)
    for (const request of seen) {
      expect(request.method).toBe('DELETE')
      expect(request.headers['x-csrf-token']).toBe('c')
      expect(request.data).toBeUndefined()
    }
  })

  it('PUT /me/write-tools sends {enabled}', async () => {
    const seen = scriptAdapter(() => ({ status: 200, data: {} }))
    await putWriteTools(['a_tool', 'b_tool'])
    expect(seen[0]).toMatchObject({ method: 'PUT', url: '/me/write-tools' })
    expect(JSON.parse(seen[0].data as string)).toEqual({ enabled: ['a_tool', 'b_tool'] })
  })

  it('PUT /me/ui-locale sends {locale}', async () => {
    const seen = scriptAdapter(() => ({ status: 204 }))
    await putUiLocale('zh')
    expect(seen[0]).toMatchObject({ method: 'PUT', url: '/me/ui-locale' })
    expect(JSON.parse(seen[0].data as string)).toEqual({ locale: 'zh' })
  })

  it('the admin lists send their filters as query parameters, and only when set', async () => {
    const seen = scriptAdapter(() => ({ status: 200, data: {} }))
    await adminListAccounts()
    await adminListAccounts('pending')
    await adminListEnrollments('needs_reenroll')
    await adminAudit()
    await adminAudit('120')
    expect(seen.map((r) => [r.url, r.params])).toEqual([
      ['/admin/accounts', {}],
      ['/admin/accounts', { status: 'pending' }],
      ['/admin/enrollments', { filter: 'needs_reenroll' }],
      ['/admin/audit', {}],
      ['/admin/audit', { before: '120' }],
    ])
  })

  it('percent-encodes an id in the path', async () => {
    const seen = scriptAdapter(() => ({ status: 200, data: {} }))
    await adminRemoveEnrollment('a/b c')
    expect(seen[0].url).toBe('/admin/enrollments/a%2Fb%20c')
  })
})

describe('signInUrl', () => {
  it('is the server-side redirect, with a return_to only when there is one', () => {
    expect(LOGIN_PATH).toBe('/account/login')
    expect(signInUrl('/account/login')).toBe('/account/login')
    expect(signInUrl('/account/login', null)).toBe('/account/login')
    expect(signInUrl('/account/login', '/account/write-tools?x=1')).toBe(
      '/account/login?return_to=%2Faccount%2Fwrite-tools%3Fx%3D1',
    )
  })
})
