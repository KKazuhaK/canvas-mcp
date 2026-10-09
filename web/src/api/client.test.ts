import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AxiosError } from 'axios'
import { clearCsrfToken, configureClient, http, setCsrfToken } from './client'
import { ApiError } from './errors'
import { getMe, logout, putCanvasToken, putWriteTools } from './endpoints'
import { errorBody, meFixture, scriptAdapter } from '@/test/fixtures'

describe('http client', () => {
  beforeEach(() => {
    clearCsrfToken()
    configureClient({})
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('is same-origin, cookie-based and has a 30 s timeout', () => {
    expect(http.defaults.baseURL).toBe('/account/api')
    expect(http.defaults.withCredentials).toBe(true)
    expect(http.defaults.timeout).toBe(30_000)
  })

  it('sends X-CSRF-Token on mutating verbs only', async () => {
    const seen = scriptAdapter(() => ({ status: 200, data: {} }))
    setCsrfToken('csrf-abc')

    await http.get('/me')
    await http.post('/x')
    await http.put('/x', {})
    await http.patch('/x', {})
    await http.delete('/x')

    const byMethod = Object.fromEntries(seen.map((r) => [r.method, r.headers['x-csrf-token']]))
    expect(byMethod.GET).toBeUndefined()
    expect(byMethod.POST).toBe('csrf-abc')
    expect(byMethod.PUT).toBe('csrf-abc')
    expect(byMethod.PATCH).toBe('csrf-abc')
    expect(byMethod.DELETE).toBe('csrf-abc')
  })

  it('takes the token from GET /me and nothing else', async () => {
    const seen = scriptAdapter((r) =>
      r.method === 'GET' ? { status: 200, data: meFixture() } : { status: 204 },
    )
    await getMe()
    await logout()
    await putWriteTools(['send_message'])
    expect(seen[1].headers['x-csrf-token']).toBe('test-csrf-token')
    expect(seen[2].headers['x-csrf-token']).toBe('test-csrf-token')
  })

  it('never sends an Authorization header', async () => {
    const seen = scriptAdapter(() => ({ status: 200, data: meFixture() }))
    setCsrfToken('csrf-abc')
    await getMe()
    await http.post('/x')
    for (const request of seen) expect(request.headers.authorization).toBeUndefined()
  })

  it('does not touch localStorage or sessionStorage', async () => {
    const local = vi.spyOn(window.localStorage, 'getItem')
    const localSet = vi.spyOn(window.localStorage, 'setItem')
    scriptAdapter(() => ({ status: 200, data: meFixture() }))
    await getMe()
    await http.post('/x')
    expect(local).not.toHaveBeenCalled()
    expect(localSet).not.toHaveBeenCalled()
  })

  it('normalises server errors to ApiError with the closed code and params', async () => {
    scriptAdapter(() => ({ status: 429, data: errorBody('rate_limited', { retry_after_s: 30 }) }))
    const error = await http.get('/x').catch((e: unknown) => e)
    expect(error).toBeInstanceOf(ApiError)
    const api = error as ApiError
    expect(api.status).toBe(429)
    expect(api.code).toBe('rate_limited')
    expect(api.params).toEqual({ retry_after_s: 30 })
  })

  it('maps an unknown code, a non-JSON body and a bare 500 to internal_error', async () => {
    scriptAdapter(() => ({ status: 422, data: errorBody('totally_new_code') }))
    expect(((await http.get('/x').catch((e: unknown) => e)) as ApiError).code).toBe('internal_error')
    scriptAdapter(() => ({ status: 502, data: '<html>bad gateway</html>' }))
    expect(((await http.get('/x').catch((e: unknown) => e)) as ApiError).code).toBe('internal_error')
    scriptAdapter(() => ({ status: 500, data: { error: 'text' } }))
    expect(((await http.get('/x').catch((e: unknown) => e)) as ApiError).code).toBe('internal_error')
  })

  it('never keeps server free text in the error', async () => {
    scriptAdapter(() => ({
      status: 422,
      data: { error: { code: 'token_rejected', message: 'IdP says: super secret detail' } },
    }))
    const error = (await http.get('/x').catch((e: unknown) => e)) as ApiError
    expect(error.message).toBe('token_rejected')
    expect(JSON.stringify(error)).not.toContain('super secret')
  })

  it('reports a request with no response as network_error', async () => {
    http.defaults.adapter = async (config) => {
      throw new AxiosError('Network Error', AxiosError.ERR_NETWORK, config)
    }
    const error = (await http.get('/x').catch((e: unknown) => e)) as ApiError
    expect(error.code).toBe('network_error')
    expect(error.isNetwork).toBe(true)
  })

  it('does not retain the request body (the Canvas token) on a failed PUT', async () => {
    const secret = 'secret-canvas-token-value-1234567890'
    scriptAdapter(() => ({ status: 422, data: errorBody('token_rejected') }))
    setCsrfToken('csrf-abc')
    const error = (await putCanvasToken(secret).catch((e: unknown) => e)) as ApiError
    expect(error).toBeInstanceOf(ApiError)
    expect(error).not.toHaveProperty('config')
    expect(error).not.toHaveProperty('request')
    expect(error).not.toHaveProperty('response')
    expect(JSON.stringify(error)).not.toContain(secret)
    expect(String(error.stack)).not.toContain(secret)
  })

  it('clears the session on 401 not_authenticated, but not for the /me probe', async () => {
    const onUnauthorized = vi.fn()
    configureClient({ onUnauthorized })

    scriptAdapter(() => ({ status: 401, data: errorBody('not_authenticated') }))
    await http.get('/me').catch(() => undefined)
    expect(onUnauthorized).not.toHaveBeenCalled()

    await http.get('/me/grants').catch(() => undefined)
    expect(onUnauthorized).toHaveBeenCalledTimes(1)
  })

  it('asks for one /me refetch on csrf_invalid and still surfaces the error', async () => {
    const onCsrfInvalid = vi.fn()
    configureClient({ onCsrfInvalid })
    scriptAdapter(() => ({ status: 403, data: errorBody('csrf_invalid') }))
    const error = (await http.post('/x').catch((e: unknown) => e)) as ApiError
    expect(onCsrfInvalid).toHaveBeenCalledTimes(1)
    expect(error.code).toBe('csrf_invalid')
  })
})
