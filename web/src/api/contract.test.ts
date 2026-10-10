import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { splitRoute } from './contract'

// The contract table is the one list of routes. The Python test
// tests/selfhost/test_account_api_contract.py checks it against the server; these
// check that the web side really uses all of it: a call in endpoints.ts, a handler
// in the dev mock.

const read = (path: string) => readFileSync(join(import.meta.dirname, '..', path), 'utf8')
const contract = read('api/contract.ts')
const KEYS = [...contract.matchAll(/^\s*'((?:GET|POST|PUT|PATCH|DELETE) \/[^']*)':/gm)].map((m) => m[1])

describe('api/contract.ts', () => {
  it('lists the routes of the server (and nothing for identities or the sign-in)', () => {
    expect(KEYS).toHaveLength(29)
    expect(new Set(KEYS).size).toBe(KEYS.length)
    for (const key of KEYS) {
      expect(key, key).not.toMatch(/identit|login\//)
    }
  })

  it('lists the consent and connected-apps routes the server serves only in local mode', () => {
    expect(KEYS.filter((key) => /consent|grants/.test(key)).sort()).toEqual([
      'DELETE /admin/grants/{id}',
      'DELETE /me/grants/{id}',
      'GET /admin/accounts/{id}/grants',
      'GET /consent/{id}',
      'GET /me/grants',
      'POST /consent/{id}',
    ])
  })

  it('splits a key into method and path', () => {
    expect(splitRoute('GET /me')).toEqual({ method: 'GET', path: '/me' })
    expect(splitRoute('POST /admin/accounts/{id}/approve')).toEqual({
      method: 'POST',
      path: '/admin/accounts/{id}/approve',
    })
  })

  it('has a call in endpoints.ts for every route', () => {
    const endpoints = read('api/endpoints.ts')
    for (const key of KEYS) expect(endpoints, key).toContain(`'${key}'`)
  })

  it('has a handler in the dev mock for every route', () => {
    const mock = read('dev/mockServer.ts')
    for (const key of KEYS) expect(mock, key).toContain(`route('${key}'`)
  })
})
