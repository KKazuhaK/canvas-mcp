import { QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook, waitFor } from '@testing-library/react'
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios'
import type { PropsWithChildren } from 'react'
import { describe, expect, it } from 'vitest'
import { http } from '@/api/client'
import { installMockServer } from '@/dev/mockServer'
import { recordRequests } from '@/test/fixtures'
import { makeTestQueryClient } from '@/test/renderWithProviders'
import { useAdminAccounts, useAdminAudit, useAdminEnrollments, useAdminGrants, useGrants, useLoginHistory } from './hooks'

const SELF = '00000000-0000-4000-8000-000000000001'

function setup() {
  installMockServer(http, { scenario: 'local-owner', latency: [0, 0] })
  const inner = http.defaults.adapter as (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>
  http.defaults.adapter = config => inner({ ...config, params: { ...config.params, limit: 1 } })
  const seen = recordRequests()
  const client = makeTestQueryClient()
  const wrapper = ({ children }: PropsWithChildren) => <QueryClientProvider client={client}>{children}</QueryClientProvider>
  return { seen, wrapper }
}

type PagedQuery = {
  data?: { pages: { next_cursor: string | null }[] }
  isSuccess: boolean
  hasNextPage: boolean
  fetchNextPage(): Promise<unknown>
}

const cases: readonly [string, () => PagedQuery, string][] = [
    ['accounts', () => useAdminAccounts(''), '/admin/accounts'],
    ['enrollments', () => useAdminEnrollments('all'), '/admin/enrollments'],
    ['audit', useAdminAudit, '/admin/audit'],
    ['history', useLoginHistory, '/me/login-history'],
    ['own grants', useGrants, '/me/grants'],
    ['account grants', () => useAdminGrants(SELF, true), `/admin/accounts/${SELF}/grants`],
  ]

describe('keyset query continuation', () => {
  it.each(cases)('appends %s until the server ends the list', async (_name, hook, url) => {
    const { seen, wrapper } = setup()
    const { result } = renderHook(hook, { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.hasNextPage).toBe(true)
    let pages = 1
    while (result.current.hasNextPage) {
      const cursor = result.current.data!.pages.at(-1)!.next_cursor
      await act(async () => { await result.current.fetchNextPage() })
      pages++
      expect(seen.at(-1)).toMatchObject({ url, params: { cursor } })
      await waitFor(() => expect(result.current.data!.pages).toHaveLength(pages))
      // A mistaken reused cursor must not make this test loop forever.
      expect(pages).toBeLessThan(10)
    }
    expect(pages).toBeGreaterThan(1)
    expect(result.current.data!.pages.at(-1)!.next_cursor).toBeNull()
  })

  it('starts a changed account filter without the previous cursor or rows', async () => {
    const { seen, wrapper } = setup()
    const { result, rerender } = renderHook(({ status }: { status: '' | 'pending' }) => useAdminAccounts(status), {
      initialProps: { status: '' }, wrapper,
    })
    await waitFor(() => expect(result.current.data?.accounts).toHaveLength(1))
    await act(async () => { await result.current.fetchNextPage() })
    await waitFor(() => expect(result.current.data!.pages).toHaveLength(2))
    expect(result.current.data!.accounts).toHaveLength(2)
    rerender({ status: 'pending' })
    await waitFor(() => expect(result.current.data?.accounts[0]?.status).toBe('pending'))
    expect(result.current.data!.accounts).toHaveLength(1)
    expect(result.current.hasNextPage).toBe(false)
    expect(seen.at(-1)).toMatchObject({ params: { status: 'pending' } })
    expect(seen.at(-1)!.params).not.toHaveProperty('cursor')
  })
})
