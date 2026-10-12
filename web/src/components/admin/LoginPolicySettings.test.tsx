import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { within } from '@testing-library/react'
import { recordRequests } from '@/test/fixtures'
import { http } from '@/api/client'
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios'
import { renderApp } from '@/test/renderWithProviders'

describe('Account login governance', () => {
  it('unlocks the selected account with its revision and CSRF without deleting or linking identities', async () => {
    const user = userEvent.setup()
    const target = '/admin/accounts/00000000-0000-4000-8000-000000000003'
    await renderApp('/admin', 'owner', () => {
      const inner = http.defaults.adapter as (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>
      http.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
        const response = await inner(config)
        if (config.url === `${target}/login-policy` && config.method === 'get') {
          response.data.policy.sso_lock_provider = 'entra'
        }
        return response
      }
    })
    const row = (await screen.findByText('Cleo Example')).closest('tr, li')!
    await user.click(within(row as HTMLElement).getByRole('button', { name: 'Account sign-in policy' }))
    await screen.findByText('SSO lock: entra')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Unlock SSO' }))
    await screen.findByText('Saved. Affected sessions ended; sign in again.')
    expect(seen.map((request) => [request.method, request.url])).toEqual([['POST', `${target}/unlock-sso`]])
    expect(JSON.parse(seen[0].data as string)).toEqual({ revision: 1 })
    expect(seen[0].headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(screen.getByRole('button', { name: 'Unlock SSO' })).toBeDisabled()
  })

  it('saves the global method policy without adding a global email-association switch', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings', 'owner')
    const lock = await screen.findByRole('switch', { name: 'Lock the first successful SSO method' })
    const seen = recordRequests()
    await user.click(lock)
    await user.click(screen.getByRole('button', { name: 'Save sign-in policy' }))
    await screen.findByText('Saved. Affected sessions ended; sign in again.')
    await waitFor(() => expect(seen.filter((request) => request.url === '/admin/settings/login-policy')).toHaveLength(1))
    const request = seen.find((item) => item.url === '/admin/settings/login-policy')!
    expect(JSON.parse(request.data as string)).toEqual({ revision: 1, policy: { allow_multiple: true, lock_first_sso: true, block_conflicting_registration: false } })
    expect(request.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(lock).toBeDisabled()
  })
})
