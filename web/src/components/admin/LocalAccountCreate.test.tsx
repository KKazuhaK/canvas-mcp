import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios'
import { http } from '@/api/client'
import { renderApp } from '@/test/renderWithProviders'
import { recordRequests } from '@/test/fixtures'

describe('Local administrator creation', () => {
  it('defaults to a regular user and only sends administrator authority after explicit selection', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'owner', () => {
      const inner = http.defaults.adapter as (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>
      http.defaults.adapter = async (config) => {
        const response = await inner(config)
        if (config.method === 'get' && config.url === '/admin/login-providers' && !response.data.providers.some((provider: { id: string }) => provider.id === 'local')) response.data.providers.push({ id: 'local', protocol: 'local', enabled: true, rank: 1, config: {}, secret_present: false, callback_uri: '' })
        return response
      }
    })
    await user.click(await screen.findByRole('button', { name: 'New local account' }))
    const checkbox = await screen.findByRole('checkbox', { name: 'Local administrator' })
    expect(checkbox).not.toBeChecked()
    const seen = recordRequests()
    for (const owner of [false, true]) {
      await user.type(await screen.findByLabelText(/^Account UPN/), owner ? 'local.rescue' : 'regular.user')
      await user.type(screen.getByLabelText(/^Password/), 'private-example-password')
      if (owner) await user.click(await screen.findByRole('checkbox', { name: 'Local administrator' }))
      await user.click(screen.getByRole('button', { name: 'Create local account' }))
      await waitFor(() => expect(seen.filter((item) => item.url === '/admin/local-accounts')).toHaveLength(owner ? 2 : 1))
      const request = seen.filter((item) => item.url === '/admin/local-accounts').at(-1)!
      expect(JSON.parse(String(request.data)).owner).toBe(owner)
      await waitFor(() => expect(screen.getByLabelText(/^Account UPN/)).toHaveValue(''))
    }
  })
})
