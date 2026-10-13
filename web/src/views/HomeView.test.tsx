import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { renderApp } from '@/test/renderWithProviders'
import { recordRequests } from '@/test/fixtures'
import { http } from '@/api/client'
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios'

describe('Account overview and focused settings', () => {
  it('previews connected clients with trust labels without treating a partial page as a total', async () => {
    await renderApp('/', 'enrolled', () => {
      const inner = http.defaults.adapter as (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>
      http.defaults.adapter = async (config) => {
        if (config.url === '/me/grants') return {
          status: 200, statusText: 'OK', headers: {}, config,
          data: { next_cursor: 'another-page', grants: [
            { id: 'one', client: { verified: true, label: 'client.example.test', name: 'Demo Client' }, last_used_at: null },
            { id: 'two', client: { verified: false, label: 'Unverified Demo' }, last_used_at: null },
          ] },
        }
        return inner(config)
      }
    })
    expect(await screen.findByText('client.example.test')).toBeInTheDocument()
    expect(screen.getByText('Unverified Demo')).toBeInTheDocument()
    expect(screen.getByText('Verified domain')).toBeInTheDocument()
    expect(screen.getByText(/A preview of your connected apps/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Manage connected apps' })).toHaveAttribute('href', '/connected-apps')
    expect(screen.queryByRole('button', { name: /^Revoke/ })).toBeNull()
  })

  it('does not request grants for a pending account', async () => {
    await renderApp('/', 'pending')
    const seen = recordRequests()
    await screen.findByRole('heading', { name: 'Waiting for approval' })
    expect(screen.queryByRole('link', { name: 'Manage connected apps' })).toBeNull()
    expect(seen.some((request) => request.url === '/me/grants')).toBe(false)
  })

  it('keeps editing and secrets off the overview while providing direct task links', async () => {
    await renderApp('/', 'enrolled')
    expect(await screen.findByRole('link', { name: 'Manage Canvas connection' })).toHaveAttribute('href', '/token')
    expect(screen.queryByLabelText(/Canvas access token/)).toBeNull()
    expect(screen.queryByLabelText(/New password/)).toBeNull()
    expect(screen.queryByLabelText('Reminder email address')).toBeNull()
    expect(screen.getByRole('link', { name: 'Token expiry email reminders' })).toHaveAttribute('href', '/token#reminders')
    expect(screen.getByRole('textbox', { name: 'Account UPN' })).toHaveAttribute('readonly')
  })

  it('takes an imminent-expiry action directly to the replacement form', async () => {
    const user = userEvent.setup()
    const { router } = await renderApp('/', 'expiring')
    await user.click(await screen.findByRole('button', { name: 'Update Canvas token' }))
    expect(router.state.location.pathname).toBe('/token')
    expect(router.state.location.search).toBe('?replace=1')
    expect(await screen.findByLabelText(/Canvas access token/)).toBeInTheDocument()
  })

  it('retains the updated custody-notice action without showing a token form on the overview', async () => {
    const user = userEvent.setup()
    await renderApp('/', 'custody_outdated')
    expect(await screen.findByText(/Please acknowledge the updated Canvas token custody notice/)).toBeInTheDocument()
    expect(screen.queryByLabelText(/Canvas access token/)).toBeNull()
    await user.click(screen.getByRole('link', { name: 'Review updated token notice' }))
    expect(await screen.findByRole('button', { name: 'Acknowledge' })).toBeDisabled()
  })

  it('keeps local password recovery accessible while external linking is disabled', async () => {
    await renderApp('/sign-in-methods', 'local', () => {
      const inner = http.defaults.adapter as (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>
      http.defaults.adapter = async (config) => {
        const response = await inner(config)
        if (config.url === '/me') {
          response.data.account.provider_id = 'local'
          response.data.account.has_local_password = true
        }
        return response
      }
    })
    const seen = recordRequests()
    expect(await screen.findByRole('heading', { name: 'Change password' })).toBeInTheDocument()
    expect(seen.some((request) => request.url === '/me/identities')).toBe(false)
    expect(screen.queryByRole('button', { name: /^Link / })).toBeNull()
  })
})
