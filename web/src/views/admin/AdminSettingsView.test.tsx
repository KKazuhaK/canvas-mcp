import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios'
import { http } from '@/api/client'
import { recordRequests } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'

describe('Database-managed settings', () => {
  it('saves SMTP configuration without showing or retaining its password', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings?topic=mail', 'owner')
    const seen = recordRequests()
    await user.click(await screen.findByRole('switch', { name: 'Enable reminder emails' }))
    await user.type(screen.getByLabelText('SMTP host'), 'smtp.example.test')
    await user.type(screen.getByLabelText('SMTP username'), 'mailer')
    await user.type(screen.getByLabelText('Sender email'), 'canvas@example.test')
    const password = screen.getByLabelText('SMTP password')
    await user.type(password, 'test-mail-secret')
    await user.click(screen.getByRole('button', { name: 'Save email settings' }))
    await waitFor(() => expect(seen.some((r) => r.url === '/admin/settings/mail' && r.method === 'PUT')).toBe(true))
    const saved = seen.find((r) => r.url === '/admin/settings/mail' && r.method === 'PUT')!
    expect(JSON.parse(saved.data as string)).toMatchObject({ revision: 1, password: 'test-mail-secret', config: { enabled: true, security: 'starttls', reminder_days: 7 } })
    expect(saved.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    await waitFor(() => expect(screen.getByLabelText('SMTP password')).toHaveValue(''))
    expect(screen.queryByText('test-mail-secret')).toBeNull()
  })

  it('saves browser duration independently of the sensitive-operation window', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings?topic=access', 'owner')
    const input = await screen.findByLabelText('Duration (minutes, 1–43200)')
    expect(input).toHaveValue(10080)
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: '30 days' }))
    await user.click(screen.getByRole('button', { name: 'Save sign-in duration' }))
    await waitFor(() => expect(seen.some((r) => r.url === '/admin/settings/browser-session')).toBe(true))
    const saved = seen.find((r) => r.url === '/admin/settings/browser-session')!
    expect(JSON.parse(saved.data as string)).toEqual({ revision: 1, ttl_seconds: 2592000 })
    expect(saved.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(screen.getByText(/within the last 10 minutes/)).toBeVisible()
  })

  it('saves sign-in names with the revision and CSRF header', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings?topic=providers', 'owner')
    await user.click(await screen.findByRole('button', { name: 'Edit entra' }))
    const seen = recordRequests()
    const name = await screen.findByRole('textbox', { name: 'Display name' })
    await user.type(name, 'Campus SSO')
    await user.click(screen.getByRole('button', { name: 'Save display name' }))
    await waitFor(() => expect(seen.some((r) => r.url === '/admin/settings/sign-in-methods')).toBe(true))
    const saved = seen.find((r) => r.url === '/admin/settings/sign-in-methods')!
    expect(JSON.parse(saved.data as string)).toEqual({ revision: 1, names: { entra: 'Campus SSO' } })
    expect(saved.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Display name' })).toHaveValue('Campus SSO'))
  })

  it('starts with no featured school, saves search off, and shows the empty-school warning', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings?topic=schools', 'owner')
    await screen.findByRole('heading', { name: 'Featured schools' })
    expect(screen.queryByRole('button', { name: /Remove canvas/ })).toBeNull()
    await user.click(screen.getByRole('switch', { name: 'School directory search' }))
    await user.click(screen.getByRole('button', { name: 'Save search setting' }))
    expect(await screen.findByText('No schools are offered. Add a featured school or enable directory search.')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'School directory search' })).not.toBeChecked()
  })

  it('confirms the affected bindings before removing an offered school', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings?topic=schools', 'featured')
    const seen = recordRequests()
    await user.click(await screen.findByRole('button', { name: 'Remove canvas.example.edu' }))
    await user.click(screen.getByRole('button', { name: 'Save schools' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('canvas.example.edu: 1 binding')
    const first = seen.find((r) => r.url === '/admin/settings/schools')!
    expect(JSON.parse(first.data as string).confirm_affected).toEqual([])
    await user.click(within(dialog).getByRole('button', { name: 'Confirm removal' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    const saves = seen.filter((r) => r.url === '/admin/settings/schools')
    expect(JSON.parse(saves[1].data as string)).toEqual({ revision: 1, featured: [], confirm_affected: ['canvas.example.edu'] })
  })

  it('shows a recent-sign-in prompt when the owner session is old', async () => {
    await renderApp('/admin/settings', 'stale-owner')
    expect(await screen.findByRole('button', { name: 'Sign in again' })).toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: 'Display name' })).toBeNull()
  })

  it('reloads a conflicting revision instead of overwriting another saved name', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings?topic=providers', 'owner', () => {
      const inner = http.defaults.adapter as (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>
      let changed = false
      http.defaults.adapter = async (config) => {
        if (!changed && config.method?.toUpperCase() === 'PUT' && config.url === '/admin/settings/sign-in-methods') {
          changed = true
          await inner({ ...config, data: JSON.stringify({ revision: 1, names: { entra: 'Externally saved name' } }) })
        }
        return inner(config)
      }
    })
    await user.click(await screen.findByRole('button', { name: 'Edit entra' }))
    await user.type(await screen.findByRole('textbox', { name: 'Display name' }), 'Stale editor name')
    await user.click(screen.getByRole('button', { name: 'Save display name' }))
    expect(await screen.findByText('Settings changed elsewhere. Reload before saving.')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Save display name' })).toBeDisabled()
    await user.click(await screen.findByRole('button', { name: 'Discard this draft and load saved values' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Display name' })).toHaveValue('Externally saved name'))
    expect(screen.queryByRole('button', { name: 'Discard this draft and load saved values' })).toBeNull()
  })
})
