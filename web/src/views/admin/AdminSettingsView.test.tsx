import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios'
import { http } from '@/api/client'
import { recordRequests } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'

describe('Database-managed settings', () => {
  it('saves sign-in names with the revision and CSRF header', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings', 'owner')
    const seen = recordRequests()
    const name = await screen.findByLabelText('Microsoft')
    await user.type(name, 'Campus SSO')
    await user.click(screen.getByRole('button', { name: 'Save names' }))
    await waitFor(() => expect(seen.some((r) => r.url === '/admin/settings/sign-in-methods')).toBe(true))
    const saved = seen.find((r) => r.url === '/admin/settings/sign-in-methods')!
    expect(JSON.parse(saved.data as string)).toEqual({ revision: 1, names: { entra: 'Campus SSO' } })
    expect(saved.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    await waitFor(() => expect(screen.getByLabelText('Microsoft')).toHaveValue('Campus SSO'))
  })

  it('starts with no featured school, saves search off, and shows the empty-school warning', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings', 'owner')
    await screen.findByRole('heading', { name: 'Featured schools' })
    expect(screen.queryByRole('button', { name: /Remove canvas/ })).toBeNull()
    await user.click(screen.getByRole('switch', { name: 'School directory search' }))
    await user.click(screen.getByRole('button', { name: 'Save search setting' }))
    expect(await screen.findByText('No schools are offered. Add a featured school or enable directory search.')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'School directory search' })).not.toBeChecked()
  })

  it('confirms the affected bindings before removing an offered school', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings', 'featured')
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
    expect(screen.queryByLabelText('Microsoft')).toBeNull()
  })

  it('reloads a conflicting revision instead of overwriting another saved name', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings', 'owner', () => {
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
    await user.type(await screen.findByLabelText('Microsoft'), 'Stale editor name')
    await user.click(screen.getByRole('button', { name: 'Save names' }))
    expect(await screen.findByText('Settings changed elsewhere. Reload before saving.')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Save names' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Reload settings' }))
    await waitFor(() => expect(screen.getByLabelText('Microsoft')).toHaveValue('Externally saved name'))
    expect(screen.queryByRole('button', { name: 'Reload settings' })).toBeNull()
  })
})
