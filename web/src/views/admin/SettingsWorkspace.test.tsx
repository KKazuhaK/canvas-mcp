import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { keys } from '@/query/keys'
import type { AdminSettingsResponse } from '@/api/types'
import { renderApp } from '@/test/renderWithProviders'
import { http } from '@/api/client'
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios'

describe('Settings workspace navigation and drafts', () => {
  it.each([
    { topic: 'access', field: 'Duration (minutes, 1–43200)', value: '60', savedValue: '10080', save: 'Save sign-in duration', endpoint: '/admin/settings/browser-session' },
    { topic: 'mail', field: 'SMTP host', value: 'draft.smtp.test', savedValue: '', save: 'Save email settings', endpoint: '/admin/settings/mail' },
  ])('recovers the $topic editor from a rejected shared revision without silently discarding its draft', async ({ topic, field, value, savedValue, save, endpoint }) => {
    const user = userEvent.setup()
    await renderApp(`/admin/settings?topic=${topic}`, 'owner', () => {
      const inner = http.defaults.adapter as (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>
      let changed = false
      http.defaults.adapter = async (config) => {
        if (!changed && config.method?.toUpperCase() === 'PUT' && config.url === endpoint) {
          changed = true
          await inner({ ...config, url: '/admin/settings/sign-in-methods', data: JSON.stringify({ revision: 1, names: { entra: 'External name' } }) })
        }
        return inner(config)
      }
    })
    const input = await screen.findByLabelText(field)
    await user.clear(input)
    await user.type(input, value)
    await user.click(screen.getByRole('button', { name: save }))
    expect(await screen.findByText('Settings changed elsewhere. Reload before saving.')).toBeVisible()
    expect(input).toHaveValue(topic === 'access' ? 60 : value)
    expect(screen.getByRole('button', { name: save })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Discard this draft and load saved values' }))
    await waitFor(() => expect(input).toHaveValue(topic === 'access' ? 10080 : savedValue))
    await waitFor(() => expect(screen.queryByText('Settings changed elsewhere. Reload before saving.')).toBeNull())
    await user.clear(input)
    await user.type(input, value)
    expect(screen.getByRole('button', { name: save })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: save }))
    expect(await screen.findByText(topic === 'access' ? 'Sign-in duration saved. Longer durations apply after signing in again.' : 'Email settings saved.')).toBeVisible()
  })

  it('keeps an unsaved name across topic switches and browser Back without putting it in the URL', async () => {
    const user = userEvent.setup()
    const { router } = await renderApp('/admin/settings?topic=providers', 'owner')
    await user.click(await screen.findByRole('button', { name: 'Edit Microsoft' }))
    const field = await screen.findByRole('textbox', { name: 'Display name' })
    await user.type(field, 'Private draft')
    await user.click(screen.getByRole('tab', { name: 'Email reminders' }))
    expect(await screen.findByText('Enable reminder emails')).toBeVisible()
    expect(field).not.toBeVisible()
    expect(router.state.location.search).toBe('?topic=mail')
    expect(router.state.location.search).not.toContain('Private')
    await act(async () => { await router.navigate(-1) })
    expect(screen.getByRole('tab', { name: 'Sign-in providers' })).toHaveAttribute('aria-selected', 'true')
    expect(field).toBeVisible()
    expect(field).toHaveValue('Private draft')
  })

  it('preserves a dirty school editor and refuses to overwrite an external school change', async () => {
    const user = userEvent.setup()
    const { client } = await renderApp('/admin/settings?topic=schools', 'featured')
    const field = await screen.findByDisplayValue('Example University')
    await user.clear(field)
    await user.type(field, 'Unsubmitted school name')
    const previous = client.getQueryData<AdminSettingsResponse>(keys.adminSettings)!
    act(() => { client.setQueryData(keys.adminSettings, { ...previous, revision: previous.revision + 1,
      schools: { ...previous.schools, featured: previous.schools.featured.map((school) => ({ ...school, display_name: 'Externally saved school' })) } }) })
    expect(field).toHaveValue('Unsubmitted school name')
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save schools' })).toBeDisabled())
    expect(await screen.findByText(/Your draft is preserved/)).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Discard this draft and load saved values' }))
    await waitFor(() => expect(field).toHaveValue('Externally saved school'))
  })

  it('keeps unrelated drafts editable after another settings section updates the revision', async () => {
    const user = userEvent.setup()
    const { client } = await renderApp('/admin/settings?topic=schools', 'featured')
    const field = await screen.findByDisplayValue('Example University')
    await user.clear(field)
    await user.type(field, 'Unsubmitted school name')
    const previous = client.getQueryData<AdminSettingsResponse>(keys.adminSettings)!
    act(() => { client.setQueryData(keys.adminSettings, { ...previous, revision: previous.revision + 1, browser_session: { ttl_seconds: 60 } }) })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save schools' })).toBeEnabled())
    expect(field).toHaveValue('Unsubmitted school name')
    expect(screen.queryByText(/Your draft is preserved/)).toBeNull()
  })

  it('uses the Site topic for an invalid topic and respects a direct mail link', async () => {
    const { router } = await renderApp('/admin/settings?topic=unsupported', 'owner')
    expect(await screen.findByRole('tab', { name: 'Site' })).toHaveAttribute('aria-selected', 'true')
    expect(await screen.findByLabelText('Public HTTPS address')).toBeVisible()
    await act(async () => { await router.navigate('/admin/settings?topic=mail') })
    expect(screen.getByRole('tab', { name: 'Email reminders' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByLabelText('SMTP password')).toBeVisible()
    expect(screen.getByLabelText('Public HTTPS address')).not.toBeVisible()
  })
})
