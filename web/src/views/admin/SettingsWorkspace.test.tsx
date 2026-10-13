import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { keys } from '@/query/keys'
import type { AdminSettingsResponse } from '@/api/types'
import { renderApp } from '@/test/renderWithProviders'

describe('Settings workspace navigation and drafts', () => {
  it('keeps an unsaved name across topic switches and browser Back without putting it in the URL', async () => {
    const user = userEvent.setup()
    const { router } = await renderApp('/admin/settings?topic=providers', 'owner')
    await user.click(await screen.findByRole('button', { name: 'Edit entra' }))
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
