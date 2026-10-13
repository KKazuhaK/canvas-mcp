import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { renderApp } from '@/test/renderWithProviders'
import { recordRequests } from '@/test/fixtures'
import { openManagedAccount } from '@/test/accountManagement'

describe('Selected-account management', () => {
  it('keeps a sign-in policy draft across detail tabs and saves only the selected account policy', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'owner')
    const drawer = await openManagedAccount('Cleo Example', 'Sign-in & access')
    const restriction = await within(drawer).findByRole('switch', { name: 'Restrict this account to selected sign-in methods' })
    await user.click(restriction)
    expect(within(drawer).getByRole('switch', { name: 'entra' })).toBeChecked()
    await user.click(within(drawer).getByRole('tab', { name: 'Canvas' }))
    await user.click(within(drawer).getByRole('tab', { name: 'Sign-in & access' }))
    expect(restriction).toBeChecked()
    expect(within(drawer).getByRole('switch', { name: 'entra' })).toBeChecked()
    const seen = recordRequests()
    await user.click(within(drawer).getByRole('button', { name: 'Save sign-in policy' }))
    await waitFor(() => expect(seen.some((request) => request.method === 'PUT')).toBe(true))
    const request = seen.find((entry) => entry.method === 'PUT')!
    expect(request.url).toBe('/admin/accounts/00000000-0000-4000-8000-000000000003/login-policy')
    expect(JSON.parse(String(request.data))).toEqual({ revision: 1, policy: { allow_multiple: null, allowed_providers: ['entra'] } })
    expect(request.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(seen.some((entry) => entry.method === 'DELETE')).toBe(false)
    expect(await within(drawer).findByText('Saved. Affected sessions ended; sign in again.')).toBeInTheDocument()
    expect(within(drawer).queryByText('Unsaved changes')).toBeNull()
  })
  it('keeps the list compact and opens management for exactly the selected account', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'owner')
    await screen.findByText('Cleo Example')
    expect(screen.queryByRole('button', { name: 'Disable: Cleo Example' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Edit account UPN' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Approve: Bob Example' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Manage Cleo Example' }))
    const drawer = await screen.findByRole('dialog', { name: 'Cleo Example' })
    expect(within(drawer).getByRole('button', { name: 'Disable: Cleo Example' })).toBeInTheDocument()
    expect(within(drawer).queryByRole('button', { name: 'Disable: Bob Example' })).toBeNull()
    expect(within(drawer).getByRole('tab', { name: 'Account', selected: true })).toBeInTheDocument()
    await user.click(within(drawer).getByRole('tab', { name: 'Canvas' }))
    expect(within(drawer).getByRole('button', { name: 'Remove token: Cleo Example' })).toBeInTheDocument()
    expect(within(drawer).queryByRole('button', { name: 'Mark token invalid: Cleo Example' })).toBeNull()
    await user.click(within(drawer).getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Cleo Example' })).toBeNull())
  })

  it('still confirms disabling a selected account before issuing a protected write', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'owner')
    await user.click(await screen.findByRole('button', { name: 'Manage Cleo Example' }))
    const drawer = await screen.findByRole('dialog', { name: 'Cleo Example' })
    const seen = recordRequests()
    await user.click(within(drawer).getByRole('button', { name: 'Disable: Cleo Example' }))
    const confirm = await screen.findByRole('dialog', { name: 'Disable Cleo Example?' })
    expect(seen.some((request) => request.method === 'POST')).toBe(false)
    await user.click(within(confirm).getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(seen.some((request) => request.url.endsWith('/00000000-0000-4000-8000-000000000003/disable'))).toBe(true))
    const call = seen.find((request) => request.url.endsWith('/disable'))!
    expect(call.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(call.url).not.toContain('00000000-0000-4000-8000-000000000002')
  })
})
