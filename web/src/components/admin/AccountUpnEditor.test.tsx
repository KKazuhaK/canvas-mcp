import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { renderApp } from '@/test/renderWithProviders'
import { recordRequests } from '@/test/fixtures'

describe('Administrator UPN editing', () => {
  it('uses the owner endpoint and current settings revision for the selected account', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'owner')
    const row = (await screen.findByText('Cleo Example')).closest('tr, li')!
    await user.click(within(row as HTMLElement).getByRole('button', { name: 'Edit account UPN' }))
    expect(screen.getByLabelText('Account UPN')).toHaveValue('cleo@example.edu')
    await user.clear(screen.getByLabelText('Account UPN'))
    await user.type(screen.getByLabelText('Account UPN'), 'renamed.user')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Save account UPN' }))
    await waitFor(() => expect(seen.some((item) => item.method === 'PUT')).toBe(true))
    const saved = seen.find((item) => item.method === 'PUT')!
    expect(saved.url).toBe('/admin/accounts/00000000-0000-4000-8000-000000000003/upn')
    expect(JSON.parse(String(saved.data))).toEqual({ revision: 1, upn: 'renamed.user' })
    expect(seen.some((item) => item.url === '/me/upn')).toBe(false)
  })
})
