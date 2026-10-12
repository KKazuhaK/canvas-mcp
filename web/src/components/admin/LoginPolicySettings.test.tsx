import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { recordRequests } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'

describe('Account login governance', () => {
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
