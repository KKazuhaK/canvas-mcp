import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { recordRequests } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'

describe('Login provider administration', () => {
  it('keeps a stored secret when the password field is left blank', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings', 'owner')
    await user.click(await screen.findByRole('button', { name: 'Edit entra' }))
    expect(screen.getByLabelText(/^Client secret/)).toHaveValue('')
    expect(screen.getByText(/A secret is saved/)).toBeInTheDocument()
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Save sign-in configuration' }))
    await waitFor(() => expect(seen.some((request) => request.url === '/admin/login-providers/entra')).toBe(true))
    const body = JSON.parse(seen.find((request) => request.url === '/admin/login-providers/entra')!.data as string)
    expect(body).toMatchObject({ revision: 1, enabled: true, rank: 0 })
    expect(body).not.toHaveProperty('client_secret')
  })
})
