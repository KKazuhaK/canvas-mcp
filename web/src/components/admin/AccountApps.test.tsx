import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { errorBody, recordRequests, scriptAdapter } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'
import { hardNavigate } from '@/utils/navigate'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

const CLEO = '00000000-0000-4000-8000-000000000003'
const CLEO_GRANT = '00000000-0000-4000-8000-000000000104'
const MOCK_CSRF = 'mock-csrf-token-not-a-secret'

beforeEach(() => {
  vi.mocked(hardNavigate).mockClear()
})

describe('an owner and the connected apps of an account', () => {
  it('offers the list only for active accounts, and only when the server has the feature', async () => {
    await renderApp('/admin', 'local-owner')
    await screen.findByText('Cleo Example')
    expect(screen.getByRole('button', { name: 'Connected apps: Cleo Example' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Connected apps: Ada Example' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Connected apps: Bob Example' })).toBeNull() // pending
    expect(screen.queryByRole('button', { name: 'Connected apps: Dev Example' })).toBeNull() // disabled
  })

  it('has no such button without the feature', async () => {
    await renderApp('/admin', 'owner')
    await screen.findByText('Cleo Example')
    expect(screen.queryByRole('button', { name: /^Connected apps/ })).toBeNull()
  })

  it('lists one account\'s apps in a dialog and ends one of them', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'local-owner')
    await screen.findByText('Cleo Example')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Connected apps: Cleo Example' }))
    const dialog = await screen.findByRole('dialog', { name: 'Connected apps of Cleo Example' })
    expect(await within(dialog).findByText('Cleo Notes')).toBeInTheDocument()
    expect(within(dialog).getByText(/Unverified: a self-registered app/)).toBeInTheDocument()
    expect(within(dialog).getByText('notes.example.test')).toBeInTheDocument()
    expect(seen.find((request) => request.url === `/admin/accounts/${CLEO}/grants`)?.method).toBe('GET')

    await user.click(within(dialog).getByRole('button', { name: 'Revoke: Cleo Notes' }))
    await waitFor(() => expect(within(dialog).getByText('No apps are connected.')).toBeInTheDocument())
    const call = seen.find((request) => request.method === 'DELETE')
    expect(call?.url).toBe(`/admin/grants/${CLEO_GRANT}`)
    expect(call?.headers['x-csrf-token']).toBe(MOCK_CSRF)
    expect(await screen.findByText('App disconnected.')).toBeInTheDocument()
  })

  it('lists the apps of the owner too', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'local-owner')
    await screen.findByText('Cleo Example')
    await user.click(screen.getByRole('button', { name: 'Connected apps: Ada Example' }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findAllByText('The app calls itself: Claude Code')).toHaveLength(1)
  })

  it('asks for a fresh sign-in instead of showing data when the server wants one', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'local-owner')
    await screen.findByText('Cleo Example')
    scriptAdapter((request) =>
      request.url.endsWith('/grants')
        ? { status: 403, data: errorBody('reauth_required', { max_age_s: 600 }) }
        : { status: 200, data: {} },
    )
    await user.click(screen.getByRole('button', { name: 'Connected apps: Cleo Example' }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText('Sign in again to continue')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Sign in again' }))
    expect(hardNavigate).toHaveBeenCalledTimes(1)
  })

  it('shows the closed message when the revoke is refused', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'local-owner')
    await screen.findByText('Cleo Example')
    await user.click(screen.getByRole('button', { name: 'Connected apps: Cleo Example' }))
    const dialog = await screen.findByRole('dialog')
    await within(dialog).findByText('Cleo Notes')
    scriptAdapter((request) =>
      request.method === 'DELETE'
        ? { status: 403, data: errorBody('forbidden') }
        : { status: 200, data: { grants: [] } },
    )
    await user.click(within(dialog).getByRole('button', { name: 'Revoke: Cleo Notes' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('You are not allowed to do that')
  })
})
