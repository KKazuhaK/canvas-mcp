import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { errorBody, recordRequests, scriptAdapter } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'
import { hardNavigate } from '@/utils/navigate'
import { openManagedAccount } from '@/test/accountManagement'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

const CLEO = '00000000-0000-4000-8000-000000000003'
const CLEO_GRANT = '00000000-0000-4000-8000-000000000104'
const MOCK_CSRF = 'mock-csrf-token-not-a-secret'

beforeEach(() => {
  vi.mocked(hardNavigate).mockClear()
})

describe('an owner and the connected apps of an account', () => {
  it('offers the list only for active accounts', async () => {
    await renderApp('/admin', 'local-owner')
    const seen = recordRequests()
    let drawer = await openManagedAccount('Cleo Example', 'Connected apps')
    expect(await within(drawer).findByText('Cleo Notes')).toBeInTheDocument()
    drawer = await openManagedAccount('Ada Example', 'Connected apps')
    expect(await within(drawer).findByText('The app calls itself: Claude Code')).toBeInTheDocument()
    for (const name of ['Bob Example', 'Dev Example']) {
      drawer = await openManagedAccount(name, 'Connected apps')
      expect(within(drawer).getByText('This account is not active. Connected apps cannot use it.')).toBeInTheDocument()
    }
    expect(seen.filter((request) => request.url.endsWith('/grants')).map((request) => request.url)).not.toContain('/admin/accounts/00000000-0000-4000-8000-000000000002/grants')
    expect(seen.filter((request) => request.url.endsWith('/grants')).map((request) => request.url)).not.toContain('/admin/accounts/00000000-0000-4000-8000-000000000004/grants')
  })

  it('offers connected apps to every deployment owner', async () => {
    await renderApp('/admin', 'owner')
    const drawer = await openManagedAccount('Cleo Example', 'Connected apps')
    expect(await within(drawer).findByText('No apps are connected.')).toBeInTheDocument()
  })

  it('lists only the selected account apps and confirms before ending one of them', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'local-owner')
    await screen.findByText('Cleo Example')
    const seen = recordRequests()
    const dialog = await openManagedAccount('Cleo Example', 'Connected apps')
    expect(await within(dialog).findByText('Cleo Notes')).toBeInTheDocument()
    expect(within(dialog).getByText(/Unverified: a self-registered app/)).toBeInTheDocument()
    expect(within(dialog).getByText('notes.example.test')).toBeInTheDocument()
    expect(seen.find((request) => request.url === `/admin/accounts/${CLEO}/grants`)?.method).toBe('GET')

    await user.click(within(dialog).getByRole('button', { name: 'Revoke: Cleo Notes' }))
    const confirmation = await screen.findByRole('dialog', { name: 'Disconnect Cleo Notes from Cleo Example?' })
    expect(seen.some((request) => request.method === 'DELETE')).toBe(false)
    await user.click(within(confirmation).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(within(dialog).getByText('No apps are connected.')).toBeInTheDocument())
    const call = seen.find((request) => request.method === 'DELETE')
    expect(call?.url).toBe(`/admin/grants/${CLEO_GRANT}`)
    expect(call?.headers['x-csrf-token']).toBe(MOCK_CSRF)
    expect(await screen.findByText('App disconnected.')).toBeInTheDocument()
  })

  it('lists the apps of the owner too', async () => {
    await renderApp('/admin', 'local-owner')
    await screen.findByText('Cleo Example')
    const dialog = await openManagedAccount('Ada Example', 'Connected apps')
    expect(await within(dialog).findAllByText('The app calls itself: Claude Code')).toHaveLength(1)
  })

  it('asks for a fresh sign-in instead of showing data when the server wants one', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'local-owner')
    const dialog = await openManagedAccount('Cleo Example')
    scriptAdapter((request) =>
      request.url.endsWith('/grants')
        ? { status: 403, data: errorBody('reauth_required', { max_age_s: 600 }) }
        : { status: 200, data: {} },
    )
    await user.click(within(dialog).getByRole('tab', { name: 'Connected apps' }))
    expect(await within(dialog).findByText('Sign in again to continue')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Sign in again' }))
    expect(hardNavigate).toHaveBeenCalledTimes(1)
  })

  it('shows the closed message when the revoke is refused', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'local-owner')
    await screen.findByText('Cleo Example')
    const dialog = await openManagedAccount('Cleo Example', 'Connected apps')
    await within(dialog).findByText('Cleo Notes')
    scriptAdapter((request) =>
      request.method === 'DELETE'
        ? { status: 403, data: errorBody('forbidden') }
        : { status: 200, data: { grants: [] } },
    )
    await user.click(within(dialog).getByRole('button', { name: 'Revoke: Cleo Notes' }))
    const confirmation = await screen.findByRole('dialog', { name: 'Disconnect Cleo Notes from Cleo Example?' })
    await user.click(within(confirmation).getByRole('button', { name: 'Revoke' }))
    expect(await within(confirmation).findByRole('alert')).toHaveTextContent('You are not allowed to do that')
  })
})
