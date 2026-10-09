import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { hardNavigate } from '@/utils/navigate'
import { renderApp } from '@/test/renderWithProviders'
import { errorBody, meFixture, recordRequests, scriptAdapter } from '@/test/fixtures'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

beforeEach(() => {
  vi.mocked(hardNavigate).mockClear()
})

describe('Sign-in methods', () => {
  it('lists identities with the current session marked and the email verified state', async () => {
    await renderApp('/identities')
    expect(await screen.findByText('This session')).toBeInTheDocument()
    expect(screen.getByText('Email verified')).toBeInTheDocument()
    expect(screen.getByText('Microsoft')).toBeInTheDocument()
    expect(screen.getByText('GitHub')).toBeInTheDocument()
    expect(screen.getByText('Never used to sign in', { exact: false })).toBeInTheDocument()
  })

  it('offers the providers that are not linked yet and leaves the SPA for the server URL', async () => {
    const user = userEvent.setup()
    await renderApp('/identities')
    const seen = recordRequests()
    await user.click(await screen.findByRole('button', { name: 'Link Google' }))
    await waitFor(() => expect(hardNavigate).toHaveBeenCalledTimes(1))
    expect(hardNavigate).toHaveBeenCalledWith(`${window.location.origin}/account/api/login/google/start`)
    const post = seen.find((r) => r.method === 'POST')
    expect(post?.url).toBe('/me/identities/link/google')
    expect(post?.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
  })

  it('asks for a fresh sign-in when the session is too old to link', async () => {
    const user = userEvent.setup()
    await renderApp('/identities', 'enrolled', () => {
      scriptAdapter((r) => {
        if (r.url === '/me') return { status: 200, data: meFixture() }
        if (r.method === 'POST') return { status: 403, data: errorBody('link_requires_recent_login') }
        if (r.url === '/providers') return { status: 200, data: { providers: [], login_mode: 'open', signups_paused: false, mcp_url: 'https://x.test/mcp' } }
        return {
          status: 200,
          data: {
            identities: [
              { id: 'i1', provider_id: 'entra', provider_name: 'Microsoft', display: 'u@x.test', email: null, email_verified: false, linked_at: '2026-01-01T00:00:00Z', last_login_at: null, is_current_session: true },
            ],
            linkable_providers: [{ id: 'github', kind: 'github_oauth2', name: 'GitHub', icon: 'github' }],
          },
        }
      })
    })
    await user.click(await screen.findByRole('button', { name: 'Link GitHub' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Sign in again to link a provider')
    await user.click(within(alert).getByRole('button', { name: 'Sign in again' }))
    expect(hardNavigate).toHaveBeenCalledWith('/account/api/login/entra/start?return_to=%2Faccount%2Fidentities')
  })

  it('maps identity_in_use from the redirect back (?error=)', async () => {
    await renderApp('/identities?error=identity_in_use')
    expect(await screen.findByRole('alert')).toHaveTextContent('already linked to a different account')
  })

  it('unlinks only after a confirmation', async () => {
    const user = userEvent.setup()
    await renderApp('/identities')
    await screen.findByText('This session')
    const seen = recordRequests()
    const buttons = screen.getAllByRole('button', { name: 'Unlink' })
    await user.click(buttons[1])
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Unlink GitHub?')).toBeInTheDocument()
    expect(seen.some((r) => r.method === 'DELETE')).toBe(false)
    await user.click(within(dialog).getByRole('button', { name: 'Unlink' }))
    await waitFor(() => expect(seen.some((r) => r.method === 'DELETE')).toBe(true))
    expect(seen.find((r) => r.method === 'DELETE')?.url).toBe('/me/identities/ident-2')
    // Now only one is left: unlinking it is disabled and explained.
    await waitFor(() => expect(screen.getByRole('button', { name: 'Unlink' })).toBeDisabled())
    expect(screen.getByText('You cannot unlink your only sign-in method.')).toBeInTheDocument()
  })
})

describe('Connected apps', () => {
  it('lists grants, mutes revoked ones and revokes after a confirmation', async () => {
    const user = userEvent.setup()
    await renderApp('/connected-apps')
    expect(await screen.findByText('Claude')).toBeInTheDocument()
    expect(screen.getByText('Example MCP Client')).toBeInTheDocument()
    expect(screen.getByText(/^Revoked /)).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Revoke' })).toHaveLength(1)

    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Revoke' }))
    const dialog = await screen.findByRole('dialog')
    expect(seen.some((r) => r.method === 'DELETE')).toBe(false)
    await user.click(within(dialog).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(seen.some((r) => r.method === 'DELETE')).toBe(true))
    expect(seen.find((r) => r.method === 'DELETE')?.url).toBe('/me/grants/g_01')
    expect(await screen.findByText('Access revoked.')).toBeInTheDocument()
  })

  it('shows an empty state that points at the connector URL', async () => {
    await renderApp('/connected-apps', 'enrolled', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 200, data: meFixture() }
          : r.url === '/providers'
            ? { status: 200, data: { providers: [], login_mode: 'open', signups_paused: false, mcp_url: 'https://x.test/mcp' } }
            : { status: 200, data: { grants: [] } },
      )
    })
    expect(await screen.findByText('No apps are connected yet')).toBeInTheDocument()
    expect(await screen.findByRole('textbox', { name: 'MCP connector URL' })).toHaveValue('https://x.test/mcp')
  })
})

describe('Recent sign-ins', () => {
  it('shows outcome, localized reason, ip or unknown, and a device summary but never the raw user agent', async () => {
    await renderApp('/activity')
    expect(await screen.findByText('Signed in')).toBeInTheDocument()
    expect(screen.getByText('Denied')).toBeInTheDocument()
    expect(screen.getByText('Error')).toBeInTheDocument()
    expect(screen.getByText(/Sign-in was denied/)).toBeInTheDocument()
    expect(screen.getByText('203.0.113.7')).toBeInTheDocument()
    expect(screen.getAllByText('unknown').length).toBeGreaterThan(0)
    expect(screen.getByText('Chrome / Windows')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('Mozilla/5.0')
  })
})

describe('Global error states', () => {
  it('shows an offline banner with retry when the network is down', async () => {
    await renderApp('/connected-apps', 'enrolled', () => {
      scriptAdapter((r) => (r.url === '/me' ? { status: 200, data: meFixture() } : { status: 503, data: errorBody('token_store_unavailable') }))
    })
    expect(await screen.findByRole('alert')).toHaveTextContent('token store is unavailable')
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })

  it('shows the rate-limit message with retry-after seconds', async () => {
    await renderApp('/connected-apps', 'enrolled', () => {
      scriptAdapter((r) => (r.url === '/me' ? { status: 200, data: meFixture() } : { status: 429, data: errorBody('rate_limited', { retry_after_s: 45 }) }))
    })
    expect(await screen.findByRole('alert')).toHaveTextContent('Try again in 45 seconds')
  })
})
