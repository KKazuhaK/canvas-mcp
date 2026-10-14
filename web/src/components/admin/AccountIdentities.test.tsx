import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { errorBody, meFixture, recordRequests, scriptAdapter } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'
import { hardNavigate } from '@/utils/navigate'
import { openManagedAccount } from '@/test/accountManagement'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

const CSRF = 'mock-csrf-token-not-a-secret'

beforeEach(() => {
  vi.mocked(hardNavigate).mockClear()
})

describe('Admin accounts: sign-in methods', () => {
  it('lists every sign-in method of an account with its provider, subject and times', async () => {
    await renderApp('/admin', 'multi-owner')
    await screen.findByText('Dev Example')
    const dev = within(await openManagedAccount('Dev Example', 'Sign-in & access'))
    expect(dev.getByText('Sign-in methods')).toBeInTheDocument()
    expect(dev.getByText('School SSO')).toBeInTheDocument()
    expect(dev.getByText('subject-4-oidc:school')).toBeInTheDocument()
    // An OIDC provider shows its issuer; the others do not.
    expect(dev.getByText('https://idp.example.edu/realms/school')).toBeInTheDocument()
    const cleo = within(await openManagedAccount('Cleo Example', 'Sign-in & access'))
    expect(cleo.queryByText(/Issuer/)).toBeNull()
  })

  it('offers Unlink only where the account keeps another method', async () => {
    await renderApp('/admin', 'multi-owner')
    await screen.findByText('Dev Example')
    let drawer = await openManagedAccount('Dev Example', 'Sign-in & access')
    expect(within(drawer).getAllByRole('button', { name: /^Unlink / })).toHaveLength(2)
    drawer = await openManagedAccount('Cleo Example', 'Sign-in & access')
    expect(within(drawer).queryByRole('button', { name: /^Unlink / })).toBeNull()
  })

  it('asks first, then unlinks with the CSRF header and updates the row', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'multi-owner')
    await screen.findByText('Dev Example')
    const drawer = await openManagedAccount('Dev Example', 'Sign-in & access')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Unlink School SSO from Dev Example' }))
    const dialog = await screen.findByRole('dialog', { name: 'Unlink School SSO from Dev Example?' })
    expect(within(dialog).getByText('Unlink School SSO from Dev Example?')).toBeInTheDocument()
    expect(within(dialog).getByText(/Connected apps stay connected/)).toBeInTheDocument()
    expect(seen.find((request) => request.method === 'DELETE')).toBeUndefined()

    await user.click(within(dialog).getByRole('button', { name: 'Unlink' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Unlink School SSO from Dev Example?' })).toBeNull())
    const call = seen.find((request) => request.method === 'DELETE')
    expect(call?.url).toBe('/admin/identities/41')
    expect(call?.headers['x-csrf-token']).toBe(CSRF)
    expect(await screen.findByText('Sign-in method unlinked.')).toBeInTheDocument()
    await waitFor(() =>
      expect(within(drawer).queryByRole('button', { name: /^Unlink / })).toBeNull(),
    )
  })

  it('asks for a new sign-in when the owner is not fresh', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'multi-owner', () => {
      scriptAdapter((request) => {
        if (request.url === '/me') {
          return {
            status: 200,
            data: meFixture(
              { role: 'owner' },
              { features: { ...meFixture().features, admin: true, identities: true } },
            ),
          }
        }
        if (request.url === '/providers') {
          return {
            status: 200,
            data: {
              providers: [
                { id: 'entra', kind: 'oidc', name: 'Microsoft', icon: 'microsoft', start_url: '/auth/login/entra' },
                { id: 'github', kind: 'oauth2', name: 'GitHub', icon: 'github', start_url: '/auth/login/github' },
              ],
              mcp_url: 'https://x.test/mcp',
            },
          }
        }
        if (request.method === 'DELETE') {
          return { status: 403, data: errorBody('reauth_required', { max_age_s: 600 }) }
        }
        if (request.url === '/admin/login-providers') {
          return { status: 200, data: { revision: 1, public_base_url: 'https://mcp.example.test', providers: ['entra', 'github'].map((id) => ({ id, protocol: id, enabled: true, rank: 0, config: {}, secret_present: true, callback_uri: '' })) } }
        }
        if (request.url.endsWith('/login-policy')) {
          return { status: 200, data: { revision: 1, policy: { allow_multiple: null, allowed_providers: null, sso_lock_provider: null } } }
        }
        return {
          status: 200,
          data: {
            accounts: [
              {
                id: '00000000-0000-4000-8000-000000000009',
                key: 'acct:00000000-0000-4000-8000-000000000009',
                display_name: 'Pat Example',
                username: 'pat',
                role: 'user',
                status: 'active',
                disabled_reason: null,
                disabled_at: null,
                created_at: null,
                approved_at: null,
                last_login_at: null,
                is_self: false,
                identity: null,
                enrollment: null,
                actions: [],
                identities: [
                  { id: '1', provider_id: 'entra', username: 'pat', subject: 's1', issuer: 'i', linked_at: null, last_login_at: null, can_unlink: true },
                  { id: '2', provider_id: 'github', username: 'pat', subject: '77', issuer: 'https://github.com', linked_at: null, last_login_at: null, can_unlink: true },
                ],
              },
            ],
            counts: { total: 1, active: 1, pending: 0, disabled: 0, owners: 0 },
          },
        }
      })
    })
    await openManagedAccount('Pat Example', 'Sign-in & access')
    await user.click(await screen.findByRole('button', { name: 'Unlink GitHub from Pat Example' }))
    const dialog = await screen.findByRole('dialog', { name: 'Unlink GitHub from Pat Example?' })
    await user.click(within(dialog).getByRole('button', { name: 'Unlink' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Sign in again to continue')
  })

  it('shows no sign-in method block when Entra is the only provider', async () => {
    await renderApp('/admin', 'owner')
    await screen.findByText('Dev Example')
    const drawer = await openManagedAccount('Dev Example', 'Sign-in & access')
    expect(within(drawer).queryByText('Sign-in methods')).toBeNull()
  })
})
