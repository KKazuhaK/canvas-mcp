import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { hardNavigate } from '@/utils/navigate'
import { renderApp } from '@/test/renderWithProviders'
import { errorBody, meFixture, recordRequests, scriptAdapter } from '@/test/fixtures'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

const BOB = '00000000-0000-4000-8000-000000000002'
const CLEO = '00000000-0000-4000-8000-000000000003'
const DEV = '00000000-0000-4000-8000-000000000004'
const MOCK_CSRF = 'mock-csrf-token-not-a-secret'

beforeEach(() => {
  vi.mocked(hardNavigate).mockClear()
})

/** The list item or table row that holds a name. */
function rowOf(name: string): HTMLElement {
  const cell = screen.getAllByText(name)[0]
  const row = cell.closest('li, tr')
  if (!(row instanceof HTMLElement)) throw new Error(`no row for ${name}`)
  return row
}

describe('Admin accounts', () => {
  it('lists the accounts with counts, status, token state and the actions the server offers', async () => {
    await renderApp('/admin', 'owner')
    expect(await screen.findByRole('heading', { name: 'Accounts' })).toBeInTheDocument()
    await screen.findByText('Bob Example')

    const counts = screen.getByRole('group', { name: 'Totals' })
    expect(within(counts).getByText('Accounts: 4')).toBeInTheDocument()
    expect(within(counts).getByText('Pending: 1')).toBeInTheDocument()
    expect(within(counts).getByText('Owners: 1')).toBeInTheDocument()

    const bob = rowOf('Bob Example')
    expect(within(bob).getByText('Pending')).toBeInTheDocument()
    expect(within(bob).getByRole('button', { name: 'Approve: Bob Example' })).toBeInTheDocument()
    expect(within(bob).getByRole('button', { name: 'Deny: Bob Example' })).toBeInTheDocument()
    expect(within(bob).queryByRole('button', { name: /^Disable/ })).toBeNull()

    const cleo = rowOf('Cleo Example')
    expect(within(cleo).getByText('Needs a new token')).toBeInTheDocument()
    expect(within(cleo).getByRole('button', { name: 'Disable: Cleo Example' })).toBeInTheDocument()
    expect(within(cleo).getByRole('button', { name: 'Remove token: Cleo Example' })).toBeInTheDocument()
    // Her token is already invalid, so it cannot be marked invalid again.
    expect(within(cleo).queryByRole('button', { name: /Mark token invalid/ })).toBeNull()

    const dev = rowOf('Dev Example')
    expect(within(dev).getByText('Disabled by an owner')).toBeInTheDocument()
    expect(within(dev).getByRole('button', { name: 'Enable: Dev Example' })).toBeInTheDocument()

    // The owner's own row can mark its token invalid but cannot disable itself.
    const self = rowOf('You').closest('li, tr') as HTMLElement
    expect(within(self).queryByRole('button', { name: /^Disable/ })).toBeNull()
  })

  it('offers no role changes, unlinking or app revocation (not built yet)', async () => {
    await renderApp('/admin', 'owner')
    await screen.findByText('Bob Example')
    for (const label of [/make owner/i, /make user/i, /unlink/i, /revoke/i]) {
      expect(screen.queryByRole('button', { name: label })).toBeNull()
    }
  })

  it('approves without a dialog, sends the CSRF header and refreshes the list', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'owner')
    await screen.findByText('Bob Example')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Approve: Bob Example' }))

    expect(await screen.findByText('Account approved.')).toBeInTheDocument()
    const post = seen.find((r) => r.method === 'POST')
    expect(post?.url).toBe(`/admin/accounts/${BOB}/approve`)
    expect(post?.headers['x-csrf-token']).toBe(MOCK_CSRF)
    expect(post?.data).toBeUndefined()
    await waitFor(() => expect(within(rowOf('Bob Example')).getByText('Active')).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: 'Approve: Bob Example' })).toBeNull()
  })

  it('asks before denying or disabling, and only then calls the server', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'owner')
    await screen.findByText('Bob Example')
    const seen = recordRequests()

    await user.click(screen.getByRole('button', { name: 'Deny: Bob Example' }))
    let dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Deny Bob Example?')).toBeInTheDocument()
    expect(seen.some((r) => r.method === 'POST')).toBe(false)
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(seen.some((r) => r.method === 'POST')).toBe(false)

    await user.click(screen.getByRole('button', { name: 'Disable: Cleo Example' }))
    dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: 'Disable' }))
    expect(await screen.findByText('Account disabled.')).toBeInTheDocument()
    expect(seen.find((r) => r.method === 'POST')?.url).toBe(`/admin/accounts/${CLEO}/disable`)
  })

  it('enables a disabled account', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'owner')
    await screen.findByText('Dev Example')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Enable: Dev Example' }))
    expect(await screen.findByText('Account enabled.')).toBeInTheDocument()
    expect(seen.find((r) => r.method === 'POST')?.url).toBe(`/admin/accounts/${DEV}/enable`)
  })

  it('filters by status through the server and searches the loaded names', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'owner')
    await screen.findByText('Bob Example')
    const seen = recordRequests()
    await user.click(screen.getByRole('combobox', { name: 'Status' }))
    await user.click(await screen.findByRole('option', { name: 'Pending' }))
    await waitFor(() => expect(seen.some((r) => r.url === '/admin/accounts')).toBe(true))
    expect(seen.find((r) => r.url === '/admin/accounts')?.params).toEqual({ status: 'pending' })
    await waitFor(() => expect(screen.queryByText('Cleo Example')).toBeNull())
    expect(screen.getByText('Bob Example')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Search name or username'), 'nobody')
    expect(await screen.findByText('No accounts match.')).toBeInTheDocument()
  })

  it('maps cannot_disable_self and last_owner to fixed messages', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'owner', () => {
      scriptAdapter((r) => {
        if (r.url === '/me') return { status: 200, data: meFixture({ role: 'owner' }, { features: { ...meFixture().features, admin: true } }) }
        if (r.method === 'POST') return { status: 409, data: errorBody('last_owner') }
        return {
          status: 200,
          data: {
            accounts: [
              {
                id: CLEO,
                key: `acct:${CLEO}`,
                display_name: 'Cleo Example',
                username: 'cleo@example.edu',
                role: 'owner',
                status: 'active',
                disabled_reason: null,
                disabled_at: null,
                created_at: null,
                approved_at: null,
                last_login_at: null,
                is_self: false,
                identity: null,
                enrollment: null,
                actions: ['disable'],
              },
            ],
            counts: { total: 1, active: 1, pending: 0, disabled: 0, owners: 1 },
          },
        }
      })
    })
    await user.click(await screen.findByRole('button', { name: 'Disable: Cleo Example' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: 'Disable' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('without an active owner')
  })

  it('asks for a fresh sign-in when the owner session is too old', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'stale-owner')
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Sign in again to continue')
    expect(screen.queryByText('Bob Example')).toBeNull()
    await user.click(within(alert).getByRole('button', { name: 'Sign in again' }))
    expect(hardNavigate).toHaveBeenCalledWith('/account/login?return_to=%2Faccount%2Fadmin')
  })
})

describe('Admin enrollments', () => {
  it('lists every token, and the accounts waiting for approval, with the actions the server offers', async () => {
    await renderApp('/admin/enrollments', 'owner')
    expect(await screen.findByRole('heading', { name: 'Canvas enrollments' })).toBeInTheDocument()
    await screen.findByText('Bob Example')
    const cleo = rowOf('Cleo Example')
    expect(within(cleo).getByText('Rejected by Canvas')).toBeInTheDocument()
    expect(within(cleo).getByText('Example University')).toBeInTheDocument()
    expect(within(cleo).getByRole('button', { name: 'Remove token: Cleo Example' })).toBeInTheDocument()
    // A pending account without a token is listed so it can be approved.
    expect(within(rowOf('Bob Example')).getByRole('button', { name: 'Approve: Bob Example' })).toBeInTheDocument()
  })

  it('narrows to the tokens that need replacing through the server', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/enrollments', 'owner')
    await screen.findByText('Bob Example')
    const seen = recordRequests()
    await user.click(screen.getByRole('combobox', { name: 'Show' }))
    await user.click(await screen.findByRole('option', { name: 'Tokens that need replacing' }))
    await waitFor(() => expect(screen.queryByText('Bob Example')).toBeNull())
    expect(seen.find((r) => r.url === '/admin/enrollments')?.params).toEqual({ filter: 'needs_reenroll' })
    expect(screen.getAllByText('Cleo Example').length).toBeGreaterThan(0)
  })

  it('removes a token only after a confirmation, then marks another invalid', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/enrollments', 'owner')
    await screen.findAllByText('Cleo Example')
    const seen = recordRequests()

    await user.click(screen.getByRole('button', { name: 'Remove token: Cleo Example' }))
    const dialog = await screen.findByRole('dialog')
    expect(seen.some((r) => r.method === 'DELETE')).toBe(false)
    await user.click(within(dialog).getByRole('button', { name: 'Remove token' }))
    expect(await screen.findByText('Token removed.')).toBeInTheDocument()
    const del = seen.find((r) => r.method === 'DELETE')
    expect(del?.url).toBe(`/admin/enrollments/${CLEO}`)
    expect(del?.headers['x-csrf-token']).toBe(MOCK_CSRF)

    await user.click(await screen.findByRole('button', { name: 'Mark token invalid: Ada Example' }))
    const second = await screen.findByRole('dialog')
    await user.click(within(second).getByRole('button', { name: 'Mark token invalid' }))
    expect(await screen.findByText('Token marked invalid.')).toBeInTheDocument()
    expect(seen.find((r) => r.url.endsWith('/mark-invalid'))?.method).toBe('POST')
  })
})

describe('Admin audit log', () => {
  it('shows the newest entries with who did what, and loads older ones with the cursor', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/audit', 'owner')
    expect(await screen.findByRole('heading', { name: 'Audit log' })).toBeInTheDocument()
    expect(await screen.findByText('Account created')).toBeInTheDocument()
    expect(screen.getByText('Enrolled Canvas token')).toBeInTheDocument()
    expect(screen.getByText('Approved account')).toBeInTheDocument()
    expect(screen.queryByText('Disabled account')).toBeNull() // the next page
    expect(screen.getAllByText('System').length).toBeGreaterThan(0)

    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Load more' }))
    expect(await screen.findByText('Disabled account')).toBeInTheDocument()
    expect(seen.find((r) => r.url === '/admin/audit')?.params).toEqual({ before: '5' })
    expect(screen.getByText('Server operator')).toBeInTheDocument()
    // One more page (a full page means there may be more), then the end.
    await user.click(screen.getByRole('button', { name: 'Load more' }))
    expect(await screen.findByText('Database upgraded')).toBeInTheDocument()
    expect(seen.filter((r) => r.url === '/admin/audit').map((r) => r.params)).toEqual([
      { before: '5' },
      { before: '2' },
    ])
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull())
  })

  it('renders detail as plain text and an unknown action as "Other"', async () => {
    await renderApp('/admin/audit', 'owner', () => {
      scriptAdapter((r) => {
        if (r.url === '/me') return { status: 200, data: meFixture({ role: 'owner' }, { features: { ...meFixture().features, admin: true } }) }
        return {
          status: 200,
          data: {
            entries: [
              {
                id: 9,
                at: '2026-01-01T00:00:00Z',
                action: 'something_new',
                actor: { kind: 'account', key: 'acct:x', name: '<img src=x onerror=alert(1)>' },
                target: null,
                reason: 'admin_disabled',
                detail: { tools: ['a_tool', 'b_tool'], count: 2, flag: true },
              },
            ],
            next_cursor: null,
          },
        }
      })
    })
    expect(await screen.findByText('Other')).toBeInTheDocument()
    expect(screen.getByText(/tools: a_tool, b_tool, count: 2, flag: true/)).toBeInTheDocument()
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
  })

  it('filters the loaded entries by action', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/audit', 'owner')
    await screen.findByText('Approved account')
    await user.click(screen.getByRole('combobox', { name: 'Action' }))
    await user.click(await screen.findByRole('option', { name: 'Approved account' }))
    await waitFor(() => expect(screen.queryByText('Enrolled Canvas token')).toBeNull())
    // The filter's own value and the one matching row.
    expect(screen.getAllByText('Approved account')).toHaveLength(2)
    expect(screen.queryByText('Account created')).toBeNull()
  })

  it('is closed to a user who is not an owner', async () => {
    await renderApp('/admin/audit', 'enrolled')
    expect(await screen.findByText('Not allowed')).toBeInTheDocument()
    expect(screen.queryByText('Account created')).toBeNull()
  })
})
