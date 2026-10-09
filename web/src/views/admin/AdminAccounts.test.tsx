import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { renderApp } from '@/test/renderWithProviders'
import { recordRequests } from '@/test/fixtures'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

describe('Admin pages are owner-only', () => {
  it.each(['/admin', '/admin/enrollments', '/admin/audit'])('shows Forbidden at %s for a non-owner', async (path) => {
    await renderApp(path, 'enrolled')
    expect(await screen.findByText('Not allowed')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Accounts' })).toBeNull()
  })

  it('makes no admin API call for a non-owner', async () => {
    let seen: ReturnType<typeof recordRequests> = []
    await renderApp('/admin', 'enrolled', () => {
      seen = recordRequests()
    })
    await screen.findByText('Not allowed')
    expect(seen.length).toBeGreaterThan(0)
    expect(seen.filter((r) => r.url.startsWith('/admin'))).toHaveLength(0)
  })

  it('shows the Admin link to an owner and hides it from a normal user', async () => {
    await renderApp('/', 'enrolled')
    await screen.findByText('Canvas token enrolled')
    expect(screen.queryByRole('link', { name: 'Admin' })).toBeNull()
  })

  it('shows the Admin link to an owner', async () => {
    await renderApp('/', 'owner')
    await screen.findByText('Canvas token enrolled')
    expect(screen.getAllByRole('link', { name: 'Admin' }).length).toBeGreaterThan(0)
  })
})

describe('Admin accounts', () => {
  it('lists accounts for an owner, with status, role and Canvas state', async () => {
    await renderApp('/admin', 'owner')
    expect(await screen.findByRole('heading', { name: 'Accounts' })).toBeInTheDocument()
    expect(await screen.findByText('Bob Example')).toBeInTheDocument()
    expect(screen.getByText('Cleo Example')).toBeInTheDocument()
    expect(screen.getByText('Needs re-enrollment')).toBeInTheDocument()
    expect(screen.getAllByText('Pending').length).toBeGreaterThan(0)
    // Cursor pagination: the mock serves three per page.
    expect(screen.queryByText('Dev Example')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Load more' }))
    expect(await screen.findByText('Dev Example')).toBeInTheDocument()
  })

  it('approving sends the action with the CSRF header', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'owner')
    await screen.findByText('Bob Example')
    const seen = recordRequests()

    await user.click(screen.getByRole('button', { name: 'Approve' }))
    await waitFor(() => expect(seen.some((r) => r.method === 'POST')).toBe(true))
    const post = seen.find((r) => r.method === 'POST')
    expect(post?.url).toBe('/admin/accounts/acct%3A00000000-0000-4000-8000-000000000002/action')
    expect(post?.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(JSON.parse(post?.data as string)).toEqual({ action: 'approve' })
    expect(await screen.findByText('Account approved.')).toBeInTheDocument()
  })

  it('disabling needs a confirmation and cannot target the owner themselves', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'owner')
    await screen.findByText('Cleo Example')
    const seen = recordRequests()

    await user.click(screen.getByRole('button', { name: 'Actions: Cleo Example' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Disable' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Disable Cleo Example?')).toBeInTheDocument()
    expect(seen.some((r) => r.method === 'POST')).toBe(false)
    await user.click(within(dialog).getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(seen.some((r) => r.method === 'POST')).toBe(true))
    expect(JSON.parse(seen.find((r) => r.method === 'POST')?.data as string)).toEqual({ action: 'disable' })

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    // The signed-in owner's own row has Disable and role changes switched off.
    await user.click(screen.getByRole('button', { name: 'Actions: Ada Example' }))
    expect(await screen.findByRole('menuitem', { name: 'Disable' })).toHaveAttribute('aria-disabled', 'true')
  })

  it('changes a role only after a confirmation', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'owner')
    await screen.findByText('Cleo Example')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Actions: Cleo Example' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Make owner' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/see and change every account/)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Make owner' }))
    await waitFor(() => expect(seen.some((r) => r.method === 'POST')).toBe(true))
    expect(JSON.parse(seen.find((r) => r.method === 'POST')?.data as string)).toEqual({
      action: 'set_role',
      role: 'owner',
    })
  })

  it('filters by status', async () => {
    const user = userEvent.setup()
    await renderApp('/admin', 'owner')
    await screen.findByText('Bob Example')
    await user.click(screen.getByRole('combobox', { name: 'Status' }))
    await user.click(await screen.findByRole('option', { name: 'Pending' }))
    await waitFor(() => expect(screen.queryByText('Cleo Example')).toBeNull())
    expect(screen.getByText('Bob Example')).toBeInTheDocument()
  })
})

describe('Admin enrollments', () => {
  it('filters to rejected tokens and revokes after a confirmation', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/enrollments', 'owner')
    expect(await screen.findByRole('heading', { name: 'Canvas enrollments' })).toBeInTheDocument()
    await screen.findAllByText('Cleo Example')
    expect(screen.getByRole('button', { name: 'Revoke: Ada Example' })).toBeInTheDocument()

    await user.click(screen.getByRole('combobox', { name: 'State' }))
    await user.click(await screen.findByRole('option', { name: 'Needs re-enrollment' }))
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Revoke: Ada Example' })).toBeNull())

    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Revoke: Cleo Example' }))
    const dialog = await screen.findByRole('dialog')
    expect(seen.some((r) => r.method === 'DELETE')).toBe(false)
    await user.click(within(dialog).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(seen.some((r) => r.method === 'DELETE')).toBe(true))
    const del = seen.find((r) => r.method === 'DELETE')
    expect(del?.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(await screen.findByText('No enrollments yet.')).toBeInTheDocument()
  })
})

describe('Admin audit', () => {
  it('lists entries, filters by action and paginates', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/audit', 'owner')
    expect(await screen.findByRole('heading', { name: 'Audit log' })).toBeInTheDocument()
    expect(await screen.findByText('Approved account')).toBeInTheDocument()
    expect(screen.getByText('System')).toBeInTheDocument()
    expect(screen.getByText('provider: entra')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Load more' }))
    expect(await screen.findByText('Changed write tools')).toBeInTheDocument()

    await user.click(screen.getByRole('combobox', { name: 'Action' }))
    await user.click(await screen.findByRole('option', { name: 'Approved account' }))
    await waitFor(() => expect(screen.queryByText('Changed write tools')).toBeNull())
  })
})
