import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { hardNavigate } from '@/utils/navigate'
import { renderApp } from '@/test/renderWithProviders'
import { recordRequests } from '@/test/fixtures'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

describe('routing and the session gate', () => {
  it('shows the signed-out landing page at / when /me answers 401', async () => {
    await renderApp('/', 'signed-out')
    expect(await screen.findByRole('heading', { name: 'Canvas account' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/login')
    expect(await screen.findByRole('textbox', { name: 'MCP connector URL' })).toBeInTheDocument()
    expect(screen.queryByLabelText(/Canvas access token/)).toBeNull()
  })

  it('shows the account page at / when signed in', async () => {
    await renderApp('/', 'enrolled')
    expect(await screen.findByText('Canvas token enrolled')).toBeInTheDocument()
    expect(screen.getByText(/Signed in as ada@example.edu/)).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: 'Main navigation' })).toBeInTheDocument()
  })

  it('sends a signed-out visitor from a protected page to /login with a validated return_to', async () => {
    const { router } = await renderApp('/write-tools', 'signed-out')
    await screen.findByRole('link', { name: /Sign in with Microsoft/ })
    expect(router.state.location.pathname).toBe('/login')
    expect(new URLSearchParams(router.state.location.search).get('return_to')).toBe('/account/write-tools')
  })

  it('renders not-found for an unknown path', async () => {
    await renderApp('/definitely/not/here', 'enrolled')
    expect(await screen.findByText('Page not found')).toBeInTheDocument()
  })

  it('walks the protected pages through the navigation', async () => {
    const user = userEvent.setup()
    await renderApp('/', 'enrolled')
    await screen.findByText('Canvas token enrolled')
    // `/` and the other pages sit under different route elements, so the layout
    // (and its nav) is rebuilt on navigation: look it up fresh each time.
    const link = (href: string) =>
      screen.getByRole('navigation', { name: 'Main navigation' }).querySelector(`a[href="${href}"]`) as HTMLElement

    await user.click(link('/write-tools'))
    expect(await screen.findByRole('heading', { name: 'Write tools' })).toBeInTheDocument()
    await user.click(link('/identities'))
    expect(await screen.findByRole('heading', { name: 'Sign-in methods' })).toBeInTheDocument()
    await user.click(link('/connected-apps'))
    expect(await screen.findByRole('heading', { name: 'Connected apps' })).toBeInTheDocument()
    await user.click(link('/activity'))
    expect(await screen.findByRole('heading', { name: 'Recent sign-ins' })).toBeInTheDocument()
    await user.click(link('/token'))
    expect(await screen.findByRole('heading', { name: 'Canvas token' })).toBeInTheDocument()
  })

  it('switches the UI language only when the toggle is pressed', async () => {
    const user = userEvent.setup()
    await renderApp('/', 'signed-out')
    expect(await screen.findByRole('link', { name: 'Sign in' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Switch language to 中文' }))
    expect(await screen.findByRole('link', { name: '登录' })).toBeInTheDocument()
    expect(document.documentElement.lang).toBe('zh')
    await user.click(screen.getByRole('button', { name: '切换语言为 English' }))
    expect(await screen.findByRole('link', { name: 'Sign in' })).toBeInTheDocument()
  })
})

describe('account status gate', () => {
  it('shows only the pending screen for an account awaiting approval', async () => {
    await renderApp('/', 'pending')
    expect(await screen.findByText('Waiting for approval')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Sign out' }).length).toBeGreaterThan(0)
    expect(screen.queryByLabelText(/Canvas access token/)).toBeNull()
    expect(screen.queryByRole('navigation', { name: 'Main navigation' })).toBeNull()
  })

  it('keeps a pending account off the write-tools page', async () => {
    await renderApp('/write-tools', 'pending')
    expect(await screen.findByText('Waiting for approval')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Write tools' })).toBeNull()
  })

  it('shows only a message and sign-out for a disabled account', async () => {
    await renderApp('/', 'disabled')
    expect(await screen.findByText('Account disabled')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Sign out' }).length).toBeGreaterThan(0)
    expect(screen.queryByLabelText(/Canvas access token/)).toBeNull()
  })
})

describe('home page states', () => {
  it('shows the how-to and the form to a person with no token yet', async () => {
    await renderApp('/', 'fresh')
    expect(await screen.findByText('Add your Canvas token')).toBeInTheDocument()
    expect(screen.getByLabelText(/Canvas access token/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Verify and save' })).toBeInTheDocument()
  })

  it('shows the invalid-token banner with the date', async () => {
    await renderApp('/', 'invalid')
    expect(await screen.findByText('Canvas rejected your token')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent(/Canvas has rejected your token since/)
  })

  it('shows the MCP URL with a copy button', async () => {
    await renderApp('/', 'fresh')
    const field = (await screen.findByRole('textbox', { name: 'MCP connector URL' })) as HTMLInputElement
    expect(field.value).toBe(`${window.location.origin}/mcp`)
    expect(field).toHaveAttribute('readonly')
    expect(screen.getByRole('button', { name: 'Copy connector URL' })).toBeInTheDocument()
  })
})

describe('sign out', () => {
  it('posts the logout with the CSRF header, then hard-navigates to /account/login', async () => {
    const user = userEvent.setup()
    const { client } = await renderApp('/', 'enrolled')
    await screen.findByText('Canvas token enrolled')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Sign out' }))
    await waitFor(() => expect(hardNavigate).toHaveBeenCalledWith('/account/login'))
    const post = seen.find((r) => r.url === '/session/logout')
    expect(post?.method).toBe('POST')
    expect(post?.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    // No stale account data survives.
    expect(client.getQueryCache().getAll()).toHaveLength(0)
  })

  it('sign-out-of-all-devices asks first', async () => {
    const user = userEvent.setup()
    await renderApp('/activity', 'enrolled')
    await screen.findByRole('heading', { name: 'Recent sign-ins' })
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Sign out of all devices' }))
    expect(seen.some((r) => r.url === '/session/logout')).toBe(false)
    const dialog = await screen.findByRole('dialog')
    await user.click(dialog.querySelectorAll('button')[1])
    await waitFor(() => expect(seen.some((r) => r.url === '/session/logout')).toBe(true))
    expect(seen.find((r) => r.url === '/session/logout')?.data).toBeUndefined()
  })
})
