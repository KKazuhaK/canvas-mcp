import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { hardNavigate } from '@/utils/navigate'
import { renderApp } from '@/test/renderWithProviders'
import { errorBody, meFixture, recordRequests, scriptAdapter } from '@/test/fixtures'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

describe('ConsentView', () => {
  beforeEach(() => {
    vi.mocked(hardNavigate).mockClear()
  })

  it('asks the question with the client, the person and the redirect host', async () => {
    await renderApp('/consent/t_9f2')
    expect(
      await screen.findByRole('heading', { name: 'Allow Claude to use Canvas MCP as Ada Example?' }),
    ).toBeInTheDocument()
    expect(screen.getByText(/sent back to claude\.ai/)).toBeInTheDocument()
    expect(screen.getByText('Read your Canvas data')).toBeInTheDocument()
    expect(screen.getByText(/This request expires/)).toBeInTheDocument()
  })

  it('renders client_uri as a hardened https link', async () => {
    await renderApp('/consent/t_9f2')
    const link = await screen.findByRole('link', { name: 'https://claude.ai' })
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  })

  it('does not link a client_uri that is not https', async () => {
    await renderApp('/consent/t_9f2', 'enrolled', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 200, data: meFixture() }
          : r.method === 'GET'
          ? {
              status: 200,
              data: {
                txn: 't_9f2',
                client_name: 'Evil',
                client_uri: 'javascript:alert(1)',
                redirect_host: 'evil.example',
                scopes: ['canvas:read', 'surprise:scope'],
                account_display_name: 'Test User',
                expires_at: '2099-01-01T00:00:00Z',
              },
            }
          : { status: 200, data: { redirect_url: 'x' } },
      )
    })
    expect(await screen.findByText('javascript:alert(1)')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /javascript/ })).toBeNull()
    // An unknown scope is shown as data, not hidden.
    expect(screen.getByText('Permission: surprise:scope')).toBeInTheDocument()
  })

  it('Allow posts the decision with the CSRF header and navigates to the server-built URL', async () => {
    const user = userEvent.setup()
    await renderApp('/consent/t_9f2')
    const seen = recordRequests()
    await user.click(await screen.findByRole('button', { name: 'Allow' }))
    await waitFor(() => expect(hardNavigate).toHaveBeenCalledTimes(1))
    expect(hardNavigate).toHaveBeenCalledWith(`${window.location.origin}/account/?consent=allowed`)
    const post = seen.find((r) => r.method === 'POST')
    expect(post?.url).toBe('/consent/t_9f2')
    expect(post?.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(JSON.parse(post?.data as string)).toEqual({ decision: 'allow' })
  })

  it('Deny posts deny', async () => {
    const user = userEvent.setup()
    await renderApp('/consent/t_9f2')
    const seen = recordRequests()
    await user.click(await screen.findByRole('button', { name: 'Deny' }))
    await waitFor(() => expect(hardNavigate).toHaveBeenCalled())
    expect(JSON.parse(seen.find((r) => r.method === 'POST')?.data as string)).toEqual({ decision: 'deny' })
  })

  it('refuses to navigate to a javascript: redirect from the server', async () => {
    const user = userEvent.setup()
    await renderApp('/consent/t_9f2', 'enrolled', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 200, data: meFixture() }
          : r.method === 'GET'
          ? {
              status: 200,
              data: {
                txn: 't_9f2',
                client_name: 'Claude',
                client_uri: null,
                redirect_host: 'claude.ai',
                scopes: ['canvas:read'],
                account_display_name: meFixture().account.display_name,
                expires_at: '2099-01-01T00:00:00Z',
              },
            }
          : { status: 200, data: { redirect_url: 'javascript:alert(1)' } },
      )
    })
    await user.click(await screen.findByRole('button', { name: 'Allow' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('not safe to open')
    expect(hardNavigate).not.toHaveBeenCalled()
  })

  it('shows the expired state for a used or expired transaction', async () => {
    await renderApp('/consent/expired')
    expect(await screen.findByText('This request has expired')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Allow' })).toBeNull()
  })

  it('shows the expired state for an unknown transaction', async () => {
    await renderApp('/consent/nope')
    expect(await screen.findByText('This request has expired')).toBeInTheDocument()
  })

  it('rejects a malformed transaction id without calling the API', async () => {
    await renderApp('/consent/bad!id')
    expect(await screen.findByText('This approval link is not valid')).toBeInTheDocument()
  })

  it('sends a signed-out visitor to sign in and keeps the transaction', async () => {
    const { router } = await renderApp('/consent/t_9f2', 'signed-out')
    await screen.findByRole('heading', { name: 'Canvas account' })
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'))
    const params = new URLSearchParams(router.state.location.search)
    expect(params.get('txn')).toBe('t_9f2')
    expect(params.get('return_to')).toBe('/account/consent/t_9f2')
    expect(await screen.findByText(/asked to approve the app/)).toBeInTheDocument()
  })

  it('surfaces a server refusal with the closed-code text', async () => {
    await renderApp('/consent/t_9f2', 'enrolled', () => {
      scriptAdapter(() => ({ status: 403, data: errorBody('forbidden') }))
    })
    expect(await screen.findByRole('alert')).toHaveTextContent('not allowed to do that')
  })
})
