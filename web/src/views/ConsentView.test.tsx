import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MOCK_TXN } from '@/dev/mockServer'
import { errorBody, meFixture, recordRequests, scriptAdapter } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'
import { hardNavigate } from '@/utils/navigate'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

const CSRF = 'mock-csrf-token-not-a-secret'
const consentPath = (txn: string) => `/consent?txn=${txn}`

beforeEach(() => {
  vi.mocked(hardNavigate).mockClear()
})

describe('the consent screen', () => {
  it('names a verified app by its domain, with where it returns to and what it may do', async () => {
    await renderApp(consentPath(MOCK_TXN.verified), 'local')
    expect(await screen.findByRole('heading', { name: 'Connect this app to your account?' })).toBeInTheDocument()
    expect(screen.getByText('claude.ai', { selector: 'p' })).toBeInTheDocument()
    expect(screen.getByText('Verified domain')).toBeInTheDocument()
    expect(screen.getByText('The app calls itself: Claude')).toBeInTheDocument()
    expect(screen.getByText('After you decide, you are sent back to:', { exact: false })).toBeInTheDocument()
    expect(screen.getByText('claude.ai', { selector: 'code' })).toBeInTheDocument()
    expect(screen.getByText('Canvas.Access')).toBeInTheDocument()
    expect(screen.getByText(/Write tools you have not switched on stay off/)).toBeInTheDocument()
    expect(screen.getByText(/Continue only if you just started connecting this app/)).toBeInTheDocument()
    expect(screen.getByText(/This request is valid until:/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Allow' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Deny' })).toBeEnabled()
    // neither warning applies
    expect(screen.queryByText(/Unverified/)).toBeNull()
    expect(screen.queryByText(/an app on this computer/)).toBeNull()
    expect(screen.queryByText('Waiting for approval')).toBeNull()
  })

  it('shows the signed-in account and a plain link to sign in as someone else', async () => {
    await renderApp(consentPath(MOCK_TXN.verified), 'local')
    await screen.findByRole('heading', { name: 'Connect this app to your account?' })
    expect(screen.getByText('Ada Example')).toBeInTheDocument()
    expect(screen.getByText(/ada@example.edu/)).toBeInTheDocument()
    const link = screen.getByRole('link', { name: 'Use a different account' })
    expect(link).toHaveAttribute('href', `/account/login?txn=${MOCK_TXN.verified}&reauth=1`)
  })

  it('warns that a self-registered app is unverified', async () => {
    await renderApp(consentPath(MOCK_TXN.unverified), 'local')
    await screen.findByRole('heading', { name: 'Connect this app to your account?' })
    expect(screen.getByText('Sample Desktop Tool')).toBeInTheDocument()
    expect(screen.getByText(/Unverified: a self-registered app/)).toBeInTheDocument()
    expect(screen.queryByText('Verified domain')).toBeNull()
  })

  it('warns when the approval is delivered to an app on the same computer', async () => {
    await renderApp(consentPath(MOCK_TXN.loopback), 'local')
    await screen.findByRole('heading', { name: 'Connect this app to your account?' })
    expect(screen.getByText('127.0.0.1', { selector: 'code' })).toBeInTheDocument()
    expect(screen.getByRole('note')).toHaveTextContent(/an app on this computer/)
  })

  it('treats text the app chose as text, never as markup', async () => {
    await renderApp(consentPath(MOCK_TXN.unverified), 'local', () => {
      scriptAdapter((request) =>
        request.url === '/me'
          ? { status: 200, data: meFixture({}, { features: { ...meFixture().features, consent: true } }) }
          : {
              status: 200,
              data: {
                client: { kind: 'dcr', label: '<img src=x onerror=alert(1)>', name: '<b>x</b>', host: null, verified: false },
                redirect: { host: 'app.test', loopback: false },
                scopes: [{ name: 'Canvas.Access' }],
                account: { display_name: 'Ada Example', username: 'ada@example.edu' },
                can_approve: true,
                expires_at: '2030-01-01T00:00:00Z',
              },
            },
      )
    })
    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
  })

  describe('deciding', () => {
    it('Allow sends the decision with the CSRF header and then goes to the address the server gave', async () => {
      const user = userEvent.setup()
      await renderApp(consentPath(MOCK_TXN.verified), 'local')
      await screen.findByRole('heading', { name: 'Connect this app to your account?' })
      const seen = recordRequests()
      await user.click(screen.getByRole('button', { name: 'Allow' }))
      await waitFor(() => expect(hardNavigate).toHaveBeenCalledTimes(1))
      const post = seen.find((request) => request.method === 'POST')
      expect(post?.url).toBe(`/consent/${MOCK_TXN.verified}`)
      expect(post?.headers['x-csrf-token']).toBe(CSRF)
      expect(JSON.parse(post?.data as string)).toEqual({ decision: 'approve' })
      const target = new URL(vi.mocked(hardNavigate).mock.calls[0][0])
      expect(target.origin + target.pathname).toBe('https://claude.ai/api/mcp/auth_callback')
      expect(target.searchParams.get('code')).toBe('mock-code')
      expect(target.searchParams.get('iss')).toBe('https://mcp.example.test/')
      // the answer is final: no second click, and the person is told where they are going
      expect(screen.getByRole('button', { name: 'Allow' })).toBeDisabled()
      expect(screen.getByRole('button', { name: 'Deny' })).toBeDisabled()
      expect(screen.getByRole('status')).toHaveTextContent('Returning to the app')
    })

    it('Deny goes back to the app with access_denied', async () => {
      const user = userEvent.setup()
      await renderApp(consentPath(MOCK_TXN.verified), 'local')
      await screen.findByRole('heading', { name: 'Connect this app to your account?' })
      const seen = recordRequests()
      await user.click(screen.getByRole('button', { name: 'Deny' }))
      await waitFor(() => expect(hardNavigate).toHaveBeenCalledTimes(1))
      expect(JSON.parse(seen.find((r) => r.method === 'POST')?.data as string)).toEqual({ decision: 'deny' })
      const target = new URL(vi.mocked(hardNavigate).mock.calls[0][0])
      expect(target.searchParams.get('error')).toBe('access_denied')
      expect(target.searchParams.has('code')).toBe(false)
    })

    it('goes to the loopback address of an app on this computer', async () => {
      const user = userEvent.setup()
      await renderApp(consentPath(MOCK_TXN.loopback), 'local')
      await screen.findByRole('heading', { name: 'Connect this app to your account?' })
      await user.click(screen.getByRole('button', { name: 'Allow' }))
      await waitFor(() => expect(hardNavigate).toHaveBeenCalledTimes(1))
      expect(vi.mocked(hardNavigate).mock.calls[0][0]).toMatch(/^http:\/\/127\.0\.0\.1:39211\/callback\?code=/)
    })

    it.each(['javascript:alert(1)', 'data:text/html,x', 'ftp://app.test/cb', 'http://evil.test/cb', 'https://user:pw@app.test/cb', ''])(
      'refuses to navigate to %j',
      async (unsafe) => {
        const user = userEvent.setup()
        await renderApp(consentPath(MOCK_TXN.verified), 'local', () => {
          scriptAdapter((request) => {
            if (request.url === '/me') {
              return { status: 200, data: meFixture({}, { features: { ...meFixture().features, consent: true } }) }
            }
            if (request.method === 'POST') return { status: 200, data: { redirect_to: unsafe } }
            return {
              status: 200,
              data: {
                client: { kind: 'cimd', label: 'claude.ai', name: 'Claude', host: 'claude.ai', verified: true },
                redirect: { host: 'claude.ai', loopback: false },
                scopes: [{ name: 'Canvas.Access' }],
                account: { display_name: 'Ada Example', username: 'ada@example.edu' },
                can_approve: true,
                expires_at: '2030-01-01T00:00:00Z',
              },
            }
          })
        })
        await user.click(await screen.findByRole('button', { name: 'Allow' }))
        expect(await screen.findByRole('alert')).toHaveTextContent('Nothing was granted')
        expect(hardNavigate).not.toHaveBeenCalled()
        expect(screen.getByRole('button', { name: 'Allow' })).toBeEnabled()
      },
    )

    it('shows the closed message when the decision is refused', async () => {
      const user = userEvent.setup()
      await renderApp(consentPath(MOCK_TXN.verified), 'local', () => {
        scriptAdapter((request) => {
          if (request.url === '/me') {
            return { status: 200, data: meFixture({}, { features: { ...meFixture().features, consent: true } }) }
          }
          if (request.method === 'POST') return { status: 400, data: errorBody('authorization_invalid') }
          return {
            status: 200,
            data: {
              client: { kind: 'dcr', label: 'App', name: 'App', host: null, verified: false },
              redirect: { host: 'app.test', loopback: false },
              scopes: [{ name: 'Canvas.Access' }],
              account: { display_name: 'Ada Example', username: 'ada@example.edu' },
              can_approve: true,
              expires_at: '2030-01-01T00:00:00Z',
            },
          }
        })
      })
      await user.click(await screen.findByRole('button', { name: 'Allow' }))
      expect(await screen.findByRole('alert')).toHaveTextContent('expired, was started in a different browser, or was already used')
      expect(hardNavigate).not.toHaveBeenCalled()
    })
  })

  describe('an account that waits for approval', () => {
    it('may look and cancel, but not allow', async () => {
      const user = userEvent.setup()
      await renderApp(consentPath(MOCK_TXN.verified), 'local-pending')
      expect(await screen.findByRole('heading', { name: 'Connect this app to your account?' })).toBeInTheDocument()
      expect(screen.getByText('Waiting for approval')).toBeInTheDocument()
      expect(screen.getByText(/you cannot connect apps yet/)).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Allow' })).toBeNull()
      expect(screen.queryByRole('button', { name: 'Deny' })).toBeNull()
      await user.click(screen.getByRole('button', { name: 'Cancel' }))
      await waitFor(() => expect(hardNavigate).toHaveBeenCalledTimes(1))
      expect(new URL(vi.mocked(hardNavigate).mock.calls[0][0]).searchParams.get('error')).toBe('access_denied')
    })
  })

  describe('a signed-out visitor', () => {
    it('goes to the server-side sign-in of this very request, and nothing is asked of the server', async () => {
      await renderApp(consentPath(MOCK_TXN.verified), 'signed-out')
      const seen = recordRequests()
      await waitFor(() => expect(hardNavigate).toHaveBeenCalledWith(`/account/login?txn=${MOCK_TXN.verified}`))
      expect(seen.find((request) => request.url.startsWith('/consent/'))).toBeUndefined()
      expect(screen.getByText('Taking you to sign in…')).toBeInTheDocument()
    })

    it('is not sent to the generic sign-in page when the session ends while the page is open', async () => {
      const { router } = await renderApp(consentPath(MOCK_TXN.verified), 'local', () => {
        scriptAdapter((request) =>
          request.url === '/me'
            ? { status: 200, data: meFixture({}, { features: { ...meFixture().features, consent: true } }) }
            : { status: 401, data: errorBody('not_authenticated') },
        )
      })
      await waitFor(() => expect(hardNavigate).toHaveBeenCalledWith(`/account/login?txn=${MOCK_TXN.verified}`))
      expect(router.state.location.pathname).toBe('/consent')
    })
  })

  describe('a request that cannot be used', () => {
    it('explains an expired, used or foreign request and offers no retry', async () => {
      await renderApp(consentPath('z'.repeat(43)), 'local')
      expect(await screen.findByRole('alert')).toHaveTextContent('expired, was started in a different browser, or was already used')
      expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull()
      expect(screen.queryByRole('button', { name: 'Allow' })).toBeNull()
      expect(screen.getByRole('link', { name: 'Back to home' })).toBeInTheDocument()
    })

    it.each(['', 'abc', 'A'.repeat(42), 'A'.repeat(44), '../../x', 'a b'.repeat(15)])(
      'a malformed id (%j) is refused without asking the server',
      async (txn) => {
        await renderApp(txn === '' ? '/consent' : `/consent?txn=${encodeURIComponent(txn)}`, 'local')
        const seen = recordRequests()
        expect(await screen.findByRole('alert')).toHaveTextContent('expired, was started in a different browser')
        expect(seen.find((request) => request.url.startsWith('/consent/'))).toBeUndefined()
        expect(hardNavigate).not.toHaveBeenCalled()
      },
    )

    it('says so when the app could not be confirmed', async () => {
      await renderApp(consentPath(MOCK_TXN.unavailable), 'local')
      expect(await screen.findByRole('alert')).toHaveTextContent('could not be confirmed')
      expect(screen.getByRole('alert')).toHaveTextContent('Nothing was granted')
    })

    it('offers another try when the store is unavailable, and only then', async () => {
      const user = userEvent.setup()
      let failing = true
      await renderApp(consentPath(MOCK_TXN.verified), 'local', () => {
        scriptAdapter((request) => {
          if (request.url === '/me') {
            return { status: 200, data: meFixture({}, { features: { ...meFixture().features, consent: true } }) }
          }
          if (failing) return { status: 503, data: errorBody('token_store_unavailable') }
          return {
            status: 200,
            data: {
              client: { kind: 'dcr', label: 'App', name: 'App', host: null, verified: false },
              redirect: { host: 'app.test', loopback: false },
              scopes: [{ name: 'Canvas.Access' }],
              account: { display_name: 'Ada Example', username: 'ada@example.edu' },
              can_approve: true,
              expires_at: '2030-01-01T00:00:00Z',
            },
          }
        })
      })
      expect(await screen.findByRole('alert')).toHaveTextContent('token store is unavailable')
      failing = false
      await user.click(screen.getByRole('button', { name: 'Try again' }))
      expect(await screen.findByRole('button', { name: 'Allow' })).toBeInTheDocument()
    })

    it('is not there when the server does not serve the consent screen', async () => {
      await renderApp(consentPath(MOCK_TXN.verified), 'enrolled')
      expect(await screen.findByText('Page not found')).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Allow' })).toBeNull()
    })
  })

  it('switches language only on request, and keeps the request id in the sign-in link', async () => {
    const user = userEvent.setup()
    await renderApp(consentPath(MOCK_TXN.verified), 'local')
    await screen.findByRole('heading', { name: 'Connect this app to your account?' })
    await user.click(screen.getByRole('button', { name: 'Switch language to \u4e2d\u6587' }))
    // "Connect this app to your account?" in Chinese
    expect(await screen.findByRole('heading', { name: /^\u8981\u628a\u8fd9\u4e2a\u5e94\u7528\u8fde\u63a5\u5230\u4f60\u7684\u8d26\u6237\u5417/ })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '\u4f7f\u7528\u5176\u4ed6\u8d26\u53f7' })).toHaveAttribute(
      'href',
      `/account/login?txn=${MOCK_TXN.verified}&reauth=1`,
    )
  })
})
