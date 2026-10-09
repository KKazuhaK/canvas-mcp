import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { hardNavigate } from '@/utils/navigate'
import { renderApp } from '@/test/renderWithProviders'
import { errorBody, meFixture, recordRequests, scriptAdapter } from '@/test/fixtures'
import { useLanguage } from '@/stores/language'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

const FIXED_SCHOOL = {
  mode: 'fixed',
  choices: [],
  selected: null,
  sole: { host: 'canvas.example.edu', name: 'Example University' },
  search_enabled: false,
}

beforeEach(() => {
  vi.mocked(hardNavigate).mockClear()
})

describe('routing and the session gate', () => {
  it('shows the signed-out landing page at / when /me answers 401', async () => {
    await renderApp('/', 'signed-out')
    expect(await screen.findByRole('heading', { name: 'Canvas account' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/sign-in')
    expect(await screen.findByRole('textbox', { name: 'MCP connector URL' })).toBeInTheDocument()
    expect(screen.queryByLabelText(/Canvas access token/)).toBeNull()
  })

  it('shows the account page at / when signed in', async () => {
    await renderApp('/', 'enrolled')
    expect(await screen.findByText('Canvas token enrolled')).toBeInTheDocument()
    expect(screen.getByText(/Signed in as ada@example.edu/)).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: 'Main navigation' })).toBeInTheDocument()
  })

  it('sends a signed-out visitor from a protected page to /sign-in with a validated return_to', async () => {
    const { router } = await renderApp('/write-tools', 'signed-out')
    await screen.findByRole('link', { name: /Sign in with Microsoft/ })
    expect(router.state.location.pathname).toBe('/sign-in')
    expect(new URLSearchParams(router.state.location.search).get('return_to')).toBe('/account/write-tools')
  })

  it('renders not-found for an unknown path', async () => {
    await renderApp('/definitely/not/here', 'enrolled')
    expect(await screen.findByText('Page not found')).toBeInTheDocument()
  })

  it.each(['/identities', '/connected-apps', '/consent/abc', '/login'])(
    'has no page at %s (that feature is not built, or lives on the server)',
    async (path) => {
      const { router } = await renderApp(path, 'enrolled')
      expect(await screen.findByText('Page not found')).toBeInTheDocument()
      expect(router.state.location.pathname).toBe(path)
    },
  )

  it('lists only the pages the server serves, and walks them through the navigation', async () => {
    const user = userEvent.setup()
    await renderApp('/', 'enrolled')
    await screen.findByText('Canvas token enrolled')
    const nav = () => screen.getByRole('navigation', { name: 'Main navigation' })
    // `/` and the other pages sit under different route elements, so the layout
    // (and its nav) is rebuilt on navigation: look it up fresh each time.
    const link = (href: string) => nav().querySelector(`a[href="${href}"]`) as HTMLElement

    expect([...nav().querySelectorAll('a')].map((a) => a.getAttribute('href'))).toEqual([
      '/',
      '/token',
      '/write-tools',
      '/activity',
    ])

    await user.click(link('/write-tools'))
    expect(await screen.findByRole('heading', { name: 'Write tools' })).toBeInTheDocument()
    await user.click(link('/activity'))
    expect(await screen.findByRole('heading', { name: 'Recent sign-ins' })).toBeInTheDocument()
    await user.click(link('/token'))
    expect(await screen.findByRole('heading', { name: 'Canvas token' })).toBeInTheDocument()
  })

  it('hides write tools when the server has no write-tool catalog', async () => {
    await renderApp('/write-tools', 'no-write-tools')
    expect(await screen.findByText('Page not found')).toBeInTheDocument()
    const nav = screen.getByRole('navigation', { name: 'Main navigation' })
    expect(nav.querySelector('a[href="/write-tools"]')).toBeNull()
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

describe('the language the server remembers', () => {
  it('tells the server about the toggle when signed in, with the CSRF header', async () => {
    const user = userEvent.setup()
    await renderApp('/', 'enrolled')
    await screen.findByText('Canvas token enrolled')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Switch language to 中文' }))
    await waitFor(() => expect(seen.some((r) => r.url === '/me/ui-locale')).toBe(true))
    const put = seen.find((r) => r.url === '/me/ui-locale')
    expect(put?.method).toBe('PUT')
    expect(put?.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(JSON.parse(put?.data as string)).toEqual({ locale: 'zh' })
  })

  it('does not call the server when signed out', async () => {
    const user = userEvent.setup()
    await renderApp('/', 'signed-out')
    await screen.findByRole('link', { name: 'Sign in' })
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Switch language to 中文' }))
    await screen.findByRole('link', { name: '登录' })
    expect(seen.filter((r) => r.url === '/me/ui-locale')).toHaveLength(0)
  })

  it('applies the remembered language only when this browser has no choice of its own', async () => {
    await renderApp('/token', 'enrolled', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 200, data: meFixture({}, { ui_locale: 'zh' }) }
          : { status: 200, data: FIXED_SCHOOL },
      )
    })
    expect(await screen.findByRole('heading', { name: 'Canvas 令牌' })).toBeInTheDocument()
    expect(useLanguage.getState().lang).toBe('zh')
    // Not stored: it is the server's memory, not a choice made here.
    expect(window.localStorage.getItem('canvas_mcp_lang')).toBeNull()
  })

  it('keeps the English default the person chose in this browser', async () => {
    window.localStorage.setItem('canvas_mcp_lang', 'en')
    await renderApp('/token', 'enrolled', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 200, data: meFixture({}, { ui_locale: 'zh' }) }
          : { status: 200, data: FIXED_SCHOOL },
      )
    })
    expect(await screen.findByRole('heading', { name: 'Canvas token' })).toBeInTheDocument()
    expect(useLanguage.getState().lang).toBe('en')
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

  it('a pending account never asks for the token form data', async () => {
    await renderApp('/', 'pending')
    await screen.findByText('Waiting for approval')
    const seen = recordRequests()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Refresh' }))
    await waitFor(() => expect(seen.some((r) => r.url === '/me')).toBe(true))
    // The sign-in history is the one /me/ read a pending account is allowed (and shown).
    expect(seen.filter((r) => r.url.startsWith('/me/') && r.url !== '/me/login-history')).toEqual([])
  })

  it('shows a pending account its recent sign-ins, as the server-rendered page did', async () => {
    await renderApp('/', 'pending')
    await screen.findByText('Waiting for approval')
    const history = await screen.findByRole('region', { name: 'Recent sign-ins' })
    expect((await within(history).findAllByText('Account created')).length).toBeGreaterThan(0)
    // Still no navigation, token form or write tools.
    expect(screen.queryByRole('navigation', { name: 'Main navigation' })).toBeNull()
    expect(screen.queryByLabelText(/Canvas access token/)).toBeNull()
  })
})

describe('owner pages', () => {
  it('lists Admin in the navigation for an owner only', async () => {
    await renderApp('/', 'owner')
    await screen.findByText('Canvas token enrolled')
    expect(
      screen.getByRole('navigation', { name: 'Main navigation' }).querySelector('a[href="/admin"]'),
    ).not.toBeNull()
  })

  it('shows a normal user a refusal on /admin, without calling the admin API', async () => {
    await renderApp('/admin', 'enrolled')
    expect(await screen.findByText('Not allowed')).toBeInTheDocument()
    expect(
      screen.getByRole('navigation', { name: 'Main navigation' }).querySelector('a[href="/admin"]'),
    ).toBeNull()
  })
})

describe('home page states', () => {
  it('shows the how-to and the form to a person with no token yet', async () => {
    await renderApp('/', 'fresh')
    expect(await screen.findByText('Add your Canvas token')).toBeInTheDocument()
    expect(screen.getByLabelText(/Canvas access token/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Verify and save' })).toBeInTheDocument()
  })

  it('shows the invalid-token banner', async () => {
    await renderApp('/', 'invalid')
    expect(await screen.findByText('Canvas rejected your token')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent(/Since /)
  })

  it('shows the MCP URL with a copy button', async () => {
    await renderApp('/', 'fresh')
    const field = (await screen.findByRole('textbox', { name: 'MCP connector URL' })) as HTMLInputElement
    expect(field.value).toBe(`${window.location.origin}/mcp`)
    expect(field).toHaveAttribute('readonly')
    expect(screen.getByRole('button', { name: 'Copy connector URL' })).toBeInTheDocument()
  })
})

describe('sign out and session loss', () => {
  it('posts the logout with the CSRF header, then hard-navigates to the landing page', async () => {
    const user = userEvent.setup()
    const { client } = await renderApp('/', 'enrolled')
    await screen.findByText('Canvas token enrolled')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Sign out' }))
    await waitFor(() => expect(hardNavigate).toHaveBeenCalledWith('/account/'))
    const post = seen.find((r) => r.url === '/session/logout')
    expect(post?.method).toBe('POST')
    expect(post?.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(post?.data).toBeUndefined()
    expect(post?.params).toBeUndefined()
    // No stale account data survives.
    expect(client.getQueryCache().getAll()).toHaveLength(0)
  })

  it('has no "sign out of all devices" (the server does not offer it)', async () => {
    await renderApp('/activity', 'enrolled')
    await screen.findByRole('heading', { name: 'Recent sign-ins' })
    expect(screen.queryByText(/all devices/i)).toBeNull()
  })

  it('goes to the sign-in page, keeping the page as return_to, when a call answers 401', async () => {
    let meCalls = 0
    const { router, client } = await renderApp('/activity', 'enrolled', () => {
      scriptAdapter((r) => {
        if (r.url === '/me') {
          meCalls += 1
          // Signed in once; after the session is gone /me answers 401 like the server.
          return meCalls === 1
            ? { status: 200, data: meFixture() }
            : { status: 401, data: errorBody('not_authenticated') }
        }
        return { status: 401, data: errorBody('not_authenticated') }
      })
    })
    await waitFor(() => expect(router.state.location.pathname).toBe('/sign-in'))
    expect(new URLSearchParams(router.state.location.search).get('return_to')).toBe('/account/activity')
    expect(client.getQueryCache().find({ queryKey: ['login-history'] })).toBeUndefined()
    expect(hardNavigate).not.toHaveBeenCalled()
  })

  it('a pending screen can sign out too', async () => {
    const user = userEvent.setup()
    await renderApp('/', 'pending')
    await screen.findByText('Waiting for approval')
    const card = screen.getByRole('region', { name: 'Waiting for approval' })
    await user.click(within(card).getByRole('button', { name: 'Sign out' }))
    await waitFor(() => expect(hardNavigate).toHaveBeenCalledWith('/account/'))
  })
})
