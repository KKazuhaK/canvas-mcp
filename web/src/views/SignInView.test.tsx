import { act, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { hardNavigate } from '@/utils/navigate'
import { resources } from '@/i18n/options'
import { http } from '@/api/client'
import { keys } from '@/query/keys'
import { renderApp } from '@/test/renderWithProviders'
import { errorBody, scriptAdapter } from '@/test/fixtures'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

const SIGN_IN_CODES = [
  'state_invalid',
  'provider_error',
  'sign_in_incomplete',
  'sign_in_unverified',
  'wrong_tenant',
  'wrong_client',
  'bad_subject',
  'bad_roles',
  'access_denied',
  'access_disabled',
  'signups_paused',
  'token_store_unavailable',
] as const

const enErrors = resources.en.errors as Record<string, string>
const zhErrors = resources.zh.errors as Record<string, string>

describe('SignInView', () => {
  beforeEach(() => {
    vi.mocked(hardNavigate).mockClear()
  })

  it('offers the server-side sign-in as a plain link, one per provider', async () => {
    await renderApp('/sign-in', 'signed-out')
    const microsoft = await screen.findByRole('link', { name: /Sign in with Microsoft/ })
    expect(microsoft).toHaveAttribute('href', '/account/login')
    expect(screen.getAllByRole('link', { name: /Sign in with/ })).toHaveLength(1)
    expect(screen.getByRole('heading', { name: 'Canvas account' })).toBeInTheDocument()
    expect(hardNavigate).not.toHaveBeenCalled()
  })

  it('passes a valid return_to through to the server redirect', async () => {
    await renderApp('/sign-in?return_to=%2Faccount%2Fwrite-tools', 'signed-out')
    const link = await screen.findByRole('link', { name: /Sign in with Microsoft/ })
    expect(link).toHaveAttribute('href', '/account/login?return_to=%2Faccount%2Fwrite-tools')
  })

  it.each([
    ['//evil.example'],
    ['https://evil.example/account'],
    ['/\\evil.example'],
    ['javascript:alert(1)'],
    ['/account/login'],
    ['/account/api/me'],
    ['/account//x'],
  ])('drops an unsafe return_to (%s)', async (bad) => {
    await renderApp(`/sign-in?return_to=${encodeURIComponent(bad)}`, 'signed-out')
    const link = await screen.findByRole('link', { name: /Sign in with Microsoft/ })
    expect(link).toHaveAttribute('href', '/account/login')
  })

  it('never redirects on its own, even with a single provider', async () => {
    await renderApp('/sign-in', 'signed-out')
    await screen.findByRole('link', { name: /Sign in with Microsoft/ })
    expect(hardNavigate).not.toHaveBeenCalled()
  })

  it.each(SIGN_IN_CODES)('shows the fixed text for ?error=%s', async (code) => {
    await renderApp(`/sign-in?error=${code}`, 'signed-out')
    // The sign-in button stays, so the person can try again.
    expect(await screen.findByRole('link', { name: /Sign in with Microsoft/ })).toBeInTheDocument()
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('Sign-in did not complete')
    expect(alert).toHaveTextContent(enErrors[code])
  })

  it('has a distinct message for every sign-in code', () => {
    const texts = SIGN_IN_CODES.map((code) => enErrors[code])
    expect(new Set(texts).size).toBe(SIGN_IN_CODES.length)
    for (const code of SIGN_IN_CODES) expect(zhErrors[code].length).toBeGreaterThan(0)
  })

  it('treats an unknown error value as the generic message without echoing it', async () => {
    await renderApp('/sign-in?error=%3Cb%3Eowned%3C%2Fb%3E', 'signed-out')
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Something went wrong on our side')
    expect(alert).not.toHaveTextContent('owned')
    expect(document.body.innerHTML).not.toContain('<b>owned')
  })

  it('does not show the codes of features that are gone (identity linking, consent)', async () => {
    await renderApp('/sign-in?error=identity_in_use', 'signed-out')
    expect(await screen.findByRole('alert')).toHaveTextContent('Something went wrong on our side')
  })

  it('offers a retry when the providers cannot be loaded', async () => {
    await renderApp('/sign-in', 'signed-out', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 401, data: errorBody('not_authenticated') }
          : { status: 500, data: errorBody('internal_error') },
      )
    })
    expect(await screen.findByText('Could not load the sign-in options')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /Sign in with/ })).toBeNull()
  })

  it('only offers a provider whose start URL is a plain path on this site', async () => {
    await renderApp('/sign-in', 'signed-out', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 401, data: errorBody('not_authenticated') }
          : {
              status: 200,
              data: {
                providers: [
                  { id: 'evil', kind: 'oidc', name: 'Evil', icon: 'key', start_url: 'https://evil.example/start' },
                  { id: 'evil2', kind: 'oidc', name: 'Evil Two', icon: 'key', start_url: '//evil.example/start' },
                  { id: 'entra', kind: 'oidc', name: 'Microsoft', icon: 'microsoft', start_url: '/account/login' },
                ],
                mcp_url: 'https://x.test/mcp',
              },
            },
      )
    })
    expect(await screen.findByRole('link', { name: /Sign in with Microsoft/ })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /Evil/ })).toBeNull()
  })

  it('explains an empty provider list', async () => {
    await renderApp('/sign-in', 'signed-out', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 401, data: errorBody('not_authenticated') }
          : { status: 200, data: { providers: [], mcp_url: 'https://x.test/mcp' } },
      )
    })
    expect(await screen.findByText('No sign-in method is set up')).toBeInTheDocument()
  })

  it('sends someone who is already signed in on to where the sign-in was headed', async () => {
    const { router } = await renderApp('/sign-in?return_to=%2Faccount%2Factivity', 'enrolled')
    expect(await screen.findByRole('heading', { name: 'Recent sign-ins' })).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/activity')
  })

  it('sends a signed-in visitor with no return_to to the account page', async () => {
    const { router } = await renderApp('/sign-in', 'enrolled')
    await screen.findByRole('navigation', { name: 'Main navigation' })
    expect(router.state.location.pathname).toBe('/')
  })
})

/** The server after the session cookie expired: everything but the provider list says 401. */
function endSession(): void {
  scriptAdapter((r) =>
    r.url === '/providers'
      ? {
          status: 200,
          data: {
            providers: [
              { id: 'entra', kind: 'oidc', name: 'Microsoft', icon: 'microsoft', start_url: '/account/login' },
            ],
            mcp_url: 'https://x.test/mcp',
          },
        }
      : { status: 401, data: errorBody('not_authenticated') },
  )
}

describe('SignInView after the session ended mid-use', () => {
  it('says so when an API call answers 401, and keeps return_to', async () => {
    const { router } = await renderApp('/activity', 'enrolled')
    await screen.findByRole('heading', { name: 'Recent sign-ins' })
    endSession()
    await act(async () => {
      await http.get('/me/login-history').catch(() => undefined)
    })
    const notice = await screen.findByRole('status', { name: '' })
    expect(notice).toHaveTextContent('Your session has ended')
    expect(notice).toHaveTextContent('Anything you had typed but not saved was not kept.')
    expect(router.state.location.pathname).toBe('/sign-in')
    expect(router.state.location.search).toContain('return_to=%2Faccount%2Factivity')
    // It is not the "sign-in failed" alert, and the sign-in button is still offered.
    expect(screen.queryByRole('alert')).toBeNull()
    expect(await screen.findByRole('link', { name: /Sign in with Microsoft/ })).toBeInTheDocument()
  })

  it('says so when the session probe starts answering 401 after it had worked', async () => {
    const { router, client } = await renderApp('/activity', 'enrolled')
    await screen.findByRole('heading', { name: 'Recent sign-ins' })
    endSession()
    await act(async () => {
      await client.refetchQueries({ queryKey: keys.me })
    })
    expect(await screen.findByText('Your session has ended')).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/sign-in')
  })

  it('shows nothing of the sort to someone who was never signed in', async () => {
    const { router } = await renderApp('/activity', 'signed-out')
    await screen.findByRole('link', { name: /Sign in with Microsoft/ })
    expect(router.state.location.pathname).toBe('/sign-in')
    expect(screen.queryByText('Your session has ended')).toBeNull()
  })

  it('cannot be switched on from the address bar', async () => {
    await renderApp('/sign-in?sessionEnded=true&error=', 'signed-out')
    await screen.findByRole('link', { name: /Sign in with Microsoft/ })
    expect(screen.queryByText('Your session has ended')).toBeNull()
  })

  it('has the same notice in Chinese', () => {
    const zh = resources.zh.auth as { login: { sessionEnded: { title: string; body: string } } }
    expect(zh.login.sessionEnded.title.length).toBeGreaterThan(0)
    expect(zh.login.sessionEnded.body.length).toBeGreaterThan(0)
  })
})
