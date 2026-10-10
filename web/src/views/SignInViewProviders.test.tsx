import { screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { errorBody, scriptAdapter } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'
import { hardNavigate } from '@/utils/navigate'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

const TXN = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO_-'

const PROVIDERS = [
  { id: 'entra', kind: 'oidc', name: 'Microsoft', icon: 'microsoft', start_url: '/account/login/entra' },
  { id: 'google', kind: 'oidc', name: 'Google', icon: 'google', start_url: '/account/login/google' },
  { id: 'github', kind: 'oauth2', name: 'GitHub', icon: 'github', start_url: '/account/login/github' },
  { id: 'oidc:school', kind: 'oidc', name: 'School SSO', icon: 'key', start_url: '/account/login/oidc/school' },
]

beforeEach(() => {
  vi.mocked(hardNavigate).mockClear()
})

function signedOutWithProviders(): void {
  scriptAdapter((request) =>
    request.url === '/me'
      ? { status: 401, data: errorBody('not_authenticated') }
      : { status: 200, data: { providers: PROVIDERS, mcp_url: 'https://x.test/mcp' } },
  )
}

describe('SignInView with several providers', () => {
  it('lists every provider in the configured order, each with its own built-in icon', async () => {
    await renderApp('/sign-in', 'signed-out', signedOutWithProviders)
    const links = await screen.findAllByRole('link', { name: /Sign in with/ })
    expect(links.map((link) => link.textContent)).toEqual([
      'Sign in with Microsoft',
      'Sign in with Google',
      'Sign in with GitHub',
      'Sign in with School SSO',
    ])
    expect(links.map((link) => link.getAttribute('href'))).toEqual([
      '/account/login/entra',
      '/account/login/google',
      '/account/login/github',
      '/account/login/oidc/school',
    ])
    // Inline SVG only: nothing is fetched for the icons.
    for (const link of links) {
      expect(link.querySelector('svg')).not.toBeNull()
      expect(link.querySelector('img')).toBeNull()
    }
  })

  it('carries a waiting app and the request for another account to every provider', async () => {
    await renderApp(`/sign-in?txn=${TXN}&reauth=1`, 'signed-out', signedOutWithProviders)
    const links = await screen.findAllByRole('link', { name: /Sign in with/ })
    expect(screen.getByRole('note')).toHaveTextContent('An app is waiting for you to sign in')
    expect(links.map((link) => link.getAttribute('href'))).toEqual([
      `/account/login/entra?txn=${TXN}&reauth=1`,
      `/account/login/google?txn=${TXN}&reauth=1`,
      `/account/login/github?txn=${TXN}&reauth=1`,
      `/account/login/oidc/school?txn=${TXN}&reauth=1`,
    ])
  })

  it('carries a return address and no request id when no app is waiting', async () => {
    await renderApp('/sign-in?return_to=%2Faccount%2Factivity', 'signed-out', signedOutWithProviders)
    const link = await screen.findByRole('link', { name: /Sign in with GitHub/ })
    expect(link).toHaveAttribute('href', '/account/login/github?return_to=%2Faccount%2Factivity')
    expect(screen.queryByRole('note')).toBeNull()
  })

  it('keeps the request id out of the link unless it has the exact shape, and drops a bad return address', async () => {
    await renderApp(
      `/sign-in?txn=${encodeURIComponent('x'.repeat(10))}&return_to=%2F%2Fevil.example&reauth=yes`,
      'signed-out',
      signedOutWithProviders,
    )
    const link = await screen.findByRole('link', { name: /Sign in with Google/ })
    expect(link).toHaveAttribute('href', '/account/login/google')
    expect(screen.queryByRole('note')).toBeNull()
  })

  it('does not carry a return address next to a waiting app', async () => {
    await renderApp(
      `/sign-in?txn=${TXN}&return_to=%2Faccount%2Factivity`,
      'signed-out',
      signedOutWithProviders,
    )
    const link = await screen.findByRole('link', { name: /Sign in with Google/ })
    expect(link).toHaveAttribute('href', `/account/login/google?txn=${TXN}`)
  })

  it('stays open for someone who is already signed in and asked for another account', async () => {
    const { router } = await renderApp('/sign-in?reauth=1', 'multi')
    const links = await screen.findAllByRole('link', { name: /Sign in with/ })
    expect(links).toHaveLength(4)
    expect(links[1]).toHaveAttribute('href', '/account/login/google?reauth=1')
    expect(router.state.location.pathname).toBe('/sign-in')
  })

  it('stays open for a waiting app even when the person is signed in', async () => {
    const { router } = await renderApp(`/sign-in?txn=${TXN}`, 'multi')
    await screen.findAllByRole('link', { name: /Sign in with/ })
    expect(router.state.location.pathname).toBe('/sign-in')
  })

  it('still sends a signed-in visitor on when nothing asks for a new sign-in', async () => {
    const { router } = await renderApp('/sign-in', 'multi')
    await screen.findByRole('navigation', { name: 'Main navigation' })
    expect(router.state.location.pathname).toBe('/')
  })

  it('takes a signed-in person whose link failed to the Sign-in methods screen with the closed code', async () => {
    const { router } = await renderApp('/sign-in?error=provider_error', 'multi')
    await waitFor(() => expect(router.state.location.pathname).toBe('/sign-in-methods'))
    expect(router.state.location.search).toBe('?error=provider_error')
    const alert = await screen.findByRole('alert')
    expect(within(alert).getByText('The sign-in method was not added')).toBeInTheDocument()
  })

  it('never shows provider text from a forwarded code', async () => {
    const { router } = await renderApp('/sign-in?error=%3Cb%3Ex%3C%2Fb%3E', 'multi')
    await waitFor(() => expect(router.state.location.pathname).toBe('/sign-in-methods'))
    await screen.findByRole('alert')
    expect(screen.queryByText('x', { selector: 'b' })).toBeNull()
  })

  it('without the Sign-in methods screen a signed-in visitor with an error still goes home', async () => {
    const { router } = await renderApp('/sign-in?error=provider_error', 'enrolled')
    await screen.findByRole('navigation', { name: 'Main navigation' })
    expect(router.state.location.pathname).toBe('/')
  })

  it('shows the closed message of a provider that failed and keeps the buttons', async () => {
    await renderApp('/sign-in?error=provider_error', 'signed-out', signedOutWithProviders)
    expect(await screen.findAllByRole('link', { name: /Sign in with/ })).toHaveLength(4)
    const alert = screen.getByRole('alert')
    expect(within(alert).getByText('Sign-in did not complete')).toBeInTheDocument()
  })

  it('never redirects on its own, even to a single non-Microsoft provider', async () => {
    await renderApp('/sign-in', 'signed-out', () => {
      scriptAdapter((request) =>
        request.url === '/me'
          ? { status: 401, data: errorBody('not_authenticated') }
          : { status: 200, data: { providers: [PROVIDERS[1]], mcp_url: 'https://x.test/mcp' } },
      )
    })
    expect(await screen.findByRole('link', { name: /Sign in with Google/ })).toBeInTheDocument()
    expect(hardNavigate).not.toHaveBeenCalled()
  })

  it('does not offer a provider with a start address that leaves this site', async () => {
    await renderApp('/sign-in', 'signed-out', () => {
      scriptAdapter((request) =>
        request.url === '/me'
          ? { status: 401, data: errorBody('not_authenticated') }
          : {
              status: 200,
              data: {
                providers: [
                  { ...PROVIDERS[1], start_url: 'https://accounts.example.test/start' },
                  { ...PROVIDERS[2], start_url: '/account/login/github?x=1' },
                  PROVIDERS[3],
                ],
                mcp_url: 'https://x.test/mcp',
              },
            },
      )
    })
    expect(await screen.findAllByRole('link', { name: /Sign in with/ })).toHaveLength(1)
    expect(screen.getByRole('link', { name: /School SSO/ })).toBeInTheDocument()
  })
})
