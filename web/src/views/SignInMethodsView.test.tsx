import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { resources } from '@/i18n/options'
import { useLanguage } from '@/stores/language'
import { errorBody, meFixture, recordRequests, scriptAdapter } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'
import { hardNavigate } from '@/utils/navigate'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

const CSRF = 'mock-csrf-token-not-a-secret'

beforeEach(() => {
  vi.mocked(hardNavigate).mockClear()
})

function rowOf(text: string): HTMLElement {
  const row = screen.getAllByText(text)[0].closest('li, tr')
  if (!(row instanceof HTMLElement)) throw new Error(`no row for ${text}`)
  return row
}

const PROVIDERS = [
  { id: 'entra', kind: 'oidc', name: 'Microsoft', icon: 'microsoft', start_url: '/account/login/entra' },
  { id: 'google', kind: 'oidc', name: 'Google', icon: 'google', start_url: '/account/login/google' },
]

/** A server with two providers whose /me/identities answer is whatever the test passes. */
function scripted(
  identities: unknown,
  onOther?: (request: { method: string; url: string }) => { status: number; data?: unknown } | undefined,
) {
  return () =>
    scriptAdapter((request) => {
      if (request.url === '/me') {
        return {
          status: 200,
          data: meFixture({}, { features: { ...meFixture().features, identities: true } }),
        }
      }
      if (request.url === '/providers') {
        return { status: 200, data: { providers: PROVIDERS, mcp_url: 'https://x.test/mcp' } }
      }
      if (request.url === '/me/identities') return { status: 200, data: identities }
      return onOther?.(request) ?? { status: 500, data: errorBody('internal_error') }
    })
}

const ENTRA_ONLY = {
  identities: [
    {
      id: '5',
      provider_id: 'entra',
      username: 'a@x.test',
      email: null,
      email_verified: false,
      linked_at: '2026-01-01T00:00:00Z',
      last_login_at: '2026-01-02T00:00:00Z',
      current: true,
      can_unlink: false,
    },
  ],
  linkable: ['google'],
  fresh: true,
  fresh_window_s: 600,
}

describe('Sign-in methods', () => {
  it('lists the linked methods with the one in use, and what can still be linked', async () => {
    await renderApp('/sign-in-methods', 'multi')
    expect(await screen.findByRole('heading', { name: 'Sign-in methods' })).toBeInTheDocument()
    await screen.findByText('ada-example')

    const entra = within(rowOf('Microsoft'))
    expect(entra.getByText('This sign-in')).toBeInTheDocument()
    expect(entra.getByText('ada@example.edu')).toBeInTheDocument()
    const github = within(rowOf('GitHub'))
    expect(github.getByText('ada-example')).toBeInTheDocument()
    // The address is shown for recognition; an unverified one carries no badge.
    expect(github.getByText('ada@example.org')).toBeInTheDocument()
    expect(github.queryByText('verified e-mail')).toBeNull()
    expect(entra.getByText('verified e-mail')).toBeInTheDocument()

    expect(screen.getByRole('button', { name: 'Link Google' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Link School SSO' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: 'Link GitHub' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Link Microsoft' })).toBeNull()
    expect(screen.getAllByRole('button', { name: /^Unlink:/ })).toHaveLength(2)
  })

  it('is a nav entry only when the server has the feature', async () => {
    await renderApp('/', 'multi')
    const nav = await screen.findByRole('navigation', { name: 'Main navigation' })
    expect([...nav.querySelectorAll('a')].map((a) => a.getAttribute('href'))).toContain('/sign-in-methods')
  })

  it('is not a page for a server with one provider', async () => {
    await renderApp('/sign-in-methods', 'enrolled')
    expect(await screen.findByText('Page not found')).toBeInTheDocument()
    const nav = screen.getByRole('navigation', { name: 'Main navigation' })
    expect(nav.querySelector('a[href="/sign-in-methods"]')).toBeNull()
  })

  it('is not a page for an account that waits for approval', async () => {
    await renderApp('/sign-in-methods', 'pending')
    expect(await screen.findByText('Waiting for approval')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Sign-in methods' })).toBeNull()
  })

  it('starts a link with the CSRF header and goes to the provider the server named', async () => {
    const user = userEvent.setup()
    await renderApp('/sign-in-methods', 'multi')
    await screen.findByText('ada-example')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Link Google' }))
    await waitFor(() => expect(hardNavigate).toHaveBeenCalledTimes(1))
    expect(hardNavigate).toHaveBeenCalledWith('https://idp.example.invalid/authorize?provider=google')
    const call = seen.find((request) => request.method === 'POST')
    expect(call?.url).toBe('/me/identities/link')
    expect(call?.headers['x-csrf-token']).toBe(CSRF)
    expect(JSON.parse(String(call?.data))).toEqual({ provider: 'google' })
  })

  it.each([
    ['javascript:alert(1)'],
    ['http://idp.example.test/authorize'],
    ['https://user:pass@idp.example.test/authorize'],
    ['https://idp.example.test/au\u0000thorize'],
    ['//idp.example.test/authorize'],
    ['/account/login/google'],
    [''],
  ])('does not navigate to an address that is not a plain https page (%j)', async (bad) => {
    const user = userEvent.setup()
    await renderApp(
      '/sign-in-methods',
      'multi',
      scripted(ENTRA_ONLY, (request) =>
        request.method === 'POST' ? { status: 200, data: { redirect_to: bad } } : undefined,
      ),
    )
    await user.click(await screen.findByRole('button', { name: 'Link Google' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be reached')
    expect(hardNavigate).not.toHaveBeenCalled()
  })

  it('shows the closed message when the link cannot start', async () => {
    const user = userEvent.setup()
    await renderApp(
      '/sign-in-methods',
      'multi',
      scripted(ENTRA_ONLY, (request) =>
        request.method === 'POST' ? { status: 503, data: errorBody('provider_unavailable') } : undefined,
      ),
    )
    await user.click(await screen.findByRole('button', { name: 'Link Google' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be reached')
    expect(hardNavigate).not.toHaveBeenCalled()
  })

  it('asks before it unlinks, then unlinks and keeps the person signed in', async () => {
    const user = userEvent.setup()
    await renderApp('/sign-in-methods', 'multi')
    await screen.findByText('ada-example')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Unlink: GitHub' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Unlink GitHub?')).toBeInTheDocument()
    expect(within(dialog).getByText(/Connected apps stay connected/)).toBeInTheDocument()
    expect(within(dialog).queryByText(/you will be signed out/)).toBeNull()
    expect(seen.find((request) => request.method === 'DELETE')).toBeUndefined()

    await user.click(within(dialog).getByRole('button', { name: 'Unlink' }))
    await waitFor(() => expect(screen.queryByText('ada-example')).toBeNull())
    const call = seen.find((request) => request.method === 'DELETE')
    expect(call?.url).toBe('/me/identities/12')
    expect(call?.headers['x-csrf-token']).toBe(CSRF)
    expect(await screen.findByText('Sign-in method removed.')).toBeInTheDocument()
    expect(hardNavigate).not.toHaveBeenCalled()
    // GitHub can be linked again, and the last method cannot be removed.
    expect(await screen.findByRole('button', { name: 'Link GitHub' })).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Unlink: Microsoft' })).toBeDisabled())
    expect(screen.getByText('An account must keep at least one sign-in method.')).toBeInTheDocument()
  })

  it('warns that the method in use signs the person out, and goes to the signed-out page', async () => {
    const user = userEvent.setup()
    await renderApp('/sign-in-methods', 'multi')
    await screen.findByText('ada-example')
    await user.click(screen.getByRole('button', { name: 'Unlink: Microsoft' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/you will be signed out/)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Unlink' }))
    await waitFor(() => expect(hardNavigate).toHaveBeenCalledWith('/account/'))
  })

  it('disables Unlink for the only method and says why', async () => {
    await renderApp('/sign-in-methods', 'multi', scripted(ENTRA_ONLY))
    const button = await screen.findByRole('button', { name: 'Unlink: Microsoft' })
    expect(button).toBeDisabled()
    expect(screen.getByText('An account must keep at least one sign-in method.')).toBeInTheDocument()
  })

  it('shows the closed message when the server refuses the last method anyway', async () => {
    const user = userEvent.setup()
    const two = {
      ...ENTRA_ONLY,
      identities: [
        ...ENTRA_ONLY.identities.map((i) => ({ ...i, can_unlink: true })),
        { ...ENTRA_ONLY.identities[0], id: '6', provider_id: 'google', current: false, can_unlink: true },
      ],
      linkable: [],
    }
    await renderApp(
      '/sign-in-methods',
      'multi',
      scripted(two, (request) =>
        request.method === 'DELETE' ? { status: 409, data: errorBody('last_identity') } : undefined,
      ),
    )
    await user.click(await screen.findByRole('button', { name: 'Unlink: Google' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: 'Unlink' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('at least one sign-in method')
  })

  it('treats a method that is already gone as done', async () => {
    const user = userEvent.setup()
    const two = {
      ...ENTRA_ONLY,
      identities: [
        ...ENTRA_ONLY.identities.map((i) => ({ ...i, can_unlink: true })),
        { ...ENTRA_ONLY.identities[0], id: '6', provider_id: 'google', current: false, can_unlink: true },
      ],
      linkable: [],
    }
    await renderApp(
      '/sign-in-methods',
      'multi',
      scripted(two, (request) =>
        request.method === 'DELETE' ? { status: 404, data: errorBody('not_found') } : undefined,
      ),
    )
    await user.click(await screen.findByRole('button', { name: 'Unlink: Google' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Unlink' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  describe('when the sign-in is older than ten minutes', () => {
    it('asks for a new sign-in and offers neither link nor unlink', async () => {
      const user = userEvent.setup()
      await renderApp('/sign-in-methods', 'multi-stale')
      const alert = await screen.findByRole('alert')
      expect(alert).toHaveTextContent('Sign in again to continue')
      expect(screen.getByRole('button', { name: 'Link Google' })).toBeDisabled()
      for (const button of screen.getAllByRole('button', { name: /^Unlink:/ })) expect(button).toBeDisabled()

      await user.click(within(alert).getByRole('button', { name: 'Sign in again' }))
      // Several providers: the chooser stays open for a person who is already signed in.
      expect(hardNavigate).toHaveBeenCalledWith(
        '/account/login?reauth=1&return_to=%2Faccount%2Fsign-in-methods',
      )
    })

    it('shows the server answer when the age ran out between the page and the click', async () => {
      const user = userEvent.setup()
      await renderApp(
        '/sign-in-methods',
        'multi',
        scripted(ENTRA_ONLY, (request) =>
          request.method === 'POST' ? { status: 403, data: errorBody('reauth_required', { max_age_s: 600 }) } : undefined,
        ),
      )
      await user.click(await screen.findByRole('button', { name: 'Link Google' }))
      expect(await screen.findByRole('button', { name: 'Sign in again' })).toBeInTheDocument()
      expect(hardNavigate).not.toHaveBeenCalled()
    })
  })

  describe('coming back from a provider', () => {
    it('says the method was added', async () => {
      await renderApp('/sign-in-methods?linked=1', 'multi')
      expect(await screen.findByText('Sign-in method added.')).toBeInTheDocument()
    })

    it.each(['identity_in_use', 'provider_already_linked', 'access_denied', 'link_session_ended', 'state_invalid'])(
      'shows the fixed text of ?error=%s',
      async (code) => {
        await renderApp(`/sign-in-methods?error=${code}`, 'multi')
        const alert = await screen.findByText('The sign-in method was not added')
        expect(alert).toBeInTheDocument()
        const errors = resources.en.errors as Record<string, string>
        expect(screen.getByRole('alert')).toHaveTextContent(errors[code])
      },
    )

    it('never echoes an unknown value', async () => {
      await renderApp('/sign-in-methods?error=%3Cb%3Eowned%3C%2Fb%3E', 'multi')
      const alert = await screen.findByRole('alert')
      expect(alert).toHaveTextContent('Something went wrong on our side')
      expect(alert).not.toHaveTextContent('owned')
      expect(document.body.innerHTML).not.toContain('<b>owned')
    })
  })

  it('has the same words in Chinese', async () => {
    await renderApp('/sign-in-methods', 'multi')
    await screen.findByText('ada-example')
    act(() => useLanguage.getState().setLanguage('zh'))
    const zh = resources.zh.account as { methods: { title: string; unlink: string; current: string } }
    expect(await screen.findByRole('heading', { name: zh.methods.title })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: new RegExp(zh.methods.unlink) }).length).toBeGreaterThan(0)
    expect(screen.getByText(zh.methods.current)).toBeInTheDocument()
  })

  it('lists the new sign-in on the activity page with the provider name', async () => {
    await renderApp('/activity', 'multi')
    expect(await screen.findByRole('heading', { name: 'Recent sign-ins' })).toBeInTheDocument()
    expect((await screen.findAllByText('Microsoft')).length).toBeGreaterThan(0)
  })
})
