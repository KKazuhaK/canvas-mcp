import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { errorBody, meFixture, recordRequests, scriptAdapter } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'
import { hardNavigate } from '@/utils/navigate'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

const CSRF = 'mock-csrf-token-not-a-secret'
const GRANT_1 = '00000000-0000-4000-8000-000000000101'
const GRANT_3 = '00000000-0000-4000-8000-000000000103'

beforeEach(() => {
  vi.mocked(hardNavigate).mockClear()
})

function rowOf(text: string): HTMLElement {
  const row = screen.getAllByText(text)[0].closest('li, tr')
  if (!(row instanceof HTMLElement)) throw new Error(`no row for ${text}`)
  return row
}

describe('Connected apps', () => {
  it('lists my apps: who, where each returns to, when connected and last used', async () => {
    await renderApp('/connected-apps', 'local')
    expect(await screen.findByRole('heading', { name: 'Connected apps' })).toBeInTheDocument()
    await screen.findByText('Sample Desktop Tool')

    const verified = within(rowOf('The app calls itself: Claude Code'))
    expect(verified.getByText('claude.ai')).toBeInTheDocument()
    expect(verified.getByText('Verified domain')).toBeInTheDocument()
    expect(verified.getByText('The app calls itself: Claude Code')).toBeInTheDocument()
    expect(verified.getByText('127.0.0.1')).toBeInTheDocument()

    const tool = within(rowOf('Sample Desktop Tool'))
    expect(tool.getByText(/Unverified: a self-registered app/)).toBeInTheDocument()
    expect(tool.getByText('tool.example.test')).toBeInTheDocument()
    expect(tool.getByText('Never')).toBeInTheDocument() // never used

    expect(screen.getAllByRole('button', { name: /^Revoke:/ })).toHaveLength(3)
    // someone else's app is not here
    expect(screen.queryByText('Cleo Notes')).toBeNull()
  })

  it('is a nav entry only when the server has the feature', async () => {
    await renderApp('/', 'local')
    const nav = await screen.findByRole('navigation', { name: 'Main navigation' })
    expect([...nav.querySelectorAll('a')].map((a) => a.getAttribute('href'))).toEqual([
      '/',
      '/token',
      '/write-tools',
      '/connected-apps',
      '/activity',
    ])
  })

  it('is not a page when the server does not have the feature', async () => {
    await renderApp('/connected-apps', 'enrolled')
    expect(await screen.findByText('Page not found')).toBeInTheDocument()
    const nav = screen.getByRole('navigation', { name: 'Main navigation' })
    expect(nav.querySelector('a[href="/connected-apps"]')).toBeNull()
  })

  it('is not a page for an account that waits for approval', async () => {
    await renderApp('/connected-apps', 'local-pending')
    expect(await screen.findByText('Waiting for approval')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Connected apps' })).toBeNull()
  })

  it('asks before it revokes, and then revokes with the CSRF header', async () => {
    const user = userEvent.setup()
    await renderApp('/connected-apps', 'local')
    await screen.findByText('Sample Desktop Tool')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Revoke: Sample Desktop Tool' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Disconnect Sample Desktop Tool?')).toBeInTheDocument()
    expect(within(dialog).getByText(/loses access right away/)).toBeInTheDocument()
    expect(seen.find((request) => request.method === 'DELETE')).toBeUndefined()

    await user.click(within(dialog).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(screen.queryByText('Sample Desktop Tool')).toBeNull())
    const call = seen.find((request) => request.method === 'DELETE')
    expect(call?.url).toBe(`/me/grants/${GRANT_3}`)
    expect(call?.headers['x-csrf-token']).toBe(CSRF)
    expect(call?.data).toBeUndefined()
    expect(await screen.findByText('App disconnected.')).toBeInTheDocument()
    await waitFor(() => expect(screen.getAllByRole('button', { name: /^Revoke:/ })).toHaveLength(2))
  })

  it('does nothing when the dialog is cancelled', async () => {
    const user = userEvent.setup()
    await renderApp('/connected-apps', 'local')
    await screen.findByText('Sample Desktop Tool')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Revoke: Sample Desktop Tool' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(seen.find((request) => request.method === 'DELETE')).toBeUndefined()
    expect(screen.getByText('Sample Desktop Tool')).toBeInTheDocument()
  })

  it('shows the closed message in the dialog when the revoke fails, and keeps the app listed', async () => {
    const user = userEvent.setup()
    await renderApp('/connected-apps', 'local', () => {
      scriptAdapter((request) => {
        if (request.url === '/me') {
          return { status: 200, data: meFixture({}, { features: { ...meFixture().features, connected_apps: true } }) }
        }
        if (request.method === 'DELETE') return { status: 503, data: errorBody('token_store_unavailable') }
        return {
          status: 200,
          data: {
            grants: [
              {
                id: GRANT_1,
                client: { kind: 'dcr', label: 'Solo App', name: 'Solo App', host: null, verified: false },
                redirect_host: 'solo.test',
                created_at: '2026-01-01T00:00:00Z',
                last_used_at: null,
                expires_at: '2026-02-01T00:00:00Z',
              },
            ],
          },
        }
      })
    })
    await user.click(await screen.findByRole('button', { name: 'Revoke: Solo App' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: 'Revoke' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('token store is unavailable')
    expect(screen.getAllByText('Solo App').length).toBeGreaterThan(0)
  })

  it('treats an app that is already gone as done', async () => {
    const user = userEvent.setup()
    let listed = true
    await renderApp('/connected-apps', 'local', () => {
      scriptAdapter((request) => {
        if (request.url === '/me') {
          return { status: 200, data: meFixture({}, { features: { ...meFixture().features, connected_apps: true } }) }
        }
        if (request.method === 'DELETE') {
          listed = false
          return { status: 404, data: errorBody('not_found') }
        }
        return {
          status: 200,
          data: {
            grants: listed
              ? [
                  {
                    id: GRANT_1,
                    client: { kind: 'dcr', label: 'Solo App', name: 'Solo App', host: null, verified: false },
                    redirect_host: 'solo.test',
                    created_at: '2026-01-01T00:00:00Z',
                    last_used_at: null,
                    expires_at: '2026-02-01T00:00:00Z',
                  },
                ]
              : [],
          },
        }
      })
    })
    await user.click(await screen.findByRole('button', { name: 'Revoke: Solo App' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(await screen.findByText('No apps are connected.')).toBeInTheDocument()
  })

  it('says so when no app is connected', async () => {
    await renderApp('/connected-apps', 'local', () => {
      scriptAdapter((request) =>
        request.url === '/me'
          ? { status: 200, data: meFixture({}, { features: { ...meFixture().features, connected_apps: true } }) }
          : { status: 200, data: { grants: [] } },
      )
    })
    expect(await screen.findByText('No apps are connected.')).toBeInTheDocument()
  })

  it('shows an unavailable list with a retry', async () => {
    await renderApp('/connected-apps', 'local', () => {
      scriptAdapter((request) =>
        request.url === '/me'
          ? { status: 200, data: meFixture({}, { features: { ...meFixture().features, connected_apps: true } }) }
          : { status: 503, data: errorBody('token_store_unavailable') },
      )
    })
    expect(await screen.findByRole('alert')).toHaveTextContent('token store is unavailable')
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })

  it('goes to the sign-in when the session has ended', async () => {
    const { router } = await renderApp('/connected-apps', 'local', () => {
      scriptAdapter((request) =>
        request.url === '/me'
          ? { status: 200, data: meFixture({}, { features: { ...meFixture().features, connected_apps: true } }) }
          : { status: 401, data: errorBody('not_authenticated') },
      )
    })
    await waitFor(() => expect(router.state.location.pathname).toBe('/sign-in'))
    expect(new URLSearchParams(router.state.location.search).get('return_to')).toBe('/account/connected-apps')
  })
})
