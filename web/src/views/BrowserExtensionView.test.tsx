import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { errorBody, meFixture, scriptAdapter, type RecordedRequest } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'
import { extensionStateFromHash } from '@/components/extension/ExtensionPairingCard'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

const STATE = 'AbCdEfGhIjKlMnOpQrStUv_-'
const AUTH = '#extension-auth=' + STATE
const ELEMENT = '#canvas-extension-authorization'

const pairingCalls = (seen: RecordedRequest[]) =>
  seen.filter((r) => r.method === 'POST' && r.url === '/me/extension/pairing')

beforeEach(() => {
  vi.clearAllMocks()
})

describe('extensionStateFromHash', () => {
  it.each([
    ['#extension-auth=' + STATE, STATE],
    ['extension-auth=' + STATE, STATE],
    ['#extension-auth=' + 'a'.repeat(16), 'a'.repeat(16)],
    ['#extension-auth=' + 'a'.repeat(128), 'a'.repeat(128)],
    ['#other=1&extension-auth=' + STATE, STATE],
    ['', null],
    ['#extension-auth=', null],
    ['#extension-auth=short', null],
    ['#extension-auth=' + 'a'.repeat(129), null],
    ['#extension-auth=' + 'a'.repeat(20) + '+/=', null],
    ['#extension-auth=' + 'a'.repeat(20) + '%3Cb%3E', null],
    ['#x=' + STATE, null],
  ])('%s', (hash, expected) => {
    expect(extensionStateFromHash(hash)).toBe(expected)
  })
})

const CODE = 'k3f9x2m7q1z8w4v6b5n0'
const inMinutes = (minutes: number) => new Date(Date.now() + minutes * 60_000).toISOString()

const BINDING = {
  createdAt: '2026-10-01T00:00:00Z',
  lastUploadAt: null as string | null,
  canvasHost: null as string | null,
  resources: [] as { path: string; capturedAt: string | null; canvasStatus: number }[],
  active: false,
  reason: null as string | null,
}

interface Script {
  binding?: typeof BINDING | null
  expiresAt?: string
  pairing?: { status: number; data: unknown }
  remove?: { status: number; data?: unknown }
}

/** A scripted server: /me, the extension status (which DELETE empties) and the pairing endpoint. */
async function open(path: string, script: Script = {}) {
  let binding = script.binding === undefined ? null : script.binding
  let seen: RecordedRequest[] = []
  const rendered = await renderApp(path, 'local', () => {
    seen = scriptAdapter((request) => {
      if (request.url === '/me') return { status: 200, data: meFixture() }
      if (request.url === '/me/extension' && request.method === 'GET') return { status: 200, data: { binding } }
      if (request.url === '/me/extension' && request.method === 'DELETE') {
        const reply = script.remove ?? { status: 204 }
        if (reply.status < 300) binding = null
        return reply
      }
      if (request.url === '/me/extension/pairing') {
        return script.pairing ?? { status: 200, data: { code: CODE, expiresAt: script.expiresAt ?? inMinutes(5) } }
      }
      return { status: 404, data: errorBody('not_found') }
    })
  })
  return { ...rendered, seen }
}

describe('Browser extension: status', () => {
  it('says so when no extension is connected', async () => {
    await open('/browser-extension')
    expect(await screen.findByRole('heading', { name: 'Browser extension' })).toBeInTheDocument()
    expect(await screen.findByText('Not connected')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Disconnect and delete/ })).toBeNull()
    expect(screen.getByText(/Your Canvas password and cookies are never sent/)).toBeInTheDocument()
  })

  it('shows the host, dates and synced resources, and flags a Canvas status other than 200', async () => {
    await open('/browser-extension', {
      binding: {
        ...BINDING,
        canvasHost: 'canvas.example.edu',
        lastUploadAt: new Date(Date.now() - 12 * 60_000).toISOString(),
        active: true,
        resources: [
          { path: '/users/self', capturedAt: new Date(Date.now() - 12 * 60_000).toISOString(), canvasStatus: 200 },
          { path: '/courses/101/assignments', capturedAt: new Date(Date.now() - 3 * 3600_000).toISOString(), canvasStatus: 200 },
          { path: '/planner/items', capturedAt: new Date(Date.now() - 12 * 60_000).toISOString(), canvasStatus: 403 },
        ],
      },
    })
    expect(await screen.findByText('Connected')).toBeInTheDocument()
    expect(screen.getByText('canvas.example.edu')).toBeInTheDocument()
    expect(screen.getByText('Your apps are answered from the synced data.')).toBeInTheDocument()
    const table = await screen.findByRole('list', { name: 'Synced data' })
    expect(within(table).getByText('/courses/101/assignments')).toBeInTheDocument()
    expect(within(table).getAllByText('12 minutes ago')).toHaveLength(2)
    expect(within(table).getByText('3 hours ago')).toBeInTheDocument()
    expect(within(table).getAllByText('OK')).toHaveLength(2)
    expect(within(table).getByText('Status 403')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Disconnect and delete synced data' })).toBeInTheDocument()
  })

  it.each([
    ['token_preferred', /Your Canvas access token is used instead while it works/],
    ['school_unknown', /not in the Portal's school list/],
    ['user_mismatch', /belongs to a different Canvas user/],
    [null, /not in use yet/],
  ])('explains why synced data is not used (%s)', async (reason, text) => {
    await open('/browser-extension', { binding: { ...BINDING, reason } })
    expect(await screen.findByText('Connected')).toBeInTheDocument()
    expect(screen.getByText(text)).toBeInTheDocument()
    expect(screen.getAllByText('Not synced yet').length).toBeGreaterThan(0)
    expect(screen.getByText(/Nothing has been synced yet/)).toBeInTheDocument()
  })

  it('shows an unavailable status with a retry', async () => {
    await renderApp('/browser-extension', 'local', () => {
      scriptAdapter((request) =>
        request.url === '/me'
          ? { status: 200, data: meFixture() }
          : { status: 503, data: errorBody('token_store_unavailable') },
      )
    })
    expect(await screen.findByText('token store is unavailable', { exact: false })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })
})

describe('Browser extension: disconnect', () => {
  const connected = { ...BINDING, canvasHost: 'canvas.example.edu', active: true }

  it('asks first, then deletes with the CSRF header and shows the not-connected state', async () => {
    const user = userEvent.setup()
    const { seen } = await open('/browser-extension', { binding: connected })
    await user.click(await screen.findByRole('button', { name: 'Disconnect and delete synced data' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Disconnect the browser extension?')).toBeInTheDocument()
    expect(seen.find((r) => r.method === 'DELETE')).toBeUndefined()

    await user.click(within(dialog).getByRole('button', { name: 'Disconnect and delete' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    const call = seen.find((r) => r.method === 'DELETE')
    expect(call?.url).toBe('/me/extension')
    expect(call?.headers['x-csrf-token']).toBeTruthy()
    expect(await screen.findByText('Browser extension disconnected.')).toBeInTheDocument()
    expect(await screen.findByText('Not connected')).toBeInTheDocument()
  })

  it('does nothing when cancelled', async () => {
    const user = userEvent.setup()
    const { seen } = await open('/browser-extension', { binding: connected })
    await user.click(await screen.findByRole('button', { name: 'Disconnect and delete synced data' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(seen.find((r) => r.method === 'DELETE')).toBeUndefined()
    expect(screen.getByText('Connected')).toBeInTheDocument()
  })

  it('keeps the dialog open with the error when the delete fails', async () => {
    const user = userEvent.setup()
    await open('/browser-extension', {
      binding: connected,
      remove: { status: 503, data: errorBody('token_store_unavailable') },
    })
    await user.click(await screen.findByRole('button', { name: 'Disconnect and delete synced data' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: 'Disconnect and delete' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('token store is unavailable')
  })
})

describe('Browser extension: pairing from the extension', () => {
  it('requests one code and renders the hidden authorization element with the state and code', async () => {
    const { seen } = await open('/browser-extension' + AUTH)
    expect(await screen.findByText('Return to the extension; it will finish connecting.')).toBeInTheDocument()
    const element = document.querySelector(ELEMENT) as HTMLElement
    expect(element).not.toBeNull()
    expect(element.tagName).toBe('DIV')
    expect(element.hidden).toBe(true)
    expect(element.getAttribute('data-state')).toBe(STATE)
    expect(element.getAttribute('data-code')).toBe(CODE)
    expect(document.querySelectorAll(ELEMENT)).toHaveLength(1)
    // It also shows the code for manual entry.
    expect(screen.getByLabelText('Pairing code')).toHaveValue(CODE)
    const calls = pairingCalls(seen)
    expect(calls).toHaveLength(1)
    expect(calls[0].headers['x-csrf-token']).toBeTruthy()
    // The status is read again after pairing.
    await waitFor(() => expect(seen.filter((r) => r.url === '/me/extension' && r.method === 'GET').length).toBeGreaterThan(1))
  })

  it.each([
    ['too short', '#extension-auth=abc'],
    ['bad characters', '#extension-auth=' + 'a'.repeat(20) + '%3Cscript%3E'],
    ['too long', '#extension-auth=' + 'a'.repeat(129)],
    ['another key', '#state=' + STATE],
  ])('ignores an invalid hash (%s): no request, no element', async (_name, hash) => {
    const { seen } = await open('/browser-extension' + hash)
    expect(await screen.findByRole('button', { name: 'Show pairing code' })).toBeInTheDocument()
    await screen.findByText('Not connected')
    expect(pairingCalls(seen)).toHaveLength(0)
    expect(document.querySelector(ELEMENT)).toBeNull()
  })

  it('has no authorization element and no request without a hash', async () => {
    const { seen } = await open('/browser-extension')
    await screen.findByText('Not connected')
    expect(document.querySelector(ELEMENT)).toBeNull()
    expect(pairingCalls(seen)).toHaveLength(0)
  })

  it('shows the failure with a retry, and no element', async () => {
    const user = userEvent.setup()
    const { seen } = await open('/browser-extension' + AUTH, {
      pairing: { status: 503, data: errorBody('token_store_unavailable') },
    })
    expect(await screen.findByText('token store is unavailable', { exact: false })).toBeInTheDocument()
    expect(document.querySelector(ELEMENT)).toBeNull()
    await user.click(screen.getAllByRole('button', { name: 'Try again' })[0])
    await waitFor(() => expect(pairingCalls(seen)).toHaveLength(2))
  })

  it('drops the code and the element when the code expires', async () => {
    await open('/browser-extension' + AUTH, { expiresAt: new Date(Date.now() + 1500).toISOString() })
    await waitFor(() => expect(document.querySelector(ELEMENT)).not.toBeNull())
    await waitFor(() => expect(document.querySelector(ELEMENT)).toBeNull(), { timeout: 4000 })
    expect(screen.getByText('The code expired.')).toBeInTheDocument()
    expect(screen.queryByLabelText('Pairing code')).toBeNull()
    expect(document.body.innerHTML).not.toContain(CODE)
    expect(screen.getByRole('button', { name: 'Get a new code' })).toBeInTheDocument()
  })
})

describe('Browser extension: manual code', () => {
  it('shows a code with a countdown only after the button, and can copy it', async () => {
    const user = userEvent.setup()
    const { seen } = await open('/browser-extension')
    await user.click(await screen.findByRole('button', { name: 'Show pairing code' }))
    expect(await screen.findByLabelText('Pairing code')).toHaveValue(CODE)
    expect(screen.getByText(/Expires in [45]:\d\d/)).toBeInTheDocument()
    expect(document.querySelector(ELEMENT)).toBeNull()
    expect(pairingCalls(seen)).toHaveLength(1)
    expect(screen.queryByRole('button', { name: 'Show pairing code' })).toBeNull()

    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    await user.click(screen.getByRole('button', { name: 'Copy pairing code' }))
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(CODE))
  })
})

describe('Browser extension: sign-in', () => {
  it('sends a signed-out visitor to sign in and back, keeping the hash', async () => {
    const { router } = await renderApp('/browser-extension' + AUTH, 'signed-out')
    await screen.findByRole('link', { name: /Sign in with Microsoft/ })
    expect(router.state.location.pathname).toBe('/sign-in')
    expect(new URLSearchParams(router.state.location.search).get('return_to')).toBe(
      '/account/browser-extension' + AUTH,
    )
  })

  it('is a navigation entry', async () => {
    await open('/')
    const nav = await screen.findByRole('navigation', { name: 'Main navigation' })
    expect(within(nav).getByRole('link', { name: 'Browser extension' })).toHaveAttribute('href', '/browser-extension')
  })
})
