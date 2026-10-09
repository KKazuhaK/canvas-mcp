import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderApp } from '@/test/renderWithProviders'
import { recordRequests } from '@/test/fixtures'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

const GOOD = '1234~AbCdEfGhIjKlMnOpQrStUvWxYz012345'

async function tokenInput() {
  return (await screen.findByLabelText(/Canvas access token/)) as HTMLInputElement
}

function bodyOf(request: { data: unknown } | undefined): Record<string, unknown> {
  return JSON.parse(request?.data as string) as Record<string, unknown>
}

describe('Canvas token form', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('is a write-only password field with autocomplete and spellcheck off', async () => {
    await renderApp('/token', 'fresh')
    const input = await tokenInput()
    expect(input).toHaveAttribute('type', 'password')
    expect(input).toHaveAttribute('autocomplete', 'off')
    expect(input).toHaveAttribute('spellcheck', 'false')
    expect(input).toHaveAttribute('minlength', '20')
    expect(input).toHaveAttribute('maxlength', '512')
    expect(screen.getByText('Never paste the token into Claude.')).toBeInTheDocument()
    // The three how-to steps render their emphasis through <Trans>, not raw HTML.
    expect(screen.getByText('Account → Settings → + New Access Token').tagName).toBe('STRONG')
    expect(screen.getByText('Claude MCP').tagName).toBe('CODE')
  })

  it('shows the one school of a single-school server and sends no school', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'fresh')
    const seen = recordRequests()
    expect(await screen.findByText('Example University')).toBeInTheDocument()
    await user.type(await tokenInput(), GOOD)
    await user.click(screen.getByRole('button', { name: 'Verify and save' }))
    await screen.findByText('Canvas token enrolled')
    expect(bodyOf(seen.find((r) => r.method === 'PUT'))).toEqual({ canvas_token: GOOD })
  })

  it('saves a valid token, sends the CSRF header, never echoes it and keeps it out of caches', async () => {
    const user = userEvent.setup()
    const { client } = await renderApp('/token', 'fresh')
    const seen = recordRequests()
    const input = await tokenInput()

    await user.type(input, GOOD)
    expect(input.value).toBe(GOOD) // controlled field holds it only while typing
    await user.click(screen.getByRole('button', { name: 'Verify and save' }))

    expect(await screen.findByText('Canvas token enrolled')).toBeInTheDocument()
    const put = seen.find((r) => r.method === 'PUT')
    expect(put).toBeDefined()
    expect(put?.url).toBe('/me/canvas-token')
    expect(put?.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')

    // Nothing on screen, in the DOM, or in React Query's caches carries the token.
    expect(document.body.innerHTML).not.toContain(GOOD)
    expect(JSON.stringify(client.getQueryCache().getAll().map((q) => [q.queryKey, q.state.data]))).not.toContain(GOOD)
    expect(client.getMutationCache().getAll()).toHaveLength(0)
    // And the replace form that is now available starts empty.
    await user.click(screen.getByRole('button', { name: 'Replace token' }))
    expect((await tokenInput()).value).toBe('')
  })

  it('sends the optional expiry date when one is entered', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'fresh')
    const seen = recordRequests()
    await user.type(await tokenInput(), GOOD)
    await user.type(screen.getByLabelText(/Expiry date/), '2031-02-03')
    await user.click(screen.getByRole('button', { name: 'Verify and save' }))
    await screen.findByText('Canvas token enrolled')
    expect(bodyOf(seen.find((r) => r.method === 'PUT'))).toEqual({
      canvas_token: GOOD,
      expires_on: '2031-02-03',
    })
    expect(screen.getByText('Expires')).toBeInTheDocument()
  })

  it('points at the expiry date when the server refuses it, and offers today as the earliest', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'fresh')
    const token = await tokenInput()
    const expiry = screen.getByLabelText(/Expiry date/)
    expect(expiry).toHaveAttribute('min', expect.stringMatching(/^\d{4}-\d{2}-\d{2}$/))
    await user.type(token, GOOD)
    await user.type(expiry, '2020-01-01')
    await user.click(screen.getByRole('button', { name: 'Verify and save' }))

    expect(
      await screen.findByText('That expiry date is not valid. Pick today or a later date.'),
    ).toBeInTheDocument()
    expect(expiry).toHaveAttribute('aria-invalid', 'true')
    // The field-level text replaces the generic sentence.
    expect(screen.queryByText(/Some of the information is not valid/)).toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()

    // Fixing the date clears the complaint.
    await user.clear(expiry)
    await user.type(expiry, '2031-02-03')
    expect(expiry).not.toHaveAttribute('aria-invalid', 'true')
  })

  it('clears the field after a server failure and shows the localized reason', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'fresh')
    const input = await tokenInput()
    await user.type(input, 'this-token-was-rejected-by-canvas-1234')
    await user.click(screen.getByRole('button', { name: 'Verify and save' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Canvas rejected that token')
    expect(input.value).toBe('')
    expect(document.body.innerHTML).not.toContain('this-token-was-rejected')
  })

  it('checks the shape locally without sending anything, and clears the field', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'fresh')
    const seen = recordRequests()
    const input = await tokenInput()
    await user.type(input, 'too short')
    await user.click(screen.getByRole('button', { name: 'Verify and save' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('does not look like a Canvas access token')
    expect(input.value).toBe('')
    expect(seen.filter((r) => r.method === 'PUT')).toHaveLength(0)
  })

  it('maps canvas_unavailable', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'fresh')
    await user.type(await tokenInput(), 'canvas-is-offline-token-1234567890')
    await user.click(screen.getByRole('button', { name: 'Verify and save' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not reach Canvas')
  })

  it('maps token_store_unavailable (503)', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'error-503')
    await user.type(await tokenInput(), GOOD)
    await user.click(screen.getByRole('button', { name: 'Verify and save' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('token store is unavailable')
  })

  it('shows the retry-after seconds when rate limited', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'rate-limited')
    await user.type(await tokenInput(), GOOD)
    await user.click(screen.getByRole('button', { name: 'Verify and save' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Try again in 30 seconds')
  })
})

describe('school picker', () => {
  it('lists the featured schools, starts on the server default and sends the host without a signature', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'picker')
    const seen = recordRequests()
    const select = await screen.findByRole('combobox', { name: 'School' })
    expect(select).toHaveTextContent('Example University (canvas.example.edu)')

    await user.click(select)
    await user.click(await screen.findByRole('option', { name: 'Sample College (learn.sample.edu)' }))
    await user.type(await tokenInput(), GOOD)
    await user.click(screen.getByRole('button', { name: 'Verify and save' }))
    await screen.findByText('Canvas token enrolled')
    expect(bodyOf(seen.find((r) => r.method === 'PUT'))).toEqual({
      canvas_token: GOOD,
      school: 'learn.sample.edu',
    })
    expect(screen.getByText('Sample College')).toBeInTheDocument()
  })

  it('searches the directory with the CSRF header and sends the signature of the pick', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'picker')
    const seen = recordRequests()
    await user.type(await screen.findByLabelText('Search for another school'), 'demo')
    await user.click(screen.getByRole('button', { name: 'Search' }))

    const hit = await screen.findByRole('button', { name: /Demo State University/ })
    const search = seen.find((r) => r.url === '/me/schools/search')
    expect(search?.method).toBe('GET')
    expect(search?.params).toEqual({ q: 'demo' })
    expect(search?.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')

    await user.click(hit)
    expect(screen.getByRole('combobox', { name: 'School' })).toHaveTextContent('Demo State University')
    await user.type(await tokenInput(), GOOD)
    await user.click(screen.getByRole('button', { name: 'Verify and save' }))
    await screen.findByText('Canvas token enrolled')
    expect(bodyOf(seen.find((r) => r.method === 'PUT'))).toEqual({
      canvas_token: GOOD,
      school: 'canvas.demo.edu',
      school_sig: 'sig-canvas.demo.edu',
    })
  })

  it('does not search for fewer than 2 characters', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'picker')
    await user.type(await screen.findByLabelText('Search for another school'), 'd')
    expect(screen.getByRole('button', { name: 'Search' })).toBeDisabled()
  })

  it('says so when nothing matches, and shows a directory outage as a fixed message', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'picker')
    const box = await screen.findByLabelText('Search for another school')
    await user.type(box, 'zzzz')
    await user.click(screen.getByRole('button', { name: 'Search' }))
    expect(await screen.findByText('No school matched that search.')).toBeInTheDocument()

    await user.clear(box)
    await user.type(box, 'offline')
    await user.click(screen.getByRole('button', { name: 'Search' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('school directory is unavailable')
  })

  it('has no search box when the server does not allow searching', async () => {
    await renderApp('/token', 'fresh')
    await tokenInput()
    expect(screen.queryByLabelText('Search for another school')).toBeNull()
  })
})

describe('replacing a token for a different Canvas user', () => {
  it('asks first, keeps the token only until the answer, then sends the confirmation', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'identity-change')
    await screen.findByText('Canvas token enrolled')
    await user.click(screen.getByRole('button', { name: 'Replace token' }))
    const seen = recordRequests()
    const input = await tokenInput()
    await user.type(input, GOOD)
    await user.click(screen.getByRole('button', { name: 'Verify and replace' }))

    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('Zed Example')
    expect(dialog).toHaveTextContent('Ada Example')
    expect(seen.filter((r) => r.method === 'PUT')).toHaveLength(1)

    await user.click(within(dialog).getByRole('button', { name: 'Replace the token' }))
    await waitFor(() => expect(seen.filter((r) => r.method === 'PUT')).toHaveLength(2))
    const second = bodyOf(seen.filter((r) => r.method === 'PUT')[1])
    expect(second).toEqual({ canvas_token: GOOD, confirm_identity_change: 'mock-confirmation' })

    expect(await screen.findByText('Zed Example', { exact: false })).toBeInTheDocument()
    expect(document.body.innerHTML).not.toContain(GOOD)
  })

  it('drops the token when the person says no, and sends nothing more', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'identity-change')
    await screen.findByText('Canvas token enrolled')
    await user.click(screen.getByRole('button', { name: 'Replace token' }))
    const seen = recordRequests()
    const input = await tokenInput()
    await user.type(input, GOOD)
    await user.click(screen.getByRole('button', { name: 'Verify and replace' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(input.value).toBe('')
    expect(document.body.innerHTML).not.toContain(GOOD)
    expect(seen.filter((r) => r.method === 'PUT')).toHaveLength(1)
  })
})

describe('the enrolled token', () => {
  it('shows the details, the school, the expiry date and the settings link', async () => {
    await renderApp('/token', 'enrolled')
    expect(await screen.findByText('Canvas token enrolled')).toBeInTheDocument()
    expect(screen.getAllByText('Ada Example').length).toBeGreaterThan(0)
    expect(screen.getByText(/id 1234567/)).toBeInTheDocument()
    expect(screen.getByText('Example University')).toBeInTheDocument()
    expect(screen.getByText('Expires')).toBeInTheDocument()
    const link = screen.getByRole('link', { name: "Open your school's Canvas settings" })
    expect(link).toHaveAttribute('href', 'https://canvas.example.edu/profile/settings')
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
    expect(screen.queryByLabelText(/Canvas access token/)).toBeNull() // replace form is collapsed
    // A valid token has nothing to re-check.
    expect(screen.queryByRole('button', { name: 'Re-check token' })).toBeNull()
  })

  it('warns before the noted expiry date', async () => {
    await renderApp('/token', 'expiring')
    expect(await screen.findByText('Your Canvas token expires soon')).toBeInTheDocument()
  })

  it('deletes only after a confirmation', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'enrolled')
    await screen.findByText('Canvas token enrolled')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Delete my token' }))
    const dialog = await screen.findByRole('dialog')
    expect(seen.some((r) => r.method === 'DELETE')).toBe(false)
    await user.click(within(dialog).getByRole('button', { name: 'Delete my token' }))
    await waitFor(() => expect(seen.some((r) => r.method === 'DELETE')).toBe(true))
    expect(seen.find((r) => r.method === 'DELETE')?.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(await screen.findByText('Add your Canvas token')).toBeInTheDocument()
  })
})

describe('a token Canvas no longer accepts', () => {
  it('shows the banner, an open replace form, and re-checks it back to valid', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'invalid')
    expect(await screen.findByText('Canvas rejected your token')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent("Claude's Canvas tools stay disabled")
    expect(await screen.findByLabelText(/Canvas access token/)).toBeVisible()

    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Re-check token' }))
    await waitFor(() => expect(seen.some((r) => r.url === '/me/canvas-token/recheck')).toBe(true))
    const post = seen.find((r) => r.url === '/me/canvas-token/recheck')
    expect(post?.method).toBe('POST')
    expect(post?.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(await screen.findByText('Canvas accepts the token again.')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('Canvas rejected your token')).toBeNull())
  })

  it('offers no re-check when an administrator turned the token off', async () => {
    await renderApp('/token', 'revoked')
    expect(await screen.findByText('An administrator turned your token off')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Re-check token' })).toBeNull()
    expect(await screen.findByLabelText(/Canvas access token/)).toBeVisible()
  })
})
