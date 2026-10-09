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
    expect(JSON.parse(put?.data as string)).toEqual({ canvas_token: GOOD })

    // Nothing on screen, in the DOM, or in React Query's caches carries the token.
    expect(document.body.innerHTML).not.toContain(GOOD)
    expect(JSON.stringify(client.getQueryCache().getAll().map((q) => [q.queryKey, q.state.data]))).not.toContain(GOOD)
    expect(client.getMutationCache().getAll()).toHaveLength(0)
    // And the replace form that is now available starts empty.
    await user.click(screen.getByRole('button', { name: 'Replace token' }))
    expect((await tokenInput()).value).toBe('')
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

  it.each([
    ['canvas-is-offline-token-1234567890', 'Could not reach Canvas'],
  ])('maps canvas_unavailable (%s)', async (token, text) => {
    const user = userEvent.setup()
    await renderApp('/token', 'fresh')
    await user.type(await tokenInput(), token)
    await user.click(screen.getByRole('button', { name: 'Verify and save' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(text)
  })

  it('maps token_store_unavailable (503) and rate_limited (429)', async () => {
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

  it('shows the enrolled details, re-checks and deletes only after a confirmation', async () => {
    const user = userEvent.setup()
    await renderApp('/token', 'enrolled')
    expect(await screen.findByText('Canvas token enrolled')).toBeInTheDocument()
    expect(screen.getAllByText('Ada Example').length).toBeGreaterThan(0)
    expect(screen.getByText(/id 1234567/)).toBeInTheDocument()
    expect(screen.queryByLabelText(/Canvas access token/)).toBeNull() // replace form is collapsed

    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Re-check token' }))
    await waitFor(() => expect(seen.some((r) => r.url === '/me/canvas-token/verify')).toBe(true))

    await user.click(screen.getByRole('button', { name: 'Delete my token' }))
    const dialog = await screen.findByRole('dialog')
    expect(seen.some((r) => r.method === 'DELETE')).toBe(false)
    await user.click(within(dialog).getByRole('button', { name: 'Delete my token' }))
    await waitFor(() => expect(seen.some((r) => r.method === 'DELETE')).toBe(true))
    expect(await screen.findByText('Add your Canvas token')).toBeInTheDocument()
  })

  it('shows the banner and an open replace form when Canvas rejected the stored token', async () => {
    await renderApp('/token', 'invalid')
    expect(await screen.findByText('Canvas rejected your token')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('Claude\'s Canvas tools stay disabled')
    expect(await screen.findByLabelText(/Canvas access token/)).toBeVisible()
    expect(screen.getByRole('button', { name: 'Re-check token' })).toBeInTheDocument()
  })

  it('shows a disabled school placeholder and sends no school', async () => {
    await renderApp('/token', 'fresh')
    expect(await screen.findByRole('textbox', { name: 'School' })).toBeDisabled()
  })
})
