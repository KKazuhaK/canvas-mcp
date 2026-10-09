import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { renderApp } from '@/test/renderWithProviders'
import { errorBody, meFixture, scriptAdapter } from '@/test/fixtures'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

describe('Recent sign-ins', () => {
  it('shows outcome and a localized reason, and never an address or a device', async () => {
    await renderApp('/activity')
    expect(await screen.findByText('Signed in')).toBeInTheDocument()
    expect(screen.getByText('Refused')).toBeInTheDocument()
    expect(screen.getByText('Waiting for approval')).toBeInTheDocument()
    expect(screen.getByText('Sign-ups paused')).toBeInTheDocument()
    expect(screen.getByText('Account created')).toBeInTheDocument()
    expect(screen.getAllByText('Microsoft').length).toBeGreaterThan(0)
    expect(screen.queryByText('IP address')).toBeNull()
    expect(screen.queryByText('Device')).toBeNull()
  })

  it('says so when there is no history', async () => {
    await renderApp('/activity', 'enrolled', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 200, data: meFixture() }
          : r.url === '/providers'
            ? { status: 200, data: { providers: [], mcp_url: 'https://x.test/mcp' } }
            : { status: 200, data: { events: [] } },
      )
    })
    expect(await screen.findByText('No sign-ins recorded yet.')).toBeInTheDocument()
  })

  it('shows a refusal that has no reason', async () => {
    await renderApp('/activity', 'enrolled', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 200, data: meFixture() }
          : r.url === '/providers'
            ? { status: 200, data: { providers: [], mcp_url: 'https://x.test/mcp' } }
            : {
                status: 200,
                data: {
                  events: [{ at: '2026-01-01T00:00:00Z', provider_id: 'entra', outcome: 'refused', reason: null }],
                },
              },
      )
    })
    expect(await screen.findByText('Refused')).toBeInTheDocument()
  })
})

describe('Global error states', () => {
  it('shows an unavailable-store message with retry', async () => {
    await renderApp('/activity', 'enrolled', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 200, data: meFixture() }
          : { status: 503, data: errorBody('token_store_unavailable') },
      )
    })
    expect(await screen.findByRole('alert')).toHaveTextContent('token store is unavailable')
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })

  it('shows the rate-limit message with retry-after seconds', async () => {
    await renderApp('/activity', 'enrolled', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 200, data: meFixture() }
          : { status: 429, data: errorBody('rate_limited', { retry_after_s: 45 }) },
      )
    })
    expect(await screen.findByRole('alert')).toHaveTextContent('Try again in 45 seconds')
  })

  it('shows a fixed message for any server error and never its text', async () => {
    await renderApp('/activity', 'enrolled', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 200, data: meFixture() }
          : {
              status: 500,
              data: { error: { code: 'internal_error', message: 'Traceback: secret detail' } },
            },
      )
    })
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Something went wrong on our side')
    expect(document.body.textContent).not.toContain('secret detail')
  })
})
