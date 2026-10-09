import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { renderApp } from '@/test/renderWithProviders'
import { errorBody, meFixture, recordRequests, scriptAdapter } from '@/test/fixtures'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

describe('WriteToolsView', () => {
  it('explains the three layers and groups the tools', async () => {
    await renderApp('/write-tools')
    expect(await screen.findByRole('heading', { name: 'Write tools' })).toBeInTheDocument()
    const layers = await screen.findByRole('region', { name: 'Who decides' })
    expect(within(layers).getByText('Server allows')).toBeInTheDocument()
    expect(within(layers).getByText('You enabled')).toBeInTheDocument()
    expect(within(layers).getByText('Course allows (decided per course)')).toBeInTheDocument()
    expect(within(layers).getByText(/Previews, confirmations, course policy/)).toBeInTheDocument()

    for (const group of ['Planner and calendar', 'Assignment submission', 'Module completion', 'Messages']) {
      expect(screen.getByRole('heading', { name: group })).toBeInTheDocument()
    }
  })

  it('flags messaging tools as sending as you and shows a risk chip per tool', async () => {
    await renderApp('/write-tools')
    const messages = await screen.findByRole('region', { name: 'Messages' })
    expect(within(messages).getAllByText('Sends as you')).toHaveLength(2)
    expect(within(messages).getAllByText('High risk')).toHaveLength(2)
  })

  it('disables tools the server does not allow and says why', async () => {
    await renderApp('/write-tools')
    const toggle = await screen.findByRole('switch', { name: 'Mark module item done' })
    expect(toggle).toBeDisabled()
    expect(screen.getByText('Not allowed by this server')).toBeInTheDocument()
  })

  it('saves only after a change, sends the CSRF header and the enabled list', async () => {
    const user = userEvent.setup()
    await renderApp('/write-tools')
    const save = await screen.findByRole('button', { name: 'Save changes' })
    expect(save).toBeDisabled()
    const seen = recordRequests()

    await user.click(screen.getByRole('switch', { name: 'Submit assignment' }))
    expect(screen.getByText('You have unsaved changes.')).toBeInTheDocument()
    expect(save).toBeEnabled()
    await user.click(save)

    await waitFor(() => expect(seen.some((r) => r.method === 'PUT')).toBe(true))
    const put = seen.find((r) => r.method === 'PUT')
    expect(put?.url).toBe('/me/write-tools')
    expect(put?.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(JSON.parse(put?.data as string)).toEqual({
      enabled: ['create_planner_note', 'send_message', 'submit_assignment'],
    })
    expect(await screen.findByText('Write tools saved.')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('You have unsaved changes.')).toBeNull())
    expect(screen.getByRole('switch', { name: 'Submit assignment' })).toBeChecked()
  })

  it('discards unsaved changes', async () => {
    const user = userEvent.setup()
    await renderApp('/write-tools')
    const toggle = await screen.findByRole('switch', { name: 'Submit assignment' })
    await user.click(toggle)
    expect(toggle).toBeChecked()
    await user.click(screen.getByRole('button', { name: 'Discard' }))
    expect(toggle).not.toBeChecked()
  })

  it('maps write_tool_not_allowed from the server', async () => {
    const user = userEvent.setup()
    await renderApp('/write-tools', 'enrolled', () => {
      scriptAdapter((r) => {
        if (r.url === '/me') return { status: 200, data: meFixture() }
        if (r.method === 'PUT') return { status: 403, data: errorBody('write_tool_not_allowed') }
        return {
          status: 200,
          data: {
            server_enabled: true,
            tools: [
              { name: 'send_message', group: 'messages', risk: 'high', server_allowed: true, enabled: false },
            ],
          },
        }
      })
    })
    await user.click(await screen.findByRole('switch', { name: 'Send message' }))
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('does not allow one of those tools')
  })

  it('disables the whole page when the server has write tools off', async () => {
    await renderApp('/write-tools', 'enrolled', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 200, data: meFixture() }
          : {
              status: 200,
              data: {
                server_enabled: false,
                tools: [{ name: 'send_message', group: 'messages', risk: 'high', server_allowed: false, enabled: false }],
              },
            },
      )
    })
    expect(await screen.findByText(/has not enabled write tools/)).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Send message' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled()
  })

  it('shows an unknown tool by its name with a neutral description', async () => {
    await renderApp('/write-tools', 'enrolled', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 200, data: meFixture() }
          : {
              status: 200,
              data: {
                server_enabled: true,
                tools: [{ name: 'brand_new_tool', group: 'modules', risk: 'low', server_allowed: true, enabled: false }],
              },
            },
      )
    })
    expect(await screen.findByRole('switch', { name: 'brand_new_tool' })).toBeInTheDocument()
    expect(screen.getByText(/without a description/)).toBeInTheDocument()
  })
})
