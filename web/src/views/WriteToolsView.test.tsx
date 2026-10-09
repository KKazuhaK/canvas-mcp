import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { hardNavigate } from '@/utils/navigate'
import { renderApp } from '@/test/renderWithProviders'
import { errorBody, meFixture, recordRequests, scriptAdapter } from '@/test/fixtures'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

beforeEach(() => {
  vi.mocked(hardNavigate).mockClear()
})

describe('WriteToolsView', () => {
  it('explains the three layers and lists the groups the server returns', async () => {
    await renderApp('/write-tools')
    expect(await screen.findByRole('heading', { name: 'Write tools' })).toBeInTheDocument()
    const layers = await screen.findByRole('region', { name: 'Who decides' })
    expect(within(layers).getByText('Server allows')).toBeInTheDocument()
    expect(within(layers).getByText('You enabled')).toBeInTheDocument()
    expect(within(layers).getByText('Course allows (decided per course)')).toBeInTheDocument()
    expect(within(layers).getByText(/Previews, confirmations, course policy/)).toBeInTheDocument()
    expect(within(layers).getByText(/needs a sign-in from the last 10 minutes/)).toBeInTheDocument()

    for (const group of [
      'Planner and calendar',
      'Assignment submission',
      'Module completion',
      'Messages',
      'Other write tools',
    ]) {
      expect(screen.getByRole('heading', { name: group })).toBeInTheDocument()
    }
  })

  it('flags inbox tools as sending as you and says what each tool changes', async () => {
    await renderApp('/write-tools')
    const messages = await screen.findByRole('region', { name: 'Messages' })
    expect(within(messages).getAllByText('Sends as you')).toHaveLength(2)
    expect(within(messages).getAllByText('Changes Canvas')).toHaveLength(2)
    const other = screen.getByRole('region', { name: 'Other write tools' })
    expect(within(other).getByText('Writes files on the server')).toBeInTheDocument()
    // A tool the app has no text for still shows, by its name.
    expect(within(other).getByRole('switch', { name: 'update_syllabus' })).toBeInTheDocument()
  })

  it('disables a tool the server does not offer and says why', async () => {
    await renderApp('/write-tools')
    const toggle = await screen.findByRole('switch', { name: 'Mark module item done' })
    expect(toggle).toBeDisabled()
    expect(screen.getByText('Not offered by this server')).toBeInTheDocument()
  })

  it('starts from what the server says is on, and Save stays disabled until something changes', async () => {
    const user = userEvent.setup()
    await renderApp('/write-tools')
    expect(await screen.findByRole('switch', { name: 'Create planner note' })).toBeChecked()
    expect(screen.getByRole('switch', { name: 'Send message' })).toBeChecked()
    expect(screen.getByRole('switch', { name: 'Submit assignment' })).not.toBeChecked()
    const save = screen.getByRole('button', { name: 'Save changes' })
    expect(save).toBeDisabled()

    await user.click(screen.getByRole('switch', { name: 'Submit assignment' }))
    expect(save).toBeEnabled()
    expect(screen.getByText('You have unsaved changes.')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Discard' }))
    expect(screen.getByRole('switch', { name: 'Submit assignment' })).not.toBeChecked()
    expect(save).toBeDisabled()
  })

  it('saves exactly the ticked offered tools, with the CSRF header', async () => {
    const user = userEvent.setup()
    await renderApp('/write-tools')
    const seen = recordRequests()
    await user.click(await screen.findByRole('switch', { name: 'Submit assignment' }))
    await user.click(screen.getByRole('switch', { name: 'Send message' })) // off
    await user.click(screen.getByRole('button', { name: 'Save changes' }))

    expect(await screen.findByText('Write tools saved.')).toBeInTheDocument()
    const put = seen.find((r) => r.method === 'PUT')
    expect(put?.url).toBe('/me/write-tools')
    expect(put?.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(JSON.parse(put?.data as string)).toEqual({ enabled: ['create_planner_note', 'submit_assignment'] })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled())
    expect(screen.getByRole('switch', { name: 'Submit assignment' })).toBeChecked()
  })

  it('"Turn all off" asks first, then calls DELETE and switches everything off', async () => {
    const user = userEvent.setup()
    await renderApp('/write-tools')
    const seen = recordRequests()
    await user.click(await screen.findByRole('button', { name: 'Turn all off' }))
    const dialog = await screen.findByRole('dialog')
    expect(seen.some((r) => r.method === 'DELETE')).toBe(false)
    await user.click(within(dialog).getByRole('button', { name: 'Turn all off' }))
    expect(await screen.findByText('All write tools are off.')).toBeInTheDocument()
    const del = seen.find((r) => r.method === 'DELETE')
    expect(del?.url).toBe('/me/write-tools')
    expect(del?.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(del?.data).toBeUndefined()
    await waitFor(() => expect(screen.getByRole('switch', { name: 'Send message' })).not.toBeChecked())
    expect(screen.queryByRole('button', { name: 'Turn all off' })).toBeNull()
  })

  it('asks for a fresh sign-in to turn a tool on, and goes to /account/login with a return_to', async () => {
    const user = userEvent.setup()
    await renderApp('/write-tools', 'stale-owner')
    await user.click(await screen.findByRole('switch', { name: 'Submit assignment' }))
    await user.click(screen.getByRole('button', { name: 'Save changes' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Sign in again to continue')
    expect(alert).toHaveTextContent('last 10 minutes')
    await user.click(within(alert).getByRole('button', { name: 'Sign in again' }))
    expect(hardNavigate).toHaveBeenCalledWith('/account/login?return_to=%2Faccount%2Fwrite-tools')
  })

  it('does not stack the browser leave-site prompt on the sign-in-again button, and says what is lost', async () => {
    const user = userEvent.setup()
    await renderApp('/write-tools', 'stale-owner')
    await user.click(await screen.findByRole('switch', { name: 'Submit assignment' }))
    const leave = () => {
      const event = new Event('beforeunload', { cancelable: true })
      window.dispatchEvent(event)
      return event.defaultPrevented
    }
    // With unsaved choices the guard is armed...
    expect(leave()).toBe(true)
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    await screen.findByText('Sign in again to continue')
    // ...and stands down once the save was refused for a stale sign-in.
    expect(leave()).toBe(false)
    expect(screen.getByRole('note', { name: '' })).toHaveTextContent(
      'you will need to turn your choices on again',
    )
  })

  it('turning a tool off never needs a fresh sign-in', async () => {
    const user = userEvent.setup()
    await renderApp('/write-tools', 'stale-owner')
    await user.click(await screen.findByRole('switch', { name: 'Send message' }))
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    expect(await screen.findByText('Write tools saved.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Sign in again' })).toBeNull()
  })

  it('maps write_tool_not_allowed to a fixed message', async () => {
    const user = userEvent.setup()
    await renderApp('/write-tools', 'enrolled', () => {
      scriptAdapter((r) => {
        if (r.url === '/me') return { status: 200, data: meFixture() }
        if (r.method === 'PUT') return { status: 422, data: errorBody('write_tool_not_allowed', { tool: 'x_tool' }) }
        return {
          status: 200,
          data: {
            groups: [
              {
                id: 'planner',
                tools: [{ name: 'create_planner_note', offered: true, enabled: false, enabled_at: null, effect: 'canvas_write' }],
              },
            ],
            kept_not_offered: [],
            offered_any: true,
            editable: true,
          },
        }
      })
    })
    await user.click(await screen.findByRole('switch', { name: 'Create planner note' }))
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('does not allow one of those tools')
  })

  it('says so when the server offers no write tools, and lists tools it kept', async () => {
    await renderApp('/write-tools', 'enrolled', () => {
      scriptAdapter((r) => {
        if (r.url === '/me') return { status: 200, data: meFixture() }
        return {
          status: 200,
          data: {
            groups: [
              { id: 'planner', tools: [] },
              { id: 'submissions', tools: [] },
              { id: 'modules', tools: [] },
              { id: 'inbox', tools: [] },
            ],
            kept_not_offered: ['old_tool'],
            offered_any: false,
            editable: true,
          },
        }
      })
    })
    expect(await screen.findByText(/does not offer any write tools/)).toBeInTheDocument()
    expect(screen.getByText('old_tool')).toBeInTheDocument()
    expect(screen.getByText(/Kept, but not offered on this server/)).toBeInTheDocument()
  })

  it('shows a fixed message when the settings cannot be read', async () => {
    await renderApp('/write-tools', 'enrolled', () => {
      scriptAdapter((r) =>
        r.url === '/me'
          ? { status: 200, data: meFixture() }
          : { status: 503, data: errorBody('write_tools_unavailable') },
      )
    })
    expect(await screen.findByRole('alert')).toHaveTextContent('write-tool settings cannot be read')
  })
})
