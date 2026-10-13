import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { recordRequests } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'

describe('Token expiry email opt-in', () => {
  it('defaults off and saves only the signed-in account preference with CSRF', async () => {
    const user = userEvent.setup()
    await renderApp('/', 'enrolled')
    const toggle = await screen.findByRole('switch', { name: 'Email me token expiry reminders' })
    expect(toggle).not.toBeChecked()
    const seen = recordRequests()
    await user.type(screen.getByLabelText('Reminder email address'), 'student@example.test')
    await user.click(toggle)
    await user.click(screen.getByRole('button', { name: 'Save reminder preferences' }))
    await waitFor(() => expect(seen.some((r) => r.url === '/notifications' && r.method === 'PUT')).toBe(true))
    const saved = seen.find((r) => r.url === '/notifications' && r.method === 'PUT')!
    expect(JSON.parse(saved.data as string)).toEqual({ enabled: true, email: 'student@example.test', locale: 'en' })
    expect(saved.headers['x-csrf-token']).toBe('mock-csrf-token-not-a-secret')
    expect(await screen.findByText('Reminder preferences saved.')).toBeVisible()
  })
})
