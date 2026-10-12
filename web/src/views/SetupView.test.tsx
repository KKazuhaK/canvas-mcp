import { act, screen, waitFor } from '@testing-library/react'
import i18next from 'i18next'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { recordRequests } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'
import zhAdmin from '@/locales/zh/admin.json'

describe('Database login installation', () => {
  it('opens first-install setup from the home page and saves credentials through the API', async () => {
    const user = userEvent.setup()
    await renderApp('/', 'setup')
    expect(await screen.findByRole('heading', { name: 'Configure sign-in' })).toBeInTheDocument()
    const seen = recordRequests()
    await user.type(screen.getByLabelText(/^Installation code/), 'A'.repeat(43))
    await user.type(screen.getByLabelText(/^Directory/), '11111111-2222-3333-4444-555555555555')
    await user.type(screen.getByLabelText(/^Client ID/), 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
    await user.type(screen.getByLabelText(/^Client secret/), 'new-client-secret-0123456789')
    expect(screen.getByLabelText('Callback URL')).toHaveValue('https://canvas.example.test/auth/callback/entra')
    await user.click(screen.getByRole('button', { name: 'Initialize sign-in' }))
    await waitFor(() => expect(seen.some((request) => request.url === '/setup' && request.method === 'POST')).toBe(true))
    const sent = seen.find((request) => request.url === '/setup' && request.method === 'POST')!
    expect(JSON.parse(sent.data as string)).toMatchObject({ code: 'A'.repeat(43), revision: 1, client_secret: 'new-client-secret-0123456789' })
    expect(await screen.findByRole('heading', { name: 'Canvas account' })).toBeInTheDocument()
  })

  it('renders installation in Chinese', async () => {
    await renderApp('/setup', 'setup')
    await act(async () => { await i18next.changeLanguage('zh') })
    expect(await screen.findByRole('heading', { name: zhAdmin.installation.title })).toBeInTheDocument()
    expect(screen.getByLabelText(new RegExp(`^${zhAdmin.installation.code}`))).toHaveAttribute('type', 'password')
  })
  it('redirects an initialized installation to sign-in', async () => {
    await renderApp('/setup', 'signed-out')
    expect(await screen.findByRole('heading', { name: 'Canvas account' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Configure sign-in' })).not.toBeInTheDocument()
  })
})
