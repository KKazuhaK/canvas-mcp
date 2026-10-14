import { act, screen, waitFor } from '@testing-library/react'
import i18next from 'i18next'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { recordRequests } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'
import zhAdmin from '@/locales/zh/admin.json'

describe('Database login installation', () => {
  it('starts with local credentials and offers every external provider without requiring Entra', async () => {
    const user = userEvent.setup()
    const { router } = await renderApp('/setup', 'setup')
    expect(await screen.findByRole('heading', { name: 'Local administrator' })).toBeInTheDocument()
    expect(screen.queryByLabelText(/^Client ID/)).not.toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: 'External sign-in (optional)' }))
    for (const name of ['Local account only', 'Microsoft Entra', 'Google', 'GitHub', 'OpenID Connect']) {
      expect(screen.getByRole('option', { name })).toBeInTheDocument()
    }
    await user.click(screen.getByRole('option', { name: 'Local account only' }))
    for (const [label, value] of [[/^Installation code/, 'A'.repeat(43)], [/^Account UPN/, 'admin'], [/^Password/, 'a long private local password'], [/^Confirm password/, 'a long private local password']] as const) {
      await user.click(screen.getByLabelText(label)); await user.paste(value)
    }
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Initialize sign-in' }))
    expect(await screen.findByRole('button', { name: 'Sign in with local account' })).toBeInTheDocument()
    const body = JSON.parse(seen.find((request) => request.url === '/setup' && request.method === 'POST')!.data as string)
    expect(body.local_account.username).toBe('admin')
    expect(body).not.toHaveProperty('provider_id')
    await user.click(screen.getByLabelText(/^Account UPN/)); await user.paste('admin')
    await user.click(screen.getByLabelText(/^Password/)); await user.paste('wrong')
    await user.click(screen.getByRole('button', { name: 'Sign in with local account' }))
    expect(await screen.findByText('The username or password is incorrect, or local sign-in is unavailable.')).toBeInTheDocument()
    await user.clear(screen.getByLabelText(/^Password/)); await user.click(screen.getByLabelText(/^Password/)); await user.paste('a long private local password')
    await user.click(screen.getByRole('button', { name: 'Sign in with local account' }))
    expect(await screen.findByRole('heading', { name: 'My account' })).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/')
    await user.click(screen.getByRole('navigation', { name: 'Main navigation' }).querySelector('a[href="/sign-in-methods"]')!)
    expect(await screen.findByRole('heading', { name: 'Change password' })).toBeInTheDocument()
    await user.click(screen.getByLabelText(/^Current password/)); await user.paste('a long private local password')
    await user.click(screen.getByLabelText(/^New password/)); await user.paste('another very long local password')
    await user.click(screen.getByLabelText(/^Confirm password/)); await user.paste('another very long local password')
    await user.click(screen.getByRole('button', { name: 'Change password' }))
    await waitFor(() => expect(router.state.location.pathname).toBe('/sign-in'))
    expect(seen.some((request) => request.url === '/me/password' && request.method === 'PUT')).toBe(true)
  })
  it('opens first-install setup from the home page and saves credentials through the API', async () => {
    const user = userEvent.setup()
    await renderApp('/', 'setup')
    expect(await screen.findByRole('heading', { name: 'Configure sign-in' })).toBeInTheDocument()
    const seen = recordRequests()
    await user.click(screen.getByLabelText(/^Installation code/)); await user.paste('A'.repeat(43))
    await user.click(screen.getByLabelText(/^Account UPN/)); await user.paste('admin')
    await user.click(screen.getByLabelText(/^Password/)); await user.paste('a long private local password')
    await user.click(screen.getByLabelText(/^Confirm password/)); await user.paste('a long private local password')
    await user.click(screen.getByRole('combobox', { name: 'External sign-in (optional)' }))
    await user.click(screen.getByRole('option', { name: 'Microsoft Entra' }))
    await user.click(screen.getByLabelText(/^Directory/)); await user.paste('11111111-2222-3333-4444-555555555555')
    await user.click(screen.getByLabelText(/^Client ID/)); await user.paste('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
    await user.click(screen.getByLabelText(/^Client secret/)); await user.paste('new-client-secret-0123456789')
    expect(screen.getByLabelText('Callback URL')).toHaveValue('https://canvas.example.test/auth/callback/entra')
    await user.click(screen.getByRole('button', { name: 'Initialize sign-in' }))
    await waitFor(() => expect(seen.some((request) => request.url === '/setup' && request.method === 'POST')).toBe(true))
    const sent = seen.find((request) => request.url === '/setup' && request.method === 'POST')!
    expect(JSON.parse(sent.data as string)).toMatchObject({ code: 'A'.repeat(43), revision: 1, local_account: { username: 'admin', password: 'a long private local password' }, provider_id: 'entra', client_secret: 'new-client-secret-0123456789' })
    expect(await screen.findByRole('heading', { name: 'Canvas MCP' })).toBeInTheDocument()
  })

  it('renders installation in Chinese', async () => {
    await renderApp('/setup', 'setup')
    await act(async () => { await i18next.changeLanguage('zh') })
    expect(await screen.findByRole('heading', { name: zhAdmin.installation.title })).toBeInTheDocument()
    expect(screen.getByLabelText(new RegExp(`^${zhAdmin.installation.code}`))).toHaveAttribute('type', 'password')
  })
  it('redirects an initialized installation to sign-in', async () => {
    await renderApp('/setup', 'signed-out')
    expect(await screen.findByRole('heading', { name: 'Canvas MCP' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Configure sign-in' })).not.toBeInTheDocument()
  })
})
