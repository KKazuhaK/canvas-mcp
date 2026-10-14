import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { recordRequests } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'
import type { LoginProviderSettings } from '@/api/types'
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios'
import { http } from '@/api/client'

describe('Login provider administration', () => {
  it('shows readable provider types while retaining custom OIDC IDs and callback paths', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings?topic=providers', 'owner', () => {
      const inner = http.defaults.adapter as (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>
      http.defaults.adapter = async (config) => {
        const response = await inner(config)
        if (config.method === 'get' && config.url === '/admin/login-providers') {
          response.data.providers.push(
            { id: 'local', protocol: 'local', enabled: true, rank: 1, config: {}, secret_present: false },
            { id: 'oidc:campus', protocol: 'oidc', enabled: true, rank: 2, config: {}, secret_present: true },
            { id: 'oidc:staff', protocol: 'oidc', enabled: true, rank: 3, config: {}, secret_present: true },
          )
        }
        return response
      }
    })
    expect(await screen.findByText('Microsoft Entra ID')).toBeInTheDocument()
    expect(screen.queryByText('entra', { exact: true })).toBeNull()
    expect(screen.queryByText('local', { exact: true })).toBeNull()
    expect(screen.getByRole('button', { name: 'Edit Local account' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Edit OpenID Connect (OIDC) · staff' })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: 'Edit OpenID Connect (OIDC) · campus' }))
    expect(screen.getByRole('textbox', { name: 'Callback URL' })).toHaveValue('https://canvas.example.test/auth/callback/oidc/campus')
    await user.type(screen.getByRole('textbox', { name: 'OpenID Connect issuer' }), 'https://campus.example.test')
    await user.type(screen.getByRole('textbox', { name: 'Client ID' }), 'campus-client')
    await user.type(screen.getByLabelText(/^Client secret/), 'campus-new-private-secret')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Save sign-in configuration' }))
    await waitFor(() => expect(seen.some(request => request.method === 'PUT' && decodeURIComponent(request.url) === '/admin/login-providers/oidc:campus')).toBe(true))
  })
  it('returns to the provider list on cancel without saving an edited connection', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings?topic=providers', 'owner')
    await user.click(await screen.findByRole('button', { name: 'Edit Microsoft' }))
    expect(screen.queryByRole('button', { name: 'Edit Microsoft' })).toBeNull()
    await user.type(screen.getByLabelText(/^Client secret/), 'cancelled-provider-secret')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(await screen.findByRole('button', { name: 'Edit Microsoft' })).toBeEnabled()
    expect(seen.some((request) => request.method === 'PUT')).toBe(false)
    await user.click(screen.getByRole('button', { name: 'Edit Microsoft' }))
    expect(screen.getByLabelText(/^Client secret/)).toHaveValue('')
  })

  it('does not submit connection settings when Enter is pressed in the independent display-name editor', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings?topic=providers', 'owner')
    await user.click(await screen.findByRole('button', { name: 'Edit Microsoft' }))
    const seen = recordRequests()
    await user.type(screen.getByRole('textbox', { name: 'Display name' }), 'Campus SSO{Enter}')
    expect(seen.some((request) => request.method === 'PUT')).toBe(false)
    expect(screen.getByRole('button', { name: 'Save display name' })).toBeEnabled()
  })
  it('saves a provider name without discarding a configuration draft or its write-only secret', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings?topic=providers', 'owner')
    await user.click(await screen.findByRole('button', { name: 'Edit Microsoft' }))
    await user.type(screen.getByLabelText(/^Client secret/), 'unsaved-configuration-secret')
    await user.type(screen.getByRole('textbox', { name: 'Display name' }), 'Campus SSO')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Save display name' }))
    await waitFor(() => expect(seen.some((request) => request.url === '/admin/settings/sign-in-methods')).toBe(true))
    expect(screen.getByLabelText(/^Client secret/)).toHaveValue('unsaved-configuration-secret')
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save sign-in configuration' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: 'Save sign-in configuration' }))
    await waitFor(() => expect(seen.some((request) => request.url === '/admin/login-providers/entra' && request.method === 'PUT')).toBe(true))
    const request = seen.find((entry) => entry.url === '/admin/login-providers/entra' && entry.method === 'PUT')!
    expect(JSON.parse(String(request.data))).toMatchObject({ revision: 2, client_secret: 'unsaved-configuration-secret' })
    const rename = seen.find((entry) => entry.url === '/admin/settings/sign-in-methods')!
    expect(JSON.parse(String(rename.data))).toEqual({ revision: 1, names: { entra: 'Campus SSO' } })
  })
  it('keeps an open provider draft and its secret when a refresh changes the revision', async () => {
    const user = userEvent.setup()
    const { client } = await renderApp('/admin/settings?topic=providers', 'owner')
    await user.click(await screen.findByRole('button', { name: 'Edit Microsoft' }))
    await user.type(screen.getByLabelText(/^Client secret/), 'unsaved-provider-secret')
    const previous = client.getQueryData<LoginProviderSettings>(['admin', 'login-providers'])!
    const seen = recordRequests()
    act(() => { client.setQueryData(['admin', 'login-providers'], { ...previous, revision: previous.revision + 1 }) })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save sign-in configuration' })).toBeDisabled())
    expect(screen.getByLabelText(/^Client secret/)).toHaveValue('unsaved-provider-secret')
    expect(seen.some((request) => request.method === 'PUT')).toBe(false)
    await user.click(screen.getByRole('button', { name: 'Discard this draft and load saved values' }))
    await waitFor(() => expect(screen.getByLabelText(/^Client secret/)).toHaveValue(''))
  })
  it('keeps a stored secret when the password field is left blank', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings?topic=providers', 'owner')
    await user.click(await screen.findByRole('button', { name: 'Edit Microsoft' }))
    expect(screen.getByLabelText(/^Client secret/)).toHaveValue('')
    expect(screen.getByText(/A secret is saved/)).toBeInTheDocument()
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Save sign-in configuration' }))
    await waitFor(() => expect(seen.some((request) => request.url === '/admin/login-providers/entra')).toBe(true))
    const body = JSON.parse(seen.find((request) => request.url === '/admin/login-providers/entra')!.data as string)
    expect(body).toMatchObject({ revision: 1, enabled: true, rank: 0 })
    expect(body).not.toHaveProperty('client_secret')
  })
})
