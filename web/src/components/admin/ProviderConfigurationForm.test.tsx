import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderWithQuery, setupI18n } from '@/test/renderWithProviders'
import zhAdmin from '@/locales/zh/admin.json'
import ProviderConfigurationForm, { type EditableProvider } from './ProviderConfigurationForm'

const provider: EditableProvider = {
  id: 'entra', protocol: 'entra', enabled: true, rank: 0, secret_present: true,
  config: { tenant_id: '11111111-2222-3333-4444-555555555555', client_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' },
}
const callback = 'https://mcp.example.com/auth/callback/entra'

beforeEach(async () => { await setupI18n('en') })

describe('Write-only sign-in provider credentials', () => {
  it('refuses a stale or otherwise disabled editor even when the form is submitted directly', async () => {
    const save = vi.fn(async () => {})
    renderWithQuery(<ProviderConfigurationForm provider={provider} callbackUri={callback} onSave={save} disabled />)
    const button = screen.getByRole('button', { name: 'Save sign-in configuration' })
    expect(button).toBeDisabled()
    fireEvent.submit(button.closest('form')!)
    expect(save).not.toHaveBeenCalled()
  })
  it('uploads an embedded PNG and explicitly restores the default icon', async () => {
    const user = userEvent.setup()
    const save = vi.fn(async () => {})
    renderWithQuery(<ProviderConfigurationForm provider={provider} callbackUri={callback} onSave={save} />)
    const file = new File([new Uint8Array([137, 80, 78, 71])], 'icon.png', { type: 'image/png' })
    await user.upload(screen.getByLabelText('Upload sign-in icon'), file)
    await waitFor(() => expect(document.querySelector('img')?.getAttribute('src')).toBe('data:image/png;base64,iVBORw=='))
    await user.click(screen.getByRole('button', { name: 'Save sign-in configuration' }))
    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({ icon_data: 'data:image/png;base64,iVBORw==' })))
    await user.click(screen.getByRole('button', { name: 'Restore default icon' }))
    await user.click(screen.getByRole('button', { name: 'Save sign-in configuration' }))
    await waitFor(() => expect(save).toHaveBeenLastCalledWith(expect.objectContaining({ icon_data: null })))
  })
  it('enables automatic email association on the edited instance without a second verification step', async () => {
    const user = userEvent.setup()
    const save = vi.fn(async () => {})
    renderWithQuery(<ProviderConfigurationForm provider={provider} callbackUri={callback} onSave={save} />)
    const automatic = screen.getByRole('switch', { name: 'Automatically link matching email to an existing account' })
    expect(automatic).not.toBeChecked()
    await user.click(automatic)
    await user.click(screen.getByRole('button', { name: 'Save sign-in configuration' }))
    await waitFor(() => expect(save).toHaveBeenCalledWith({ config: provider.config, enabled: true, rank: 0, auto_link_email: true }))
    expect(screen.queryByRole('dialog')).toBeNull()
  })
  it('omits the saved secret from an ordinary edit', async () => {
    const user = userEvent.setup()
    const save = vi.fn(async () => {})
    renderWithQuery(<ProviderConfigurationForm provider={provider} callbackUri={callback} onSave={save} />)
    expect(screen.getByLabelText('Client secret')).toHaveValue('')
    expect(screen.getByText(/Leave blank to keep it/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Save sign-in configuration' }))
    await waitFor(() => expect(save).toHaveBeenCalledWith({ config: provider.config, enabled: true, rank: 0, auto_link_email: false }))
  })

  it('sends a replacement once and clears it after a successful save', async () => {
    const user = userEvent.setup()
    const save = vi.fn(async () => {})
    renderWithQuery(<ProviderConfigurationForm provider={provider} callbackUri={callback} onSave={save} />)
    const input = screen.getByLabelText('Client secret')
    expect(input).toHaveAttribute('type', 'password')
    await user.type(input, 'new-client-secret-value')
    await user.click(screen.getByRole('button', { name: 'Save sign-in configuration' }))
    await waitFor(() => expect(save).toHaveBeenCalledWith({ config: provider.config, enabled: true, rank: 0, auto_link_email: false, client_secret: 'new-client-secret-value' }))
    await waitFor(() => expect(input).toHaveValue(''))
  })

  it('requires a secret at installation and presents the exact callback', async () => {
    const user = userEvent.setup()
    const save = vi.fn(async () => {})
    renderWithQuery(<ProviderConfigurationForm provider={{ ...provider, secret_present: false }} callbackUri={callback} onSave={save} installation />)
    expect(screen.getByLabelText('Callback URL')).toHaveValue(callback)
    expect(screen.getByLabelText('Callback URL')).toHaveAttribute('readonly')
    expect(screen.getByLabelText(/^Client secret/)).toBeRequired()
    expect(screen.queryByRole('switch')).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Initialize sign-in' }))
    expect(save).not.toHaveBeenCalled()
    await user.type(screen.getByLabelText(/^Client secret/), 'first-client-secret-value')
    await user.click(screen.getByRole('button', { name: 'Initialize sign-in' }))
    await waitFor(() => expect(save).toHaveBeenCalledOnce())
  })

  it('renders credential handling in Chinese too', async () => {
    await setupI18n('zh')
    renderWithQuery(<ProviderConfigurationForm provider={provider} callbackUri={callback} onSave={async () => {}} />)
    expect(screen.getByLabelText(zhAdmin.providerConfig.secret)).toHaveValue('')
    expect(screen.getByText(zhAdmin.providerConfig.keepSecret)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: zhAdmin.providerConfig.save })).toBeInTheDocument()
  })
})
