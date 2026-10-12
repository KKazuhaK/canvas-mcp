import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { recordRequests } from '@/test/fixtures'
import { renderApp } from '@/test/renderWithProviders'

describe('Site address administration', () => {
  it('requires confirmation and shows restart instructions without retrying configuration', async () => {
    const user = userEvent.setup()
    await renderApp('/admin/settings', 'owner')
    const field = await screen.findByLabelText('Public HTTPS address')
    await user.clear(field)
    await user.click(field)
    await user.paste('https://new.canvas.example.test')
    const seen = recordRequests()
    await user.click(screen.getByRole('button', { name: 'Change site address' }))
    expect(await screen.findByRole('dialog')).toHaveTextContent(/invalidate all existing sessions/)
    expect(seen.some((request) => request.url === '/admin/settings/site')).toBe(false)
    await user.click(screen.getByRole('button', { name: 'Save and end existing connections' }))
    await screen.findByText(/Restart the container to activate it/)
    await waitFor(() => expect(seen.filter((request) => request.url === '/admin/settings/site')).toHaveLength(1))
    const body = JSON.parse(seen.find((request) => request.url === '/admin/settings/site')!.data as string)
    expect(body).toEqual({ revision: 1, public_base_url: 'https://new.canvas.example.test', confirm: true })
    expect(field).toBeDisabled()
  })
})
