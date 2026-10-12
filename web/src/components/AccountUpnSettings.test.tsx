import { screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { renderApp } from '@/test/renderWithProviders'

describe('Personal account UPN', () => {
  it('shows the administrator-owned login name without an edit action', async () => {
    await renderApp('/', 'enrolled')
    const input = await screen.findByLabelText('Account UPN')
    expect(input).toHaveAttribute('readonly')
    expect(screen.queryByRole('button', { name: 'Save account UPN' })).toBeNull()
    expect(await screen.findByText('Only administrators can change your account UPN.')).toBeVisible()
    expect(screen.getByRole('heading', { name: 'My account' })).toBeVisible()
  })
})
