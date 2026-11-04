import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderWithQuery, setupI18n } from '@/test/renderWithProviders'
import { hardNavigate } from '@/utils/navigate'
import ReauthNotice from './ReauthNotice'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

beforeEach(async () => {
  vi.mocked(hardNavigate).mockClear()
  await setupI18n('en')
})

describe('the step-up sign-in button', () => {
  it('always asks for reauth, so a fresh session cannot be sent straight back', async () => {
    const user = userEvent.setup()
    renderWithQuery(<MemoryRouter initialEntries={['/sign-in-methods']}><ReauthNotice /></MemoryRouter>)
    await user.click(screen.getByRole('button', { name: 'Sign in again' }))
    expect(hardNavigate).toHaveBeenCalledTimes(1)
    const target = new URL(String(vi.mocked(hardNavigate).mock.calls[0][0]), 'https://canvas.example.test')
    expect(target.pathname).toBe('/auth/login')
    expect(target.searchParams.get('reauth')).toBe('1')
    expect(target.searchParams.get('return_to')).toMatch(/^\/account\//)
  })
})
