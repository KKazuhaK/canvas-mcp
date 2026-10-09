import { act, screen, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { renderApp } from '@/test/renderWithProviders'
import { useLanguage } from '@/stores/language'

describe('document title', () => {
  it('names the page and follows the language', async () => {
    await renderApp('/token', 'enrolled')
    await screen.findByRole('heading', { level: 1 })
    await waitFor(() => expect(document.title).toBe('Canvas token - Canvas account'))
    act(() => useLanguage.getState().setLanguage('zh'))
    await waitFor(() => expect(document.title).toBe('Canvas 令牌 - Canvas 账户'))
  })

  it('falls back to the plain app title on unnamed routes', async () => {
    await renderApp('/', 'enrolled')
    await screen.findByRole('heading', { level: 1 })
    await waitFor(() => expect(document.title).toBe('Canvas account'))
  })
})
