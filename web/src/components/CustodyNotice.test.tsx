import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { setupI18n } from '@/test/renderWithProviders'
import CustodyNotice from './CustodyNotice'

describe('custody notice', () => {
  it.each(['en', 'zh'] as const)('renders the versioned text in %s', async (lang) => {
    await setupI18n(lang)
    render(<CustodyNotice version={1} checked={false} onChange={() => {}} />)
    expect(screen.getByRole('note')).toHaveTextContent(lang === 'en' ? 'technically decrypt' : '技术上可以解密')
    expect(screen.getByRole('note')).toHaveTextContent(lang === 'en' ? 'expiry date' : '到期日期')
    expect(screen.getByRole('note')).toHaveTextContent(lang === 'en' ? 'Approved Integrations' : '已批准的集成')
    expect(screen.getByRole('checkbox')).not.toBeChecked()
    expect(screen.getByRole('checkbox')).toBeRequired()
  })

  it('refuses to acknowledge a version whose text is missing from the app', async () => {
    await setupI18n('en')
    render(<CustodyNotice version={99} checked={false} onChange={() => {}} />)
    expect(screen.getByRole('note')).toHaveTextContent('Reload this page')
    expect(screen.getByRole('checkbox')).toBeDisabled()
  })
})
