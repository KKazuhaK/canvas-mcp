import { screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { getVersion } from '@/api/endpoints'
import type { BuildInfo } from '@/api/types'
import { renderWithQuery, setupI18n } from '@/test/renderWithProviders'
import BuildFooter from './BuildFooter'

vi.mock('@/api/endpoints', () => ({ getVersion: vi.fn() }))
afterEach(() => vi.resetAllMocks())

describe('server build stamp', () => {
  it.each(['en', 'zh'] as const)('shows server version, full commit tooltip and UTC time in %s', async (lang) => {
    await setupI18n(lang)
    const stamp = { version: '1.14.0-beta.11', commit: 'abcdef0123456789abcdef0123456789abcdef01', built_at: '2026-10-13T08:00:00Z' }
    vi.mocked(getVersion).mockResolvedValue(stamp)
    renderWithQuery(<BuildFooter />)
    const footer = await screen.findByRole('contentinfo')
    expect(footer).toHaveTextContent(stamp.version)
    expect(footer).toHaveTextContent(stamp.built_at)
    expect(screen.getByTitle(stamp.commit)).toHaveTextContent(stamp.commit.slice(0, 12))
    expect(footer).toHaveTextContent('UTC')
  })

  it('does not invent a release when the metadata request fails', async () => {
    await setupI18n()
    vi.mocked(getVersion).mockRejectedValue(new Error('unavailable'))
    renderWithQuery(<BuildFooter />)
    expect(screen.queryByRole('contentinfo')).not.toBeInTheDocument()
  })

  it('ignores a malformed response without taking down the account page', async () => {
    await setupI18n()
    vi.mocked(getVersion).mockResolvedValue({ version: 'unexpected' } as BuildInfo)
    renderWithQuery(<BuildFooter />)
    expect(screen.queryByRole('contentinfo')).not.toBeInTheDocument()
  })
})
