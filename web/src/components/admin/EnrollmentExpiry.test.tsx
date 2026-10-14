import { screen } from '@testing-library/react'
import { beforeEach, describe, expect, it } from 'vitest'
import type { AdminEnrollment } from '@/api/types'
import { renderWithQuery, setupI18n } from '@/test/renderWithProviders'
import EnrollmentExpiry from './EnrollmentExpiry'

const enrollment: AdminEnrollment = {
  id: 'test-enrollment', is_primary: true, custody_notice_version: 1,
  custody_ack_at: null, custody_current: true, canvas_user_name: 'Example',
  canvas_user_id: '42', school: null, state: 'active', invalid_reason: null,
  invalid_since: null, last_verified_at: null, last_used_at: null,
  created_at: null, updated_at: null, expires_on: '2027-04-10',
  expires_at: '2027-04-10T08:00:00Z', expiry_source: 'canvas', expiry_notice: 'soon',
}

beforeEach(async () => { await setupI18n('en') })

describe('Owner enrollment expiry', () => {
  it('shows the automatic date and server reminder classification', () => {
    renderWithQuery(<EnrollmentExpiry enrollment={enrollment} />)
    expect(screen.getByText('Apr 10, 2027')).toBeInTheDocument()
    expect(screen.getByText('Expiring soon')).toBeInTheDocument()
  })

  it('does not display a date or reminder from unknown metadata even if old values remain', () => {
    renderWithQuery(<EnrollmentExpiry enrollment={{ ...enrollment, expiry_source: 'unknown' }} />)
    expect(screen.getByText('Not available')).toBeInTheDocument()
    expect(screen.queryByText('Apr 10, 2027')).toBeNull()
    expect(screen.queryByText('Expiring soon')).toBeNull()
  })

  it('distinguishes explicit no-expiry metadata from an unavailable date', () => {
    renderWithQuery(<EnrollmentExpiry enrollment={{ ...enrollment, expires_on: null, expires_at: null, expiry_notice: 'none' }} />)
    expect(screen.getByText('Never expires')).toBeInTheDocument()
    expect(screen.queryByText('Not available')).toBeNull()
  })

  it('localizes the date and expired state in Chinese', async () => {
    await setupI18n('zh')
    renderWithQuery(<EnrollmentExpiry enrollment={{ ...enrollment, expiry_notice: 'passed' }} />)
    expect(screen.getByText('2027年4月10日')).toBeInTheDocument()
    expect(screen.getByText('已到期')).toBeInTheDocument()
  })
})
