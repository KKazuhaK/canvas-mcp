import { describe, expect, it } from 'vitest'
import { formatDateTime, formatRelative, knownTimeZone } from './time'

const NOON_UTC = '2026-01-15T12:00:00Z'

describe('formatDateTime', () => {
  it('uses the server display zone, and names it', () => {
    expect(formatDateTime(NOON_UTC, 'en', 'UTC')).toBe('Jan 15, 2026, 12:00 PM UTC')
    expect(formatDateTime(NOON_UTC, 'en', 'America/Los_Angeles')).toBe('Jan 15, 2026, 4:00 AM PST')
  })

  it('gives the same instant a different wall time in a different zone', () => {
    const la = formatDateTime(NOON_UTC, 'en', 'America/Los_Angeles')
    const tokyo = formatDateTime(NOON_UTC, 'en', 'Asia/Tokyo')
    expect(la).not.toBe(tokyo)
    expect(tokyo).toContain('9:00 PM')
  })

  it('falls back to the browser zone for a missing or unknown zone', () => {
    const plain = formatDateTime(NOON_UTC, 'en')
    expect(formatDateTime(NOON_UTC, 'en', null)).toBe(plain)
    expect(formatDateTime(NOON_UTC, 'en', 'Not/AZone')).toBe(plain)
    expect(knownTimeZone('Not/AZone')).toBeNull()
    expect(knownTimeZone('UTC')).toBe('UTC')
  })

  it('returns null for an absent or invalid time', () => {
    expect(formatDateTime(null, 'en', 'UTC')).toBeNull()
    expect(formatDateTime('nope', 'en', 'UTC')).toBeNull()
  })
})

describe('formatRelative', () => {
  const now = Date.parse(NOON_UTC)
  const ago = (seconds: number) => new Date(now - seconds * 1000).toISOString()

  it('reads naturally in each step', () => {
    expect(formatRelative(ago(20), 'en', now)).toBe('now')
    expect(formatRelative(ago(5 * 60), 'en', now)).toBe('5 minutes ago')
    expect(formatRelative(ago(3 * 3600), 'en', now)).toBe('3 hours ago')
    expect(formatRelative(ago(2 * 86400), 'en', now)).toBe('2 days ago')
  })

  it('is null for a missing or invalid value, and follows the language', () => {
    expect(formatRelative(null, 'en', now)).toBeNull()
    expect(formatRelative('nope', 'en', now)).toBeNull()
    expect(formatRelative(ago(5 * 60), 'zh', now)).toContain('5')
  })
})
