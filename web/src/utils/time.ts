import type { Language } from '@/stores/language'

/** Intl locale for a UI language. */
export function intlLocale(lang: Language): string {
  return lang === 'zh' ? 'zh-CN' : 'en-US'
}

function parse(iso: string | null | undefined): Date | null {
  if (!iso) return null
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? null : date
}

/** Absolute timestamp in the viewer's locale and time zone, or null if absent/invalid. */
export function formatDateTime(iso: string | null | undefined, lang: Language): string | null {
  const date = parse(iso)
  if (!date) return null
  return new Intl.DateTimeFormat(intlLocale(lang), {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

export function formatDate(iso: string | null | undefined, lang: Language): string | null {
  const date = parse(iso)
  if (!date) return null
  return new Intl.DateTimeFormat(intlLocale(lang), { dateStyle: 'medium' }).format(date)
}

/**
 * A calendar date the server sends as YYYY-MM-DD (no time zone), shown as that
 * same day in the viewer's locale. Parsed by hand so a UTC midnight can never slip
 * to the previous day.
 */
export function formatCalendarDate(ymd: string | null | undefined, lang: Language): string | null {
  if (!ymd) return null
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(ymd)
  if (!match) return null
  const date = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]))
  if (Number.isNaN(date.getTime())) return null
  return new Intl.DateTimeFormat(intlLocale(lang), { dateStyle: 'medium' }).format(date)
}
