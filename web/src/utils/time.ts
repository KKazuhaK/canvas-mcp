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

/** Short summary of a User-Agent string, e.g. "Chrome on Windows". Never the raw string. */
export function summariseUserAgent(ua: string | null | undefined): string | null {
  if (!ua) return null
  const browser =
    /Edg\//.test(ua)
      ? 'Edge'
      : /OPR\/|Opera/.test(ua)
        ? 'Opera'
        : /Firefox\//.test(ua)
          ? 'Firefox'
          : /Chrome\//.test(ua)
            ? 'Chrome'
            : /Safari\//.test(ua)
              ? 'Safari'
              : null
  const os = /Windows/.test(ua)
    ? 'Windows'
    : /Android/.test(ua)
      ? 'Android'
      : /iPhone|iPad|iOS/.test(ua)
        ? 'iOS'
        : /Mac OS X|Macintosh/.test(ua)
          ? 'macOS'
          : /Linux/.test(ua)
            ? 'Linux'
            : null
  if (browser && os) return `${browser} / ${os}`
  return browser ?? os
}
