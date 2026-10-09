// Redirect safety. `return_to` and `txn` arrive in the query string, which anyone
// can craft, so neither is used until it passes the validators in this file.
// OAuth and consent hand-offs never use query parameters as a destination: they
// navigate to a URL that came from the server's JSON (see safeRedirectTarget).

const SITE_PREFIX = '/account'
const PROBE_ORIGIN = 'https://return-to.invalid'
// C0 controls, DEL and the C1 range: browsers strip some of these inside URLs,
// which is how '/\t/evil.example' becomes '//evil.example'.
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/

function passesPathChecks(value: string): boolean {
  if (value.length === 0 || value.length > 1024) return false
  if (CONTROL_CHARS.test(value)) return false
  if (value.includes('\\')) return false
  if (!value.startsWith('/') || value.startsWith('//')) return false
  return true
}

/**
 * Accepts only a same-site relative path inside the /account SPA and returns it
 * unchanged, or null. Rejects scheme-relative URLs ('//evil'), absolute URLs,
 * backslashes, control characters, encoded variants of those, and any path
 * outside /account (including /account-evil and /account/api/*, which are not
 * pages).
 */
export function sanitizeReturnTo(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null
  if (!passesPathChecks(raw)) return null

  let decoded: string
  try {
    decoded = decodeURIComponent(raw)
  } catch {
    return null
  }
  // The decoded form must pass the same checks, so '/%2fevil.example' and
  // '/%5cevil.example' cannot smuggle a second slash or a backslash through.
  if (!passesPathChecks(decoded)) return null

  let parsed: URL
  try {
    parsed = new URL(raw, PROBE_ORIGIN)
  } catch {
    return null
  }
  if (parsed.origin !== PROBE_ORIGIN) return null

  const path = parsed.pathname
  const inSpa = path === SITE_PREFIX || path.startsWith(`${SITE_PREFIX}/`)
  if (!inSpa) return null
  if (path === `${SITE_PREFIX}/api` || path.startsWith(`${SITE_PREFIX}/api/`)) return null
  if (path.split('/').some((segment) => segment === '..' || segment === '.')) return null
  return raw
}

const TXN_PATTERN = /^[A-Za-z0-9_-]{1,128}$/

/** Consent transaction ids are opaque tokens; anything else is dropped. */
export function sanitizeTxn(raw: string | null | undefined): string | null {
  return typeof raw === 'string' && TXN_PATTERN.test(raw) ? raw : null
}

/**
 * A destination the server handed back in JSON (consent redirect_url, IdP
 * authorize URL for linking). Only http(s) or a same-site path is accepted, so a
 * compromised response cannot navigate to javascript: or data: URLs.
 */
export function safeRedirectTarget(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 4096) return null
  if (CONTROL_CHARS.test(raw)) return null
  try {
    const base = typeof window !== 'undefined' ? window.location.origin : PROBE_ORIGIN
    const url = new URL(raw, base)
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
    return url.href
  } catch {
    return null
  }
}

/** Only https links are rendered as links (client_uri, docs). */
export function safeHttpsUrl(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null
  try {
    const url = new URL(raw)
    return url.protocol === 'https:' ? url.href : null
  } catch {
    return null
  }
}

/** Where the SPA is mounted. The router basename is stripped from its locations. */
export const SITE_BASE = SITE_PREFIX

/**
 * In-app login path for a router location (basename already stripped). The
 * `return_to` is the full site path, kept only if it passes sanitizeReturnTo.
 */
export function loginPathFor(routerPath: string, txn?: string | null): string {
  const query = new URLSearchParams()
  const fromPath = /^\/consent\/([^/?#]+)/.exec(routerPath)?.[1]
  const safeTxn = sanitizeTxn(txn ?? fromPath)
  if (safeTxn) query.set('txn', safeTxn)
  const target = sanitizeReturnTo(`${SITE_BASE}${routerPath === '/' ? '' : routerPath}`)
  if (target && target !== SITE_BASE) query.set('return_to', target)
  const qs = query.toString()
  return `/login${qs ? `?${qs}` : ''}`
}
