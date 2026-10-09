// Redirect safety. `return_to` arrives in the query string, which anyone can craft,
// so it is not used until it passes sanitizeReturnTo. These are the same rules the
// server applies to /account/login?return_to= (sanitize_return_to in account_web.py),
// which checks again before sealing the value into the sign-in cookie.

const SITE_PREFIX = '/account'
const MAX_LENGTH = 512
/** Server routes that are not SPA pages, so they are never a place to return to. */
const FORBIDDEN_PREFIXES = ['/account/api', '/account/login', '/account/callback']
// C0 controls, DEL and the C1 range: browsers strip some of these inside URLs,
// which is how '/\t/evil.example' becomes '//evil.example'.
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/
// eslint-disable-next-line no-control-regex
const NOT_ASCII = /[^\u0000-\u007f]/

function isClean(text: string): boolean {
  if (text.length === 0 || text.length > MAX_LENGTH) return false
  if (NOT_ASCII.test(text) || CONTROL_CHARS.test(text)) return false
  if (text.includes('\\') || text.includes('//')) return false
  const path = text.split(/[?#]/, 1)[0]
  if (path !== SITE_PREFIX && !path.startsWith(`${SITE_PREFIX}/`)) return false
  if (path.split('/').some((segment) => segment === '.' || segment === '..')) return false
  const lowered = path.toLowerCase()
  return !FORBIDDEN_PREFIXES.some((prefix) => lowered === prefix || lowered.startsWith(`${prefix}/`))
}

/**
 * Accepts only a same-site path inside the /account app and returns it unchanged,
 * or null. At most 512 ASCII characters; it must start with /account and must not
 * be the API, the login or the callback; no '//', backslash, control character or
 * '.'/'..' segment; and all of that holds again after percent-decoding (repeatedly,
 * so a double-encoded trick fails too).
 */
export function sanitizeReturnTo(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null
  let candidate = raw
  for (let round = 0; round < 4; round += 1) {
    if (!isClean(candidate)) return null
    let decoded: string
    try {
      decoded = decodeURIComponent(candidate)
    } catch {
      return null
    }
    if (decoded === candidate) return raw
    candidate = decoded
  }
  return null
}

/** Only https links are rendered as links (the school's Canvas settings page). */
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

/** The SPA's own sign-in page; the server-side redirect lives at /account/login. */
export const SIGN_IN_PATH = '/sign-in'

/**
 * In-app sign-in path for a router location (basename already stripped). The
 * `return_to` is the full site path, kept only if it passes sanitizeReturnTo.
 */
export function loginPathFor(routerPath: string): string {
  const pathOnly = routerPath.split(/[?#]/, 1)[0]
  if (pathOnly === SIGN_IN_PATH) return SIGN_IN_PATH
  const target = sanitizeReturnTo(`${SITE_BASE}${routerPath === '/' ? '' : routerPath}`)
  if (target && target !== SITE_BASE) {
    return `${SIGN_IN_PATH}?${new URLSearchParams({ return_to: target }).toString()}`
  }
  return SIGN_IN_PATH
}

/** The page the browser is on, as a validated return_to (null on the sign-in page or anything unsafe). */
export function currentReturnTo(): string | null {
  if (typeof window === 'undefined') return null
  const { pathname, search } = window.location
  if (pathname === '/account/sign-in') return null
  return sanitizeReturnTo(`${pathname}${search}`)
}
