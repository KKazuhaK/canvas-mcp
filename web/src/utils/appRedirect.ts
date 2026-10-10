// Where the consent screen may send the browser after a decision.
//
// The address comes from the server's JSON answer (the app's own return address with the
// code or the error), so the page still checks it before navigating: only https, or http to
// the person's own computer (an app listening on a loopback port). Anything else (a script
// or data URL, another scheme, an address with a password, control characters) is refused
// and the person sees an error instead of being navigated.

const MAX_LENGTH = 4096
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]'])
// C0 controls, DEL, the C1 range, whitespace and backslashes: browsers strip or rewrite some of
// these inside URLs, which is how a harmless-looking address becomes another one.
// eslint-disable-next-line no-control-regex
const UNSAFE_CHARS = /[\u0000-\u0020\u007f-\u009f\\]/

/** The address unchanged if it is safe to navigate to, else null. */
export function safeAppRedirect(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_LENGTH) return null
  if (UNSAFE_CHARS.test(raw)) return null
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return null
  }
  if (url.username !== '' || url.password !== '') return null
  if (url.protocol === 'https:') return raw
  if (url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname)) return raw
  return null
}

/** The request id the server puts in /account/consent?txn= (a 256-bit URL-safe token). */
export const TXN_PATTERN = /^[A-Za-z0-9_-]{43}$/

/** The server-side sign-in for a waiting request: a full-page navigation that keeps the request id. */
export function consentLoginPath(txn: string, options: { reauth?: boolean } = {}): string {
  const query = new URLSearchParams({ txn })
  if (options.reauth) query.set('reauth', '1')
  return `/account/login?${query.toString()}`
}
