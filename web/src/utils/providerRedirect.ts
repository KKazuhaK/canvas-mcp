// Where "link a sign-in method" may send the browser: the identity provider's own page.
//
// The address comes from the server's JSON answer (the provider's authorization URL), so the
// page still checks it before navigating: https only, no user information, no control
// characters or backslashes, a bounded length. Anything else is refused and the person sees an
// error instead of being navigated.

const MAX_LENGTH = 4096
// C0 controls, DEL, the C1 range, whitespace and backslashes: browsers strip or rewrite some of
// these inside URLs, which is how a harmless-looking address becomes another one.
// eslint-disable-next-line no-control-regex
const UNSAFE_CHARS = /[\u0000-\u0020\u007f-\u009f\\]/

/** The address unchanged if it is safe to navigate to, else null. */
export function safeProviderRedirect(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_LENGTH) return null
  if (UNSAFE_CHARS.test(raw)) return null
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return null
  }
  if (url.protocol !== 'https:') return null
  if (url.username !== '' || url.password !== '') return null
  if (url.hostname === '') return null
  return raw
}
