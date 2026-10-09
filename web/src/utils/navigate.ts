/**
 * Full-page navigation (OAuth hand-offs, consent redirects, post-logout). Kept
 * in one module so tests can replace it; jsdom does not implement navigation.
 * Callers pass only same-site paths or URLs the server returned in JSON after
 * `safeRedirectTarget` accepted them.
 */
export function hardNavigate(url: string): void {
  window.location.assign(url)
}
