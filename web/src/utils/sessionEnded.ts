/**
 * Router state (never the URL) that marks a redirect to the sign-in page as "your
 * session ended while you were using the app". Being state, it cannot be forged by a
 * crafted link, and the sign-in page reads it with a strict check.
 */
export const SESSION_ENDED_STATE = { sessionEnded: true } as const

export function isSessionEnded(state: unknown): boolean {
  return (
    typeof state === 'object' &&
    state !== null &&
    (state as { sessionEnded?: unknown }).sessionEnded === true
  )
}
