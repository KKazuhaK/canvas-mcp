// Client-side shape check of a Canvas access token, for fast feedback only. The
// server repeats it and then verifies the token against Canvas.
export const TOKEN_MIN_LENGTH = 20
export const TOKEN_MAX_LENGTH = 512
const TOKEN_PATTERN = /^[A-Za-z0-9~._-]+$/

export type TokenShapeError = 'token_invalid_format'

/** Trim and check. Returns the cleaned token, or the error code to display. */
export function checkTokenShape(
  raw: string,
): { ok: true; token: string } | { ok: false; code: TokenShapeError } {
  const token = raw.trim()
  if (
    token.length < TOKEN_MIN_LENGTH ||
    token.length > TOKEN_MAX_LENGTH ||
    !TOKEN_PATTERN.test(token)
  ) {
    return { ok: false, code: 'token_invalid_format' }
  }
  return { ok: true, token }
}
