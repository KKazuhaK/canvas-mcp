import { describe, expect, it } from 'vitest'
import { checkTokenShape } from './tokenInput'

describe('checkTokenShape', () => {
  it('trims and accepts a plausible token', () => {
    const result = checkTokenShape('  1234~abcdEFGH.ijkl_mnop-QRSTUVWX  ')
    expect(result).toEqual({ ok: true, token: '1234~abcdEFGH.ijkl_mnop-QRSTUVWX' })
  })

  it('rejects too short, too long and odd characters', () => {
    expect(checkTokenShape('short')).toEqual({ ok: false, code: 'token_invalid_format' })
    expect(checkTokenShape('a'.repeat(513))).toEqual({ ok: false, code: 'token_invalid_format' })
    expect(checkTokenShape('a'.repeat(30) + ' ' + 'b'.repeat(5)).ok).toBe(false)
    expect(checkTokenShape('a'.repeat(25) + '<script>').ok).toBe(false)
    expect(checkTokenShape('').ok).toBe(false)
  })

  it('accepts the boundaries 20 and 512', () => {
    expect(checkTokenShape('a'.repeat(20)).ok).toBe(true)
    expect(checkTokenShape('a'.repeat(512)).ok).toBe(true)
  })
})
