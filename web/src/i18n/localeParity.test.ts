import { describe, expect, it } from 'vitest'
import { NAMESPACES, flattenKeys, resources } from './options'

type Tree = Record<string, unknown>

function leaves(messages: Tree, prefix = ''): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(messages)) {
    const path = prefix ? `${prefix}.${key}` : key
    if (typeof value === 'object' && value !== null) Object.assign(out, leaves(value as Tree, path))
    else out[path] = String(value)
  }
  return out
}

const placeholders = (text: string) => [...text.matchAll(/\{\{\s*([\w.]+)\s*\}\}/g)].map((m) => m[1]).sort()
const tags = (text: string) => [...text.matchAll(/<\/?([a-z]+)>/g)].map((m) => m[0]).sort()

describe('locale parity (en vs zh)', () => {
  it('ships every namespace in both languages', () => {
    for (const ns of NAMESPACES) {
      expect(resources.en[ns], `en/${ns}.json`).toBeDefined()
      expect(resources.zh[ns], `zh/${ns}.json`).toBeDefined()
    }
  })

  describe.each(NAMESPACES)('%s', (ns) => {
    it('has identical key sets', () => {
      expect(flattenKeys(resources.zh[ns] as Tree)).toEqual(flattenKeys(resources.en[ns] as Tree))
    })

    it('has non-empty strings and the same {{placeholders}} and <tags> per key', () => {
      const en = leaves(resources.en[ns] as Tree)
      const zh = leaves(resources.zh[ns] as Tree)
      for (const key of Object.keys(en)) {
        expect(en[key].trim().length, `en ${ns}:${key}`).toBeGreaterThan(0)
        expect(zh[key].trim().length, `zh ${ns}:${key}`).toBeGreaterThan(0)
        expect(placeholders(zh[key]), `placeholders ${ns}:${key}`).toEqual(placeholders(en[key]))
        expect(tags(zh[key]), `tags ${ns}:${key}`).toEqual(tags(en[key]))
      }
    })
  })

  it('has no key containing the i18next namespace separator', () => {
    for (const lang of ['en', 'zh'] as const) {
      for (const ns of NAMESPACES) {
        for (const key of flattenKeys(resources[lang][ns] as Tree)) {
          expect(key.includes(':'), `${lang} ${ns}:${key}`).toBe(false)
        }
      }
    }
  })

  it('does not put raw HTML in translations (markup comes from <Trans components>)', () => {
    const allowed = new Set(['b', 'c'])
    for (const lang of ['en', 'zh'] as const) {
      for (const ns of NAMESPACES) {
        for (const [key, text] of Object.entries(leaves(resources[lang][ns] as Tree))) {
          for (const [, name] of text.matchAll(/<\/?([A-Za-z][\w-]*)/g)) {
            expect(allowed.has(name), `${lang} ${ns}:${key} uses <${name}>`).toBe(true)
          }
        }
      }
    }
  })
})
