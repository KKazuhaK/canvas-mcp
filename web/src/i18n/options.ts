import type { Language } from '@/stores/language'

export const NAMESPACES = ['common', 'auth', 'account', 'admin', 'errors'] as const
export type Namespace = (typeof NAMESPACES)[number]

type Messages = Record<string, unknown>

// All locale files are bundled (they are small) so the first paint never waits
// on a second request and `connect-src 'self'` has nothing extra to allow.
const modules = import.meta.glob<Messages>('../locales/*/*.json', {
  eager: true,
  import: 'default',
})

function collect(): Record<Language, Record<Namespace, Messages>> {
  const out = {
    en: {} as Record<Namespace, Messages>,
    zh: {} as Record<Namespace, Messages>,
  }
  for (const [path, messages] of Object.entries(modules)) {
    const match = /\/locales\/(en|zh)\/([a-z]+)\.json$/.exec(path)
    if (!match) continue
    const lang = match[1] as Language
    const ns = match[2] as Namespace
    out[lang][ns] = messages
  }
  return out
}

export const resources = collect()

/** Every leaf key of a message tree as a dotted path, for parity checks. */
export function flattenKeys(messages: Messages, prefix = ''): string[] {
  const keys: string[] = []
  for (const [key, value] of Object.entries(messages)) {
    const path = prefix ? `${prefix}.${key}` : key
    if (typeof value === 'object' && value !== null) {
      keys.push(...flattenKeys(value as Messages, path))
    } else {
      keys.push(path)
    }
  }
  return keys.sort()
}
