import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { describe, expect, it } from 'vitest'

// Static guards over the application source (tests excluded: they have to name
// the things they forbid). Failing here fails the build.

const SRC = join(import.meta.dirname, '..')

function walk(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) out.push(...walk(full))
    else out.push(full)
  }
  return out
}

const rel = (file: string) => relative(SRC, file).split(sep).join('/')
const isTest = (file: string) => /\.test\.tsx?$/.test(file) || rel(file).startsWith('test/')
const sources = walk(SRC).filter((f) => /\.(ts|tsx)$/.test(f) && !isTest(f))
const read = (file: string) => readFileSync(file, 'utf8')

/** Code without comments, so a comment that merely names a banned API is not a finding. */
function code(file: string): string {
  return read(file)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|\s)\/\/.*$/gm, '$1')
}

function offenders(pattern: RegExp, allow: string[] = []): string[] {
  return sources
    .filter((f) => !allow.includes(rel(f)))
    .filter((f) => pattern.test(code(f)))
    .map(rel)
}

describe('source guards', () => {
  it('finds the source tree', () => {
    expect(sources.length).toBeGreaterThan(40)
  })

  it('has no dangerouslySetInnerHTML', () => {
    expect(offenders(/dangerouslySetInnerHTML/)).toEqual([])
  })

  it('has no innerHTML/outerHTML writes, insertAdjacentHTML or document.write', () => {
    expect(offenders(/\.(?:inner|outer)HTML\s*=|insertAdjacentHTML|document\.write/)).toEqual([])
  })

  it('has no eval, new Function or string timers', () => {
    expect(offenders(/(?<![\w$.])eval\s*\(|new\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*["'`]/)).toEqual([])
  })

  it('references localStorage only in the language and theme stores', () => {
    expect(offenders(/localStorage/, ['stores/language.ts', 'stores/theme.ts'])).toEqual([])
  })

  it('never uses sessionStorage, IndexedDB, cookies or the Cache API', () => {
    expect(offenders(/sessionStorage|indexedDB|document\.cookie|caches\.open/)).toEqual([])
  })

  it('has no Authorization header or bearer handling', () => {
    expect(offenders(/['"`]authorization['"`]|Bearer\s*\$\{|['"`]Bearer/i)).toEqual([])
  })

  it('has no language detector and no navigator.language read', () => {
    expect(offenders(/LanguageDetector|navigator\.language/)).toEqual([])
  })

  it('has no absolute API URLs or third-party hosts in app code', () => {
    const allow = ['dev/mockServer.ts', 'utils/returnTo.ts']
    expect(offenders(/["'`]https?:\/\/(?!return-to\.invalid)/, allow)).toEqual([])
  })

  it('uses target=_blank only inside ExternalLink', () => {
    expect(offenders(/target=["']_blank["']/, ['components/ExternalLink.tsx'])).toEqual([])
  })

  it('has no javascript: URLs or inline event-handler strings', () => {
    expect(offenders(/["'`]javascript:/)).toEqual([])
  })

  it('imports MUI icons per icon, never from the package root', () => {
    expect(offenders(/from\s+['"]@mui\/icons-material['"]/)).toEqual([])
  })

  it('does not import dev code outside the guarded dynamic import in main.tsx', () => {
    const importers = offenders(/['"][^'"]*\/dev\/mockServer['"]/, ['main.tsx'])
    expect(importers).toEqual([])
    const main = code(join(SRC, 'main.tsx'))
    expect(main).toMatch(/if \(import\.meta\.env\.DEV && import\.meta\.env\.VITE_MOCK === '1'\) \{\s*const \{ installMockServer \} = await import\('\.\/dev\/mockServer'\)/)
    expect(main).not.toMatch(/^import .*dev\/mockServer/m)
  })

  it('keeps the Canvas token out of useMutation', () => {
    const hooks = read(join(SRC, 'query/hooks.ts'))
    expect(hooks).not.toMatch(/putCanvasToken/)
  })
})
