import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'

const ROOT = join(import.meta.dirname, '..', '..')
const SCRIPT = join(ROOT, 'scripts', 'check-dist.mjs')
const created: string[] = []

function runCheck(dist: string) {
  const result = spawnSync(process.execPath, [SCRIPT, dist], { encoding: 'utf8' })
  return { code: result.status, out: `${result.stdout}${result.stderr}` }
}

function fakeDist(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'cmcp-dist-'))
  created.push(dir)
  for (const [name, content] of Object.entries(files)) {
    const full = join(dir, name)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, content)
  }
  return dir
}

const GOOD_HTML = `<!doctype html><html><head>
<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex">
<script type="module" crossorigin src="/account/assets/index-abc.js"></script>
</head><body><div id="root"></div><noscript><p>This page needs JavaScript.</p></noscript></body></html>`

afterAll(() => {
  for (const dir of created) rmSync(dir, { recursive: true, force: true })
})

describe('scripts/check-dist.mjs', () => {
  it('accepts a clean build', () => {
    const dist = fakeDist({ 'index.html': GOOD_HTML, 'assets/index-abc.js': 'console.log(1)' })
    expect(runCheck(dist)).toMatchObject({ code: 0 })
  })

  it.each([
    ['an inline script', GOOD_HTML.replace('</head>', '<script>alert(1)</script></head>'), 'assets/index-abc.js', 'x'],
    ['an inline event handler', GOOD_HTML.replace('<div', '<div onclick="x()"'), 'assets/index-abc.js', 'x'],
    ['a CDN script', GOOD_HTML.replace('/account/assets/index-abc.js', 'https://cdn.example/x.js'), 'assets/index-abc.js', 'x'],
    ['a remote stylesheet', GOOD_HTML.replace('</head>', '<link rel="stylesheet" href="https://fonts.googleapis.com/css"></head>'), 'assets/index-abc.js', 'x'],
    ['a missing referrer policy', GOOD_HTML.replace('<meta name="referrer" content="no-referrer">', ''), 'assets/index-abc.js', 'x'],
    ['eval in the bundle', GOOD_HTML, 'assets/index-abc.js', 'const f = eval("1")'],
    ['new Function in the bundle', GOOD_HTML, 'assets/index-abc.js', 'new Function("return 1")'],
    ['the dev mock module', GOOD_HTML, 'assets/index-abc.js', 'function installMockServer(){}'],
    ['mock fixtures', GOOD_HTML, 'assets/index-abc.js', 'const n = "Ada Example"'],
    ['a source map', GOOD_HTML, 'assets/index-abc.js.map', '{}'],
    ['no <noscript> notice', GOOD_HTML.replace(/<noscript>.*<\/noscript>/, ''), 'assets/index-abc.js', 'x'],
    ['an empty <noscript> notice', GOOD_HTML.replace(/<noscript>.*<\/noscript>/, '<noscript> </noscript>'), 'assets/index-abc.js', 'x'],
    ['a <noscript> that loads an image', GOOD_HTML.replace('</noscript>', '<img src="/account/x.png"></noscript>'), 'assets/index-abc.js', 'x'],
  ])('rejects %s', (_label, html, extra, content) => {
    const files: Record<string, string> = { 'index.html': html, 'assets/index-abc.js': 'x' }
    files[extra] = content
    const { code, out } = runCheck(fakeDist(files))
    expect(code, out).toBe(1)
  })

  it('rejects a CSS file that inlines a data: URI or imports a remote font', () => {
    const dist = fakeDist({
      'index.html': GOOD_HTML,
      'assets/index-abc.js': 'x',
      'assets/a.css': '@import url("https://fonts.example/f.css"); a{background:url(data:image/png;base64,AAAA)}',
    })
    expect(runCheck(dist).code).toBe(1)
  })
})

describe('the production bundle never carries the dev mock', () => {
  it('excludes it even when VITE_MOCK=1 is set at build time', () => {
    const outDir = mkdtempSync(join(tmpdir(), 'cmcp-build-'))
    created.push(outDir)
    // The real CLI, as `npm run build` runs it, but with `--mode mock`, which loads
    // .env.mock (VITE_MOCK=1), the same switch `npm run dev:mock` uses. NODE_ENV is
    // pinned because vitest sets it to "test", which would make DEV true.
    const build = spawnSync(
      process.execPath,
      [join(ROOT, 'node_modules', 'vite', 'bin', 'vite.js'), 'build', '--mode', 'mock', '--outDir', outDir, '--emptyOutDir', '--logLevel', 'error'],
      { cwd: ROOT, encoding: 'utf8', env: { ...process.env, NODE_ENV: 'production' } },
    )
    expect(build.status, `${build.stdout}${build.stderr}`).toBe(0)
    const { code, out } = runCheck(outDir)
    expect(code, out).toBe(0)
  }, 120_000)

  it('would have caught it: the same build with DEV forced on is rejected', () => {
    const outDir = mkdtempSync(join(tmpdir(), 'cmcp-build-dev-'))
    created.push(outDir)
    const build = spawnSync(
      process.execPath,
      [join(ROOT, 'node_modules', 'vite', 'bin', 'vite.js'), 'build', '--mode', 'mock', '--outDir', outDir, '--emptyOutDir', '--logLevel', 'error'],
      { cwd: ROOT, encoding: 'utf8', env: { ...process.env, NODE_ENV: 'development' } },
    )
    expect(build.status, `${build.stdout}${build.stderr}`).toBe(0)
    const { code, out } = runCheck(outDir)
    expect(code, out).toBe(1)
    expect(out).toContain('dev-mock marker')
  }, 120_000)
})

describe('index.html source', () => {
  it('carries a plain-text <noscript> notice, so a browser without JavaScript sees why', () => {
    const html = readFileSync(join(ROOT, 'index.html'), 'utf8')
    const notice = /<noscript>([\s\S]*?)<\/noscript>/.exec(html)?.[1] ?? ''
    expect(notice).toContain('needs JavaScript')
    expect(notice).toContain('ACCOUNT_UI=legacy')
    expect(notice).not.toMatch(/<(?:script|link|img|iframe)/i)
  })
})
