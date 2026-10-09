#!/usr/bin/env node
// Static checks on the production build in dist/. Run after `npm run build`:
//
//   npm run check:dist
//
// The page is served with
//   default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline';
//   img-src 'self' data:; font-src 'self'; connect-src 'self'; ...
// so everything below is something that policy (or the security rules in
// README.md) would break or that must never ship.

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const dist = process.argv[2] ? resolve(process.cwd(), process.argv[2]) : join(root, 'dist')
const BASE = '/account/'

const failures = []
const fail = (message) => failures.push(message)

function walk(dir) {
  const out = []
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) out.push(...walk(full))
    else out.push(full)
  }
  return out
}

if (!existsSync(join(dist, 'index.html'))) {
  console.error(`check-dist: ${join(dist, 'index.html')} not found. Run "npm run build" first.`)
  process.exit(2)
}

const files = walk(dist)
const rel = (file) => relative(dist, file).split('\\').join('/')
const html = readFileSync(join(dist, 'index.html'), 'utf8')

// ---- index.html ----------------------------------------------------------------

const scriptTags = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)]
if (scriptTags.length !== 1) fail(`index.html must contain exactly one <script>, found ${scriptTags.length}`)
for (const [, attrs, body] of scriptTags) {
  if (body.trim() !== '') fail('index.html has an inline <script> body')
  if (!/\btype="module"/.test(attrs)) fail('the <script> is not type="module"')
  const src = /\bsrc="([^"]+)"/.exec(attrs)?.[1]
  if (!src) fail('the <script> has no src')
  else if (!src.startsWith(`${BASE}assets/`)) fail(`script src is not under ${BASE}assets/: ${src}`)
}
if (/\son[a-z]+\s*=/i.test(html)) fail('index.html has an inline event handler attribute')
if (/javascript:/i.test(html)) fail('index.html contains a javascript: URL')
if (/<style\b/i.test(html)) fail('index.html has an inline <style> (style-src allows it, but none is expected)')
if (!/<meta name="referrer" content="no-referrer"/.test(html)) fail('missing <meta name="referrer" content="no-referrer">')
if (!/<meta name="robots" content="noindex"/.test(html)) fail('missing <meta name="robots" content="noindex">')
if (/<base\b/i.test(html)) fail('index.html has a <base> element; the mount path is fixed')

for (const [, tag] of html.matchAll(/<(?:script|link|img|source|iframe)\b([^>]*)>/gi)) {
  for (const [, , url] of tag.matchAll(/\b(src|href)="([^"]+)"/gi)) {
    if (/^(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(url) || /^(?:https?|data|blob):/i.test(url)) {
      fail(`index.html references a non-local URL: ${url}`)
    } else if (!url.startsWith(BASE)) {
      fail(`index.html reference is not under ${BASE}: ${url}`)
    } else if (!existsSync(join(dist, url.slice(BASE.length)))) {
      fail(`index.html references a missing file: ${url}`)
    }
  }
}

// ---- emitted files -------------------------------------------------------------

const ALLOWED_EXTENSIONS = new Set(['.html', '.js', '.css', '.svg', '.png', '.ico', '.woff2', '.txt', '.json', '.webmanifest'])
const MOCK_MARKERS = [
  'mockServer',
  'installMockServer',
  'MOCK_SCENARIOS',
  'mock-csrf-token',
  'mock-login-bounce',
  'Ada Example',
  'Bob Example',
  'Cleo Example',
  'ada@example.edu',
  'VITE_MOCK',
]

for (const file of files) {
  const name = rel(file)
  const ext = name.slice(name.lastIndexOf('.')).toLowerCase()
  if (name.endsWith('.map')) fail(`${name}: source map shipped`)
  else if (!ALLOWED_EXTENSIONS.has(ext)) fail(`${name}: unexpected file type`)

  if (ext === '.js') {
    const text = readFileSync(file, 'utf8')
    if (/(?<![\w$.])eval\s*\(/.test(text)) fail(`${name}: calls eval()`)
    if (/new\s+Function\s*\(/.test(text)) fail(`${name}: uses new Function()`)
    if (/\bimportScripts\s*\(/.test(text)) fail(`${name}: uses importScripts()`)
    if (/\b(?:import|fetch)\s*\(\s*["'`]https?:/.test(text)) fail(`${name}: loads a remote URL`)
    if (/new\s+Worker\s*\(\s*["'`]https?:/.test(text)) fail(`${name}: starts a remote worker`)
    if (/\.write\s*\(\s*["'`]<script/i.test(text)) fail(`${name}: document.write of a script`)
    for (const marker of MOCK_MARKERS) {
      if (text.includes(marker)) fail(`${name}: contains dev-mock marker "${marker}"`)
    }
  }

  if (ext === '.css') {
    const text = readFileSync(file, 'utf8')
    for (const [, url] of text.matchAll(/url\(\s*["']?([^"')]+)["']?\s*\)/gi)) {
      if (/^(?:https?:)?\/\//i.test(url)) fail(`${name}: CSS references a remote URL: ${url}`)
      if (/^data:/i.test(url)) fail(`${name}: CSS inlines a data: URI (assetsInlineLimit should be 0)`)
    }
    if (/@import\s+(?:url\()?["']?(?:https?:)?\/\//i.test(text)) fail(`${name}: CSS @import of a remote URL`)
  }
}

if (files.some((f) => /(?:^|\/)src\/dev\//.test(rel(f)))) fail('a src/dev path is present in dist')

// ---- result --------------------------------------------------------------------

if (failures.length > 0) {
  console.error('check-dist FAILED:')
  for (const message of failures) console.error(`  - ${message}`)
  process.exit(1)
}
console.log(`check-dist OK: ${files.length} files, no inline script, no remote URLs, no eval, no dev mock.`)
