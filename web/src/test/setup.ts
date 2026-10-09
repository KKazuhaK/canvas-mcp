import '@testing-library/jest-dom/vitest'
import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'

// Node 26 exposes a configurable global localStorage accessor whose value is
// undefined unless --localstorage-file is supplied, and it shadows jsdom's
// storage. Give each isolated test worker a real in-memory Storage instead.
// The app itself only touches localStorage for the language and theme
// preferences (stores/language.ts, stores/theme.ts); a guard test enforces it.
if (typeof window !== 'undefined') {
  const values = new Map<string, string>()
  const storage: Storage = {
    get length() {
      return values.size
    },
    clear() {
      values.clear()
    },
    getItem(key) {
      return values.get(String(key)) ?? null
    },
    key(index) {
      return [...values.keys()][index] ?? null
    },
    removeItem(key) {
      values.delete(String(key))
    },
    setItem(key, value) {
      values.set(String(key), String(value))
    },
  }
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: storage,
  })

  // jsdom has no matchMedia; the theme store reads prefers-color-scheme.
  if (typeof window.matchMedia !== 'function') {
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      writable: true,
      value: (query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addEventListener: () => {},
        removeEventListener: () => {},
        addListener: () => {},
        removeListener: () => {},
        dispatchEvent: () => false,
      }),
    })
  }
}

afterEach(() => {
  cleanup()
  try {
    localStorage.clear()
  } catch {
    // ignore
  }
})
