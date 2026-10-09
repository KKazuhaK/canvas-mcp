import i18next from 'i18next'
import { create } from 'zustand'

// The UI language. English is the default no matter what the browser says; the
// language changes ONLY when the person presses the toggle (or opens a link with
// an explicit ?lang=en|zh, for parity with the server-rendered pages). There is
// deliberately no browser-language detection anywhere in this app.
//
// localStorage holds this one UI preference and nothing else about the person.
// Every access is wrapped: the page must work when storage throws (private
// windows, blocked site data, previews).

export type Language = 'en' | 'zh'
export const LANGUAGES: readonly Language[] = ['en', 'zh']
export const LANGUAGE_STORAGE_KEY = 'canvas_mcp_lang'
export const DEFAULT_LANGUAGE: Language = 'en'

export function isLanguage(value: unknown): value is Language {
  return value === 'en' || value === 'zh'
}

function readQueryLanguage(): Language | null {
  try {
    const value = new URLSearchParams(window.location.search).get('lang')
    return isLanguage(value) ? value : null
  } catch {
    return null
  }
}

function readStoredLanguage(): Language | null {
  try {
    const value = window.localStorage.getItem(LANGUAGE_STORAGE_KEY)
    return isLanguage(value) ? value : null
  } catch {
    return null
  }
}

/** ?lang= (explicit link) beats the stored toggle, which beats the English default. */
export function readInitialLanguage(): Language {
  return readQueryLanguage() ?? readStoredLanguage() ?? DEFAULT_LANGUAGE
}

function mirrorToDocument(lang: Language): void {
  try {
    document.documentElement.lang = lang
  } catch {
    // ignore
  }
}

interface LanguageState {
  lang: Language
  /** The explicit toggle: persists the choice and switches i18n. */
  setLanguage: (lang: Language) => void
}

const initial = readInitialLanguage()
mirrorToDocument(initial)

export const useLanguage = create<LanguageState>((set) => ({
  lang: initial,
  setLanguage: (lang) => {
    try {
      window.localStorage.setItem(LANGUAGE_STORAGE_KEY, lang)
    } catch {
      // Not persisted; the choice still applies for this page view.
    }
    mirrorToDocument(lang)
    if (i18next.isInitialized) void i18next.changeLanguage(lang)
    set({ lang })
  },
}))
