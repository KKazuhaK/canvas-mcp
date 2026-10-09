import { create } from 'zustand'

// Light/dark preference. 'auto' follows prefers-color-scheme (the default); the
// optional toggle persists the explicit choice in localStorage, wrapped in
// try/catch so a throwing storage never breaks the page.

export type ThemeMode = 'auto' | 'light' | 'dark'
export type ResolvedTheme = 'light' | 'dark'
export const THEME_STORAGE_KEY = 'canvas_mcp_theme'
export const THEME_MODES: readonly ThemeMode[] = ['auto', 'light', 'dark']

export function isThemeMode(value: unknown): value is ThemeMode {
  return value === 'auto' || value === 'light' || value === 'dark'
}

function readStoredMode(): ThemeMode {
  try {
    const value = window.localStorage.getItem(THEME_STORAGE_KEY)
    return isThemeMode(value) ? value : 'auto'
  } catch {
    return 'auto'
  }
}

const DARK_QUERY = '(prefers-color-scheme: dark)'

function systemPrefersDark(): boolean {
  try {
    return window.matchMedia(DARK_QUERY).matches
  } catch {
    return false
  }
}

interface ThemeState {
  mode: ThemeMode
  systemDark: boolean
  setMode: (mode: ThemeMode) => void
  setSystemDark: (dark: boolean) => void
}

export const useThemeStore = create<ThemeState>((set) => ({
  mode: readStoredMode(),
  systemDark: systemPrefersDark(),
  setMode: (mode) => {
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, mode)
    } catch {
      // Not persisted; applies for this page view.
    }
    set({ mode })
  },
  setSystemDark: (systemDark) => set({ systemDark }),
}))

export function resolveTheme(mode: ThemeMode, systemDark: boolean): ResolvedTheme {
  if (mode === 'auto') return systemDark ? 'dark' : 'light'
  return mode
}

export function useResolvedTheme(): ResolvedTheme {
  const mode = useThemeStore((s) => s.mode)
  const systemDark = useThemeStore((s) => s.systemDark)
  return resolveTheme(mode, systemDark)
}

/** Keep the store in step with the OS setting. Returns the unsubscribe function. */
export function watchSystemTheme(): () => void {
  let media: MediaQueryList
  try {
    media = window.matchMedia(DARK_QUERY)
  } catch {
    return () => {}
  }
  const onChange = (event: MediaQueryListEvent) => useThemeStore.getState().setSystemDark(event.matches)
  useThemeStore.getState().setSystemDark(media.matches)
  media.addEventListener('change', onChange)
  return () => media.removeEventListener('change', onChange)
}
