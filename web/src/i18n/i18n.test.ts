import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// Each test loads fresh copies of the modules, which is what a page reload does.
async function loadFresh() {
  vi.resetModules()
  const language = await import('@/stores/language')
  const { initI18n } = await import('@/i18n')
  const i18next = (await import('i18next')).default
  return { language, initI18n, i18next }
}

function setNavigatorLanguage(value: string) {
  Object.defineProperty(window.navigator, 'language', { value, configurable: true })
  Object.defineProperty(window.navigator, 'languages', { value: [value], configurable: true })
}

describe('language selection', () => {
  const realStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage')

  beforeEach(() => {
    window.history.replaceState({}, '', '/')
    document.documentElement.lang = ''
  })

  afterEach(() => {
    if (realStorage) Object.defineProperty(globalThis, 'localStorage', realStorage)
    window.history.replaceState({}, '', '/')
    setNavigatorLanguage('en-US')
  })

  it('defaults to English even when the browser says Chinese', async () => {
    setNavigatorLanguage('zh-CN')
    const { language, initI18n, i18next } = await loadFresh()
    expect(language.useLanguage.getState().lang).toBe('en')
    await initI18n()
    expect(i18next.language).toBe('en')
    expect(i18next.t('common:actions.signOut')).toBe('Sign out')
    expect(document.documentElement.lang).toBe('en')
  })

  it('does not install a language detector', async () => {
    const { initI18n, i18next } = await loadFresh()
    await initI18n()
    expect(i18next.modules?.languageDetector).toBeUndefined()
  })

  it('switches only on the explicit toggle, and the choice survives a reload', async () => {
    setNavigatorLanguage('en-US')
    const first = await loadFresh()
    await first.initI18n()
    first.language.useLanguage.getState().setLanguage('zh')
    expect(first.language.useLanguage.getState().lang).toBe('zh')
    expect(first.i18next.language).toBe('zh')
    expect(first.i18next.t('common:actions.signOut')).toBe('退出登录')
    expect(window.localStorage.getItem('canvas_mcp_lang')).toBe('zh')
    expect(document.documentElement.lang).toBe('zh')

    const second = await loadFresh()
    expect(second.language.useLanguage.getState().lang).toBe('zh')
    await second.initI18n()
    expect(second.i18next.language).toBe('zh')

    second.language.useLanguage.getState().setLanguage('en')
    expect(window.localStorage.getItem('canvas_mcp_lang')).toBe('en')
  })

  it('ignores a garbage stored value', async () => {
    window.localStorage.setItem('canvas_mcp_lang', 'fr')
    const { language } = await loadFresh()
    expect(language.useLanguage.getState().lang).toBe('en')
  })

  it('honours an explicit ?lang= link without persisting it', async () => {
    window.history.replaceState({}, '', '/?lang=zh')
    const { language } = await loadFresh()
    expect(language.useLanguage.getState().lang).toBe('zh')
    expect(window.localStorage.getItem('canvas_mcp_lang')).toBeNull()

    window.history.replaceState({}, '', '/?lang=de')
    const other = await loadFresh()
    expect(other.language.useLanguage.getState().lang).toBe('en')
  })

  it('keeps working when storage throws', async () => {
    Object.defineProperty(globalThis, 'localStorage', {
      configurable: true,
      get() {
        throw new Error('storage blocked')
      },
    })
    const { language, initI18n, i18next } = await loadFresh()
    expect(language.useLanguage.getState().lang).toBe('en')
    await initI18n()
    expect(() => language.useLanguage.getState().setLanguage('zh')).not.toThrow()
    expect(language.useLanguage.getState().lang).toBe('zh')
    expect(i18next.language).toBe('zh')
  })
})

describe('theme preference', () => {
  const realStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage')
  afterEach(() => {
    if (realStorage) Object.defineProperty(globalThis, 'localStorage', realStorage)
  })

  it('defaults to auto, persists an explicit choice and survives throwing storage', async () => {
    vi.resetModules()
    const first = await import('@/stores/theme')
    expect(first.useThemeStore.getState().mode).toBe('auto')
    first.useThemeStore.getState().setMode('dark')
    expect(window.localStorage.getItem('canvas_mcp_theme')).toBe('dark')

    vi.resetModules()
    const second = await import('@/stores/theme')
    expect(second.useThemeStore.getState().mode).toBe('dark')
    expect(second.resolveTheme('auto', true)).toBe('dark')
    expect(second.resolveTheme('auto', false)).toBe('light')
    expect(second.resolveTheme('light', true)).toBe('light')

    Object.defineProperty(globalThis, 'localStorage', {
      configurable: true,
      get() {
        throw new Error('blocked')
      },
    })
    vi.resetModules()
    const third = await import('@/stores/theme')
    expect(third.useThemeStore.getState().mode).toBe('auto')
    expect(() => third.useThemeStore.getState().setMode('light')).not.toThrow()
    expect(third.useThemeStore.getState().mode).toBe('light')
  })
})
