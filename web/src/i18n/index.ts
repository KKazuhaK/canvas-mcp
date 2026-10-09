import i18next from 'i18next'
import { initReactI18next } from 'react-i18next'
import { useLanguage, type Language } from '@/stores/language'
import { NAMESPACES, resources } from './options'

/**
 * Initialise i18next with the language from the language store.
 *
 * There is NO language detector here on purpose: the only inputs are the
 * explicit toggle (persisted by the store) and an explicit ?lang= link. A Chinese
 * browser still gets English until the person asks otherwise.
 */
export async function initI18n(lng: Language = useLanguage.getState().lang): Promise<typeof i18next> {
  if (i18next.isInitialized) {
    if (i18next.language !== lng) await i18next.changeLanguage(lng)
    return i18next
  }
  await i18next.use(initReactI18next).init({
    resources,
    lng,
    fallbackLng: 'en',
    supportedLngs: ['en', 'zh'],
    ns: [...NAMESPACES],
    defaultNS: 'common',
    // React escapes everything it renders. Translations are never given to
    // dangerouslySetInnerHTML; markup comes from <Trans components={...}>.
    interpolation: { escapeValue: false },
    returnNull: false,
  })
  return i18next
}

export { i18next }
