import LanguageIcon from '@mui/icons-material/Language'
import Button from '@mui/material/Button'
import { useTranslation } from 'react-i18next'
import { hasCsrfToken } from '@/api/client'
import { putUiLocale } from '@/api/endpoints'
import { useLanguage, type Language } from '@/stores/language'

/**
 * The explicit language switch: the only thing that changes the UI language.
 * The label is the OTHER language's own name, so it is readable either way.
 *
 * When signed in, the choice is also told to the server (PUT /me/ui-locale), which
 * keeps it in the canvas_mcp_lang cookie the server-rendered pages read too. That
 * call is best effort: the page language never waits for it.
 */
export default function LanguageToggle() {
  const { t } = useTranslation()
  const lang = useLanguage((s) => s.lang)
  const setLanguage = useLanguage((s) => s.setLanguage)
  const next: Language = lang === 'en' ? 'zh' : 'en'
  const name = t(`common:language.names.${next}`)

  function choose() {
    setLanguage(next)
    if (hasCsrfToken()) void putUiLocale(next).catch(() => undefined)
  }

  return (
    <Button
      color="inherit"
      size="small"
      startIcon={<LanguageIcon fontSize="small" />}
      aria-label={t('common:language.switchTo', { name })}
      lang={next}
      onClick={choose}
    >
      {name}
    </Button>
  )
}
