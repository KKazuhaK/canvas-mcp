import LanguageIcon from '@mui/icons-material/Language'
import Button from '@mui/material/Button'
import { useTranslation } from 'react-i18next'
import { useLanguage, type Language } from '@/stores/language'

/**
 * The explicit language switch: the only thing that changes the UI language.
 * The label is the OTHER language's own name, so it is readable either way.
 */
export default function LanguageToggle() {
  const { t } = useTranslation()
  const lang = useLanguage((s) => s.lang)
  const setLanguage = useLanguage((s) => s.setLanguage)
  const next: Language = lang === 'en' ? 'zh' : 'en'
  const name = t(`common:language.names.${next}`)
  return (
    <Button
      color="inherit"
      size="small"
      startIcon={<LanguageIcon fontSize="small" />}
      aria-label={t('common:language.switchTo', { name })}
      lang={next}
      onClick={() => setLanguage(next)}
    >
      {name}
    </Button>
  )
}
