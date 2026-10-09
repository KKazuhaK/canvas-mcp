import { useTranslation } from 'react-i18next'
import { useLanguage } from '@/stores/language'
import { formatDateTime } from '@/utils/time'

/** A timestamp in the viewer's locale and time zone, with the ISO value in `dateTime`. */
export default function TimeText({
  iso,
  fallback,
}: {
  iso: string | null | undefined
  /** Text when the value is absent. Defaults to "Never". */
  fallback?: string
}) {
  const { t } = useTranslation()
  const lang = useLanguage((s) => s.lang)
  const text = formatDateTime(iso, lang)
  if (text === null || !iso) return <>{fallback ?? t('common:time.never')}</>
  return <time dateTime={iso}>{text}</time>
}
