import { useTranslation } from 'react-i18next'
import { useLanguage } from '@/stores/language'
import { useDisplayZone } from '@/stores/displayZone'
import { formatDateTime } from '@/utils/time'

/** A timestamp in the viewer's locale and the server's display time zone, with the ISO value in `dateTime`. */
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
  const zone = useDisplayZone((s) => s.zone)
  const text = formatDateTime(iso, lang, zone)
  if (text === null || !iso) return <>{fallback ?? t('common:time.never')}</>
  return <time dateTime={iso}>{text}</time>
}
