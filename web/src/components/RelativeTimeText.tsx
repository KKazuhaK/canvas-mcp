import { useTranslation } from 'react-i18next'
import { useLanguage } from '@/stores/language'
import { useDisplayZone } from '@/stores/displayZone'
import { formatDateTime, formatRelative } from '@/utils/time'

/** "5 minutes ago", with the exact time (in the server's display zone) as the tooltip. */
export default function RelativeTimeText({
  iso,
  fallback,
}: {
  iso: string | null | undefined
  fallback?: string
}) {
  const { t } = useTranslation()
  const lang = useLanguage((s) => s.lang)
  const zone = useDisplayZone((s) => s.zone)
  const relative = formatRelative(iso, lang)
  if (relative === null || !iso) return <>{fallback ?? t('common:time.never')}</>
  return (
    <time dateTime={iso} title={formatDateTime(iso, lang, zone) ?? undefined}>
      {relative}
    </time>
  )
}
