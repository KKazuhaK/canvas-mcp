import Box from '@mui/material/Box'
import { useTranslation } from 'react-i18next'
import McpUrlCard from '@/components/McpUrlCard'
import PageHeader from '@/components/PageHeader'
import NotificationSettings from '@/components/NotificationSettings'
import TokenSection from '@/components/token/TokenSection'
import { useMe } from '@/query/hooks'
import { PageSkeleton } from './StateViews'

/** /token: enrollment, replacement, health checks and reminder preferences. */
export default function TokenView() {
  const { t } = useTranslation()
  const me = useMe()
  return (
    <>
      <PageHeader title={t('common:nav.token')} />
      {me.data ? (
        <Box sx={{ display: 'grid', gap: 2 }}>
          {me.data.canvas ? <TokenSection canvas={me.data.canvas} /> : null}
          <Box id="reminders" sx={{ scrollMarginTop: 90 }}><NotificationSettings /></Box>
          <McpUrlCard />
        </Box>
      ) : (
        <PageSkeleton />
      )}
    </>
  )
}
