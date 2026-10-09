import Box from '@mui/material/Box'
import { useTranslation } from 'react-i18next'
import McpUrlCard from '@/components/McpUrlCard'
import PageHeader from '@/components/PageHeader'
import TokenSection from '@/components/token/TokenSection'
import { useMe } from '@/query/hooks'
import { PageSkeleton } from './StateViews'

/** /token: the dedicated Canvas token screen (same components as the home page). */
export default function TokenView() {
  const { t } = useTranslation()
  const me = useMe()
  return (
    <>
      <PageHeader title={t('common:nav.token')} />
      {me.data ? (
        <Box sx={{ display: 'grid', gap: 2 }}>
          {me.data.canvas ? <TokenSection canvas={me.data.canvas} /> : null}
          <McpUrlCard />
        </Box>
      ) : (
        <PageSkeleton />
      )}
    </>
  )
}
