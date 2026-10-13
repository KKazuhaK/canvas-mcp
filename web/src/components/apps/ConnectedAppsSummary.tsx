import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import CircularProgress from '@mui/material/CircularProgress'
import Typography from '@mui/material/Typography'
import { Link as RouterLink } from 'react-router'
import { useTranslation } from 'react-i18next'
import ErrorNotice from '@/components/ErrorNotice'
import TimeText from '@/components/TimeText'
import { useGrants } from '@/query/hooks'
import AppIdentity from './AppIdentity'

export default function ConnectedAppsSummary() {
  const { t } = useTranslation()
  const grants = useGrants()
  const shown = grants.data?.grants.slice(0, 3) ?? []
  return <Card component="section" aria-labelledby="connected-apps-summary">
    <CardContent sx={{ display: 'grid', gap: 2 }}>
      <Typography id="connected-apps-summary" variant="h2" component="h2">
        {t('account:apps.title')}
      </Typography>
      {grants.isPending ? <CircularProgress size={24} aria-label={t('common:states.loading')} /> : null}
      {grants.isError ? <ErrorNotice error={grants.error} onRetry={() => void grants.refetch()} /> : null}
      {grants.data ? <>
        <Typography color="text.secondary">{shown.length ? t('account:overview.appsPreview') : t('account:overview.noApps')}</Typography>
        {shown.map((grant) => <Box key={grant.id} sx={{ display: 'grid', gap: 0.5 }}>
          <AppIdentity client={grant.client} />
          <Typography variant="body2" color="text.secondary">
            {t('account:apps.columns.lastUsed')}: <TimeText iso={grant.last_used_at} fallback={t('account:apps.never')} />
          </Typography>
        </Box>)}
      </> : null}
      <Box><Button component={RouterLink} to="/connected-apps">{t('account:overview.manageApps')}</Button></Box>
    </CardContent>
  </Card>
}
