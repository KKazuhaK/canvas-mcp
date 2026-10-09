import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Chip from '@mui/material/Chip'
import Typography from '@mui/material/Typography'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { LoginEvent, LoginOutcome } from '@/api/types'
import ConfirmDialog from '@/components/ConfirmDialog'
import ErrorNotice from '@/components/ErrorNotice'
import PageHeader from '@/components/PageHeader'
import ResponsiveTable, { type Column } from '@/components/ResponsiveTable'
import TimeText from '@/components/TimeText'
import { useLoginHistory, useLogout, useProviders } from '@/query/hooks'
import { summariseUserAgent } from '@/utils/time'
import { codeText } from '@/utils/errorText'
import { PageSkeleton } from './StateViews'

const OUTCOME_COLOR: Record<LoginOutcome, 'success' | 'warning' | 'error'> = {
  success: 'success',
  denied: 'warning',
  error: 'error',
}

/** /activity: the last 20 sign-in attempts, plus sign out and sign out everywhere. */
export default function ActivityView() {
  const { t } = useTranslation()
  const history = useLoginHistory()
  const providers = useProviders()
  const logout = useLogout()
  const [confirmAll, setConfirmAll] = useState(false)

  const providerName = (id: string) => providers.data?.providers.find((p) => p.id === id)?.name ?? id

  const columns: Column<LoginEvent>[] = [
    {
      key: 'time',
      header: t('account:activity.columns.time'),
      primary: true,
      render: (e) => <TimeText iso={e.at} />,
    },
    {
      key: 'provider',
      header: t('account:activity.columns.provider'),
      render: (e) => providerName(e.provider_id),
    },
    {
      key: 'result',
      header: t('account:activity.columns.result'),
      render: (e) => (
        <Chip
          size="small"
          color={OUTCOME_COLOR[e.outcome]}
          label={t(`account:activity.outcome.${e.outcome}`)}
        />
      ),
    },
    {
      key: 'reason',
      header: t('account:activity.columns.reason'),
      render: (e) => (e.reason ? codeText(t, e.reason) : '–'),
    },
    {
      key: 'ip',
      header: t('account:activity.columns.ip'),
      render: (e) => (e.ip && e.ip !== 'unknown' ? e.ip : t('account:activity.ipUnknown')),
    },
    {
      key: 'device',
      header: t('account:activity.columns.device'),
      render: (e) => summariseUserAgent(e.user_agent) ?? t('common:time.unknown'),
    },
  ]

  return (
    <>
      <PageHeader title={t('account:activity.title')} subtitle={t('account:activity.intro')} />
      <Box sx={{ display: 'grid', gap: 2 }}>
        {history.isPending ? <PageSkeleton /> : null}
        {history.isError ? (
          <ErrorNotice error={history.error} onRetry={() => void history.refetch()} />
        ) : null}
        {history.data && history.data.events.length === 0 ? (
          <Typography color="text.secondary">{t('account:activity.empty')}</Typography>
        ) : null}
        {history.data && history.data.events.length > 0 ? (
          <ResponsiveTable
            label={t('account:activity.title')}
            columns={columns}
            rows={history.data.events}
            rowKey={(e) => `${e.at}|${e.provider_id}|${e.outcome}`}
          />
        ) : null}

        <Card component="section" aria-labelledby="sessions-title">
          <CardContent sx={{ display: 'grid', gap: 1.5 }}>
            <Typography id="sessions-title" variant="h3" component="h2">
              {t('account:activity.sessionsTitle')}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {t('account:activity.sessionsBody')}
            </Typography>
            {logout.isError && !confirmAll ? <ErrorNotice error={logout.error} /> : null}
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <Button variant="outlined" disabled={logout.isPending} onClick={() => logout.mutate(false)}>
                {t('common:actions.signOut')}
              </Button>
              <Button color="error" disabled={logout.isPending} onClick={() => setConfirmAll(true)}>
                {t('common:actions.signOutAll')}
              </Button>
            </Box>
          </CardContent>
        </Card>
      </Box>

      <ConfirmDialog
        open={confirmAll}
        title={t('common:actions.signOutAll')}
        body={t('account:activity.sessionsBody')}
        confirmLabel={t('common:actions.signOutAll')}
        pending={logout.isPending}
        error={logout.error}
        onClose={() => {
          logout.reset()
          setConfirmAll(false)
        }}
        onConfirm={() => logout.mutate(true)}
      />
    </>
  )
}
