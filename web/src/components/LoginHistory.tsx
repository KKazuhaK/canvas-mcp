import LoadMore from '@/components/LoadMore'
import Typography from '@mui/material/Typography'
import Chip from '@mui/material/Chip'
import Box from '@mui/material/Box'
import TextField from '@mui/material/TextField'
import MenuItem from '@mui/material/MenuItem'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { LoginEvent, LoginOutcome } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'
import ResponsiveTable, { type Column } from '@/components/ResponsiveTable'
import TimeText from '@/components/TimeText'
import { useLoginHistory, useProviders } from '@/query/hooks'
import { PageSkeleton } from '@/views/StateViews'

const OUTCOME_COLOR: Record<LoginOutcome, 'success' | 'warning' | 'error'> = {
  success: 'success',
  pending: 'warning',
  refused: 'error',
}

/**
 * The signed-in person's last sign-ins (GET /me/login-history, which a pending account
 * may read). No address or device: the server keeps none.
 */
export default function LoginHistory({ label }: { label: string }) {
  const { t } = useTranslation()
  const history = useLoginHistory()
  const providers = useProviders()
  const [outcome, setOutcome] = useState('all')
  const [days, setDays] = useState('all')
  const events = history.data?.events.filter((event) => {
    if (outcome !== 'all' && event.outcome !== outcome) return false
    if (days === 'all') return true
    return event.at !== null && Date.parse(event.at) >= Date.now() - Number(days) * 86400000
  }) ?? []

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
      render: (e) => (e.reason ? t(`account:activity.reason.${e.reason}`, { defaultValue: e.reason }) : '–'),
    },
  ]

  return (
    <>
      <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mb: 1 }}>
        <TextField select label={t('account:activity.filterResult')} value={outcome} sx={{ minWidth: 180 }}
          onChange={(event) => setOutcome(event.target.value)}>
          <MenuItem value="all">{t('account:activity.all')}</MenuItem>
          {(['success', 'pending', 'refused'] as const).map((value) => <MenuItem key={value} value={value}>{t(`account:activity.outcome.${value}`)}</MenuItem>)}
        </TextField>
        <TextField select label={t('account:activity.filterTime')} value={days} sx={{ minWidth: 180 }}
          onChange={(event) => setDays(event.target.value)}>
          <MenuItem value="all">{t('account:activity.all')}</MenuItem>
          {['1', '7', '30'].map((value) => <MenuItem key={value} value={value}>{t(value === '1' ? 'account:activity.lastDay' : 'account:activity.lastDays', { days: value })}</MenuItem>)}
        </TextField>
      </Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{t('account:activity.loadedScope')}</Typography>
      {history.isPending ? <PageSkeleton /> : null}
      {history.isError ? (
        <ErrorNotice error={history.error} onRetry={() => void history.refetch()} />
      ) : null}
      {history.data && history.data.events.length === 0 ? (
        <Typography color="text.secondary">{t('account:activity.empty')}</Typography>
      ) : null}
      {history.data && history.data.events.length > 0 ? (
        events.length ? <ResponsiveTable
          label={label}
          columns={columns}
          rows={events}
          rowKey={(e) => String(e.id)}
        /> : <Typography color="text.secondary">{t('account:activity.noMatches')}</Typography>
      ) : null}
      <LoadMore query={history} />
    </>
  )
}
