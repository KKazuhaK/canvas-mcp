import Typography from '@mui/material/Typography'
import Chip from '@mui/material/Chip'
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
      render: (e) => (e.reason ? t(`account:activity.reason.${e.reason}`) : '–'),
    },
  ]

  return (
    <>
      {history.isPending ? <PageSkeleton /> : null}
      {history.isError ? (
        <ErrorNotice error={history.error} onRetry={() => void history.refetch()} />
      ) : null}
      {history.data && history.data.events.length === 0 ? (
        <Typography color="text.secondary">{t('account:activity.empty')}</Typography>
      ) : null}
      {history.data && history.data.events.length > 0 ? (
        <ResponsiveTable
          label={label}
          columns={columns}
          rows={history.data.events}
          rowKey={(e) => `${e.at}|${e.provider_id}|${e.outcome}|${e.reason}`}
        />
      ) : null}
    </>
  )
}
