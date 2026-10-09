import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import MenuItem from '@mui/material/MenuItem'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { AdminEnrollment, EnrollmentTokenState } from '@/api/types'
import ConfirmDialog from '@/components/ConfirmDialog'
import ErrorNotice from '@/components/ErrorNotice'
import ResponsiveTable, { type Column } from '@/components/ResponsiveTable'
import TimeText from '@/components/TimeText'
import { useAdminEnrollments, useRevokeEnrollment } from '@/query/hooks'
import { useToast } from '@/stores/toast'
import { PageSkeleton } from '../StateViews'

const STATE_COLOR: Record<EnrollmentTokenState, 'success' | 'warning' | 'default'> = {
  valid: 'success',
  invalid: 'warning',
  unknown: 'default',
  none: 'default',
}

type Filter = EnrollmentTokenState | 'all'

/** /admin/enrollments: who has a Canvas token stored, and whether Canvas still accepts it. */
export default function AdminEnrollmentsView() {
  const { t } = useTranslation()
  const query = useAdminEnrollments()
  const revoke = useRevokeEnrollment()
  const [filter, setFilter] = useState<Filter>('all')
  const [target, setTarget] = useState<AdminEnrollment | null>(null)

  const rows = (query.data?.enrollments ?? []).filter((e) => filter === 'all' || e.state === filter)

  const columns: Column<AdminEnrollment>[] = [
    {
      key: 'account',
      header: t('admin:enrollments.columns.account'),
      primary: true,
      render: (e) => <Typography sx={{ fontWeight: 600, overflowWrap: 'anywhere' }}>{e.display_name}</Typography>,
    },
    {
      key: 'canvasUser',
      header: t('admin:enrollments.columns.canvasUser'),
      render: (e) => e.canvas_user_name ?? t('common:time.unknown'),
    },
    {
      key: 'state',
      header: t('admin:enrollments.columns.state'),
      render: (e) => (
        <Chip size="small" color={STATE_COLOR[e.state]} label={t(`admin:enrollments.state.${e.state}`)} />
      ),
    },
    {
      key: 'lastUsed',
      header: t('admin:enrollments.columns.lastUsed'),
      render: (e) => (
        <Box>
          <TimeText iso={e.last_used_at} />
          <Box component="details" sx={{ mt: 0.5 }}>
            <Typography component="summary" variant="caption" color="text.secondary" sx={{ cursor: 'pointer' }}>
              {t('admin:enrollments.details')}
            </Typography>
            <Box component="dl" sx={{ m: 0, mt: 0.5, display: 'grid', gridTemplateColumns: 'auto 1fr', columnGap: 1.5, rowGap: 0.25 }}>
              {[
                [t('admin:enrollments.accountId'), e.account_id],
                [t('admin:enrollments.canvasUserId'), e.canvas_user_id === null ? '–' : String(e.canvas_user_id)],
              ].map(([label, value]) => (
                <Box key={label} sx={{ display: 'contents' }}>
                  <Typography component="dt" variant="caption" color="text.secondary">
                    {label}
                  </Typography>
                  <Typography component="dd" variant="caption" sx={{ m: 0, overflowWrap: 'anywhere' }}>
                    {value}
                  </Typography>
                </Box>
              ))}
              <Typography component="dt" variant="caption" color="text.secondary">
                {t('admin:enrollments.enrolledAt')}
              </Typography>
              <Typography component="dd" variant="caption" sx={{ m: 0 }}>
                <TimeText iso={e.enrolled_at} />
              </Typography>
              <Typography component="dt" variant="caption" color="text.secondary">
                {t('admin:enrollments.updatedAt')}
              </Typography>
              <Typography component="dd" variant="caption" sx={{ m: 0 }}>
                <TimeText iso={e.updated_at} />
              </Typography>
              {e.invalid_since ? (
                <>
                  <Typography component="dt" variant="caption" color="text.secondary">
                    {t('admin:enrollments.invalidSince')}
                  </Typography>
                  <Typography component="dd" variant="caption" sx={{ m: 0 }}>
                    <TimeText iso={e.invalid_since} />
                  </Typography>
                </>
              ) : null}
            </Box>
          </Box>
        </Box>
      ),
    },
    {
      key: 'actions',
      header: t('admin:enrollments.columns.actions'),
      actions: true,
      render: (e) => (
        <Button
          size="small"
          color="error"
          aria-label={`${t('admin:enrollments.revoke')}: ${e.display_name}`}
          onClick={() => {
            revoke.reset()
            setTarget(e)
          }}
        >
          {t('admin:enrollments.revoke')}
        </Button>
      ),
    },
  ]

  return (
    <>
      <Typography variant="h1" component="h1" sx={{ mb: 2 }}>
        {t('admin:enrollments.title')}
      </Typography>
      <TextField
        size="small"
        select
        label={t('admin:enrollments.filter')}
        value={filter}
        onChange={(e) => setFilter(e.target.value as Filter)}
        sx={{ mb: 2, minWidth: 220 }}
      >
        <MenuItem value="all">{t('admin:enrollments.filterAll')}</MenuItem>
        {(['valid', 'invalid', 'unknown'] as const).map((s) => (
          <MenuItem key={s} value={s}>
            {t(`admin:enrollments.state.${s}`)}
          </MenuItem>
        ))}
      </TextField>

      {query.isPending ? <PageSkeleton /> : null}
      {query.isError ? <ErrorNotice error={query.error} onRetry={() => void query.refetch()} /> : null}
      {query.data && rows.length === 0 ? (
        <Typography color="text.secondary">{t('admin:enrollments.empty')}</Typography>
      ) : null}
      {rows.length > 0 ? (
        <ResponsiveTable
          label={t('admin:enrollments.title')}
          columns={columns}
          rows={rows}
          rowKey={(e) => e.account_id}
        />
      ) : null}

      <ConfirmDialog
        open={target !== null}
        title={t('admin:enrollments.confirmTitle', { name: target?.display_name ?? '' })}
        body={t('admin:enrollments.confirmBody')}
        confirmLabel={t('admin:enrollments.revoke')}
        pending={revoke.isPending}
        error={revoke.error}
        onClose={() => {
          revoke.reset()
          setTarget(null)
        }}
        onConfirm={() => {
          if (!target) return
          revoke.mutate(target.account_id, {
            onSuccess: () => {
              setTarget(null)
              useToast.getState().show(t('admin:enrollments.done'))
            },
          })
        }}
      />
    </>
  )
}
