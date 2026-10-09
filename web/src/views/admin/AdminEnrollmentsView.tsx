import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import MenuItem from '@mui/material/MenuItem'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { AdminAccount, AdminEnrollmentFilter } from '@/api/types'
import AdminActions from '@/components/admin/AdminActions'
import ErrorNotice from '@/components/ErrorNotice'
import ResponsiveTable, { type Column } from '@/components/ResponsiveTable'
import { AccountStatusChip, DisabledSince, TokenStateChip } from '@/components/StatusChips'
import TimeText from '@/components/TimeText'
import { useAdminEnrollments } from '@/query/hooks'
import { PageSkeleton } from '../StateViews'

function EnrollmentDetails({ account }: { account: AdminAccount }) {
  const { t } = useTranslation()
  const enrollment = account.enrollment
  if (enrollment === null) return null
  return (
    <Box component="details" sx={{ mt: 0.5 }}>
      <Typography component="summary" variant="caption" color="text.secondary" sx={{ cursor: 'pointer' }}>
        {t('admin:enrollments.details')}
      </Typography>
      <Box component="dl" sx={{ m: 0, mt: 0.5, display: 'grid', gridTemplateColumns: 'auto 1fr', columnGap: 1.5, rowGap: 0.25 }}>
        <Typography component="dt" variant="caption" color="text.secondary">
          {t('admin:enrollments.accountId')}
        </Typography>
        <Typography component="dd" variant="caption" sx={{ m: 0, overflowWrap: 'anywhere' }}>
          {account.id}
        </Typography>
        <Typography component="dt" variant="caption" color="text.secondary">
          {t('admin:enrollments.canvasUserId')}
        </Typography>
        <Typography component="dd" variant="caption" sx={{ m: 0, overflowWrap: 'anywhere' }}>
          {enrollment.canvas_user_id}
        </Typography>
        <Typography component="dt" variant="caption" color="text.secondary">
          {t('admin:enrollments.enrolledAt')}
        </Typography>
        <Typography component="dd" variant="caption" sx={{ m: 0 }}>
          <TimeText iso={enrollment.created_at} />
        </Typography>
        <Typography component="dt" variant="caption" color="text.secondary">
          {t('admin:enrollments.updatedAt')}
        </Typography>
        <Typography component="dd" variant="caption" sx={{ m: 0 }}>
          <TimeText iso={enrollment.updated_at} />
        </Typography>
        <Typography component="dt" variant="caption" color="text.secondary">
          {t('admin:enrollments.lastVerified')}
        </Typography>
        <Typography component="dd" variant="caption" sx={{ m: 0 }}>
          <TimeText iso={enrollment.last_verified_at} />
        </Typography>
        {enrollment.invalid_since ? (
          <>
            <Typography component="dt" variant="caption" color="text.secondary">
              {t('admin:enrollments.invalidSince')}
            </Typography>
            <Typography component="dd" variant="caption" sx={{ m: 0 }}>
              <TimeText iso={enrollment.invalid_since} />
            </Typography>
          </>
        ) : null}
      </Box>
    </Box>
  )
}

/** /admin/enrollments: who has a Canvas token stored, and whether Canvas still accepts it. */
export default function AdminEnrollmentsView() {
  const { t } = useTranslation()
  const [filter, setFilter] = useState<AdminEnrollmentFilter>('all')
  const query = useAdminEnrollments(filter)
  const rows = query.data?.rows ?? []
  const counts = query.data?.counts

  const columns: Column<AdminAccount>[] = [
    {
      key: 'account',
      header: t('admin:enrollments.columns.account'),
      primary: true,
      render: (a) => (
        <Box>
          <Typography sx={{ fontWeight: 600, overflowWrap: 'anywhere' }}>{a.display_name}</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>
            {a.username || t('admin:accounts.noUsername')}
          </Typography>
          {a.status !== 'active' ? (
            <Box sx={{ mt: 0.5 }}>
              <AccountStatusChip status={a.status} />
              {a.status === 'disabled' ? (
                <Box>
                  <DisabledSince iso={a.disabled_at} />
                </Box>
              ) : null}
            </Box>
          ) : null}
        </Box>
      ),
    },
    {
      key: 'canvasUser',
      header: t('admin:enrollments.columns.canvasUser'),
      render: (a) => a.enrollment?.canvas_user_name || t('admin:enrollments.notEnrolled'),
    },
    {
      key: 'school',
      header: t('admin:enrollments.columns.school'),
      render: (a) => {
        const school = a.enrollment?.school
        if (!school) return '–'
        return (
          <Box>
            <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>
              {school.name}
            </Typography>
            {!school.offered ? (
              <Typography variant="caption" color="warning.main">
                {t('admin:enrollments.schoolNotOffered')}
              </Typography>
            ) : null}
          </Box>
        )
      },
    },
    {
      key: 'state',
      header: t('admin:enrollments.columns.state'),
      render: (a) => (
        <Box sx={{ display: 'grid', gap: 0.5, justifyItems: 'start' }}>
          <TokenStateChip state={a.enrollment ? a.enrollment.state : 'none'} />
          {a.enrollment?.invalid_reason ? (
            <Typography variant="caption" color="text.secondary">
              {t(`admin:enrollments.reason.${a.enrollment.invalid_reason}`)}
            </Typography>
          ) : null}
        </Box>
      ),
    },
    {
      key: 'lastUsed',
      header: t('admin:enrollments.columns.lastUsed'),
      render: (a) => (
        <Box>
          <TimeText iso={a.enrollment?.last_used_at} />
          <EnrollmentDetails account={a} />
        </Box>
      ),
    },
    {
      key: 'actions',
      header: t('admin:enrollments.columns.actions'),
      actions: true,
      render: (a) => <AdminActions account={a} />,
    },
  ]

  return (
    <>
      <Typography variant="h1" component="h1" sx={{ mb: 2 }}>
        {t('admin:enrollments.title')}
      </Typography>
      {counts ? (
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }} aria-label={t('admin:enrollments.counts')} role="group">
          <Chip
            size="small"
            variant="outlined"
            color={counts.needing > 0 ? 'warning' : 'default'}
            label={`${t('admin:enrollments.count.needing')}: ${counts.needing}`}
          />
          <Chip
            size="small"
            variant="outlined"
            label={`${t('admin:enrollments.count.total')}: ${counts.total_enrollments}`}
          />
          <Chip
            size="small"
            variant="outlined"
            label={`${t('admin:enrollments.count.disabled')}: ${counts.disabled}`}
          />
          <Chip
            size="small"
            variant="outlined"
            color={counts.pending > 0 ? 'warning' : 'default'}
            label={`${t('admin:enrollments.count.pending')}: ${counts.pending}`}
          />
        </Box>
      ) : null}
      <TextField
        size="small"
        select
        label={t('admin:enrollments.filter')}
        value={filter}
        onChange={(e) => setFilter(e.target.value as AdminEnrollmentFilter)}
        sx={{ mb: 2, minWidth: 240 }}
      >
        <MenuItem value="all">{t('admin:enrollments.filterAll')}</MenuItem>
        <MenuItem value="needs_reenroll">{t('admin:enrollments.filterNeeding')}</MenuItem>
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
          rowKey={(a) => a.id}
        />
      ) : null}
    </>
  )
}
