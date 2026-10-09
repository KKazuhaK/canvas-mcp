import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import MenuItem from '@mui/material/MenuItem'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { AuditAction, AuditEntry } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'
import ResponsiveTable, { type Column } from '@/components/ResponsiveTable'
import TimeText from '@/components/TimeText'
import { useAdminAudit } from '@/query/hooks'
import { useDebounced } from '@/utils/useDebounced'
import { PageSkeleton } from '../StateViews'

const ACTIONS: AuditAction[] = [
  'login',
  'approve',
  'disable',
  'enable',
  'set_role',
  'link',
  'unlink',
  'write_tool_toggle',
  'token_enroll',
  'token_delete',
  'grant_revoke',
  'enrollment_revoke',
]

/** Detail is a flat map of short scalars; render it as plain "key: value" text. */
function detailText(detail: AuditEntry['detail']): string {
  if (!detail) return '–'
  return Object.entries(detail)
    .map(([k, v]) => `${k}: ${String(v)}`)
    .join(', ')
}

/** /admin/audit: filterable, cursor-paginated audit log. */
export default function AdminAuditView() {
  const { t } = useTranslation()
  const [action, setAction] = useState<AuditAction | ''>('')
  const [actor, setActor] = useState('')
  const debouncedActor = useDebounced(actor.trim(), 300)
  const filters = useMemo(() => ({ action, actor: debouncedActor }), [action, debouncedActor])
  const audit = useAdminAudit(filters)
  const rows = audit.data?.pages.flatMap((page) => page.entries) ?? []

  const columns: Column<AuditEntry>[] = [
    {
      key: 'time',
      header: t('admin:audit.columns.time'),
      primary: true,
      render: (e) => <TimeText iso={e.at} />,
    },
    {
      key: 'actor',
      header: t('admin:audit.columns.actor'),
      render: (e) => e.actor_name ?? t('admin:audit.system'),
    },
    {
      key: 'action',
      header: t('admin:audit.columns.action'),
      render: (e) => t(`admin:audit.actions.${e.action}`),
    },
    {
      key: 'target',
      header: t('admin:audit.columns.target'),
      render: (e) => e.target_name ?? '–',
    },
    {
      key: 'detail',
      header: t('admin:audit.columns.detail'),
      render: (e) => (
        <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>
          {detailText(e.detail)}
        </Typography>
      ),
    },
  ]

  return (
    <>
      <Typography variant="h1" component="h1" sx={{ mb: 2 }}>
        {t('admin:audit.title')}
      </Typography>
      <Box sx={{ display: 'flex', gap: 1.5, flexWrap: 'wrap', mb: 2 }}>
        <TextField
          size="small"
          select
          label={t('admin:audit.actionFilter')}
          value={action}
          onChange={(e) => setAction(e.target.value as AuditAction | '')}
          sx={{ flex: '1 1 220px' }}
        >
          <MenuItem value="">{t('admin:audit.allActions')}</MenuItem>
          {ACTIONS.map((a) => (
            <MenuItem key={a} value={a}>
              {t(`admin:audit.actions.${a}`)}
            </MenuItem>
          ))}
        </TextField>
        <TextField
          size="small"
          label={t('admin:audit.actorFilter')}
          value={actor}
          onChange={(e) => setActor(e.target.value)}
          sx={{ flex: '1 1 220px' }}
        />
      </Box>

      {audit.isPending ? <PageSkeleton /> : null}
      {audit.isError ? <ErrorNotice error={audit.error} onRetry={() => void audit.refetch()} /> : null}
      {audit.data && rows.length === 0 ? (
        <Typography color="text.secondary">{t('admin:audit.empty')}</Typography>
      ) : null}
      {rows.length > 0 ? (
        <ResponsiveTable
          label={t('admin:audit.title')}
          columns={columns}
          rows={rows}
          rowKey={(e) => e.id}
        />
      ) : null}
      {audit.hasNextPage ? (
        <Box sx={{ mt: 2 }}>
          <Button
            variant="outlined"
            disabled={audit.isFetchingNextPage}
            onClick={() => void audit.fetchNextPage()}
          >
            {t('common:actions.loadMore')}
          </Button>
        </Box>
      ) : null}
    </>
  )
}
