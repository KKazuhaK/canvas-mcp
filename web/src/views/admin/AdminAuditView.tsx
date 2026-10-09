import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import MenuItem from '@mui/material/MenuItem'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { AuditDetailValue, AuditEntry } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'
import ResponsiveTable, { type Column } from '@/components/ResponsiveTable'
import TimeText from '@/components/TimeText'
import { useAdminAudit } from '@/query/hooks'
import { PageSkeleton } from '../StateViews'

/** The audit actions the server writes (token_store.AUDIT_ACTIONS); anything else shows as "Other". */
const KNOWN_ACTIONS = [
  'account_created',
  'account_created_by_operator',
  'account_activated',
  'account_approved',
  'account_denied',
  'account_disabled',
  'account_enabled',
  'role_changed',
  'token_enrolled',
  'token_replaced',
  'token_deleted',
  'token_marked_invalid',
  'write_tools_changed',
  'schema_migrated',
  'pending_purged',
] as const

function isKnown(action: string): boolean {
  return (KNOWN_ACTIONS as readonly string[]).includes(action)
}

function detailValue(value: AuditDetailValue): string {
  return Array.isArray(value) ? value.join(', ') : String(value)
}

/** Detail is a flat map of short scalars (or string lists); render it as plain "key: value" text. */
function detailText(entry: AuditEntry): string {
  const parts = Object.entries(entry.detail).map(([k, v]) => `${k}: ${detailValue(v)}`)
  if (entry.reason) parts.unshift(`reason: ${entry.reason}`)
  return parts.length > 0 ? parts.join(', ') : '–'
}

/** /admin/audit: the audit log, newest first, 100 at a time. The action filter narrows the loaded entries. */
export default function AdminAuditView() {
  const { t } = useTranslation()
  const [action, setAction] = useState('')
  const audit = useAdminAudit()
  const loaded = audit.data?.pages.flatMap((page) => page.entries) ?? []
  const rows = loaded.filter((entry) => action === '' || entry.action === action)

  function actorText(entry: AuditEntry): string {
    if (entry.actor.kind === 'operator') return t('admin:audit.operator')
    if (entry.actor.kind === 'system') return t('admin:audit.system')
    return entry.actor.name ?? entry.actor.key ?? '–'
  }

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
      render: (e) => actorText(e),
    },
    {
      key: 'action',
      header: t('admin:audit.columns.action'),
      render: (e) => (isKnown(e.action) ? t(`admin:audit.actions.${e.action}`) : t('admin:audit.actions.other')),
    },
    {
      key: 'target',
      header: t('admin:audit.columns.target'),
      render: (e) => (e.target ? (e.target.name ?? e.target.key) : '–'),
    },
    {
      key: 'detail',
      header: t('admin:audit.columns.detail'),
      render: (e) => (
        <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>
          {detailText(e)}
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
          onChange={(e) => setAction(e.target.value)}
          helperText={t('admin:audit.filterNote')}
          sx={{ flex: '1 1 260px', maxWidth: 360 }}
        >
          <MenuItem value="">{t('admin:audit.allActions')}</MenuItem>
          {KNOWN_ACTIONS.map((a) => (
            <MenuItem key={a} value={a}>
              {t(`admin:audit.actions.${a}`)}
            </MenuItem>
          ))}
        </TextField>
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
          rowKey={(e) => String(e.id)}
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
