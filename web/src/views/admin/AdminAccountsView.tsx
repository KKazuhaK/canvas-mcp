import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import MenuItem from '@mui/material/MenuItem'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { AdminAccount, AdminStatusFilter } from '@/api/types'
import AccountApps from '@/components/admin/AccountApps'
import AdminActions from '@/components/admin/AdminActions'
import ErrorNotice from '@/components/ErrorNotice'
import ResponsiveTable, { type Column } from '@/components/ResponsiveTable'
import { AccountStatusChip, DisabledSince, TokenStateChip } from '@/components/StatusChips'
import TimeText from '@/components/TimeText'
import { useAdminAccounts, useMe } from '@/query/hooks'
import { PageSkeleton } from '../StateViews'

function Details({ account }: { account: AdminAccount }) {
  const { t } = useTranslation()
  const rows: [string, string | null][] = [
    [t('admin:accounts.details.provider'), account.identity?.provider_id ?? null],
    [t('admin:accounts.details.tenant'), account.identity?.tenant_id ?? null],
    [t('admin:accounts.details.subject'), account.identity?.subject ?? null],
    [t('admin:accounts.details.accountId'), account.id],
  ]
  return (
    <Box component="details" sx={{ mt: 0.5 }}>
      <Typography component="summary" variant="caption" color="text.secondary" sx={{ cursor: 'pointer' }}>
        {t('admin:accounts.details.summary')}
      </Typography>
      <Box component="dl" sx={{ m: 0, mt: 0.5, display: 'grid', gridTemplateColumns: 'auto 1fr', columnGap: 1.5, rowGap: 0.25 }}>
        {rows.map(([label, value]) =>
          value === null ? null : (
            <Box key={label} sx={{ display: 'contents' }}>
              <Typography component="dt" variant="caption" color="text.secondary">
                {label}
              </Typography>
              <Typography component="dd" variant="caption" sx={{ m: 0, overflowWrap: 'anywhere' }}>
                {value}
              </Typography>
            </Box>
          ),
        )}
        <Typography component="dt" variant="caption" color="text.secondary">
          {t('admin:accounts.details.created')}
        </Typography>
        <Typography component="dd" variant="caption" sx={{ m: 0 }}>
          <TimeText iso={account.created_at} />
        </Typography>
        <Typography component="dt" variant="caption" color="text.secondary">
          {t('admin:accounts.details.approved')}
        </Typography>
        <Typography component="dd" variant="caption" sx={{ m: 0 }}>
          <TimeText iso={account.approved_at} />
        </Typography>
      </Box>
    </Box>
  )
}

/** /admin: accounts (owner only; the server re-authorises every call and wants a recent sign-in). */
export default function AdminAccountsView() {
  const { t } = useTranslation()
  const [status, setStatus] = useState<AdminStatusFilter | ''>('')
  const [search, setSearch] = useState('')
  const accounts = useAdminAccounts(status)
  // Only with the server's own authorization server: then an account may have connected apps.
  const connectedApps = useMe().data?.features.connected_apps === true

  const needle = search.trim().toLowerCase()
  const rows = (accounts.data?.accounts ?? []).filter(
    (a) =>
      needle === '' ||
      a.display_name.toLowerCase().includes(needle) ||
      a.username.toLowerCase().includes(needle),
  )
  const counts = accounts.data?.counts

  const columns: Column<AdminAccount>[] = [
    {
      key: 'account',
      header: t('admin:accounts.columns.account'),
      primary: true,
      render: (a) => (
        <Box>
          <Typography sx={{ fontWeight: 600, overflowWrap: 'anywhere' }}>
            {a.display_name}
            {a.is_self ? (
              <Chip size="small" variant="outlined" label={t('admin:accounts.you')} sx={{ ml: 1 }} />
            ) : null}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>
            {a.username || t('admin:accounts.noUsername')}
          </Typography>
          <Details account={a} />
        </Box>
      ),
    },
    {
      key: 'status',
      header: t('admin:accounts.columns.status'),
      render: (a) => (
        <Box sx={{ display: 'grid', gap: 0.5, justifyItems: 'start' }}>
          <AccountStatusChip status={a.status} />
          {a.disabled_reason ? (
            <Typography variant="caption" color="text.secondary">
              {t(`admin:accounts.disabledReason.${a.disabled_reason}`)}
            </Typography>
          ) : null}
          {a.status === 'disabled' ? <DisabledSince iso={a.disabled_at} /> : null}
        </Box>
      ),
    },
    { key: 'role', header: t('admin:accounts.columns.role'), render: (a) => t(`common:role.${a.role}`) },
    {
      key: 'canvas',
      header: t('admin:accounts.columns.canvas'),
      render: (a) => <TokenStateChip state={a.enrollment ? a.enrollment.state : 'none'} />,
    },
    {
      key: 'lastLogin',
      header: t('admin:accounts.columns.lastLogin'),
      render: (a) => <TimeText iso={a.last_login_at} fallback={t('admin:accounts.neverLoggedIn')} />,
    },
    {
      key: 'actions',
      header: t('admin:accounts.columns.actions'),
      actions: true,
      render: (a) => (
        <Box sx={{ display: 'grid', gap: 0.5, justifyItems: 'start' }}>
          <AdminActions account={a} />
          {connectedApps && a.status === 'active' ? <AccountApps account={a} /> : null}
        </Box>
      ),
    },
  ]

  return (
    <>
      <Typography variant="h1" component="h1" sx={{ mb: 2 }}>
        {t('admin:accounts.title')}
      </Typography>
      {counts ? (
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }} aria-label={t('admin:accounts.counts')} role="group">
          {(['total', 'active', 'pending', 'disabled', 'owners'] as const).map((key) => (
            <Chip
              key={key}
              size="small"
              variant="outlined"
              color={key === 'pending' && counts.pending > 0 ? 'warning' : 'default'}
              label={`${t(`admin:accounts.count.${key}`)}: ${counts[key]}`}
            />
          ))}
        </Box>
      ) : null}
      <Box sx={{ display: 'flex', gap: 1.5, flexWrap: 'wrap', mb: 2 }}>
        <TextField
          size="small"
          type="search"
          label={t('admin:accounts.search')}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          sx={{ flex: '1 1 220px' }}
        />
        <TextField
          size="small"
          select
          label={t('admin:accounts.statusFilter')}
          value={status}
          onChange={(e) => setStatus(e.target.value as AdminStatusFilter | '')}
          sx={{ flex: '0 1 180px', minWidth: 140 }}
        >
          <MenuItem value="">{t('admin:accounts.allStatuses')}</MenuItem>
          {(['active', 'pending', 'disabled'] as const).map((s) => (
            <MenuItem key={s} value={s}>
              {t(`common:status.${s}`)}
            </MenuItem>
          ))}
        </TextField>
      </Box>

      {accounts.isPending ? <PageSkeleton /> : null}
      {accounts.isError ? (
        <ErrorNotice error={accounts.error} onRetry={() => void accounts.refetch()} />
      ) : null}
      {accounts.data && rows.length === 0 ? (
        <Typography color="text.secondary">{t('admin:accounts.empty')}</Typography>
      ) : null}
      {rows.length > 0 ? (
        <ResponsiveTable
          label={t('admin:accounts.title')}
          columns={columns}
          rows={rows}
          rowKey={(a) => a.id}
        />
      ) : null}
    </>
  )
}
