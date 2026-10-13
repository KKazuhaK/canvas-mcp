import LoadMore from '@/components/LoadMore'
import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import MenuItem from '@mui/material/MenuItem'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogTitle from '@mui/material/DialogTitle'
import DialogContent from '@mui/material/DialogContent'
import DialogActions from '@mui/material/DialogActions'
import Tab from '@mui/material/Tab'
import Tabs from '@mui/material/Tabs'
import Stack from '@mui/material/Stack'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Alert from '@mui/material/Alert'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { AdminAccount, AdminStatusFilter } from '@/api/types'
import AccountApps from '@/components/admin/AccountApps'
import AccountUpnEditor from '@/components/admin/AccountUpnEditor'
import { AccountLoginPolicy } from '@/components/admin/LoginPolicySettings'
import AccountIdentities from '@/components/admin/AccountIdentities'
import AdminActions from '@/components/admin/AdminActions'
import ErrorNotice from '@/components/ErrorNotice'
import ResponsiveTable, { type Column } from '@/components/ResponsiveTable'
import { AccountStatusChip, DisabledSince, TokenStateChip } from '@/components/StatusChips'
import TimeText from '@/components/TimeText'
import LocalAccountCreate from '@/components/admin/LocalAccountCreate'
import PageHeader from '@/components/PageHeader'
import { getLoginProviderSettings } from '@/api/endpoints'
import DetailDrawer from '@/components/admin/DetailDrawer'
import EnrollmentExpiry from '@/components/admin/EnrollmentExpiry'
import { useAdminAccounts } from '@/query/hooks'
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
          // The tenant is empty for a Google, GitHub or OIDC identity: no empty row.
          !value ? null : (
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
      </Box>
    </Box>
  )
}

function AccountDetail({ account }: { account: AdminAccount }) {
  const { t } = useTranslation()
  const [topic, setTopic] = useState('profile')
  return <>
    <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }}>
      <AccountStatusChip status={account.status} /><Chip size="small" variant="outlined" label={t(`common:role.${account.role}`)} /><TokenStateChip state={account.enrollment?.state ?? 'none'} />
    </Stack>
    <Typography color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>{account.upn || account.username || t('admin:accounts.noUsername')}</Typography>
    <AdminActions account={account} only={['approve', 'deny', 'disable', 'enable']} />
    <Tabs value={topic} onChange={(_, value: string) => setTopic(value)} variant="scrollable" scrollButtons="auto" allowScrollButtonsMobile aria-label={t('admin:accountDetail.topics')}>
      {(['profile', 'signIn', 'canvas', 'apps'] as const).map((value) => <Tab key={value} value={value} id={`account-detail-tab-${value}`} aria-controls={`account-detail-panel-${value}`} label={t(`admin:accountDetail.${value}`)} />)}
    </Tabs>
    <Stack hidden={topic !== 'profile'} role="tabpanel" id="account-detail-panel-profile" aria-labelledby="account-detail-tab-profile" sx={{ display: topic === 'profile' ? 'flex' : 'none' }} spacing={2}>
      <Card><CardContent><Stack spacing={2}>
        {account.upn_required && <Alert severity="warning">{t('admin:accountDetail.missingUpn')}</Alert>}
        <Typography variant="body2" color="text.secondary">{t('auth:local.username')}</Typography>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{ justifyContent: 'space-between', alignItems: { sm: 'center' } }}>
          <Typography sx={{ overflowWrap: 'anywhere' }}>{account.upn || account.username || t('admin:accounts.noUsername')}</Typography>
          <AccountUpnEditor account={account} />
        </Stack>
        <Box component="dl" sx={{ m: 0, display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'auto 1fr' }, gap: 1 }}>
          <Typography component="dt" color="text.secondary">{t('admin:accounts.columns.lastLogin')}</Typography>
          <Typography component="dd" sx={{ m: 0 }}><TimeText iso={account.last_login_at} fallback={t('admin:accounts.neverLoggedIn')} /></Typography>
          <Typography component="dt" color="text.secondary">{t('admin:accounts.details.created')}</Typography>
          <Typography component="dd" sx={{ m: 0 }}><TimeText iso={account.created_at} /></Typography>
          <Typography component="dt" color="text.secondary">{t('admin:accounts.details.approved')}</Typography>
          <Typography component="dd" sx={{ m: 0 }}><TimeText iso={account.approved_at} /></Typography>
        </Box>
      </Stack></CardContent></Card>
      <Details account={account} />
    </Stack>
    <Stack hidden={topic !== 'signIn'} role="tabpanel" id="account-detail-panel-signIn" aria-labelledby="account-detail-tab-signIn" sx={{ display: topic === 'signIn' ? 'flex' : 'none' }} spacing={2}>
      <AccountLoginPolicy id={account.id} inline active={topic === 'signIn'} /><AccountIdentities account={account} />
    </Stack>
    <Stack hidden={topic !== 'canvas'} role="tabpanel" id="account-detail-panel-canvas" aria-labelledby="account-detail-tab-canvas" sx={{ display: topic === 'canvas' ? 'flex' : 'none' }} spacing={2}>
      {account.enrollment ? <>
        <Typography>{account.enrollment.canvas_user_name}</Typography>
        <Typography sx={{ overflowWrap: 'anywhere' }}>{account.enrollment.school?.name ?? '–'}</Typography>
        <Typography color="text.secondary">{t('account:enrolled.expires')}</Typography><EnrollmentExpiry enrollment={account.enrollment} />
        <Typography variant="body2" color="text.secondary">{t('account:expiry.source')}: {t(account.enrollment.expiry_source === 'canvas' ? 'account:expiry.sources.canvas' : 'account:expiry.sources.unknown')}</Typography>
        <Typography>{t('admin:enrollments.lastVerified')}: <TimeText iso={account.enrollment.last_verified_at} /></Typography>
        <AdminActions account={account} only={['mark_invalid', 'remove_enrollment']} />
      </> : <Typography>{t('admin:enrollments.notEnrolled')}</Typography>}
    </Stack>
    <Box hidden={topic !== 'apps'} role="tabpanel" id="account-detail-panel-apps" aria-labelledby="account-detail-tab-apps" sx={{ display: topic === 'apps' ? 'block' : 'none' }}>
      {account.status === 'active' ? <AccountApps account={account} inline active={topic === 'apps'} /> : <Typography>{t('admin:accountDetail.appsInactive')}</Typography>}
    </Box>
  </>
}

/** /admin: accounts (owner only; the server re-authorises every call and wants a recent sign-in). */
export default function AdminAccountsView() {
  const { t } = useTranslation()
  const [status, setStatus] = useState<AdminStatusFilter | ''>('')
  const [search, setSearch] = useState('')
  const accounts = useAdminAccounts(status)
  const providers = useQuery({ queryKey: ['admin', 'login-providers'], queryFn: getLoginProviderSettings })
  const [creating, setCreating] = useState(false)
  const [createBusy, setCreateBusy] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const selected = accounts.data?.accounts.find((account) => account.id === selectedId)
  const localEnabled = providers.data?.providers?.some((provider) => provider.id === 'local' && provider.enabled)

  const needle = search.trim().toLowerCase()
  const rows = (accounts.data?.accounts ?? []).filter(
    (a) =>
      needle === '' ||
      a.display_name.toLowerCase().includes(needle) ||
      (a.upn ?? '').toLowerCase().includes(needle) ||
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
          <Typography component="div" sx={{ fontWeight: 600, overflowWrap: 'anywhere' }}>
            {a.display_name}
            {a.is_self ? (
              <Chip size="small" variant="outlined" label={t('admin:accounts.you')} sx={{ ml: 1 }} />
            ) : null}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>
            {a.upn || a.username || t('admin:accounts.noUsername')}
          </Typography>
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
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          <AdminActions account={a} only={['approve']} />
          <Button size="small" variant="outlined" onClick={() => setSelectedId(a.id)} aria-label={t('admin:accountDetail.manageLabel', { name: a.display_name })}>{t('admin:accountDetail.manage')}</Button>
        </Box>
      ),
    },
  ]

  return (
    <>
      <PageHeader title={t('admin:accounts.title')} actions={localEnabled ? <Button variant="contained" onClick={() => setCreating(true)}>{t('admin:localAccount.new')}</Button> : undefined} />
      <Dialog open={creating} onClose={() => { if (!createBusy) setCreating(false) }} fullWidth maxWidth="sm">
        <DialogTitle>{t('admin:localAccount.new')}</DialogTitle>
        <DialogContent>{creating && <LocalAccountCreate onBusyChange={setCreateBusy} />}</DialogContent>
        <DialogActions><Button disabled={createBusy} onClick={() => setCreating(false)}>{t('admin:settings.cancel')}</Button></DialogActions>
      </Dialog>
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
          helperText={t('admin:accounts.searchScope')}
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
      <LoadMore query={accounts} />
      <DetailDrawer open={selected !== undefined} title={selected?.display_name ?? ''} onClose={() => setSelectedId(null)}>
        {selected && <AccountDetail key={selected.id} account={selected} />}
      </DetailDrawer>
    </>
  )
}
