import MoreVertIcon from '@mui/icons-material/MoreVert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import IconButton from '@mui/material/IconButton'
import Menu from '@mui/material/Menu'
import MenuItem from '@mui/material/MenuItem'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type {
  AccountStatus,
  AdminAccount,
  AdminAccountActionBody,
  CanvasTokenState,
} from '@/api/types'
import ConfirmDialog from '@/components/ConfirmDialog'
import ErrorNotice from '@/components/ErrorNotice'
import ResponsiveTable, { type Column } from '@/components/ResponsiveTable'
import TimeText from '@/components/TimeText'
import { useAdminAccountAction, useAdminAccounts, useMe, useProviders } from '@/query/hooks'
import { useToast } from '@/stores/toast'
import { useDebounced } from '@/utils/useDebounced'
import { PageSkeleton } from '../StateViews'

const STATUS_COLOR: Record<AccountStatus, 'success' | 'warning' | 'default'> = {
  active: 'success',
  pending: 'warning',
  disabled: 'default',
}
const CANVAS_COLOR: Record<CanvasTokenState, 'success' | 'warning' | 'default'> = {
  valid: 'success',
  invalid: 'warning',
  unknown: 'default',
  none: 'default',
}

type Pending =
  | { kind: 'disable'; account: AdminAccount }
  | { kind: 'revoke_grants'; account: AdminAccount }
  | { kind: 'set_role'; account: AdminAccount }
  | { kind: 'unlink_identity'; account: AdminAccount }

function RowActions({
  account,
  isSelf,
  busy,
  onRun,
  onConfirm,
}: {
  account: AdminAccount
  isSelf: boolean
  busy: boolean
  onRun: (id: string, body: AdminAccountActionBody) => void
  onConfirm: (pending: Pending) => void
}) {
  const { t } = useTranslation()
  const [anchor, setAnchor] = useState<HTMLElement | null>(null)
  const close = () => setAnchor(null)
  const menuId = `account-menu-${account.id}`
  const name = account.display_name

  const items: { key: string; label: string; run: () => void; disabled?: boolean }[] = []
  if (account.status === 'disabled') {
    items.push({
      key: 'enable',
      label: t('admin:accounts.actions.enable'),
      run: () => onRun(account.id, { action: 'enable' }),
    })
  } else {
    items.push({
      key: 'disable',
      label: t('admin:accounts.actions.disable'),
      run: () => onConfirm({ kind: 'disable', account }),
      disabled: isSelf,
    })
  }
  items.push({
    key: 'role',
    label:
      account.role === 'owner'
        ? t('admin:accounts.actions.makeUser')
        : t('admin:accounts.actions.makeOwner'),
    run: () => onConfirm({ kind: 'set_role', account }),
    disabled: isSelf,
  })
  if (account.grants_count > 0) {
    items.push({
      key: 'grants',
      label: t('admin:accounts.actions.revokeGrants'),
      run: () => onConfirm({ kind: 'revoke_grants', account }),
    })
  }
  if (account.providers.length > 1) {
    items.push({
      key: 'unlink',
      label: t('admin:accounts.actions.unlinkIdentity'),
      run: () => onConfirm({ kind: 'unlink_identity', account }),
    })
  }

  return (
    <>
      {account.status === 'pending' ? (
        <Button
          size="small"
          variant="contained"
          disabled={busy}
          onClick={() => onRun(account.id, { action: 'approve' })}
        >
          {t('admin:accounts.actions.approve')}
        </Button>
      ) : null}
      <IconButton
        size="small"
        aria-label={`${t('admin:accounts.columns.actions')}: ${name}`}
        aria-haspopup="menu"
        aria-controls={anchor ? menuId : undefined}
        aria-expanded={anchor ? 'true' : undefined}
        disabled={busy}
        onClick={(e) => setAnchor(e.currentTarget)}
      >
        <MoreVertIcon fontSize="small" />
      </IconButton>
      <Menu id={menuId} anchorEl={anchor} open={anchor !== null} onClose={close}>
        {items.map((item) => (
          <MenuItem
            key={item.key}
            disabled={item.disabled}
            onClick={() => {
              close()
              item.run()
            }}
          >
            {item.label}
          </MenuItem>
        ))}
      </Menu>
    </>
  )
}

/** /admin: accounts (owner only; the server re-authorises every call). */
export default function AdminAccountsView() {
  const { t } = useTranslation()
  const me = useMe()
  const providers = useProviders()
  const [status, setStatus] = useState<AccountStatus | ''>('')
  const [search, setSearch] = useState('')
  const q = useDebounced(search.trim(), 300)
  const filters = useMemo(() => ({ status, q }), [status, q])
  const accounts = useAdminAccounts(filters)
  const action = useAdminAccountAction()
  const [pending, setPending] = useState<Pending | null>(null)
  const [unlinkProvider, setUnlinkProvider] = useState('')

  const rows = accounts.data?.pages.flatMap((page) => page.accounts) ?? []
  const providerName = (id: string) => providers.data?.providers.find((p) => p.id === id)?.name ?? id

  function run(id: string, body: AdminAccountActionBody, after?: () => void) {
    action.mutate(
      { id, body },
      {
        onSuccess: () => {
          useToast.getState().show(t(`admin:accounts.done.${body.action}`))
          after?.()
        },
      },
    )
  }

  function confirm() {
    if (!pending) return
    const { account } = pending
    const done = () => setPending(null)
    switch (pending.kind) {
      case 'disable':
        return run(account.id, { action: 'disable' }, done)
      case 'revoke_grants':
        return run(account.id, { action: 'revoke_grants' }, done)
      case 'set_role':
        return run(
          account.id,
          { action: 'set_role', role: account.role === 'owner' ? 'user' : 'owner' },
          done,
        )
      case 'unlink_identity':
        return run(account.id, { action: 'unlink_identity', identity_id: unlinkProvider }, done)
    }
  }

  function openConfirm(next: Pending) {
    action.reset()
    setUnlinkProvider(next.kind === 'unlink_identity' ? (next.account.providers[0] ?? '') : '')
    setPending(next)
  }

  const columns: Column<AdminAccount>[] = [
    {
      key: 'account',
      header: t('admin:accounts.columns.account'),
      primary: true,
      render: (a) => (
        <Box>
          <Typography sx={{ fontWeight: 600, overflowWrap: 'anywhere' }}>{a.display_name}</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>
            {a.email ?? t('admin:accounts.noEmail')}
          </Typography>
        </Box>
      ),
    },
    {
      key: 'status',
      header: t('admin:accounts.columns.status'),
      render: (a) => (
        <Chip size="small" color={STATUS_COLOR[a.status]} label={t(`common:status.${a.status}`)} />
      ),
    },
    { key: 'role', header: t('admin:accounts.columns.role'), render: (a) => t(`common:role.${a.role}`) },
    {
      key: 'providers',
      header: t('admin:accounts.columns.providers'),
      render: (a) => a.providers.map(providerName).join(', ') || '–',
    },
    {
      key: 'canvas',
      header: t('admin:accounts.columns.canvas'),
      render: (a) => (
        <Chip
          size="small"
          variant="outlined"
          color={CANVAS_COLOR[a.canvas_state]}
          label={t(`admin:accounts.canvasState.${a.canvas_state}`)}
        />
      ),
    },
    { key: 'grants', header: t('admin:accounts.columns.grants'), render: (a) => a.grants_count },
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
        <RowActions
          account={a}
          isSelf={me.data?.account.id === a.id}
          busy={action.isPending}
          onRun={(id, body) => run(id, body)}
          onConfirm={openConfirm}
        />
      ),
    },
  ]

  const name = pending?.account.display_name ?? ''
  const dialog = (() => {
    if (!pending) return { title: '', body: '', label: '', destructive: true }
    switch (pending.kind) {
      case 'disable':
        return {
          title: t('admin:accounts.confirm.disableTitle', { name }),
          body: t('admin:accounts.confirm.disableBody'),
          label: t('admin:accounts.actions.disable'),
          destructive: true,
        }
      case 'revoke_grants':
        return {
          title: t('admin:accounts.confirm.revokeGrantsTitle', { name }),
          body: t('admin:accounts.confirm.revokeGrantsBody'),
          label: t('admin:accounts.actions.revokeGrants'),
          destructive: true,
        }
      case 'set_role': {
        const toOwner = pending.account.role !== 'owner'
        return {
          title: t('admin:accounts.confirm.setRoleTitle', { name }),
          body: toOwner
            ? t('admin:accounts.confirm.setRoleOwner', { name })
            : t('admin:accounts.confirm.setRoleUser', { name }),
          label: toOwner ? t('admin:accounts.actions.makeOwner') : t('admin:accounts.actions.makeUser'),
          destructive: !toOwner,
        }
      }
      case 'unlink_identity':
        return {
          title: t('admin:accounts.confirm.unlinkTitle', { name }),
          body: t('admin:accounts.confirm.unlinkBody'),
          label: t('admin:accounts.actions.unlinkIdentity'),
          destructive: true,
        }
    }
  })()

  return (
    <>
      <Typography variant="h1" component="h1" sx={{ mb: 2 }}>
        {t('admin:accounts.title')}
      </Typography>
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
          onChange={(e) => setStatus(e.target.value as AccountStatus | '')}
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
      {action.isError && !pending ? <ErrorNotice error={action.error} /> : null}
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
      {accounts.hasNextPage ? (
        <Box sx={{ mt: 2 }}>
          <Button
            variant="outlined"
            disabled={accounts.isFetchingNextPage}
            onClick={() => void accounts.fetchNextPage()}
          >
            {t('common:actions.loadMore')}
          </Button>
        </Box>
      ) : null}

      <ConfirmDialog
        open={pending !== null}
        title={dialog.title}
        body={dialog.body}
        confirmLabel={dialog.label}
        destructive={dialog.destructive}
        pending={action.isPending}
        error={action.error}
        confirmDisabled={pending?.kind === 'unlink_identity' && unlinkProvider === ''}
        onClose={() => {
          action.reset()
          setPending(null)
        }}
        onConfirm={confirm}
      >
        {pending?.kind === 'unlink_identity' ? (
          // CONTRACT GAP: AdminAccount lists provider ids, not identity ids, so the
          // chosen provider id is sent as `identity_id`. Revisit when the backend
          // exposes identity ids on the admin account.
          <TextField
            select
            fullWidth
            size="small"
            sx={{ mt: 2 }}
            label={t('admin:accounts.confirm.unlinkField')}
            value={unlinkProvider}
            onChange={(e) => setUnlinkProvider(e.target.value)}
          >
            {pending.account.providers.map((id) => (
              <MenuItem key={id} value={id}>
                {providerName(id)}
              </MenuItem>
            ))}
          </TextField>
        ) : null}
      </ConfirmDialog>
    </>
  )
}
