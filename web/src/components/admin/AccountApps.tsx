import LoadMore from '@/components/LoadMore'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogTitle from '@mui/material/DialogTitle'
import Typography from '@mui/material/Typography'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { AdminAccount, Grant } from '@/api/types'
import AppIdentity from '@/components/apps/AppIdentity'
import ErrorNotice from '@/components/ErrorNotice'
import ConfirmDialog from '@/components/ConfirmDialog'
import TimeText from '@/components/TimeText'
import { useAdminGrants, useAdminRevokeGrant } from '@/query/hooks'
import { useToast } from '@/stores/toast'

function GrantRow({
  grant,
  busy,
  onRevoke,
}: {
  grant: Grant
  busy: boolean
  onRevoke: (grant: Grant) => void
}) {
  const { t } = useTranslation()
  const name = grant.client.label || t('account:apps.unnamed')
  return (
    <Box
      component="li"
      sx={{ display: 'grid', gap: 0.5, py: 1.5, borderBottom: 1, borderColor: 'divider' }}
    >
      <AppIdentity client={grant.client} />
      <Typography variant="caption" color="text.secondary">
        {t('admin:apps.returnsTo')} <code>{grant.redirect_host || '–'}</code> · {t('admin:apps.connected')}{' '}
        <TimeText iso={grant.created_at} /> · {t('admin:apps.lastUsed')}{' '}
        <TimeText iso={grant.last_used_at} fallback={t('account:apps.never')} />
      </Typography>
      <Box>
        <Button
          size="small"
          color="error"
          disabled={busy}
          aria-label={t('admin:apps.revokeLabel', { app: name })}
          onClick={() => onRevoke(grant)}
        >
          {t('admin:apps.revoke')}
        </Button>
      </Box>
    </Box>
  )
}

/**
 * One selected account's connected apps, inline in its detail view or in a dialog.
 * Every protected read and revocation is still re-authorized by the server.
 */
export default function AccountApps({ account, inline = false, active = true }: { account: AdminAccount; inline?: boolean; active?: boolean }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const grants = useAdminGrants(account.id, open || (inline && active))
  const revoke = useAdminRevokeGrant(account.id)
  const [target, setTarget] = useState<Grant | null>(null)

  async function end(grant: Grant) {
    try {
      const result = await revoke.mutateAsync(grant.id)
      setTarget(null)
      useToast
        .getState()
        .show(result.changed ? t('admin:apps.revoked') : t('admin:apps.unchanged'), result.changed ? 'success' : 'info')
    } catch {
      // Shown below from the mutation.
    }
  }

  const content = <>
    {grants.isPending ? <Typography color="text.secondary">{t('common:states.loading')}</Typography> : null}
    {grants.isError ? <ErrorNotice error={grants.error} onRetry={() => void grants.refetch()} /> : null}
    {grants.data && grants.data.grants.length === 0 ? <Typography color="text.secondary">{t('admin:apps.empty')}</Typography> : null}
    {grants.data && grants.data.grants.length > 0 ? <Box component="ul" sx={{ listStyle: 'none', m: 0, p: 0 }}>
      {grants.data.grants.map((grant) => <GrantRow key={grant.id} grant={grant} busy={revoke.isPending}
        onRevoke={(next) => { revoke.reset(); setTarget(next) }} />)}
    </Box> : null}
    <LoadMore query={grants} />
  </>

  return <>
    {inline ? content : <>
      <Button
        size="small"
        variant="outlined"
        aria-label={t('admin:apps.buttonLabel', { name: account.display_name })}
        onClick={() => {
          revoke.reset()
          setOpen(true)
        }}
      >
        {t('admin:apps.button')}
      </Button>
      <Dialog
        open={open}
        onClose={() => { if (!revoke.isPending) setOpen(false) }}
        aria-labelledby={`account-apps-${account.id}`}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle id={`account-apps-${account.id}`}>
          {t('admin:apps.title', { name: account.display_name })}
        </DialogTitle>
        <DialogContent>
          {content}
        </DialogContent>
        <DialogActions>
          <Button disabled={revoke.isPending} onClick={() => setOpen(false)}>{t('common:actions.close')}</Button>
        </DialogActions>
      </Dialog>
    </>}
    <ConfirmDialog open={target !== null}
      title={t('admin:apps.revokeTitle', { app: target?.client.label || t('account:apps.unnamed'), name: account.display_name })}
      body={t('admin:apps.revokeBody')} confirmLabel={t('admin:apps.revoke')} pending={revoke.isPending} error={revoke.error}
      onClose={() => { setTarget(null); revoke.reset() }} onConfirm={() => { if (target) void end(target) }} />
  </>
}
