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
 * The owner's view of one account's connected apps, in a dialog opened from the accounts
 * table. The server re-checks the owner (and the 10-minute sign-in rule) on every call and
 * again inside the revoking transaction; the dialog only offers what it will answer.
 */
export default function AccountApps({ account }: { account: AdminAccount }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const grants = useAdminGrants(account.id, open)
  const revoke = useAdminRevokeGrant(account.id)

  async function end(grant: Grant) {
    try {
      const result = await revoke.mutateAsync(grant.id)
      useToast
        .getState()
        .show(result.changed ? t('admin:apps.revoked') : t('admin:apps.unchanged'), result.changed ? 'success' : 'info')
    } catch {
      // Shown below from the mutation.
    }
  }

  return (
    <>
      <Button
        size="small"
        variant="text"
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
        onClose={() => setOpen(false)}
        aria-labelledby={`account-apps-${account.id}`}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle id={`account-apps-${account.id}`}>
          {t('admin:apps.title', { name: account.display_name })}
        </DialogTitle>
        <DialogContent>
          {grants.isPending ? <Typography color="text.secondary">{t('common:states.loading')}</Typography> : null}
          {grants.isError ? (
            <ErrorNotice error={grants.error} onRetry={() => void grants.refetch()} />
          ) : null}
          {revoke.isError ? <ErrorNotice error={revoke.error} /> : null}
          {grants.data && grants.data.grants.length === 0 ? (
            <Typography color="text.secondary">{t('admin:apps.empty')}</Typography>
          ) : null}
          {grants.data && grants.data.grants.length > 0 ? (
            <Box component="ul" sx={{ listStyle: 'none', m: 0, p: 0 }}>
              {grants.data.grants.map((grant) => (
                <GrantRow
                  key={grant.id}
                  grant={grant}
                  busy={revoke.isPending}
                  onRevoke={(g) => void end(g)}
                />
              ))}
            </Box>
          ) : null}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>{t('common:actions.close')}</Button>
        </DialogActions>
      </Dialog>
    </>
  )
}
