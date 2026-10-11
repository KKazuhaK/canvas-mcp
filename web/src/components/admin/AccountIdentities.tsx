import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Typography from '@mui/material/Typography'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { AdminAccount, AdminIdentity } from '@/api/types'
import ConfirmDialog from '@/components/ConfirmDialog'
import TimeText from '@/components/TimeText'
import { useAdminUnlinkIdentity, useProviders } from '@/query/hooks'
import { useToast } from '@/stores/toast'

/**
 * Every sign-in method of one account, with an owner Unlink (shown only where the server says
 * `can_unlink`: the account keeps at least one). The server re-checks that the caller is still an
 * owner with a recent sign-in inside the same transaction; a stale sign-in comes back as
 * reauth_required, which the dialog shows with its sign-in-again button.
 */
export default function AccountIdentities({ account }: { account: AdminAccount }) {
  const { t } = useTranslation()
  const providers = useProviders()
  const unlink = useAdminUnlinkIdentity()
  const [target, setTarget] = useState<AdminIdentity | null>(null)
  const identities = account.identities
  if (!identities || identities.length === 0) return null

  const nameOf = (id: string) => providers.data?.providers.find((p) => p.id === id)?.name ?? id

  async function confirm() {
    if (target === null) return
    try {
      await unlink.mutateAsync(target.id)
      setTarget(null)
      useToast.getState().show(t('admin:accounts.identities.done'), 'success')
    } catch {
      // The failure is on the mutation (shown in the dialog).
    }
  }

  return (
    <Box sx={{ mt: 1 }}>
      <Typography variant="caption" color="text.secondary" component="div" sx={{ fontWeight: 600 }}>
        {t('admin:accounts.identities.title')}
      </Typography>
      <Box component="ul" sx={{ listStyle: 'none', m: 0, p: 0, display: 'grid', gap: 0.75 }}>
        {identities.map((identity) => (
          <Box component="li" key={identity.id} sx={{ display: 'flex', gap: 1, alignItems: 'flex-start', justifyContent: 'space-between' }}>
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="caption" component="div" sx={{ overflowWrap: 'anywhere' }}>
                <strong>{nameOf(identity.provider_id)}</strong>
                {identity.username ? `: ${identity.username}` : ''}
              </Typography>
              <Typography variant="caption" color="text.secondary" component="div" sx={{ overflowWrap: 'anywhere' }}>
                <code>{identity.subject}</code>
              </Typography>
              {identity.provider_id.startsWith('oidc:') && identity.issuer ? (
                <Typography variant="caption" color="text.secondary" component="div" sx={{ overflowWrap: 'anywhere' }}>
                  {t('admin:accounts.identities.issuer')}: <code>{identity.issuer}</code>
                </Typography>
              ) : null}
              <Typography variant="caption" color="text.secondary" component="div">
                {t('admin:accounts.identities.linked')}: <TimeText iso={identity.linked_at} />
                {' · '}
                {t('admin:accounts.identities.lastSignIn')}:{' '}
                <TimeText iso={identity.last_login_at} />
              </Typography>
            </Box>
            {identity.can_unlink ? (
              <Button
                size="small"
                color="error"
                aria-label={t('admin:accounts.identities.unlinkLabel', {
                  provider: nameOf(identity.provider_id),
                  name: account.display_name,
                })}
                onClick={() => {
                  unlink.reset()
                  setTarget(identity)
                }}
              >
                {t('admin:accounts.identities.unlink')}
              </Button>
            ) : null}
          </Box>
        ))}
      </Box>
      <ConfirmDialog
        open={target !== null}
        title={
          target
            ? t('admin:accounts.identities.confirmTitle', {
                provider: nameOf(target.provider_id),
                name: account.display_name,
              })
            : ''
        }
        body={t('admin:accounts.identities.confirmBody')}
        confirmLabel={t('admin:accounts.identities.unlink')}
        pending={unlink.isPending}
        error={unlink.error}
        onClose={() => {
          unlink.reset()
          setTarget(null)
        }}
        onConfirm={() => void confirm()}
      />
    </Box>
  )
}
