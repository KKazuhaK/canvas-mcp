import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Typography from '@mui/material/Typography'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ApiError } from '@/api/errors'
import type { Grant } from '@/api/types'
import AppIdentity from '@/components/apps/AppIdentity'
import ConfirmDialog from '@/components/ConfirmDialog'
import ErrorNotice from '@/components/ErrorNotice'
import PageHeader from '@/components/PageHeader'
import ResponsiveTable, { type Column } from '@/components/ResponsiveTable'
import TimeText from '@/components/TimeText'
import { useGrants, useRevokeGrant } from '@/query/hooks'
import { useToast } from '@/stores/toast'
import { PageSkeleton } from './StateViews'

/** What to call an app in a sentence: its domain, its name, or "Unnamed app". */
function appName(grant: Grant, unnamed: string): string {
  return grant.client.label || unnamed
}

/**
 * /connected-apps: the apps that were let in through the consent screen (the server's own
 * authorization server, SELFHOST_AUTH_MODE=local). Revoking one ends it for good: it cuts the
 * app off at once (other server processes notice within seconds) and the app has to ask again.
 */
export default function ConnectedAppsView() {
  const { t } = useTranslation()
  const grants = useGrants()
  const revoke = useRevokeGrant()
  const [target, setTarget] = useState<Grant | null>(null)
  const unnamed = t('account:apps.unnamed')

  async function confirmRevoke() {
    if (target === null) return
    try {
      await revoke.mutateAsync(target.id)
      useToast.getState().show(t('account:apps.revoked'))
      setTarget(null)
    } catch (error) {
      // Already gone (another tab, an owner): the list refreshes, and that is what was asked for.
      if (error instanceof ApiError && error.code === 'not_found') {
        setTarget(null)
        revoke.reset()
      }
    }
  }

  const columns: Column<Grant>[] = [
    {
      key: 'app',
      header: t('account:apps.columns.app'),
      primary: true,
      render: (g) => <AppIdentity client={g.client} />,
    },
    {
      key: 'returnsTo',
      header: t('account:apps.columns.returnsTo'),
      render: (g) => (
        <Box component="code" sx={{ overflowWrap: 'anywhere' }}>
          {g.redirect_host || '–'}
        </Box>
      ),
    },
    {
      key: 'connected',
      header: t('account:apps.columns.connected'),
      render: (g) => <TimeText iso={g.created_at} />,
    },
    {
      key: 'lastUsed',
      header: t('account:apps.columns.lastUsed'),
      render: (g) => <TimeText iso={g.last_used_at} fallback={t('account:apps.never')} />,
    },
    {
      key: 'actions',
      header: t('account:apps.columns.actions'),
      actions: true,
      render: (g) => (
        <Button
          size="small"
          color="error"
          aria-label={t('account:apps.revokeLabel', { name: appName(g, unnamed) })}
          onClick={() => {
            revoke.reset()
            setTarget(g)
          }}
        >
          {t('account:apps.revoke')}
        </Button>
      ),
    },
  ]

  return (
    <>
      <PageHeader title={t('account:apps.title')} subtitle={t('account:apps.intro')} />
      {grants.isPending ? <PageSkeleton /> : null}
      {grants.isError ? <ErrorNotice error={grants.error} onRetry={() => void grants.refetch()} /> : null}
      {grants.data && grants.data.grants.length === 0 ? (
        <Typography color="text.secondary">{t('account:apps.empty')}</Typography>
      ) : null}
      {grants.data && grants.data.grants.length > 0 ? (
        <ResponsiveTable
          label={t('account:apps.title')}
          columns={columns}
          rows={grants.data.grants}
          rowKey={(g) => g.id}
        />
      ) : null}
      <ConfirmDialog
        open={target !== null}
        title={target ? t('account:apps.revokeTitle', { name: appName(target, unnamed) }) : ''}
        body={t('account:apps.revokeBody')}
        confirmLabel={t('account:apps.revoke')}
        pending={revoke.isPending}
        error={revoke.error}
        onClose={() => {
          revoke.reset()
          setTarget(null)
        }}
        onConfirm={() => void confirmRevoke()}
      />
    </>
  )
}
