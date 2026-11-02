import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Chip from '@mui/material/Chip'
import Typography from '@mui/material/Typography'
import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useLocation } from 'react-router'
import type { ExtensionBinding, ExtensionResource } from '@/api/types'
import ConfirmDialog from '@/components/ConfirmDialog'
import ErrorNotice from '@/components/ErrorNotice'
import ExtensionPairingCard, { extensionStateFromHash } from '@/components/extension/ExtensionPairingCard'
import PageHeader from '@/components/PageHeader'
import RelativeTimeText from '@/components/RelativeTimeText'
import ResponsiveTable, { type Column } from '@/components/ResponsiveTable'
import TimeText from '@/components/TimeText'
import { useDeleteExtension, useExtension } from '@/query/hooks'
import { useToast } from '@/stores/toast'
import { PageSkeleton } from './StateViews'

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Box sx={{ display: 'grid', gap: 0.25 }}>
      <Typography variant="caption" color="text.secondary">
        {label}
      </Typography>
      <Box sx={{ overflowWrap: 'anywhere' }}>{children}</Box>
    </Box>
  )
}

function StatusCard({ binding, onDisconnect }: { binding: ExtensionBinding | null; onDisconnect: () => void }) {
  const { t } = useTranslation()
  const notSynced = t('account:extension.notSyncedYet')
  const columns: Column<ExtensionResource>[] = [
    {
      key: 'path',
      header: t('account:extension.columns.path'),
      primary: true,
      render: (r) => <Box component="code">{r.path}</Box>,
    },
    {
      key: 'captured',
      header: t('account:extension.columns.captured'),
      render: (r) => <RelativeTimeText iso={r.capturedAt} fallback={notSynced} />,
    },
    {
      key: 'status',
      header: t('account:extension.columns.status'),
      render: (r) =>
        r.canvasStatus === 200 ? (
          <Chip size="small" color="success" variant="outlined" label={t('account:extension.statusOk')} />
        ) : (
          <Chip
            size="small"
            color="error"
            label={t('account:extension.statusBlocked', { status: r.canvasStatus })}
          />
        ),
    },
  ]
  return (
    <Card component="section" aria-labelledby="extension-status-title">
      <CardContent sx={{ display: 'grid', gap: 2 }}>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, alignItems: 'center' }}>
          <Typography id="extension-status-title" variant="h2" component="h2" sx={{ mr: 'auto' }}>
            {t('account:extension.status.title')}
          </Typography>
          <Chip
            color={binding ? 'success' : 'default'}
            label={binding ? t('account:extension.status.connected') : t('account:extension.status.notConnected')}
          />
        </Box>
        {binding === null ? (
          <Typography color="text.secondary">{t('account:extension.status.notConnectedBody')}</Typography>
        ) : (
          <>
            <Box sx={{ display: 'grid', gap: 1.5, gridTemplateColumns: { xs: '1fr', sm: 'repeat(3, 1fr)' } }}>
              <Field label={t('account:extension.status.canvasHost')}>
                {binding.canvasHost ? <code>{binding.canvasHost}</code> : notSynced}
              </Field>
              <Field label={t('account:extension.status.paired')}>
                <TimeText iso={binding.createdAt} />
              </Field>
              <Field label={t('account:extension.status.lastSync')}>
                <TimeText iso={binding.lastUploadAt} fallback={notSynced} />
              </Field>
            </Box>
            <Typography color={binding.active ? 'text.primary' : 'text.secondary'}>
              {binding.active
                ? t('account:extension.reason.active')
                : t(`account:extension.reason.${binding.reason ?? 'inactive'}`)}
            </Typography>
            <Box sx={{ display: 'grid', gap: 1 }}>
              <Typography variant="h3" component="h3">
                {t('account:extension.resources.title')}
              </Typography>
              {binding.resources.length === 0 ? (
                <Typography color="text.secondary">{t('account:extension.resources.empty')}</Typography>
              ) : (
                <ResponsiveTable
                  label={t('account:extension.resources.title')}
                  columns={columns}
                  rows={binding.resources}
                  rowKey={(r) => r.path}
                />
              )}
            </Box>
            <Box>
              <Button color="error" variant="outlined" onClick={onDisconnect}>
                {t('account:extension.disconnect.button')}
              </Button>
            </Box>
          </>
        )}
      </CardContent>
    </Card>
  )
}

/**
 * /browser-extension: pair a browser extension that reads Canvas while you are signed in (for schools
 * that do not allow access tokens), see what it synced, and remove it with its data. The extension opens
 * this page with `#extension-auth=<state>`; the pairing card answers it.
 */
export default function BrowserExtensionView() {
  const { t } = useTranslation()
  const { hash } = useLocation()
  const status = useExtension()
  const remove = useDeleteExtension()
  const [confirming, setConfirming] = useState(false)
  const state = extensionStateFromHash(hash)

  async function disconnect() {
    try {
      await remove.mutateAsync()
      useToast.getState().show(t('account:extension.disconnect.done'))
      setConfirming(false)
    } catch {
      // Shown in the dialog.
    }
  }

  return (
    <>
      <PageHeader title={t('account:extension.title')} subtitle={t('account:extension.intro')} />
      <Box sx={{ display: 'grid', gap: 2 }}>
        <ExtensionPairingCard key={state ?? 'manual'} state={state} />
        {status.isPending ? <PageSkeleton /> : null}
        {status.isError ? <ErrorNotice error={status.error} onRetry={() => void status.refetch()} /> : null}
        {status.data ? (
          <StatusCard
            binding={status.data.binding}
            onDisconnect={() => {
              remove.reset()
              setConfirming(true)
            }}
          />
        ) : null}
      </Box>
      <ConfirmDialog
        open={confirming}
        title={t('account:extension.disconnect.title')}
        body={t('account:extension.disconnect.body')}
        confirmLabel={t('account:extension.disconnect.confirm')}
        pending={remove.isPending}
        error={remove.error}
        onClose={() => {
          remove.reset()
          setConfirming(false)
        }}
        onConfirm={() => void disconnect()}
      />
    </>
  )
}
