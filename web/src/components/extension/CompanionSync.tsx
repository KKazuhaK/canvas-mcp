import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Typography from '@mui/material/Typography'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { AUTO_SYNC_AFTER_MS, useCompanion } from './companion'

type State = { kind: 'idle' } | { kind: 'busy' } | { kind: 'done'; updated: number } | { kind: 'error'; message: string }

/**
 * "Sync now" through this browser's extension, shown only when it is connected to this portal.
 * Opening the page syncs by itself when the portal's copy is more than an hour old; that run only
 * fetches what is due, while the button refreshes everything.
 */
export default function CompanionSync({ lastUploadAt, onSynced }: { lastUploadAt: string | null; onSynced: () => void }) {
  const { t } = useTranslation()
  const { companion, sync } = useCompanion()
  const [state, setState] = useState<State>({ kind: 'idle' })
  const autoStarted = useRef(false)

  const run = useCallback(
    async (force: boolean) => {
      setState({ kind: 'busy' })
      const result = await sync(force)
      setState(
        result.ok
          ? { kind: 'done', updated: result.updated }
          : { kind: 'error', message: result.error ?? t('account:extension.sync.noAnswer') },
      )
      onSynced()
    },
    [sync, onSynced, t],
  )

  const linked = companion.status === 'present' && companion.connected
  useEffect(() => {
    if (!linked || autoStarted.current) return
    const last = Date.parse(lastUploadAt ?? '')
    if (Number.isFinite(last) && Date.now() - last < AUTO_SYNC_AFTER_MS) return
    autoStarted.current = true
    void run(false)
  }, [linked, lastUploadAt, run])

  if (!linked) return null
  return (
    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1.5, alignItems: 'center' }}>
      <Button variant="outlined" onClick={() => void run(true)} disabled={state.kind === 'busy'}>
        {t(state.kind === 'busy' ? 'account:extension.sync.running' : 'account:extension.sync.now')}
      </Button>
      {state.kind === 'done' ? (
        <Typography role="status" color="success.main">
          {state.updated > 0
            ? t('account:extension.sync.done', { count: state.updated })
            : t('account:extension.sync.unchanged')}
        </Typography>
      ) : null}
      {state.kind === 'error' ? (
        <Typography role="alert" color="error">
          {state.message}
        </Typography>
      ) : null}
      {state.kind === 'idle' && companion.lastError ? (
        <Typography color="text.secondary">{t('account:extension.sync.lastError', { message: companion.lastError })}</Typography>
      ) : null}
    </Box>
  )
}
