import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogTitle from '@mui/material/DialogTitle'
import TextField from '@mui/material/TextField'
import Alert from '@mui/material/Alert'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { getAdminSettings, saveAccountUpn } from '@/api/endpoints'
import type { AdminAccount } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'

export default function AccountUpnEditor({ account }: { account: AdminAccount }) {
  const { t } = useTranslation()
  const cache = useQueryClient()
  const [open, setOpen] = useState(false)
  const [upn, setUpn] = useState(account.upn ?? '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  async function save() {
    setBusy(true); setError(null)
    try {
      const settings = await getAdminSettings()
      await saveAccountUpn(account.id, upn, settings.revision)
      setOpen(false)
      await cache.invalidateQueries({ queryKey: ['admin'] })
      if (account.is_self) await cache.invalidateQueries({ queryKey: ['me'] })
    } catch (reason) { setError(reason) }
    finally { setBusy(false) }
  }
  return <>
    <Button onClick={() => { setUpn(account.upn ?? ''); setError(null); setOpen(true) }}>{t('auth:upn.edit')}</Button>
    <Dialog open={open} onClose={() => { if (!busy) setOpen(false) }}>
      <DialogTitle>{t('auth:upn.edit')}</DialogTitle>
      <DialogContent>
        <Alert severity="info">{t('auth:upn.adminHelp')}</Alert>
        {error !== null && <ErrorNotice error={error} />}
        <TextField fullWidth label={t('auth:local.username')} value={upn} disabled={busy} onChange={(event) => setUpn(event.target.value)} slotProps={{ htmlInput: { maxLength: 254 } }} />
      </DialogContent>
      <DialogActions><Button disabled={busy} onClick={() => setOpen(false)}>{t('admin:settings.cancel')}</Button><Button disabled={busy || upn.trim().length < 3} onClick={() => { void save() }}>{t('auth:upn.save')}</Button></DialogActions>
    </Dialog>
  </>
}
