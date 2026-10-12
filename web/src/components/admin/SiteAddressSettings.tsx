import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogTitle from '@mui/material/DialogTitle'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { AdminSettingsResponse, SiteAddressResponse } from '@/api/types'
import { saveSiteAddress } from '@/api/endpoints'
import ErrorNotice from '@/components/ErrorNotice'

export default function SiteAddressSettings({ data }: { data: AdminSettingsResponse }) {
  const { t } = useTranslation()
  const [value, setValue] = useState(data.site.public_base_url)
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [saved, setSaved] = useState<SiteAddressResponse | null>(null)
  async function save() {
    setBusy(true); setError(null)
    try {
      setSaved(await saveSiteAddress(data.revision, value))
      setConfirm(false)
    } catch (reason) { setError(reason) }
    finally { setBusy(false) }
  }
  const pending = saved?.site.restart_required ?? data.site.restart_required
  return <Card><CardContent><Stack spacing={2}>
    <Typography component="h2" variant="h6">{t('admin:site.title')}</Typography>
    <Typography>{t('admin:site.help')}</Typography>
    {error !== null && <ErrorNotice error={error} />}
    <TextField label={t('admin:site.address')} value={value} disabled={busy || pending} onChange={(event) => setValue(event.target.value)} slotProps={{ htmlInput: { maxLength: 512 } }} />
    {pending ? <Alert severity="warning">{t('admin:site.restart', { url: saved?.site.public_base_url ?? data.site.public_base_url })}</Alert> :
      <Button variant="outlined" disabled={busy || !value || value === data.site.public_base_url} onClick={() => setConfirm(true)}>{t('admin:site.save')}</Button>}
    <Dialog open={confirm} onClose={() => { if (!busy) setConfirm(false) }}>
      <DialogTitle>{t('admin:site.confirmTitle')}</DialogTitle>
      <DialogContent><Typography>{t('admin:site.confirmBody', { url: value })}</Typography></DialogContent>
      <DialogActions><Button disabled={busy} onClick={() => setConfirm(false)}>{t('admin:settings.cancel')}</Button><Button disabled={busy} onClick={() => { void save() }}>{t('admin:site.confirm')}</Button></DialogActions>
    </Dialog>
  </Stack></CardContent></Card>
}
