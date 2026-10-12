import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useLocation } from 'react-router'
import { saveAccountUpn } from '@/api/endpoints'
import type { Account } from '@/api/types'
import ErrorNotice from './ErrorNotice'
import { hardNavigate } from '@/utils/navigate'

export default function AccountUpnSettings({ account }: { account: Account }) {
  const { t } = useTranslation()
  const location = useLocation()
  const [upn, setUpn] = useState(account.upn ?? '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  async function save() {
    setBusy(true); setError(null)
    try { const result = await saveAccountUpn(upn); hardNavigate(result.redirect_to === '/account' ? `/account${location.pathname}${location.search}` : result.redirect_to) }
    catch (reason) { setError(reason); setBusy(false) }
  }
  return <Card><CardContent><Stack spacing={2}>
    {account.upn_required && <Alert severity="info">{t('auth:upn.required')}</Alert>}
    {error !== null && <ErrorNotice error={error} />}
    <TextField label={t('auth:local.username')} value={upn} disabled={busy} onChange={(event) => setUpn(event.target.value)} helperText={t('auth:upn.help')} slotProps={{ htmlInput: { maxLength: 254 } }} />
    <Button disabled={busy || upn.trim().length < 3} onClick={() => { void save() }}>{t('auth:upn.save')}</Button>
  </Stack></CardContent></Card>
}
