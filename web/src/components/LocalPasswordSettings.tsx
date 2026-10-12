import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router'
import { changeLocalPassword } from '@/api/endpoints'
import ErrorNotice from './ErrorNotice'

export default function LocalPasswordSettings() {
  const { t } = useTranslation()
  const cache = useQueryClient()
  const navigate = useNavigate()
  const [current, setCurrent] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  async function submit(event: FormEvent) {
    event.preventDefault()
    if (busy || password !== confirm) return
    setBusy(true); setError(null)
    try {
      await changeLocalPassword({ current_password: current, new_password: password })
      setCurrent(''); setPassword(''); setConfirm('')
      cache.clear()
      void navigate('/sign-in', { replace: true })
    } catch (reason) { setError(reason) }
    finally { setBusy(false) }
  }
  return <Card><CardContent><Box component="form" onSubmit={(event) => { void submit(event) }}><Stack spacing={2}>
    <Typography component="h2" variant="h6">{t('auth:local.changePassword')}</Typography>
    <Typography>{t('auth:local.changeHelp')}</Typography>
    {error !== null && <ErrorNotice error={error} />}
    <TextField required label={t('auth:local.currentPassword')} type="password" autoComplete="current-password" value={current} disabled={busy} onChange={(event) => setCurrent(event.target.value)} slotProps={{ htmlInput: { maxLength: 128 } }} />
    <TextField required label={t('auth:local.newPassword')} type="password" autoComplete="new-password" value={password} disabled={busy} onChange={(event) => setPassword(event.target.value)} helperText={t('auth:local.passwordHelp')} slotProps={{ htmlInput: { minLength: 15, maxLength: 128 } }} />
    <TextField required label={t('auth:local.confirm')} type="password" autoComplete="new-password" value={confirm} disabled={busy} error={confirm.length > 0 && password !== confirm} onChange={(event) => setConfirm(event.target.value)} />
    <Button type="submit" variant="outlined" disabled={busy || password !== confirm}>{t('auth:local.changePassword')}</Button>
  </Stack></Box></CardContent></Card>
}
