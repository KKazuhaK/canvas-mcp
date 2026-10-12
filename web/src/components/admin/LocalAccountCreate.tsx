import Alert from '@mui/material/Alert'
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
import { createLocalAccount, getLoginProviderSettings } from '@/api/endpoints'
import ErrorNotice from '@/components/ErrorNotice'

export default function LocalAccountCreate() {
  const { t } = useTranslation()
  const cache = useQueryClient()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState<unknown>(null)
  async function submit(event: FormEvent) {
    event.preventDefault()
    if (busy) return
    setBusy(true); setError(null); setDone(false)
    try {
      const settings = await getLoginProviderSettings()
      await createLocalAccount({ revision: settings.revision, username, password })
      setUsername(''); setPassword(''); setDone(true)
      await cache.invalidateQueries({ queryKey: ['admin'] })
    } catch (reason) { setError(reason) }
    finally { setBusy(false) }
  }
  return <Card><CardContent><Box component="form" onSubmit={(event) => { void submit(event) }}><Stack spacing={2}>
    <Typography component="h2" variant="h6">{t('admin:localAccount.create')}</Typography>
    <Typography>{t('admin:localAccount.help')}</Typography>
    {error !== null && <ErrorNotice error={error} />}
    {done && <Alert severity="success">{t('admin:localAccount.created')}</Alert>}
    <TextField required label={t('auth:local.username')} autoComplete="off" value={username} disabled={busy} onChange={(event) => setUsername(event.target.value)} helperText={t('auth:local.usernameHelp')} />
    <TextField required label={t('auth:local.password')} type="password" autoComplete="new-password" value={password} disabled={busy} onChange={(event) => setPassword(event.target.value)} helperText={t('auth:local.passwordHelp')} slotProps={{ htmlInput: { minLength: 15, maxLength: 128 } }} />
    <Button type="submit" variant="contained" disabled={busy}>{t('admin:localAccount.create')}</Button>
  </Stack></Box></CardContent></Card>
}
