import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router'
import { loginLocal } from '@/api/endpoints'
import { SITE_BASE, sanitizeReturnTo } from '@/utils/returnTo'
import ErrorNotice from './ErrorNotice'

export default function LocalLoginForm({ txn, returnTo }: { txn: string | null; returnTo: string | null }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const cache = useQueryClient()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  async function submit(event: FormEvent) {
    event.preventDefault()
    if (busy) return
    setBusy(true); setError(null)
    try {
      const response = await loginLocal({ username, password, ...(txn ? { txn } : {}), ...(returnTo ? { return_to: returnTo } : {}) })
      setPassword('')
      const target = sanitizeReturnTo(response.redirect_to)
      await cache.resetQueries()
      void navigate(target ? target.slice(SITE_BASE.length) || '/' : '/', { replace: true })
    } catch (reason) { setError(reason) }
    finally { setBusy(false) }
  }
  return <Box component="form" onSubmit={(event) => { void submit(event) }}><Stack spacing={2}>
    {error !== null && <ErrorNotice error={error} />}
    <TextField required label={t('auth:local.username')} autoComplete="username" value={username} disabled={busy} onChange={(event) => setUsername(event.target.value)} slotProps={{ htmlInput: { maxLength: 64 } }} />
    <TextField required label={t('auth:local.password')} type="password" autoComplete="current-password" value={password} disabled={busy} onChange={(event) => setPassword(event.target.value)} slotProps={{ htmlInput: { maxLength: 128 } }} />
    <Button variant="contained" type="submit" disabled={busy}>{t('auth:local.signIn')}</Button>
  </Stack></Box>
}
