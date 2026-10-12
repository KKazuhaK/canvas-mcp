import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import MenuItem from '@mui/material/MenuItem'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate } from 'react-router'
import { getProviders, getSetupStatus, initializeLogin } from '@/api/endpoints'
import ErrorNotice from '@/components/ErrorNotice'
import ProviderConfigurationForm, { type ProviderSave } from '@/components/admin/ProviderConfigurationForm'
import { keys } from '@/query/keys'
import { FullPageLoading } from './StateViews'

export default function SetupView() {
  const { t } = useTranslation()
  const query = useQuery({ queryKey: ['setup'], queryFn: getSetupStatus, staleTime: 0 })
  const cache = useQueryClient()
  const [code, setCode] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [kind, setKind] = useState<'local' | 'entra' | 'google' | 'github' | 'oidc'>('local')
  const [slug, setSlug] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  if (query.isPending) return <FullPageLoading />
  if (query.isError) return <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
  if (query.data.initialized) return <Navigate to="/sign-in" replace />
  const status = query.data
  const identifier = kind === 'oidc' ? `oidc:${slug}` : kind
  const valid = /^[a-z0-9][a-z0-9._-]{2,63}$/i.test(username.trim()) && password.length >= 15 && password.length <= 128 && password === confirm && code.length > 0 && (kind !== 'oidc' || /^[a-z][a-z0-9-]{0,31}$/.test(slug))
  async function save(values?: ProviderSave) {
    if (!valid || busy) return
    setBusy(true)
    setError(null)
    try {
      await initializeLogin({ revision: status.revision, code, local_account: { username, password }, ...(values ? { provider_id: identifier, config: values.config, client_secret: values.client_secret ?? '' } : {}) })
      setCode(''); setPassword(''); setConfirm('')
      await cache.fetchQuery({ queryKey: keys.providers, queryFn: getProviders, staleTime: 0 })
      await query.refetch()
    } catch (reason) { setError(reason) }
    finally { setBusy(false) }
  }
  return <Card><CardContent><Stack spacing={3}>
    <Typography component="h1" variant="h4">{t('admin:installation.title')}</Typography>
    <Typography>{t('admin:installation.help')}</Typography>
    {error !== null && <ErrorNotice error={error} />}
    <TextField required label={t('admin:installation.code')} type="password" value={code} autoComplete="off" disabled={busy} onChange={(event) => setCode(event.target.value)} />
    <Typography component="h2" variant="h6">{t('admin:localAccount.owner')}</Typography>
    <TextField required label={t('auth:local.username')} autoComplete="username" value={username} disabled={busy} onChange={(event) => setUsername(event.target.value)} helperText={t('auth:local.usernameHelp')} />
    <TextField required label={t('auth:local.password')} type="password" autoComplete="new-password" value={password} disabled={busy} onChange={(event) => setPassword(event.target.value)} helperText={t('auth:local.passwordHelp')} slotProps={{ htmlInput: { minLength: 15, maxLength: 128 } }} />
    <TextField required label={t('auth:local.confirm')} type="password" autoComplete="new-password" value={confirm} disabled={busy} error={confirm.length > 0 && password !== confirm} onChange={(event) => setConfirm(event.target.value)} />
    <TextField select label={t('admin:installation.method')} value={kind} disabled={busy} onChange={(event) => setKind(event.target.value as typeof kind)}>
      <MenuItem value="local">{t('admin:localAccount.only')}</MenuItem>
      <MenuItem value="entra">Microsoft Entra</MenuItem><MenuItem value="google">Google</MenuItem><MenuItem value="github">GitHub</MenuItem><MenuItem value="oidc">OpenID Connect</MenuItem>
    </TextField>
    {kind === 'oidc' && <TextField required label={t('admin:providerConfig.slug')} value={slug} onChange={(event) => setSlug(event.target.value)} />}
    {kind === 'local' ? <Button variant="contained" disabled={!valid || busy} onClick={() => { void save() }}>{t('admin:providerConfig.initialize')}</Button> : <Box>
      <ProviderConfigurationForm key={identifier} installation disabled={!valid || busy} callbackUri={status.callback_uri.replace('/entra', `/${identifier.replace(':', '/')}`)}
        provider={{ id: identifier, protocol: kind, enabled: true, rank: 1, config: {}, secret_present: false }} onSave={save} />
    </Box>}
  </Stack></CardContent></Card>
}
