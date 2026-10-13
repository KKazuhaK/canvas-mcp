import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import MenuItem from '@mui/material/MenuItem'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import Alert from '@mui/material/Alert'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { getLoginProviderSettings, saveLoginProvider } from '@/api/endpoints'
import type { LoginProviderConfiguration } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'
import { ApiError } from '@/api/errors'
import { keys } from '@/query/keys'
import ProviderConfigurationForm, { type EditableProvider } from './ProviderConfigurationForm'
import ProviderNameEditor from './ProviderNameEditor'
import ProviderIcon from '@/components/ProviderIcon'
import type { LoginProviderSettings as ProviderSettingsResponse } from '@/api/types'

export default function LoginProviderSettings({ names = {} }: { names?: Record<string, string> }) {
  const { t } = useTranslation()
  const cache = useQueryClient()
  const query = useQuery({ queryKey: ['admin', 'login-providers'], queryFn: getLoginProviderSettings })
  const [selected, setSelected] = useState<EditableProvider | null>(null)
  const [selectedRevision, setSelectedRevision] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)
  const [editorEpoch, setEditorEpoch] = useState(0)
  const [saved, setSaved] = useState(false)
  const [kind, setKind] = useState<LoginProviderConfiguration['protocol']>('google')
  const [slug, setSlug] = useState('')
  if (query.isError) return <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
  if (!query.data) return null
  const identifier = kind === 'oidc' ? `oidc:${slug}` : kind
  const validId = kind !== 'oidc' || /^[a-z][a-z0-9_-]{0,31}$/.test(slug)
  const exists = query.data.providers.some((provider) => provider.id === identifier)
  const stale = selected !== null && selectedRevision !== query.data.revision
  function select(provider: EditableProvider) {
    setSelected(provider)
    setSaved(false)
    setSelectedRevision(query.data!.revision)
    setEditorEpoch((value) => value + 1)
  }
  return <Card><CardContent><Stack spacing={2}>
    <Typography component="h2" variant="h6">{t('admin:providerConfig.title')}</Typography>
    {saved && <Alert severity="success" role="status">{t('admin:workspace.saved')}</Alert>}
    {query.data.providers.map((provider) => <Stack key={provider.id} direction="row" spacing={2} sx={{ alignItems: 'center' }}>
      <ProviderIcon icon={provider.protocol === 'entra' ? 'microsoft' : provider.protocol === 'google' ? 'google' : provider.protocol === 'github' ? 'github' : 'key'} data={provider.icon_data} />
      <Stack sx={{ minWidth: 0 }}><Typography sx={{ overflowWrap: 'anywhere' }}>{names[provider.id] || provider.id}</Typography><Typography variant="caption" color="text.secondary">{provider.id}</Typography></Stack>
      <Button disabled={selected !== null} onClick={() => select(provider)}>{t('admin:providerConfig.edit', { provider: provider.id })}</Button>
    </Stack>)}
    {selected === null && <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
      <TextField select label={t('admin:providerConfig.type')} value={kind} onChange={(event) => setKind(event.target.value as LoginProviderConfiguration['protocol'])}>
        {(['local', 'entra', 'google', 'github', 'oidc'] as const).map((value) => <MenuItem key={value} value={value}>{value === 'local' ? t('admin:localAccount.name') : value === 'entra' ? 'Microsoft Entra' : value === 'oidc' ? 'OIDC' : value === 'github' ? 'GitHub' : 'Google'}</MenuItem>)}
      </TextField>
      {kind === 'oidc' && <TextField label={t('admin:providerConfig.slug')} value={slug} onChange={(event) => setSlug(event.target.value)} />}
      <Button disabled={selected !== null || !validId || exists || query.data.providers.length >= 8} onClick={() => select({ id: identifier, protocol: kind, enabled: true, rank: query.data.providers.length, config: {}, secret_present: false })}>{t('admin:providerConfig.add')}</Button>
    </Stack>}
    {selected !== null && <Typography component="h3" variant="h3">{t('admin:providerConfig.edit', { provider: names[selected.id] || selected.id })}</Typography>}
    {stale && <Alert severity="warning">{t('admin:workspace.staleDraft')}<Button disabled={busy} onClick={() => {
      const current = query.data.providers.find((provider) => provider.id === selected?.id)
      if (current) select(current)
      else setSelected(null)
    }}>{t('admin:workspace.discardDraft')}</Button></Alert>}
    {selected !== null && query.data.providers.some((provider) => provider.id === selected.id) && <ProviderNameEditor key={`${selected.id}:name:${editorEpoch}`} id={selected.id} disabled={stale || busy} onBusyChange={setBusy} onSaved={(before, after) => {
      setSelectedRevision((current) => current === before ? after : current)
      cache.setQueryData<ProviderSettingsResponse>(['admin', 'login-providers'], (previous) => previous?.revision === before ? { ...previous, revision: after } : previous)
    }} />}
    {selected !== null && <ProviderConfigurationForm key={`${selected.id}:${editorEpoch}`} provider={selected}
      disabled={stale || busy} onBusyChange={setBusy}
      callbackUri={`${query.data.public_base_url}/auth/callback/${selected.id.replace(':', '/')}`}
      onSave={async (values) => {
        let fresh
        try { fresh = await saveLoginProvider(selected.id, { ...values, revision: selectedRevision! }) }
        catch (error) {
          if (error instanceof ApiError && error.code === 'settings_conflict') void query.refetch()
          throw error
        }
        cache.setQueryData(['admin', 'login-providers'], fresh)
        setSelected(null)
        setSaved(true)
        for (const key of [keys.adminSettings, keys.providers, keys.me, keys.adminAudit]) await cache.invalidateQueries({ queryKey: key })
      }} />}
    {selected !== null && <Button disabled={busy} onClick={() => setSelected(null)}>{t('admin:settings.cancel')}</Button>}
    <Button disabled={selected !== null} onClick={() => { void query.refetch() }}>{t('admin:providerConfig.reload')}</Button>
  </Stack></CardContent></Card>
}
