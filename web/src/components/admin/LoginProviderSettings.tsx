import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import MenuItem from '@mui/material/MenuItem'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import AddRounded from '@mui/icons-material/AddRounded'
import EditOutlined from '@mui/icons-material/EditOutlined'
import RefreshRounded from '@mui/icons-material/RefreshRounded'
import ArrowBackRounded from '@mui/icons-material/ArrowBackRounded'
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
  const typeName = (protocol: LoginProviderConfiguration['protocol']) => t(`admin:providerConfig.protocols.${protocol}`)
  const displayName = (provider: EditableProvider) => names[provider.id] || (provider.protocol === 'oidc'
    ? `${typeName(provider.protocol)} · ${provider.id.slice('oidc:'.length)}` : typeName(provider.protocol))
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
  return <Card><CardContent sx={{ p: { xs: 2, sm: 3 } }}><Stack spacing={3}>
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} sx={{ alignItems: { sm: 'center' }, justifyContent: 'space-between' }}>
      <Typography component="h2" variant="h6" sx={{ overflowWrap: 'anywhere' }}>{selected === null ? t('admin:providerConfig.title') : t('admin:providerConfig.edit', { provider: displayName(selected) })}</Typography>
      {selected === null && <Button variant="outlined" size="small" startIcon={<RefreshRounded />} aria-label={t('admin:providerConfig.reload')} onClick={() => { void query.refetch() }} sx={{ alignSelf: { xs: 'flex-start', sm: 'auto' }, flexShrink: 0 }}>{t('admin:providerConfig.refresh')}</Button>}
      {selected !== null && <Button variant="outlined" size="small" color="inherit" startIcon={<ArrowBackRounded />} disabled={busy} onClick={() => setSelected(null)} sx={{ alignSelf: { xs: 'flex-start', sm: 'auto' }, flexShrink: 0 }}>{t('admin:providerConfig.back')}</Button>}
    </Stack>
    {saved && <Alert severity="success" role="status">{t('admin:workspace.saved')}</Alert>}
    {selected === null && <Stack spacing={1.5}>{query.data.providers.map((provider) => <Box key={provider.id} sx={{ border: 1, borderColor: 'divider', borderRadius: 2, p: 2 }}>
      <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}>
      <ProviderIcon icon={provider.protocol === 'entra' ? 'microsoft' : provider.protocol === 'google' ? 'google' : provider.protocol === 'github' ? 'github' : 'key'} data={provider.icon_data} />
      <Stack spacing={0.5} sx={{ minWidth: 0, flex: 1 }}><Typography sx={{ fontWeight: 600, overflowWrap: 'anywhere' }}>{displayName(provider)}</Typography>
        {displayName(provider) !== typeName(provider.protocol) && <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>{typeName(provider.protocol)}</Typography>}
        <Chip size="small" variant="outlined" color={provider.enabled ? 'success' : 'default'} label={t(provider.enabled ? 'admin:providerConfig.active' : 'admin:providerConfig.inactive')} sx={{ alignSelf: 'flex-start' }} />
      </Stack>
      <Button variant="outlined" startIcon={<EditOutlined />} aria-label={t('admin:providerConfig.edit', { provider: displayName(provider) })} onClick={() => select(provider)} sx={{ flexShrink: 0 }}>{t('admin:providerConfig.editAction')}</Button>
      </Stack>
    </Box>)}</Stack>}
    {selected === null && <Box sx={{ borderTop: 1, borderColor: 'divider', pt: 3 }}><Stack spacing={2}>
      <Typography component="h3" variant="subtitle1" sx={{ fontWeight: 600 }}>{t('admin:providerConfig.add')}</Typography>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} sx={{ alignItems: { sm: 'flex-start' } }}>
      <TextField select size="small" sx={{ minWidth: { sm: 200 } }} label={t('admin:providerConfig.type')} value={kind} onChange={(event) => setKind(event.target.value as LoginProviderConfiguration['protocol'])}>
        {(['local', 'hub', 'entra', 'google', 'github', 'oidc'] as const).map((value) => <MenuItem key={value} value={value}>{typeName(value)}</MenuItem>)}
      </TextField>
      {kind === 'oidc' && <TextField size="small" label={t('admin:providerConfig.slug')} value={slug} onChange={(event) => setSlug(event.target.value)} />}
      <Button variant="contained" startIcon={<AddRounded />} disabled={!validId || exists || query.data.providers.length >= 8} onClick={() => select({ id: identifier, protocol: kind, enabled: true, rank: query.data.providers.length, config: {}, secret_present: false })} sx={{ minHeight: 40, flexShrink: 0 }}>{t('admin:providerConfig.add')}</Button>
      </Stack>
    </Stack></Box>}
    {stale && <Alert severity="warning">{t('admin:workspace.staleDraft')}<Button disabled={busy} onClick={() => {
      const current = query.data.providers.find((provider) => provider.id === selected?.id)
      if (current) select(current)
      else setSelected(null)
    }}>{t('admin:workspace.discardDraft')}</Button></Alert>}
    {selected !== null && <ProviderConfigurationForm key={`${selected.id}:${editorEpoch}`} provider={selected}
      onCancel={() => setSelected(null)}
      nameEditor={query.data.providers.some((provider) => provider.id === selected.id) ? <ProviderNameEditor key={`${selected.id}:name:${editorEpoch}`} id={selected.id} disabled={stale || busy} onBusyChange={setBusy} onSaved={(before, after) => {
      setSelectedRevision((current) => current === before ? after : current)
      cache.setQueryData<ProviderSettingsResponse>(['admin', 'login-providers'], (previous) => previous?.revision === before ? { ...previous, revision: after } : previous)
    }} /> : undefined}
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
  </Stack></CardContent></Card>
}
