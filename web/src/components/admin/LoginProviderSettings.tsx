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
import { getLoginProviderSettings, saveLoginProvider } from '@/api/endpoints'
import type { LoginProviderConfiguration } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'
import { keys } from '@/query/keys'
import LocalAccountCreate from './LocalAccountCreate'
import ProviderConfigurationForm, { type EditableProvider } from './ProviderConfigurationForm'

export default function LoginProviderSettings() {
  const { t } = useTranslation()
  const cache = useQueryClient()
  const query = useQuery({ queryKey: ['admin', 'login-providers'], queryFn: getLoginProviderSettings })
  const [selected, setSelected] = useState<EditableProvider | null>(null)
  const [kind, setKind] = useState<LoginProviderConfiguration['protocol']>('google')
  const [slug, setSlug] = useState('')
  if (query.isError) return <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
  if (!query.data) return null
  const identifier = kind === 'oidc' ? `oidc:${slug}` : kind
  const validId = kind !== 'oidc' || /^[a-z][a-z0-9_-]{0,31}$/.test(slug)
  const exists = query.data.providers.some((provider) => provider.id === identifier)
  return <Card><CardContent><Stack spacing={2}>
    <Typography component="h2" variant="h6">{t('admin:providerConfig.title')}</Typography>
    {query.data.providers.map((provider) => <Stack key={provider.id} direction="row" spacing={2} sx={{ alignItems: 'center' }}>
      <Typography>{provider.id}</Typography>
      <Button onClick={() => setSelected(provider)}>{t('admin:providerConfig.edit', { provider: provider.id })}</Button>
    </Stack>)}
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
      <TextField select label={t('admin:providerConfig.type')} value={kind} onChange={(event) => setKind(event.target.value as LoginProviderConfiguration['protocol'])}>
        {(['local', 'entra', 'google', 'github', 'oidc'] as const).map((value) => <MenuItem key={value} value={value}>{value === 'local' ? t('admin:localAccount.name') : value === 'entra' ? 'Microsoft Entra' : value === 'oidc' ? 'OIDC' : value === 'github' ? 'GitHub' : 'Google'}</MenuItem>)}
      </TextField>
      {kind === 'oidc' && <TextField label={t('admin:providerConfig.slug')} value={slug} onChange={(event) => setSlug(event.target.value)} />}
      <Button disabled={!validId || exists || query.data.providers.length >= 8} onClick={() => setSelected({ id: identifier, protocol: kind, enabled: true, rank: query.data.providers.length, config: {}, secret_present: false })}>{t('admin:providerConfig.add')}</Button>
    </Stack>
    {selected !== null && <ProviderConfigurationForm key={`${selected.id}:${query.data.revision}`} provider={selected}
      callbackUri={`${query.data.public_base_url}/auth/callback/${selected.id.replace(':', '/')}`}
      onSave={async (values) => {
        const fresh = await saveLoginProvider(selected.id, { ...values, revision: query.data.revision })
        cache.setQueryData(['admin', 'login-providers'], fresh)
        setSelected(null)
        for (const key of [keys.adminSettings, keys.providers, keys.me, keys.adminAudit]) await cache.invalidateQueries({ queryKey: key })
      }} />}
    {selected !== null && <Button onClick={() => setSelected(null)}>{t('admin:settings.cancel')}</Button>}
    {query.data.providers.some((provider) => provider.id === 'local' && provider.enabled) && <LocalAccountCreate />}
    <Button onClick={() => { setSelected(null); void query.refetch() }}>{t('admin:providerConfig.reload')}</Button>
  </Stack></CardContent></Card>
}
