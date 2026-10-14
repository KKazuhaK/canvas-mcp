import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import FormControlLabel from '@mui/material/FormControlLabel'
import MenuItem from '@mui/material/MenuItem'
import Stack from '@mui/material/Stack'
import Switch from '@mui/material/Switch'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useState, type FormEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import ErrorNotice from '@/components/ErrorNotice'
import Alert from '@mui/material/Alert'
import ProviderIcon from '@/components/ProviderIcon'
import SaveOutlined from '@mui/icons-material/SaveOutlined'
import UploadOutlined from '@mui/icons-material/UploadOutlined'
import RestartAlt from '@mui/icons-material/RestartAlt'

function FormSection({ title, children }: { title: string; children: ReactNode }) {
  return <Box component="section" sx={{ border: 1, borderColor: 'divider', borderRadius: 2, p: { xs: 2, sm: 3 } }}>
    <Stack spacing={2.5}>
      <Typography component="h3" variant="subtitle1" sx={{ fontWeight: 600 }}>{title}</Typography>
      {children}
    </Stack>
  </Box>
}

export interface EditableProvider {
  id: string
  protocol: 'entra' | 'google' | 'github' | 'oidc' | 'local'
  enabled: boolean
  rank: number
  config: Record<string, string | string[] | boolean>
  secret_present: boolean
  auto_link_email?: boolean
  icon_data?: string | null
}

export interface ProviderSave {
  config: EditableProvider['config']
  enabled: boolean
  rank: number
  client_secret?: string
  auto_link_email?: boolean
  icon_data?: string | null
}

export default function ProviderConfigurationForm({ provider, callbackUri, onSave, installation = false, disabled = false, onBusyChange, nameEditor, onCancel }: {
  provider: EditableProvider
  callbackUri: string
  onSave: (values: ProviderSave) => Promise<void>
  installation?: boolean
  disabled?: boolean
  onBusyChange?: (busy: boolean) => void
  nameEditor?: ReactNode
  onCancel?: () => void
}) {
  const { t } = useTranslation()
  const [config, setConfig] = useState(provider.config)
  const [secret, setSecret] = useState('')
  const [enabled, setEnabled] = useState(provider.enabled)
  const [rank, setRank] = useState(provider.rank)
  const [autoLinkEmail, setAutoLinkEmail] = useState(provider.auto_link_email ?? false)
  const [iconData, setIconData] = useState(provider.icon_data ?? null)
  const [iconChanged, setIconChanged] = useState(false)
  const [iconError, setIconError] = useState(false)
  const [iconReading, setIconReading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const dirty = secret.length > 0 || iconChanged || enabled !== provider.enabled || rank !== provider.rank
    || autoLinkEmail !== (provider.auto_link_email ?? false) || JSON.stringify(config) !== JSON.stringify(provider.config)
  function text(key: string, fallback = '') {
    const value = config[key]
    return typeof value === 'string' ? value : fallback
  }
  function change(key: string, value: string | boolean | string[]) {
    setConfig((current) => ({ ...current, [key]: value }))
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (disabled || iconReading || busy) return
    setBusy(true)
    onBusyChange?.(true)
    setError(null)
    const values: ProviderSave = { config, enabled, rank }
    if (!installation && provider.protocol !== 'local') values.auto_link_email = autoLinkEmail
    if (!installation && iconChanged) values.icon_data = iconData
    if (secret.length > 0) values.client_secret = secret
    try {
      await onSave(values)
      setSecret('')
    } catch (reason) {
      setError(reason)
    } finally {
      setBusy(false)
      onBusyChange?.(false)
    }
  }
  return <Box component="form" onSubmit={(event) => { void submit(event) }}>
    <Stack spacing={3}>
      {error !== null && <ErrorNotice error={error} />}
      {!installation && dirty ? <Typography role="status" color="text.secondary">{t('admin:workspace.unsaved')}</Typography> : null}
      {!installation && <FormSection title={t('admin:providerConfig.appearance')}>
        {nameEditor}
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} sx={{ alignItems: { xs: 'flex-start', sm: 'center' } }}>
          <ProviderIcon icon={provider.protocol === 'entra' ? 'microsoft' : provider.protocol} data={iconData} />
          <Button component="label" variant="outlined" startIcon={<UploadOutlined />} disabled={busy || iconReading}>{t('admin:providerConfig.icon')}
            <input type="file" accept="image/png" hidden disabled={busy || iconReading} aria-label={t('admin:providerConfig.icon')} onChange={(event) => {
              const file = event.target.files?.[0]
              event.target.value = ''
              if (!file) return
              if (file.type !== 'image/png' || file.size > 65536) { setIconError(true); return }
              setIconReading(true)
              const reader = new FileReader()
              reader.onload = () => { if (typeof reader.result === 'string') { setIconData(reader.result); setIconChanged(true); setIconError(false) } }
              reader.onerror = () => setIconError(true)
              reader.onloadend = () => setIconReading(false)
              reader.readAsDataURL(file)
            }} />
          </Button>
          <Button variant="outlined" color="inherit" startIcon={<RestartAlt />} disabled={busy || iconReading} onClick={() => { setIconData(null); setIconChanged(true); setIconError(false) }}>{t('admin:providerConfig.resetIcon')}</Button>
        </Stack>
        {iconError ? <Alert severity="error">{t('admin:providerConfig.iconHelp')}</Alert> : <Typography variant="caption">{t('admin:providerConfig.iconHelp')}</Typography>}
        <TextField type="number" sx={{ maxWidth: { sm: 240 } }} label={t('admin:providerConfig.position')} value={rank + 1} disabled={busy} slotProps={{ htmlInput: { min: 1, max: 8, step: 1 } }} onChange={(event) => setRank(Number(event.target.value) - 1)} />
      </FormSection>}
      {provider.protocol !== 'local' && <FormSection title={t('admin:providerConfig.connection')}>
        <TextField label={t('admin:providerConfig.callback')} value={callbackUri} slotProps={{ input: { readOnly: true } }} helperText={t('admin:providerConfig.callbackHelp')} />
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
          {provider.protocol === 'entra' && <TextField fullWidth required label={t('admin:providerConfig.tenant')} value={text('tenant_id')} disabled={busy} onChange={(event) => change('tenant_id', event.target.value)} />}
          {provider.protocol === 'oidc' && <TextField fullWidth required type="url" label={t('admin:providerConfig.issuer')} value={text('issuer')} disabled={busy} onChange={(event) => change('issuer', event.target.value)} />}
          <TextField fullWidth required label={t('admin:providerConfig.clientId')} value={text('client_id')} disabled={busy} onChange={(event) => change('client_id', event.target.value)} />
        </Stack>
        <TextField required={!provider.secret_present} type="password" autoComplete="new-password" label={t('admin:providerConfig.secret')} value={secret} disabled={busy} onChange={(event) => setSecret(event.target.value)} slotProps={{ htmlInput: { minLength: 16, maxLength: 4096 } }} helperText={t(provider.secret_present ? 'admin:providerConfig.keepSecret' : 'admin:providerConfig.newSecret')} />
        {provider.protocol === 'entra' && <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
          <TextField fullWidth required label={t('admin:providerConfig.userRole')} value={text('required_role', 'Canvas.User')} disabled={busy} onChange={(event) => change('required_role', event.target.value)} />
          <TextField fullWidth required label={t('admin:providerConfig.ownerRole')} value={text('owner_role', 'Canvas.Owner')} disabled={busy} onChange={(event) => change('owner_role', event.target.value)} />
        </Stack>}
        {provider.protocol === 'oidc' && <>
          <TextField required label={t('admin:providerConfig.scopes')} value={Array.isArray(config.scopes) ? config.scopes.join(' ') : 'openid email profile'} disabled={busy} onChange={(event) => change('scopes', event.target.value.split(/\s+/).filter(Boolean))} />
          <TextField select label={t('admin:providerConfig.tokenAuth')} value={text('token_auth_method')} disabled={busy} onChange={(event) => {
            if (event.target.value) change('token_auth_method', event.target.value)
            else setConfig((current) => Object.fromEntries(Object.entries(current).filter(([key]) => key !== 'token_auth_method')))
          }}>
            <MenuItem value="">{t('admin:providerConfig.discovery')}</MenuItem>
            <MenuItem value="client_secret_basic">client_secret_basic</MenuItem>
            <MenuItem value="client_secret_post">client_secret_post</MenuItem>
          </TextField>
          <FormControlLabel control={<Switch checked={config.userinfo === true} disabled={busy} onChange={(_, value) => change('userinfo', value)} />} label={t('admin:providerConfig.userinfo')} />
        </>}
      </FormSection>}
      {!installation && <FormSection title={t('admin:providerConfig.rules')}>
        <FormControlLabel control={<Switch checked={enabled} disabled={busy} onChange={(_, value) => setEnabled(value)} />} label={t('admin:providerConfig.enabled')} />
        {provider.protocol !== 'local' && <FormControlLabel control={<Switch checked={autoLinkEmail} disabled={busy} onChange={(_, value) => setAutoLinkEmail(value)} />} label={t('admin:providerConfig.autoLinkEmail')} />}
      </FormSection>}
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ borderTop: installation ? 0 : 1, borderColor: 'divider', pt: installation ? 0 : 2.5 }}>
        <Button type="submit" variant="contained" startIcon={!installation && <SaveOutlined />} disabled={busy || disabled || iconReading}>{t(installation ? 'admin:providerConfig.initialize' : 'admin:providerConfig.save')}</Button>
        {onCancel && <Button variant="outlined" color="inherit" disabled={busy || iconReading} onClick={onCancel}>{t('admin:settings.cancel')}</Button>}
      </Stack>
    </Stack>
  </Box>
}
