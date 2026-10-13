import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Dialog from '@mui/material/Dialog'
import DialogContent from '@mui/material/DialogContent'
import DialogTitle from '@mui/material/DialogTitle'
import FormControlLabel from '@mui/material/FormControlLabel'
import MenuItem from '@mui/material/MenuItem'
import Stack from '@mui/material/Stack'
import Switch from '@mui/material/Switch'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { getLoginPolicy, saveLoginPolicy, getAccountLoginPolicy, saveAccountLoginPolicy, unlockAccountSso, getLoginProviderSettings } from '@/api/endpoints'
import ErrorNotice from '@/components/ErrorNotice'
import { ApiError } from '@/api/errors'
import DraftStatus from './DraftStatus'
import { useSettingsDraft } from './useSettingsDraft'

function GlobalEditor({ revision, initial }: { revision: number; initial: Record<string, boolean> }) {
  const { t } = useTranslation()
  const cache = useQueryClient()
  const draft = useSettingsDraft(revision, initial)
  const { value: policy, setValue: setPolicy } = draft
  const [busy, setBusy] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState<unknown>(null)
  async function save() {
    setBusy(true); setError(null)
    try {
      const fresh = await saveLoginPolicy({ revision: draft.revision, policy })
      draft.accept(fresh.revision, fresh.policy)
      cache.setQueryData(['admin', 'login-policy'], fresh)
      setSaved(true)
    }
    catch (reason) {
      setError(reason)
      if (reason instanceof ApiError && reason.code === 'settings_conflict') void cache.invalidateQueries({ queryKey: ['admin', 'login-policy'] })
    }
    finally { setBusy(false) }
  }
  return <Stack spacing={2}>
    <Typography component="h2" variant="h6">{t('admin:loginPolicy.title')}</Typography>
    {error !== null && <ErrorNotice error={error} />}
    {saved && !draft.dirty && <Alert severity="success">{t('admin:loginPolicy.saved')}</Alert>}
    <DraftStatus {...draft} reset={() => { draft.reset(); setError(null) }} />
    {(['allow_multiple', 'lock_first_sso', 'block_conflicting_registration'] as const).map((key) => <FormControlLabel key={key} control={<Switch checked={policy[key]} disabled={busy || saved} onChange={(_, value) => setPolicy((previous) => ({ ...previous, [key]: value }))} />} label={t(`admin:loginPolicy.${key}`)} />)}
    <Typography variant="body2">{t('admin:loginPolicy.help')}</Typography>
    <Button variant="contained" disabled={busy || saved || draft.stale || !draft.dirty} onClick={() => { void save() }}>{t('admin:loginPolicy.save')}</Button>
  </Stack>
}

export default function LoginPolicySettings() {
  const query = useQuery({ queryKey: ['admin', 'login-policy'], queryFn: getLoginPolicy })
  return <Card><CardContent>{query.isError ? <ErrorNotice error={query.error} onRetry={() => void query.refetch()} /> : query.data ? <GlobalEditor revision={query.data.revision} initial={query.data.policy} /> : null}</CardContent></Card>
}

function AccountEditor({ id, enabled = true }: { id: string; enabled?: boolean }) {
  const { t } = useTranslation()
  const query = useQuery({ queryKey: ['admin', 'account-login-policy', id], queryFn: () => getAccountLoginPolicy(id), enabled })
  const providers = useQuery({ queryKey: ['admin', 'login-providers'], queryFn: getLoginProviderSettings, enabled })
  if (query.isError) return <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
  if (providers.isError) return <ErrorNotice error={providers.error} onRetry={() => void providers.refetch()} />
  if (!query.data || !providers.data) return enabled ? <Typography color="text.secondary">{t('common:states.loading')}</Typography> : null
  return <AccountEditorForm id={id} data={query.data} providers={providers.data.providers.map((provider) => provider.id)} />
}

function AccountEditorForm({ id, data, providers }: { id: string; data: Awaited<ReturnType<typeof getAccountLoginPolicy>>; providers: string[] }) {
  const { t } = useTranslation()
  const cache = useQueryClient()
  const draft = useSettingsDraft(data.revision, { allow_multiple: data.policy.allow_multiple, allowed_providers: data.policy.allowed_providers })
  const multiple = draft.value.allow_multiple === null ? 'inherit' : String(draft.value.allow_multiple)
  const restrict = draft.value.allowed_providers !== null
  const allowed = draft.value.allowed_providers ?? providers
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState<unknown>(null)
  async function perform(unlock: boolean) {
    if (busy || done || draft.stale) return
    setBusy(true); setError(null)
    try {
      const fresh = unlock ? await unlockAccountSso(id, draft.revision)
        : await saveAccountLoginPolicy(id, { revision: draft.revision, policy: draft.value })
      draft.accept(fresh.revision, { allow_multiple: fresh.policy.allow_multiple, allowed_providers: fresh.policy.allowed_providers })
      cache.setQueryData(['admin', 'account-login-policy', id], fresh)
      setDone(true)
    } catch (reason) {
      setError(reason)
      if (reason instanceof ApiError && reason.code === 'settings_conflict') void cache.invalidateQueries({ queryKey: ['admin', 'account-login-policy', id] })
    }
    finally { setBusy(false) }
  }
  return <Stack spacing={2}>
    {error !== null && <ErrorNotice error={error} />}
    {done && <Alert severity="success">{t('admin:loginPolicy.saved')}</Alert>}
    <DraftStatus {...draft} reset={() => { draft.reset(); setError(null) }} />
    <Typography>{t('admin:loginPolicy.locked', { provider: data.policy.sso_lock_provider ?? t('admin:loginPolicy.none') })}</Typography>
    {data.policy.sso_lock_provider && <><Typography variant="body2">{t('admin:loginPolicy.unlockHelp')}</Typography><Button disabled={busy || done || draft.stale} onClick={() => { void perform(true) }}>{t('admin:loginPolicy.unlock')}</Button></>}
    <TextField select label={t('admin:loginPolicy.allow_multiple')} value={multiple} disabled={busy || done} onChange={(event) => draft.setValue((previous) => ({ ...previous, allow_multiple: event.target.value === 'inherit' ? null : event.target.value === 'true' }))}>
      <MenuItem value="inherit">{t('admin:loginPolicy.inherit')}</MenuItem>
      <MenuItem value="true">{t('admin:loginPolicy.allow')}</MenuItem>
      <MenuItem value="false">{t('admin:loginPolicy.forbid')}</MenuItem>
    </TextField>
    <FormControlLabel control={<Switch checked={restrict} disabled={busy || done} onChange={(_, value) => draft.setValue((previous) => ({ ...previous, allowed_providers: value ? providers : null }))} />} label={t('admin:loginPolicy.restrict')} />
    {restrict && providers.map((provider) => <FormControlLabel key={provider} label={provider} control={<Switch checked={allowed.includes(provider)} disabled={busy || done} onChange={(_, checked) => draft.setValue((previous) => ({ ...previous, allowed_providers: checked ? [...allowed, provider] : allowed.filter((item) => item !== provider) }))} />} />)}
    <Button variant="contained" disabled={busy || done || draft.stale || !draft.dirty} onClick={() => { void perform(false) }}>{t('admin:loginPolicy.save')}</Button>
  </Stack>
}

export function AccountLoginPolicy({ id, inline = false, active = true }: { id: string; inline?: boolean; active?: boolean }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  if (inline) return <Card><CardContent><Typography component="h3" variant="h3" sx={{ mb: 2 }}>{t('admin:loginPolicy.title')}</Typography><AccountEditor id={id} enabled={active} /></CardContent></Card>
  return <><Button onClick={() => setOpen(true)}>{t('admin:loginPolicy.title')}</Button><Dialog open={open} onClose={() => setOpen(false)} fullWidth><DialogTitle>{t('admin:loginPolicy.title')}</DialogTitle><DialogContent>{open && <AccountEditor id={id} />}</DialogContent></Dialog></>
}
