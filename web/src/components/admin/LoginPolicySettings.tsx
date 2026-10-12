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
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { getLoginPolicy, saveLoginPolicy, getAccountLoginPolicy, saveAccountLoginPolicy, unlockAccountSso, getLoginProviderSettings } from '@/api/endpoints'
import ErrorNotice from '@/components/ErrorNotice'

function GlobalEditor({ revision, initial }: { revision: number; initial: Record<string, boolean> }) {
  const { t } = useTranslation()
  const [policy, setPolicy] = useState(initial)
  const [busy, setBusy] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState<unknown>(null)
  async function save() {
    setBusy(true); setError(null)
    try { await saveLoginPolicy({ revision, policy }); setSaved(true) }
    catch (reason) { setError(reason) }
    finally { setBusy(false) }
  }
  return <Stack spacing={2}>
    <Typography component="h2" variant="h6">{t('admin:loginPolicy.title')}</Typography>
    {error !== null && <ErrorNotice error={error} />}
    {saved && <Alert severity="success">{t('admin:loginPolicy.saved')}</Alert>}
    {(['allow_multiple', 'lock_first_sso', 'block_conflicting_registration'] as const).map((key) => <FormControlLabel key={key} control={<Switch checked={policy[key]} disabled={busy || saved} onChange={(_, value) => setPolicy((previous) => ({ ...previous, [key]: value }))} />} label={t(`admin:loginPolicy.${key}`)} />)}
    <Typography variant="body2">{t('admin:loginPolicy.help')}</Typography>
    <Button disabled={busy || saved} onClick={() => { void save() }}>{t('admin:loginPolicy.save')}</Button>
  </Stack>
}

export default function LoginPolicySettings() {
  const query = useQuery({ queryKey: ['admin', 'login-policy'], queryFn: getLoginPolicy })
  return <Card><CardContent>{query.isError ? <ErrorNotice error={query.error} /> : query.data ? <GlobalEditor key={query.data.revision} revision={query.data.revision} initial={query.data.policy} /> : null}</CardContent></Card>
}

function AccountEditor({ id }: { id: string }) {
  const query = useQuery({ queryKey: ['admin', 'account-login-policy', id], queryFn: () => getAccountLoginPolicy(id) })
  const providers = useQuery({ queryKey: ['admin', 'login-providers'], queryFn: getLoginProviderSettings })
  if (query.isError) return <ErrorNotice error={query.error} />
  if (!query.data || !providers.data) return null
  return <AccountEditorForm key={query.data.revision} id={id} data={query.data} providers={providers.data.providers.map((provider) => provider.id)} />
}

function AccountEditorForm({ id, data, providers }: { id: string; data: Awaited<ReturnType<typeof getAccountLoginPolicy>>; providers: string[] }) {
  const { t } = useTranslation()
  const [multiple, setMultiple] = useState(data.policy.allow_multiple === null ? 'inherit' : String(data.policy.allow_multiple))
  const [restrict, setRestrict] = useState(data.policy.allowed_providers !== null)
  const [allowed, setAllowed] = useState(data.policy.allowed_providers ?? providers)
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState<unknown>(null)
  async function perform(unlock: boolean) {
    setBusy(true); setError(null)
    try {
      if (unlock) await unlockAccountSso(id, data.revision)
      else await saveAccountLoginPolicy(id, { revision: data.revision, policy: { allow_multiple: multiple === 'inherit' ? null : multiple === 'true', allowed_providers: restrict ? allowed : null } })
      setDone(true)
    } catch (reason) { setError(reason) }
    finally { setBusy(false) }
  }
  return <Stack spacing={2}>
    {error !== null && <ErrorNotice error={error} />}
    {done && <Alert severity="success">{t('admin:loginPolicy.saved')}</Alert>}
    <Typography>{t('admin:loginPolicy.locked', { provider: data.policy.sso_lock_provider ?? t('admin:loginPolicy.none') })}</Typography>
    {data.policy.sso_lock_provider && <><Typography variant="body2">{t('admin:loginPolicy.unlockHelp')}</Typography><Button disabled={busy || done} onClick={() => { void perform(true) }}>{t('admin:loginPolicy.unlock')}</Button></>}
    <TextField select label={t('admin:loginPolicy.allow_multiple')} value={multiple} disabled={busy || done} onChange={(event) => setMultiple(event.target.value)}>
      <MenuItem value="inherit">{t('admin:loginPolicy.inherit')}</MenuItem>
      <MenuItem value="true">{t('admin:loginPolicy.allow')}</MenuItem>
      <MenuItem value="false">{t('admin:loginPolicy.forbid')}</MenuItem>
    </TextField>
    <FormControlLabel control={<Switch checked={restrict} disabled={busy || done} onChange={(_, value) => setRestrict(value)} />} label={t('admin:loginPolicy.restrict')} />
    {restrict && providers.map((provider) => <FormControlLabel key={provider} label={provider} control={<Switch checked={allowed.includes(provider)} disabled={busy || done} onChange={(_, checked) => setAllowed((current) => checked ? [...current, provider] : current.filter((item) => item !== provider))} />} />)}
    <Button disabled={busy || done} onClick={() => { void perform(false) }}>{t('admin:loginPolicy.save')}</Button>
  </Stack>
}

export function AccountLoginPolicy({ id }: { id: string }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  return <><Button onClick={() => setOpen(true)}>{t('admin:loginPolicy.title')}</Button><Dialog open={open} onClose={() => setOpen(false)} fullWidth><DialogTitle>{t('admin:loginPolicy.title')}</DialogTitle><DialogContent>{open && <AccountEditor id={id} />}</DialogContent></Dialog></>
}
