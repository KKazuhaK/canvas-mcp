import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import FormControlLabel from '@mui/material/FormControlLabel'
import MenuItem from '@mui/material/MenuItem'
import Stack from '@mui/material/Stack'
import Switch from '@mui/material/Switch'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { getMailSettings, saveMailSettings, testMailSettings } from '@/api/endpoints'
import type { MailSettingsResponse } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'
import { keys } from '@/query/keys'

function Editor({ data }: { data: MailSettingsResponse }) {
  const { t } = useTranslation()
  const cache = useQueryClient()
  const [config, setConfig] = useState(data.config)
  const probe = useMutation({ mutationFn: testMailSettings })
  const [password, setPassword] = useState('')
  const save = useMutation({ mutationFn: () => saveMailSettings({ revision: data.revision, config, password: password || null }),
    onSuccess: (fresh) => {
      cache.setQueryData(['mailSettings'], fresh)
      void cache.invalidateQueries({ queryKey: keys.adminSettings })
      void cache.invalidateQueries({ queryKey: keys.adminAudit })
      void cache.invalidateQueries({ queryKey: ['notifications'] })
    }, onSettled: () => setPassword('') })
  return <Stack spacing={2}>
    <Typography component="h2" variant="h6">{t('admin:mail.title')}</Typography>
    <Typography>{t('admin:mail.help')}</Typography>
    <FormControlLabel label={t('admin:mail.enabled')} control={<Switch checked={config.enabled} disabled={save.isPending} onChange={(_, value) => setConfig({ ...config, enabled: value })} />} />
    {(['host', 'username', 'from_email'] as const).map((key) => <TextField key={key} label={t(`admin:mail.${key}`)} value={config[key]} disabled={save.isPending} onChange={(event) => setConfig({ ...config, [key]: event.target.value })} slotProps={{ htmlInput: { maxLength: 254 } }} />)}
    <TextField label={t('admin:mail.port')} type="number" value={config.port} disabled={save.isPending} onChange={(event) => setConfig({ ...config, port: Number(event.target.value) })} slotProps={{ htmlInput: { min: 1, max: 65535 } }} />
    <TextField label={t('admin:mail.security')} select value={config.security} disabled={save.isPending} onChange={(event) => setConfig({ ...config, security: event.target.value as 'starttls' | 'tls' })}><MenuItem value="starttls">STARTTLS</MenuItem><MenuItem value="tls">TLS</MenuItem></TextField>
    <TextField label={t('admin:mail.password')} type="password" value={password} disabled={save.isPending} onChange={(event) => setPassword(event.target.value)} helperText={t(data.secret_present ? 'admin:mail.secretSaved' : 'admin:mail.secretEmpty')} slotProps={{ htmlInput: { autoComplete: 'new-password', maxLength: 1024 } }} />
    <TextField label={t('admin:mail.days')} type="number" value={config.reminder_days} disabled={save.isPending} onChange={(event) => setConfig({ ...config, reminder_days: Number(event.target.value) })} slotProps={{ htmlInput: { min: 1, max: 90 } }} />
    {probe.isError && <ErrorNotice error={probe.error} />}
    {probe.isSuccess && <Alert severity="success">{t('admin:mail.testSuccess')}</Alert>}
    <Button disabled={probe.isPending || save.isPending || !data.config.enabled} onClick={() => probe.mutate()}>{t('admin:mail.test')}</Button>
    {save.isError && <ErrorNotice error={save.error} />}
    {save.isSuccess && <Alert severity="success">{t('admin:mail.saved')}</Alert>}
    <Button disabled={save.isPending || !Number.isInteger(config.port) || !Number.isInteger(config.reminder_days) || config.reminder_days < 1 || config.reminder_days > 90 || (config.enabled && (!config.host || !config.from_email))} onClick={() => save.mutate()}>{t('admin:mail.save')}</Button>
  </Stack>
}

export default function MailSettingsPanel() {
  const query = useQuery({ queryKey: ['mailSettings'], queryFn: getMailSettings })
  if (query.isPending) return null
  if (query.isError) return <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
  return <Card><CardContent><Editor key={query.data.revision} data={query.data} /></CardContent></Card>
}
