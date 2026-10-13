import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import FormControlLabel from '@mui/material/FormControlLabel'
import Stack from '@mui/material/Stack'
import Switch from '@mui/material/Switch'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { getNotificationPreferences, saveNotificationPreferences } from '@/api/endpoints'
import type { NotificationPreferences } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'
import { useLanguage } from '@/stores/language'

function Editor({ data }: { data: NotificationPreferences }) {
  const { t } = useTranslation()
  const locale = useLanguage((state) => state.lang)
  const cache = useQueryClient()
  const [enabled, setEnabled] = useState(data.enabled)
  const [email, setEmail] = useState(data.email)
  const save = useMutation({ mutationFn: () => saveNotificationPreferences({ enabled, email, locale }),
    onSuccess: (fresh) => cache.setQueryData(['notifications'], fresh) })
  return <Stack spacing={2}>
    <Typography component="h2" variant="h6">{t('account:notifications.title')}</Typography>
    <Typography>{t('account:notifications.help', { days: data.reminder_days })}</Typography>
    {!data.mail_available && <Alert severity="info" role="note">{t('account:notifications.unavailable')}</Alert>}
    <FormControlLabel label={t('account:notifications.enabled')} control={<Switch checked={enabled} onChange={(_, next) => setEnabled(next)} disabled={save.isPending} />} />
    <TextField label={t('account:notifications.email')} type="email" value={email} onChange={(event) => setEmail(event.target.value)} disabled={save.isPending} slotProps={{ htmlInput: { maxLength: 254, autoComplete: 'email' } }} />
    {save.isError && <ErrorNotice error={save.error} />}
    {save.isSuccess && <Alert severity="success">{t('account:notifications.saved')}</Alert>}
    <Button onClick={() => save.mutate()} disabled={save.isPending || (enabled && !email.trim())}>{t('account:notifications.save')}</Button>
  </Stack>
}

export default function NotificationSettings() {
  const query = useQuery({ queryKey: ['notifications'], queryFn: getNotificationPreferences })
  if (query.isPending) return null
  if (query.isError) return <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
  return <Card><CardContent><Editor data={query.data} /></CardContent></Card>
}
