import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { saveBrowserSession } from '@/api/endpoints'
import { ApiError } from '@/api/errors'
import type { AdminSettingsResponse } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'
import { keys } from '@/query/keys'

export default function BrowserSessionSettings({ data }: { data: AdminSettingsResponse }) {
  const { t } = useTranslation()
  const cache = useQueryClient()
  const [minutes, setMinutes] = useState(String(data.browser_session.ttl_seconds / 60))
  const seconds = Number(minutes) * 60
  const valid = minutes.trim() !== '' && Number.isInteger(seconds) && seconds >= 60 && seconds <= 2592000
  const save = useMutation({
    mutationFn: () => saveBrowserSession(data.revision, seconds),
    onSuccess: (fresh) => {
      cache.setQueryData(keys.adminSettings, fresh)
      void cache.invalidateQueries({ queryKey: keys.adminAudit })
    },
  })
  const conflict = save.error instanceof ApiError && save.error.code === 'settings_conflict'
  return <Card><CardContent><Stack spacing={2}>
    <Typography component="h2" variant="h6">{t('admin:browserSession.title')}</Typography>
    <Typography>{t('admin:browserSession.help')}</Typography>
    <TextField type="number" label={t('admin:browserSession.minutes')} value={minutes} disabled={save.isPending}
      onChange={(event) => setMinutes(event.target.value)} slotProps={{ htmlInput: { min: 1, max: 43200, step: 'any' } }} />
    <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }}>
      {[15, 60, 1440, 10080, 43200].map((value) => <Button key={value} disabled={save.isPending} onClick={() => setMinutes(String(value))}>{t(`admin:browserSession.presets.${value}`)}</Button>)}
    </Stack>
    {save.isError && <ErrorNotice error={save.error} />}
    {conflict && <Button onClick={() => void cache.invalidateQueries({ queryKey: keys.adminSettings })}>{t('admin:settings.reload')}</Button>}
    {save.isSuccess && <Alert severity="success">{t('admin:browserSession.saved')}</Alert>}
    <Button disabled={!valid || save.isPending || conflict || seconds === data.browser_session.ttl_seconds} onClick={() => save.mutate()}>{t('admin:browserSession.save')}</Button>
  </Stack></CardContent></Card>
}
