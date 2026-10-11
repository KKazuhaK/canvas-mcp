import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Chip from '@mui/material/Chip'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogTitle from '@mui/material/DialogTitle'
import FormControlLabel from '@mui/material/FormControlLabel'
import Stack from '@mui/material/Stack'
import Switch from '@mui/material/Switch'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { checkSchool, getAdminSettings, saveDirectorySearch, saveFeaturedSchools, saveProviderNames } from '@/api/endpoints'
import { ApiError } from '@/api/errors'
import type { AdminSettingsResponse } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'
import { keys } from '@/query/keys'
import { PageSkeleton } from '../StateViews'

function Editor({ data, reload }: { data: AdminSettingsResponse; reload: () => void }) {
  const { t } = useTranslation()
  const cache = useQueryClient()
  const providers = data.sign_in_methods.filter((p) => p.configured)
  const [names, setNames] = useState(() => Object.fromEntries(providers.map((p) => [p.id, p.display_name ?? ''])))
  const [schools, setSchools] = useState(data.schools.featured)
  const [enabled, setEnabled] = useState(data.schools.directory_search)
  const [host, setHost] = useState('')
  const [name, setName] = useState('')
  const [affected, setAffected] = useState<Record<string, number> | null>(null)
  const save = useMutation({
    mutationFn: (operation: () => Promise<AdminSettingsResponse>) => operation(),
    onSuccess: (fresh) => {
      cache.setQueryData(keys.adminSettings, fresh)
      void cache.invalidateQueries({ queryKey: keys.providers })
      void cache.invalidateQueries({ queryKey: keys.schools })
      void cache.invalidateQueries({ queryKey: keys.adminAudit })
    },
    onError: (error) => {
      if (error instanceof ApiError && error.code === 'confirmation_required' && typeof error.params.affected === 'object') setAffected(error.params.affected)
    },
  })
  const check = useMutation({ mutationFn: () => checkSchool(host), onSuccess: (result) => {
    if (result.valid && result.suggested_name) setName(result.suggested_name)
  } })
  const busy = save.isPending
  const conflicted = save.error instanceof ApiError && save.error.code === 'settings_conflict'
  const submitSchools = (confirmed: string[] = []) => save.mutate(() => saveFeaturedSchools({ revision: data.revision, featured: schools.map((s) => ({ host: s.host, display_name: s.display_name })), confirm_affected: confirmed }))
  function move(index: number, direction: number) {
    const next = [...schools]
    ;[next[index], next[index + direction]] = [next[index + direction], next[index]]
    setSchools(next)
  }
  return <Stack spacing={3}>
    {data.schools.warnings.includes('no_schools_offered') && <Alert severity="warning">{t('admin:settings.noSchools')}</Alert>}
    {save.isError && <ErrorNotice error={save.error} />}
    {conflicted && <Button onClick={reload}>{t('admin:settings.reload')}</Button>}
    <Card><CardContent><Stack spacing={2}>
      <Typography variant="h6" component="h2">{t('admin:settings.providers')}</Typography>
      {providers.map((p) => <Stack key={p.id} direction={{ xs: 'column', sm: 'row' }} spacing={1}>
        <TextField fullWidth label={p.default_name} value={names[p.id]} placeholder={p.default_name} disabled={busy} slotProps={{ htmlInput: { maxLength: 40 } }} onChange={(e) => setNames({ ...names, [p.id]: e.target.value })} />
        <Button disabled={busy} onClick={() => setNames({ ...names, [p.id]: '' })}>{t('admin:settings.reset')}</Button>
      </Stack>)}
      <Button disabled={busy || conflicted} onClick={() => save.mutate(() => saveProviderNames(data.revision, names))}>{t('admin:settings.saveNames')}</Button>
    </Stack></CardContent></Card>
    <Card><CardContent><Stack spacing={2}>
      <Typography variant="h6" component="h2">{t('admin:settings.featured')}</Typography>
      {schools.map((school, index) => <Box key={school.host} sx={{ border: 1, borderColor: 'divider', p: 2 }}>
        <Stack spacing={1}>
          <Typography sx={{ overflowWrap: 'anywhere' }}>{school.host}</Typography>
          <TextField label={t('admin:settings.name')} value={school.display_name} disabled={busy} onChange={(e) => setSchools(schools.map((s) => s.host === school.host ? { ...s, display_name: e.target.value } : s))} slotProps={{ htmlInput: { maxLength: 120 } }} />
          <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }}>
            <Chip label={t('admin:settings.enrollments', { count: school.enrollments })} />
            {school.allow_private && <Chip label={t('admin:settings.private')} color="warning" />}
          </Stack>
          <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }}>
            <Button disabled={busy || index === 0} onClick={() => move(index, -1)} aria-label={t('admin:settings.up', { host: school.host })}>↑</Button>
            <Button disabled={busy || index === schools.length - 1} onClick={() => move(index, 1)} aria-label={t('admin:settings.down', { host: school.host })}>↓</Button>
            <Button disabled={busy} onClick={() => setSchools(schools.filter((s) => s.host !== school.host))}>{t('admin:settings.remove', { host: school.host })}</Button>
          </Stack>
        </Stack>
      </Box>)}
      <TextField label={t('admin:settings.host')} value={host} disabled={busy} onChange={(e) => { setHost(e.target.value); check.reset() }} />
      <TextField label={t('admin:settings.name')} value={name} disabled={busy} onChange={(e) => setName(e.target.value)} />
      {check.isError && <ErrorNotice error={check.error} />}
      {check.data && (check.data.valid ? <Alert severity="success">{t('admin:settings.valid')} {check.data.in_directory === false ? t('admin:settings.notDirectory') : check.data.in_directory === null ? t('admin:settings.directoryUnknown') : ''}</Alert> : <ErrorNotice error={new ApiError(422, check.data.reason ?? 'school_invalid')} />)}
      <Stack direction="row" spacing={1}>
        <Button disabled={!host.trim() || check.isPending || busy} onClick={() => check.mutate()}>{t('admin:settings.check')}</Button>
        <Button disabled={!host.trim() || schools.length >= 50 || busy || schools.some((s) => s.host === host.trim().toLowerCase())} onClick={() => { setSchools([...schools, { host: host.trim().toLowerCase(), display_name: name, rank: schools.length + 1, enrollments: 0, allow_private: false }]); setHost(''); setName(''); check.reset() }}>{t('admin:settings.add')}</Button>
      </Stack>
      <Button disabled={busy || conflicted} onClick={() => submitSchools()}>{t('admin:settings.saveSchools')}</Button>
    </Stack></CardContent></Card>
    <Card><CardContent><Stack spacing={2}>
      <Typography variant="h6" component="h2">{t('admin:settings.directory')}</Typography>
      <FormControlLabel control={<Switch checked={enabled} disabled={busy} onChange={(_, value) => setEnabled(value)} />} label={t('admin:settings.directory')} />
      <Typography>{t('admin:settings.directoryHelp')}</Typography>
      <Button disabled={busy || conflicted} onClick={() => save.mutate(() => saveDirectorySearch(data.revision, enabled))}>{t('admin:settings.saveSearch')}</Button>
    </Stack></CardContent></Card>
    <Dialog open={affected !== null} onClose={() => { if (!busy) setAffected(null) }}>
      <DialogTitle>{t('admin:settings.confirmTitle')}</DialogTitle>
      <DialogContent><Typography>{t('admin:settings.confirmBody')}</Typography>{Object.entries(affected ?? {}).map(([school, count]) => <Typography key={school}>{school}: {t('admin:settings.enrollments', { count })}</Typography>)}</DialogContent>
      <DialogActions><Button disabled={busy} onClick={() => setAffected(null)}>{t('admin:settings.cancel')}</Button><Button disabled={busy} onClick={() => submitSchools(Object.keys(affected ?? {}))}>{t('admin:settings.confirm')}</Button></DialogActions>
    </Dialog>
  </Stack>
}

export default function AdminSettingsView() {
  const { t } = useTranslation()
  const query = useQuery({ queryKey: keys.adminSettings, queryFn: getAdminSettings })
  if (query.isPending) return <PageSkeleton />
  if (query.isError) return <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
  return <Stack spacing={3}><Typography component="h1" variant="h4">{t('admin:settings.title')}</Typography><Editor key={query.data.revision} data={query.data} reload={() => void query.refetch()} /></Stack>
}
