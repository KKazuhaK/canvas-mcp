import Alert from '@mui/material/Alert'
import BrowserSessionSettings from '@/components/admin/BrowserSessionSettings'
import MailSettingsPanel from '@/components/admin/MailSettingsPanel'
import LoginPolicySettings from '@/components/admin/LoginPolicySettings'
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
import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { checkSchool, getAdminSettings, saveDirectorySearch, saveFeaturedSchools } from '@/api/endpoints'
import { ApiError } from '@/api/errors'
import type { AdminSettingsResponse } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'
import LoginProviderSettings from '@/components/admin/LoginProviderSettings'
import SiteAddressSettings from '@/components/admin/SiteAddressSettings'
import DraftStatus from '@/components/admin/DraftStatus'
import SettingsTopics, { useSettingsTopic, type SettingsTopic } from '@/components/admin/SettingsTopics'
import { useSettingsDraft } from '@/components/admin/useSettingsDraft'
import PageHeader from '@/components/PageHeader'
import { Link as RouterLink } from 'react-router'
import { keys } from '@/query/keys'
import { PageSkeleton } from '../StateViews'

function TopicPanel({ topic, children }: { topic: SettingsTopic; children: ReactNode }) {
  const selected = useSettingsTopic()
  return <Stack role="tabpanel" id={`settings-panel-${topic}`} aria-labelledby={`settings-tab-${topic}`} hidden={selected !== topic} spacing={3} sx={{ display: selected === topic ? 'flex' : 'none' }}>{children}</Stack>
}

function Editor({ data, reload }: { data: AdminSettingsResponse; reload: () => Promise<AdminSettingsResponse | undefined> }) {
  const { t } = useTranslation()
  const cache = useQueryClient()
  const schoolsDraft = useSettingsDraft(data.revision, data.schools.featured)
  const directoryDraft = useSettingsDraft(data.revision, data.schools.directory_search)
  const { value: schools, setValue: setSchools } = schoolsDraft
  const { value: enabled, setValue: setEnabled } = directoryDraft
  const [host, setHost] = useState('')
  const [name, setName] = useState('')
  const [affected, setAffected] = useState<Record<string, number> | null>(null)
  const save = useMutation({
    mutationFn: ({ operation }: { scope: 'schools' | 'directory'; operation: () => Promise<AdminSettingsResponse> }) => operation(),
    onSuccess: (fresh, { scope }) => {
      if (scope === 'schools') { schoolsDraft.accept(fresh.revision, fresh.schools.featured); setAffected(null) }
      if (scope === 'directory') directoryDraft.accept(fresh.revision, fresh.schools.directory_search)
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
  const submitSchools = (confirmed: string[] = []) => save.mutate({ scope: 'schools', operation: () => saveFeaturedSchools({ revision: schoolsDraft.revision, featured: schools.map((s) => ({ host: s.host, display_name: s.display_name })), confirm_affected: confirmed }) })
  async function reloadConflict() {
    const fresh = await reload()
    if (!fresh) return
    if (save.variables?.scope === 'schools') schoolsDraft.accept(fresh.revision, fresh.schools.featured)
    if (save.variables?.scope === 'directory') directoryDraft.accept(fresh.revision, fresh.schools.directory_search)
    save.reset()
  }
  function move(index: number, direction: number) {
    const next = [...schools]
    ;[next[index], next[index + direction]] = [next[index + direction], next[index]]
    setSchools(next)
  }
  return <Stack spacing={3}>
    {save.isError && <ErrorNotice error={save.error} />}
    {conflicted && <Button onClick={() => void reloadConflict()}>{t('admin:settings.reload')}</Button>}
    <TopicPanel topic="providers">
    <LoginProviderSettings names={Object.fromEntries(data.sign_in_methods.map((provider) => [provider.id, provider.effective_name]))} />
    </TopicPanel>
    <TopicPanel topic="schools">
    {data.schools.warnings.includes('no_schools_offered') && <Alert severity="warning">{t('admin:settings.noSchools')}</Alert>}
    <Card><CardContent><Stack spacing={2}>
      <Typography variant="h6" component="h2">{t('admin:settings.featured')}</Typography>
      <DraftStatus {...schoolsDraft} />
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
      {save.isSuccess && save.variables.scope === 'schools' && <Alert severity="success">{t('admin:workspace.saved')}</Alert>}
      <Button variant="contained" disabled={busy || conflicted || schoolsDraft.stale || !schoolsDraft.dirty} onClick={() => submitSchools()}>{t('admin:settings.saveSchools')}</Button>
    </Stack></CardContent></Card>
    <Card><CardContent><Stack spacing={2}>
      <Typography variant="h6" component="h2">{t('admin:settings.directory')}</Typography>
      <DraftStatus {...directoryDraft} />
      <FormControlLabel control={<Switch checked={enabled} disabled={busy} onChange={(_, value) => setEnabled(value)} />} label={t('admin:settings.directory')} />
      <Typography>{t('admin:settings.directoryHelp')}</Typography>
      {save.isSuccess && save.variables.scope === 'directory' && <Alert severity="success">{t('admin:workspace.saved')}</Alert>}
      <Button variant="contained" disabled={busy || conflicted || directoryDraft.stale || !directoryDraft.dirty} onClick={() => save.mutate({ scope: 'directory', operation: () => saveDirectorySearch(directoryDraft.revision, enabled) })}>{t('admin:settings.saveSearch')}</Button>
    </Stack></CardContent></Card>
    </TopicPanel>
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
  return <Stack spacing={3} sx={{ maxWidth: 1000 }}>
    <PageHeader title={t('admin:settings.title')} subtitle={t('admin:workspace.intro')} />
    <Alert role="status" severity={query.data.local_admin.ready ? 'success' : 'warning'}><Stack spacing={2} sx={{ alignItems: 'flex-start' }}>
      <span>{t(query.data.local_admin.ready ? 'admin:localAccount.ready' : 'admin:localAccount.missing')}</span>
      {!query.data.local_admin.ready && <Button component={RouterLink} to="/admin" color="inherit">{t('admin:accounts.title')}</Button>}
    </Stack></Alert>
    <SettingsTopics />
    <TopicPanel topic="site"><SiteAddressSettings data={query.data} /></TopicPanel>
    <TopicPanel topic="access"><LoginPolicySettings /><BrowserSessionSettings data={query.data} /></TopicPanel>
    <TopicPanel topic="mail"><MailSettingsPanel /></TopicPanel>
    <Editor data={query.data} reload={async () => (await query.refetch()).data} />
  </Stack>
}
