import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { getAdminSettings, saveProviderNames } from '@/api/endpoints'
import ErrorNotice from '@/components/ErrorNotice'
import { ApiError } from '@/api/errors'
import { keys } from '@/query/keys'
import DraftStatus from './DraftStatus'
import { useSettingsDraft } from './useSettingsDraft'
import SaveOutlined from '@mui/icons-material/SaveOutlined'
import RestartAlt from '@mui/icons-material/RestartAlt'

export default function ProviderNameEditor({ id, disabled, onSaved, onBusyChange }: { id: string; disabled: boolean; onSaved: (before: number, after: number) => void; onBusyChange: (busy: boolean) => void }) {
  const { t } = useTranslation()
  const cache = useQueryClient()
  const query = useQuery({ queryKey: keys.adminSettings, queryFn: getAdminSettings })
  const provider = query.data?.sign_in_methods.find((entry) => entry.id === id && entry.configured)
  const draft = useSettingsDraft(query.data?.revision ?? 0, provider?.display_name ?? '')
  const save = useMutation({
    mutationFn: ({ revision, name }: { revision: number; name: string }) => saveProviderNames(revision, { [id]: name }),
    onMutate: () => onBusyChange(true),
    onError: (error) => {
      if (error instanceof ApiError && error.code === 'settings_conflict') void query.refetch()
    },
    onSettled: () => onBusyChange(false),
    onSuccess: (fresh, previous) => {
      draft.accept(fresh.revision, fresh.sign_in_methods.find((entry) => entry.id === id)?.display_name ?? '')
      cache.setQueryData(keys.adminSettings, fresh)
      onSaved(previous.revision, fresh.revision)
      void cache.invalidateQueries({ queryKey: keys.providers })
      void cache.invalidateQueries({ queryKey: keys.adminAudit })
    },
  })
  if (query.isError) return <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
  if (!provider) return null
  return <Stack spacing={2}>
    <TextField fullWidth label={t('admin:settings.displayName')} value={draft.value} placeholder={provider.default_name} helperText={t('admin:settings.defaultName', { name: provider.default_name })} disabled={disabled || save.isPending}
      slotProps={{ htmlInput: { maxLength: 40 } }} onChange={(event) => draft.setValue(event.target.value)} onKeyDown={(event) => {
        // This name has a separate save request from the enclosing credentials.
        if (event.key === 'Enter') event.preventDefault()
      }} />
    <DraftStatus {...draft} reset={() => { draft.reset(); save.reset() }} />
    {save.isError && <ErrorNotice error={save.error} />}
    {save.isSuccess && !draft.dirty && <Alert severity="success">{t('admin:workspace.saved')}</Alert>}
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ alignItems: { sm: 'flex-start' } }}>
      <Button variant="outlined" startIcon={<SaveOutlined />} disabled={disabled || save.isPending || draft.stale || !draft.dirty} onClick={() => save.mutate({ revision: draft.revision, name: draft.value })}>{t('admin:settings.saveName')}</Button>
      <Button variant="outlined" color="inherit" startIcon={<RestartAlt />} disabled={disabled || save.isPending} onClick={() => draft.setValue('')}>{t('admin:settings.reset')}</Button>
    </Stack>
  </Stack>
}
