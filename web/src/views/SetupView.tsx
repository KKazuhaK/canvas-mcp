import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate } from 'react-router'
import { getProviders, getSetupStatus, initializeLogin } from '@/api/endpoints'
import ErrorNotice from '@/components/ErrorNotice'
import ProviderConfigurationForm from '@/components/admin/ProviderConfigurationForm'
import { keys } from '@/query/keys'
import { FullPageLoading } from './StateViews'

export default function SetupView() {
  const { t } = useTranslation()
  const query = useQuery({ queryKey: ['setup'], queryFn: getSetupStatus, staleTime: 0 })
  const cache = useQueryClient()
  const [code, setCode] = useState('')
  if (query.isPending) return <FullPageLoading />
  if (query.isError) return <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
  if (query.data.initialized) return <Navigate to="/sign-in" replace />
  return <Card><CardContent><Stack spacing={3}>
    <Typography component="h1" variant="h4">{t('admin:installation.title')}</Typography>
    <Typography>{t('admin:installation.help')}</Typography>
    <TextField required label={t('admin:installation.code')} type="password" value={code} autoComplete="off" onChange={(event) => setCode(event.target.value)} />
    <ProviderConfigurationForm installation callbackUri={query.data.callback_uri}
      provider={{ id: 'entra', protocol: 'entra', enabled: true, rank: 0, config: {}, secret_present: false }}
      onSave={async (values) => {
        await initializeLogin({ revision: query.data.revision, code, config: values.config, client_secret: values.client_secret ?? '' })
        setCode('')
        await cache.fetchQuery({ queryKey: keys.providers, queryFn: getProviders, staleTime: 0 })
        await query.refetch()
      }} />
  </Stack></CardContent></Card>
}
