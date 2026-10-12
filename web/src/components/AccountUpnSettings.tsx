import Alert from '@mui/material/Alert'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import { useTranslation } from 'react-i18next'
import type { Account } from '@/api/types'

export default function AccountUpnSettings({ account }: { account: Account }) {
  const { t } = useTranslation()
  return <Card><CardContent><Stack spacing={2}>
    {account.upn_required && <Alert severity="info">{t('auth:upn.required')}</Alert>}
    <TextField label={t('auth:local.username')} value={account.upn ?? ''} helperText={t('auth:upn.help')} slotProps={{ input: { readOnly: true } }} />
  </Stack></CardContent></Card>
}
