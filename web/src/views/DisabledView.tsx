import BlockIcon from '@mui/icons-material/Block'
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import { useLogout } from '@/query/hooks'

/** Disabled account: a message and sign-out, nothing else. */
export default function DisabledView() {
  const { t } = useTranslation()
  const logout = useLogout()
  return (
    <Card component="section" aria-labelledby="disabled-title">
      <CardContent sx={{ display: 'grid', gap: 2 }}>
        <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'center' }}>
          <BlockIcon color="error" />
          <Typography id="disabled-title" variant="h2" component="h1">
            {t('auth:disabled.title')}
          </Typography>
        </Box>
        <Alert severity="warning" role="note">{t('auth:disabled.body')}</Alert>
        <div>
          <Button variant="outlined" onClick={() => logout.mutate(false)} disabled={logout.isPending}>
            {t('common:actions.signOut')}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
