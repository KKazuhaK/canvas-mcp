import HourglassTopIcon from '@mui/icons-material/HourglassTop'
import Alert from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import LoginHistory from '@/components/LoginHistory'
import { keys } from '@/query/keys'
import { useLogout } from '@/query/hooks'

/**
 * Account exists but an owner has not approved it yet. Token form and write tools stay
 * hidden; the person's own recent sign-ins are shown, as on the server-rendered page.
 */
export default function PendingView() {
  const { t } = useTranslation()
  const client = useQueryClient()
  const logout = useLogout()
  return (
    <Box sx={{ display: 'grid', gap: 2 }}>
      <Card component="section" aria-labelledby="pending-title">
        <CardContent sx={{ display: 'grid', gap: 2 }}>
          <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'center' }}>
            <HourglassTopIcon color="primary" />
            <Typography id="pending-title" variant="h2" component="h1">
              {t('auth:pending.title')}
            </Typography>
          </Box>
          <Alert severity="info" role="note">
            <AlertTitle>{t('auth:pending.body')}</AlertTitle>
            {t('auth:pending.hint')}
          </Alert>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <Button
              variant="contained"
              onClick={() => void client.invalidateQueries({ queryKey: keys.me })}
            >
              {t('common:actions.refresh')}
            </Button>
            <Button onClick={() => logout.mutate()} disabled={logout.isPending}>
              {t('common:actions.signOut')}
            </Button>
          </Box>
        </CardContent>
      </Card>
      <Card component="section" aria-labelledby="pending-history-title">
        <CardContent sx={{ display: 'grid', gap: 1.5 }}>
          <Typography id="pending-history-title" variant="h3" component="h2">
            {t('account:activity.title')}
          </Typography>
          <LoginHistory label={t('account:activity.title')} />
        </CardContent>
      </Card>
    </Box>
  )
}
