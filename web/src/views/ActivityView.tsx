import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import ErrorNotice from '@/components/ErrorNotice'
import LoginHistory from '@/components/LoginHistory'
import PageHeader from '@/components/PageHeader'
import { useLogout } from '@/query/hooks'

/** /activity: the last 20 sign-ins, plus sign out. (No address or device: the server keeps none.) */
export default function ActivityView() {
  const { t } = useTranslation()
  const logout = useLogout()

  return (
    <>
      <PageHeader title={t('account:activity.title')} subtitle={t('account:activity.intro')} />
      <Box sx={{ display: 'grid', gap: 2 }}>
        <LoginHistory label={t('account:activity.title')} />

        <Card component="section" aria-labelledby="sessions-title">
          <CardContent sx={{ display: 'grid', gap: 1.5 }}>
            <Typography id="sessions-title" variant="h3" component="h2">
              {t('account:activity.sessionsTitle')}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {t('account:activity.sessionsBody')}
            </Typography>
            {logout.isError ? <ErrorNotice error={logout.error} /> : null}
            <Box>
              <Button variant="outlined" disabled={logout.isPending} onClick={() => logout.mutate()}>
                {t('common:actions.signOut')}
              </Button>
            </Box>
          </CardContent>
        </Card>
      </Box>
    </>
  )
}
