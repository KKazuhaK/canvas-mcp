import Alert from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Skeleton from '@mui/material/Skeleton'
import { Link as RouterLink } from 'react-router'
import { useTranslation } from 'react-i18next'
import PublicLayout from '@/layouts/PublicLayout'

/** Loading skeleton for a whole page. */
export function PageSkeleton() {
  const { t } = useTranslation()
  return (
    <Box role="status" aria-label={t('common:states.loading')} sx={{ display: 'grid', gap: 2, p: 2 }}>
      <Skeleton variant="text" width="40%" height={48} />
      <Skeleton variant="rounded" height={140} />
      <Skeleton variant="rounded" height={90} />
    </Box>
  )
}

export function FullPageLoading() {
  return (
    <PublicLayout>
      <PageSkeleton />
    </PublicLayout>
  )
}

function StateNotice({
  severity,
  titleKey,
  bodyKey,
}: {
  severity: 'warning' | 'info' | 'error'
  titleKey: string
  bodyKey: string
}) {
  const { t } = useTranslation()
  return (
    <Box sx={{ display: 'grid', gap: 2 }}>
      <Alert severity={severity} role="note">
        <AlertTitle>{t(titleKey)}</AlertTitle>
        {t(bodyKey)}
      </Alert>
      <div>
        <Button component={RouterLink} to="/" variant="outlined">
          {t('common:actions.goHome')}
        </Button>
      </div>
    </Box>
  )
}

/** Inline (inside an existing layout). */
export function ForbiddenNotice() {
  return <StateNotice severity="warning" titleKey="common:states.forbidden.title" bodyKey="common:states.forbidden.body" />
}

export function NotFoundView() {
  return (
    <PublicLayout>
      <StateNotice severity="info" titleKey="common:states.notFound.title" bodyKey="common:states.notFound.body" />
    </PublicLayout>
  )
}

/** Router errorElement: a fixed message, never error text or a stack. */
export function RouteError() {
  const { t } = useTranslation()
  return (
    <PublicLayout>
      <Alert
        severity="error"
        role="alert"
        action={
          <Button color="inherit" size="small" onClick={() => window.location.reload()}>
            {t('common:states.reload')}
          </Button>
        }
      >
        <AlertTitle>{t('common:states.crash.title')}</AlertTitle>
        {t('common:states.crash.body')}
      </Alert>
    </PublicLayout>
  )
}
