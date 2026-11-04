import Alert from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import LoginRounded from '@mui/icons-material/LoginRounded'
import { useTranslation } from 'react-i18next'
import { useLocation } from 'react-router'
import { LOGIN_PATH, signInUrl } from '@/api/endpoints'
import { hardNavigate } from '@/utils/navigate'
import { SITE_BASE, sanitizeReturnTo } from '@/utils/returnTo'

/**
 * The server wants a sign-in from the last 10 minutes (owner pages, and turning a
 * write tool on). The button is a full-page trip through /auth/login that comes
 * back to this page. It is a button, not an automatic redirect: a redirect would
 * throw away what the person was in the middle of, and a session that never counts
 * as fresh could loop.
 *
 * The trip always asks for `reauth`. Without it the server may send a person whose session
 * is still fresh straight back to `return_to`, and a stale one could loop on this notice.
 * With several providers `reauth` also keeps the chooser open for a signed-in person.
 */
export default function ReauthNotice() {
  const { t } = useTranslation()
  const location = useLocation()
  const here = `${SITE_BASE}${location.pathname === '/' ? '' : location.pathname}${location.search}`
  const returnTo = sanitizeReturnTo(here)
  return (
    <Alert
      severity="warning"
      role="alert"
    >
      <AlertTitle>{t('errors:reauth_required_title')}</AlertTitle>
      <Stack spacing={2} sx={{ alignItems: 'flex-start' }}>
        <span>{t('errors:reauth_required')}</span>
        <Button variant="contained" startIcon={<LoginRounded />} onClick={() => hardNavigate(signInUrl(LOGIN_PATH, { returnTo, reauth: true }))}>
          {t('common:actions.signInAgain')}
        </Button>
      </Stack>
    </Alert>
  )
}
