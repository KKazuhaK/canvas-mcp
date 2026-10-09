import Alert from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Button from '@mui/material/Button'
import { useTranslation } from 'react-i18next'
import { useLocation } from 'react-router'
import { LOGIN_PATH, signInUrl } from '@/api/endpoints'
import { hardNavigate } from '@/utils/navigate'
import { SITE_BASE, sanitizeReturnTo } from '@/utils/returnTo'

/**
 * The server wants a sign-in from the last 10 minutes (owner pages, and turning a
 * write tool on). The button is a full-page trip through /account/login that comes
 * back to this page. It is a button, not an automatic redirect: a redirect would
 * throw away what the person was in the middle of, and a session that never counts
 * as fresh could loop.
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
      action={
        <Button color="inherit" size="small" onClick={() => hardNavigate(signInUrl(LOGIN_PATH, returnTo))}>
          {t('common:actions.signInAgain')}
        </Button>
      }
    >
      <AlertTitle>{t('errors:reauth_required_title')}</AlertTitle>
      {t('errors:reauth_required')}
    </Alert>
  )
}
