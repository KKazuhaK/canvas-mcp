import Alert from '@mui/material/Alert'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router'

/** The only notice code the address may carry; any other value is ignored, never shown. */
export const APP_REQUEST_NOTICE = 'authorization_unavailable'

/**
 * Tells the person that the app request they came from can no longer be used (the server
 * sends them here with `?notice=authorization_unavailable` after a sign-in). The text is
 * fixed; the value in the address only switches it on. It is read once and then removed
 * from the address, so a reload does not show it again.
 */
export default function AppRequestNotice() {
  const { t } = useTranslation()
  const [params, setParams] = useSearchParams()
  const [shown] = useState(() => params.get('notice') === APP_REQUEST_NOTICE)
  const hasNotice = params.has('notice')
  useEffect(() => {
    if (!hasNotice) return
    const next = new URLSearchParams(params)
    next.delete('notice')
    setParams(next, { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasNotice])
  if (!shown) return null
  return (
    <Alert severity="info" role="note" sx={{ mb: 2 }}>
      {t('auth:login.appUnavailable')}
    </Alert>
  )
}
