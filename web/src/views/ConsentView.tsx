import HourglassTopIcon from '@mui/icons-material/HourglassTop'
import Alert from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Chip from '@mui/material/Chip'
import Link from '@mui/material/Link'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link as RouterLink, useSearchParams } from 'react-router'
import { ApiError, isUnauthenticated } from '@/api/errors'
import type { ConsentDecision, ConsentResponse } from '@/api/types'
import AppIdentity from '@/components/apps/AppIdentity'
import ErrorNotice from '@/components/ErrorNotice'
import TimeText from '@/components/TimeText'
import PublicLayout from '@/layouts/PublicLayout'
import { useConsent, useDecideConsent, useMe } from '@/query/hooks'
import { safeAppRedirect, TXN_PATTERN, consentLoginPath } from '@/utils/appRedirect'
import { hardNavigate } from '@/utils/navigate'
import { FullPageLoading, NotFoundNotice } from './StateViews'

/** Only a failure that may pass is worth another try: a used, expired or foreign request never comes back. */
function retryable(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    (error.isNetwork || error.code === 'token_store_unavailable' || error.code === 'internal_error')
  )
}

function RequestNotice({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const { t } = useTranslation()
  return (
    <Box sx={{ display: 'grid', gap: 2 }}>
      <ErrorNotice error={error} title={t('account:consent.errorTitle')} onRetry={onRetry} />
      <div>
        <Button component={RouterLink} to="/" variant="outlined">
          {t('common:actions.goHome')}
        </Button>
      </div>
    </Box>
  )
}

function Details({ consent, txn }: { consent: ConsentResponse; txn: string }) {
  const { t } = useTranslation()
  const scopes = consent.scopes.map((scope) => scope.name)
  return (
    <Box sx={{ display: 'grid', gap: 2 }}>
      <AppIdentity client={consent.client} large />

      <Box sx={{ display: 'grid', gap: 0.75 }}>
        <Typography>
          {t('account:consent.returnsTo')}{' '}
          <Box component="code" sx={{ overflowWrap: 'anywhere' }}>
            {consent.redirect.host}
          </Box>
        </Typography>
        {consent.redirect.loopback ? (
          <Alert severity="warning" role="note">
            {t('account:consent.loopbackWarning')}
          </Alert>
        ) : null}
      </Box>

      <Box sx={{ display: 'grid', gap: 0.75 }}>
        <Typography>{t('account:consent.can')}</Typography>
        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
          {scopes.map((name) => (
            <Chip key={name} size="small" variant="outlined" label={name} sx={{ fontFamily: 'monospace' }} />
          ))}
        </Box>
        <Typography variant="body2" color="text.secondary">
          {t('account:consent.canBody')}
        </Typography>
      </Box>

      <Typography>
        {t('account:consent.signedInAs')}{' '}
        <strong>{consent.account.display_name}</strong>
        {consent.account.username ? (
          <Typography component="span" variant="body2" color="text.secondary">
            {' '}
            ({consent.account.username})
          </Typography>
        ) : null}{' '}
        {/* A plain link: the sign-in is a server-side redirect, not a route of this app. */}
        <Link href={consentLoginPath(txn, { reauth: true })} variant="body2">
          {t('account:consent.useDifferent')}
        </Link>
      </Typography>

      <Typography variant="body2" color="text.secondary">
        {t('account:consent.phishing')}
      </Typography>
      <Typography variant="body2" color="text.secondary">
        {t('account:consent.validUntil')} <TimeText iso={consent.expires_at} />
      </Typography>
    </Box>
  )
}

function ConsentCard({ txn }: { txn: string }) {
  const { t } = useTranslation()
  const consent = useConsent(txn, true)
  const decide = useDecideConsent(txn)
  const [unsafe, setUnsafe] = useState(false)
  const sessionEnded = consent.isError && isUnauthenticated(consent.error)

  // The session ended while the page was open: sign in again for this very request.
  useEffect(() => {
    if (sessionEnded) hardNavigate(consentLoginPath(txn))
  }, [sessionEnded, txn])

  if (consent.isPending) return <FullPageLoading />
  if (consent.isError) {
    return (
      <PublicLayout>
        <RequestNotice
          error={consent.error}
          onRetry={retryable(consent.error) ? () => void consent.refetch() : undefined}
        />
      </PublicLayout>
    )
  }

  const data = consent.data
  const sent = decide.isSuccess && !unsafe

  function answer(decision: ConsentDecision) {
    setUnsafe(false)
    decide.mutate(decision, {
      onSuccess: (response) => {
        const target = safeAppRedirect(response.redirect_to)
        if (target === null) setUnsafe(true)
        else hardNavigate(target)
      },
      // The session ended between the screen and the button: sign in again for this same request.
      onError: (error) => {
        if (isUnauthenticated(error)) hardNavigate(consentLoginPath(txn))
      },
    })
  }

  const busy = decide.isPending || sent
  return (
    <PublicLayout>
      <Card component="section" aria-labelledby="consent-title">
        <CardContent sx={{ display: 'grid', gap: 2 }}>
          <Typography id="consent-title" variant="h1" component="h1">
            {t('account:consent.title')}
          </Typography>

          <Details consent={data} txn={txn} />

          {!data.can_approve ? (
            <Alert severity="info" role="note" icon={<HourglassTopIcon fontSize="inherit" />}>
              <AlertTitle>{t('account:consent.pendingTitle')}</AlertTitle>
              {t('account:consent.pendingBody')}
            </Alert>
          ) : null}

          {decide.isError ? <ErrorNotice error={decide.error} /> : null}
          {unsafe ? <Alert severity="error" role="alert">{t('account:consent.decisionFailed')}</Alert> : null}
          {sent ? (
            <Alert severity="info" role="status">
              {t('account:consent.redirecting')}
            </Alert>
          ) : null}

          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            {data.can_approve ? (
              <>
                <Button variant="contained" size="large" disabled={busy} onClick={() => answer('approve')}>
                  {t('account:consent.allow')}
                </Button>
                <Button variant="outlined" size="large" disabled={busy} onClick={() => answer('deny')}>
                  {t('account:consent.deny')}
                </Button>
              </>
            ) : (
              <Button variant="outlined" size="large" disabled={busy} onClick={() => answer('deny')}>
                {t('account:consent.cancel')}
              </Button>
            )}
          </Box>
        </CardContent>
      </Card>
    </PublicLayout>
  )
}

/**
 * /consent?txn=...: an app asks to be connected to the signed-in account (the server's own
 * authorization server, SELFHOST_AUTH_MODE=local). The server sends the browser here after
 * the /account sign-in. Not behind RequireAuth: a signed-out visitor is not sent to the generic
 * sign-in page but straight to the server-side sign-in of this very request (a full-page
 * navigation that keeps the request id), and comes back here.
 *
 * Everything shown comes from GET /consent?txn=...; what happens next comes from the answer to the
 * decision: the page navigates to the app's own return address (checked first) and never
 * submits a form. The request id is single-use and tied to the browser that started it, so
 * a link opened elsewhere only shows an error.
 */
export default function ConsentView() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const txn = params.get('txn') ?? ''
  const valid = TXN_PATTERN.test(txn)
  const me = useMe()
  const signedOut = isUnauthenticated(me.error)

  useEffect(() => {
    if (valid && signedOut) hardNavigate(consentLoginPath(txn))
  }, [valid, signedOut, txn])

  if (!valid) {
    return (
      <PublicLayout>
        <RequestNotice error={new ApiError(400, 'authorization_invalid')} />
      </PublicLayout>
    )
  }
  if (me.isPending || signedOut) {
    return (
      <PublicLayout>
        <Box role="status" aria-label={t('account:consent.signingIn')}>
          <Typography color="text.secondary">{signedOut ? t('account:consent.signingIn') : t('common:states.loading')}</Typography>
        </Box>
      </PublicLayout>
    )
  }
  if (me.isError) {
    return (
      <PublicLayout>
        <RequestNotice error={me.error} onRetry={retryable(me.error) ? () => void me.refetch() : undefined} />
      </PublicLayout>
    )
  }
  if (!me.data.features.consent) {
    return (
      <PublicLayout>
        <NotFoundNotice />
      </PublicLayout>
    )
  }
  return <ConsentCard txn={txn} />
}
