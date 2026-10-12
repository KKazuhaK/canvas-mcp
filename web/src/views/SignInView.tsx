import Alert from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Skeleton from '@mui/material/Skeleton'
import Typography from '@mui/material/Typography'
import { Navigate, useLocation, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { isUnauthenticated } from '@/api/errors'
import { signInUrl } from '@/api/endpoints'
import ErrorNotice from '@/components/ErrorNotice'
import LocalLoginForm from '@/components/LocalLoginForm'
import McpUrlCard from '@/components/McpUrlCard'
import ProviderIcon from '@/components/ProviderIcon'
import { useMe, useProviders } from '@/query/hooks'
import { codeText } from '@/utils/errorText'
import { TXN_PATTERN } from '@/utils/appRedirect'
import { SITE_BASE, sanitizeReturnTo } from '@/utils/returnTo'
import { isSessionEnded } from '@/utils/sessionEnded'

/** A provider's start URL must be a plain same-site path; anything else is not offered. */
function isPlainPath(url: string): boolean {
  return /^\/[A-Za-z0-9/_-]{1,128}$/.test(url) && !url.includes('//')
}

/**
 * /sign-in. One button per provider from GET /providers, each a plain link to the
 * server-side sign-in redirect (a full-page navigation to /auth/login, then the
 * identity provider, then back). The server returns here with ?error=<code> when a
 * sign-in fails; the code is mapped to fixed text and the raw value is never shown.
 *
 * With several providers the server sends the person here (from /auth/login) and the
 * request id of a waiting app (`txn`) and "use a different account" (`reauth`) travel on to
 * every provider's start link; the server checks both again. A waiting app or a requested
 * re-sign-in keeps this page open even for a person who is already signed in.
 *
 * There is deliberately no automatic redirect to the provider: a person who just
 * signed out, or whose browser drops the session cookie, would be bounced around
 * in a loop.
 */
export default function SignInView() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const sessionEnded = isSessionEnded(useLocation().state)
  const providers = useProviders()
  const me = useMe()
  const errorParam = params.get('error')
  const rawTxn = params.get('txn')
  const txn = rawTxn !== null && TXN_PATTERN.test(rawTxn) ? rawTxn : null
  const reauth = params.get('reauth') === '1'
  // A waiting app's request ends at the consent screen, not at a page of this app.
  const returnTo = txn === null ? sanitizeReturnTo(params.get('return_to')) : null

  // Already signed in (for example a stale tab): go where the sign-in was headed. A
  // probe that now answers 401 keeps its last good data, but that person is signed out.
  // A failed sign-in code keeps the page open: a signed-in person gets here from a failed
  // re-sign-in or app consent, and needs to see that it failed (a failed link never gets
  // here; the server sends it to the Sign-in methods screen).
  if (me.data && !isUnauthenticated(me.error) && !reauth && txn === null && errorParam === null) {
    const inApp = returnTo ? returnTo.slice(SITE_BASE.length) || '/' : '/'
    return <Navigate to={inApp} replace />
  }

  const data = providers.data
  if (data?.setup_required) return <Navigate to="/setup" replace />
  const offered = data?.providers.filter((provider) => isPlainPath(provider.start_url)) ?? []
  return (
    <>
      <Card component="section" aria-labelledby="sign-in-title">
        <CardContent sx={{ display: 'grid', gap: 2 }}>
          <Box>
            <Typography id="sign-in-title" variant="h1" component="h1">
              {t('auth:login.title')}
            </Typography>
            <Typography color="text.secondary" sx={{ mt: 0.5 }}>
              {t('auth:login.subtitle')}
            </Typography>
          </Box>

          {txn !== null ? (
            <Alert severity="info" role="note">
              {t('auth:login.appWaiting')}
            </Alert>
          ) : null}

          {sessionEnded && errorParam === null ? (
            <Alert severity="info" role="status">
              <AlertTitle>{t('auth:login.sessionEnded.title')}</AlertTitle>
              {t('auth:login.sessionEnded.body')}
            </Alert>
          ) : null}

          {errorParam !== null ? (
            <Alert severity="error" role="alert">
              <AlertTitle>{t('auth:login.errorTitle')}</AlertTitle>
              {codeText(t, errorParam)}
            </Alert>
          ) : null}

          {providers.isPending ? (
            <Box role="status" aria-label={t('common:states.loading')} sx={{ display: 'grid', gap: 1 }}>
              <Skeleton variant="rounded" height={44} />
            </Box>
          ) : null}

          {providers.isError ? (
            <ErrorNotice
              error={providers.error}
              title={t('auth:login.loadFailed.title')}
              onRetry={() => void providers.refetch()}
            />
          ) : null}

          {data && offered.length === 0 ? (
            <Alert severity="warning" role="note">
              <AlertTitle>{t('auth:login.noProviders.title')}</AlertTitle>
              {t('auth:login.noProviders.body')}
            </Alert>
          ) : null}

          {offered.length > 0 ? (
            <Box component="ul" sx={{ listStyle: 'none', m: 0, p: 0, display: 'grid', gap: 1.5 }}>
              {offered.map((provider) => provider.id === 'local' ? <li key="local"><LocalLoginForm txn={txn} returnTo={returnTo} /></li> : (
                <li key={provider.id}>
                  <Button
                    component="a"
                    href={signInUrl(provider.start_url, { returnTo, txn, reauth })}
                    variant="outlined"
                    size="large"
                    fullWidth
                    startIcon={<ProviderIcon icon={provider.icon} />}
                    sx={{ justifyContent: 'flex-start' }}
                  >
                    {t('auth:login.signInWith', { name: provider.name })}
                  </Button>
                </li>
              ))}
            </Box>
          ) : null}
        </CardContent>
      </Card>
      <McpUrlCard />
    </>
  )
}
