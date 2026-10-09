import Alert from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Skeleton from '@mui/material/Skeleton'
import Typography from '@mui/material/Typography'
import { Navigate, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { signInUrl } from '@/api/endpoints'
import ErrorNotice from '@/components/ErrorNotice'
import McpUrlCard from '@/components/McpUrlCard'
import ProviderIcon from '@/components/ProviderIcon'
import { useMe, useProviders } from '@/query/hooks'
import { codeText } from '@/utils/errorText'
import { SITE_BASE, sanitizeReturnTo } from '@/utils/returnTo'

/** A provider's start URL must be a plain same-site path; anything else is not offered. */
function isPlainPath(url: string): boolean {
  return /^\/[A-Za-z0-9/_-]{1,128}$/.test(url) && !url.includes('//')
}

/**
 * /sign-in. One button per provider from GET /providers, each a plain link to the
 * server-side sign-in redirect (a full-page navigation to /account/login, then the
 * identity provider, then back). The server returns here with ?error=<code> when a
 * sign-in fails; the code is mapped to fixed text and the raw value is never shown.
 *
 * There is deliberately no automatic redirect to the provider: a person who just
 * signed out, or whose browser drops the session cookie, would be bounced around
 * in a loop.
 */
export default function SignInView() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const providers = useProviders()
  const me = useMe()
  const errorParam = params.get('error')
  const returnTo = sanitizeReturnTo(params.get('return_to'))

  // Already signed in (for example a stale tab): go where the sign-in was headed.
  if (me.data) {
    const inApp = returnTo ? returnTo.slice(SITE_BASE.length) || '/' : '/'
    return <Navigate to={inApp} replace />
  }

  const data = providers.data
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
              {offered.map((provider) => (
                <li key={provider.id}>
                  <Button
                    component="a"
                    href={signInUrl(provider.start_url, returnTo)}
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
