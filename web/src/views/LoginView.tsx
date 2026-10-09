import Alert from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Skeleton from '@mui/material/Skeleton'
import Typography from '@mui/material/Typography'
import { useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { loginStartUrl } from '@/api/endpoints'
import ErrorNotice from '@/components/ErrorNotice'
import McpUrlCard from '@/components/McpUrlCard'
import ProviderIcon from '@/components/ProviderIcon'
import { useProviders } from '@/query/hooks'
import { codeText } from '@/utils/errorText'
import { hardNavigate } from '@/utils/navigate'
import { sanitizeReturnTo, sanitizeTxn } from '@/utils/returnTo'

/**
 * /login. One button per provider from GET /providers, each a plain link to the
 * full-page navigation /account/api/login/{id}/start. `txn` and `return_to` are
 * validated before they are passed on.
 *
 * Auto-redirect fires ONLY when exactly one provider is configured and there is
 * no ?error. That guard is what stops a failing provider from bouncing the
 * person back and forth forever.
 */
export default function LoginView() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const providers = useProviders()
  const errorParam = params.get('error')
  const txn = sanitizeTxn(params.get('txn'))
  const returnTo = sanitizeReturnTo(params.get('return_to'))
  const fired = useRef(false)

  const list = providers.data?.providers
  const autoTarget =
    list && list.length === 1 && errorParam === null
      ? loginStartUrl(list[0].id, { txn, returnTo })
      : null

  useEffect(() => {
    if (autoTarget !== null && !fired.current) {
      fired.current = true
      hardNavigate(autoTarget)
    }
  }, [autoTarget])

  const data = providers.data
  return (
    <>
      <Card component="section" aria-labelledby="login-title">
        <CardContent sx={{ display: 'grid', gap: 2 }}>
          <Box>
            <Typography id="login-title" variant="h1" component="h1">
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

          {txn ? <Alert severity="info" role="note">{t('auth:login.consentHint')}</Alert> : null}

          {providers.isPending ? (
            <Box role="status" aria-label={t('common:states.loading')} sx={{ display: 'grid', gap: 1 }}>
              <Skeleton variant="rounded" height={44} />
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

          {data?.signups_paused ? <Alert severity="info" role="note">{t('auth:login.signupsPaused')}</Alert> : null}
          {data?.login_mode === 'invite_only' ? (
            <Alert severity="info" role="note">{t('auth:login.inviteOnly')}</Alert>
          ) : null}
          {data?.login_mode === 'closed' ? <Alert severity="warning" role="note">{t('auth:login.closed')}</Alert> : null}

          {data && data.providers.length === 0 ? (
            <Alert severity="warning" role="note">
              <AlertTitle>{t('auth:login.noProviders.title')}</AlertTitle>
              {t('auth:login.noProviders.body')}
            </Alert>
          ) : null}

          {autoTarget !== null && list ? (
            <Alert severity="info" role="status">
              {t('auth:login.redirecting', { name: list[0].name })}
            </Alert>
          ) : null}

          {data && data.providers.length > 0 ? (
            <Box component="ul" sx={{ listStyle: 'none', m: 0, p: 0, display: 'grid', gap: 1.5 }}>
              {data.providers.map((provider) => (
                <li key={provider.id}>
                  <Button
                    component="a"
                    href={loginStartUrl(provider.id, { txn, returnTo })}
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
