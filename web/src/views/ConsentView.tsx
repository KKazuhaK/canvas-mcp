import Alert from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Skeleton from '@mui/material/Skeleton'
import Typography from '@mui/material/Typography'
import { Navigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ApiError, isUnauthenticated } from '@/api/errors'
import type { ConsentDecision } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'
import ExternalLink from '@/components/ExternalLink'
import { useConsent, useDecideConsent, useMe } from '@/query/hooks'
import { useLanguage } from '@/stores/language'
import { formatDateTime } from '@/utils/time'
import { loginPathFor, sanitizeTxn } from '@/utils/returnTo'

function Problem({ titleKey, bodyKey }: { titleKey: string; bodyKey: string }) {
  const { t } = useTranslation()
  return (
    <Alert severity="warning" role="alert">
      <AlertTitle>{t(titleKey)}</AlertTitle>
      {t(bodyKey)}
    </Alert>
  )
}

/** /consent/:txn: approve or deny an MCP client. */
export default function ConsentView() {
  const { t } = useTranslation()
  const lang = useLanguage((s) => s.lang)
  const rawTxn = useParams().txn
  const txn = sanitizeTxn(rawTxn)
  // GET /me first: it is the source of the CSRF token the decision POST needs,
  // and it tells us whether there is a session at all.
  const me = useMe()
  const consent = useConsent(txn)
  const decide = useDecideConsent(txn ?? '')

  if (txn === null) {
    return <Problem titleKey="auth:consent.invalidLink.title" bodyKey="auth:consent.invalidLink.body" />
  }
  if (isUnauthenticated(me.error) || isUnauthenticated(consent.error)) {
    // No session: sign in first, then come back through the same transaction.
    return <Navigate to={loginPathFor(`/consent/${txn}`, txn)} replace />
  }
  if (me.isError) return <ErrorNotice error={me.error} onRetry={() => void me.refetch()} />
  if (me.data && me.data.account.status === 'pending') {
    return <Problem titleKey="auth:pending.title" bodyKey="auth:pending.body" />
  }
  if (me.data && me.data.account.status === 'disabled') {
    return <Problem titleKey="auth:disabled.title" bodyKey="auth:disabled.body" />
  }
  if (consent.isPending || me.isPending) {
    return (
      <Box role="status" aria-label={t('common:states.loading')} sx={{ display: 'grid', gap: 2 }}>
        <Skeleton variant="text" height={48} />
        <Skeleton variant="rounded" height={160} />
      </Box>
    )
  }
  if (consent.isError) {
    const err = consent.error
    if (err instanceof ApiError && (err.code === 'consent_expired' || err.code === 'not_found')) {
      return <Problem titleKey="auth:consent.expired.title" bodyKey="auth:consent.expired.body" />
    }
    return <ErrorNotice error={err} onRetry={() => void consent.refetch()} />
  }

  const info = consent.data
  const expires = formatDateTime(info.expires_at, lang)
  const busy = decide.isPending || decide.isSuccess
  const choose = (decision: ConsentDecision) => decide.mutate(decision)

  return (
    <Card component="section" aria-labelledby="consent-title">
      <CardContent sx={{ display: 'grid', gap: 2 }}>
        <Typography id="consent-title" variant="h1" component="h1" sx={{ overflowWrap: 'anywhere' }}>
          {t('auth:consent.title', { client: info.client_name, name: info.account_display_name })}
        </Typography>
        <Typography color="text.secondary">
          {t('auth:consent.intro', { client: info.client_name })}
        </Typography>
        {info.client_uri ? (
          <Typography variant="body2">
            {t('auth:consent.website')}: <ExternalLink href={info.client_uri}>{info.client_uri}</ExternalLink>
          </Typography>
        ) : null}

        <Box>
          <Typography variant="h3" component="h2">
            {t('auth:consent.scopesTitle')}
          </Typography>
          <Box component="ul" sx={{ m: 0, mt: 0.5, pl: 3 }}>
            {info.scopes.map((scope) => (
              <li key={scope}>
                {t(`auth:consent.scopes.${scope.replace(/[^A-Za-z0-9_]/g, '_')}`, {
                  defaultValue: t('auth:consent.unknownScope', { scope }),
                })}
              </li>
            ))}
          </Box>
        </Box>

        <Typography variant="body2" color="text.secondary">
          {t('auth:consent.redirectHost', { host: info.redirect_host })}
        </Typography>
        {expires ? (
          <Typography variant="body2" color="text.secondary">
            {t('auth:consent.expires', { time: expires })}
          </Typography>
        ) : null}

        {decide.isError ? (
          decide.error instanceof ApiError && decide.error.code === 'internal_error' && decide.error.status === 0 ? (
            <Alert severity="error" role="alert">
              {t('auth:consent.badRedirect')}
            </Alert>
          ) : (
            <ErrorNotice error={decide.error} />
          )
        ) : null}

        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          <Button variant="contained" disabled={busy} onClick={() => choose('allow')}>
            {busy ? t('auth:consent.working') : t('auth:consent.allow')}
          </Button>
          <Button variant="outlined" disabled={busy} onClick={() => choose('deny')}>
            {t('auth:consent.deny')}
          </Button>
        </Box>
      </CardContent>
    </Card>
  )
}
