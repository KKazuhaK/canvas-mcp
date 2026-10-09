import Alert from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Chip from '@mui/material/Chip'
import Typography from '@mui/material/Typography'
import { useState } from 'react'
import { useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { loginStartUrl } from '@/api/endpoints'
import { ApiError } from '@/api/errors'
import type { Identity, Provider } from '@/api/types'
import ConfirmDialog from '@/components/ConfirmDialog'
import ErrorNotice from '@/components/ErrorNotice'
import McpUrlCard from '@/components/McpUrlCard'
import PageHeader from '@/components/PageHeader'
import ProviderIcon from '@/components/ProviderIcon'
import { useDeleteIdentity, useIdentities, useProviders, useStartLink } from '@/query/hooks'
import { useLanguage } from '@/stores/language'
import { useToast } from '@/stores/toast'
import { codeText } from '@/utils/errorText'
import { hardNavigate } from '@/utils/navigate'
import { formatDateTime } from '@/utils/time'
import { PageSkeleton } from './StateViews'

/** /identities: the sign-in methods linked to this account. */
export default function IdentitiesView() {
  const { t } = useTranslation()
  const lang = useLanguage((s) => s.lang)
  const [params] = useSearchParams()
  const returnedError = params.get('error')
  const identities = useIdentities()
  const providers = useProviders()
  const remove = useDeleteIdentity()
  const link = useStartLink()
  const [toUnlink, setToUnlink] = useState<Identity | null>(null)

  const iconFor = (providerId: string): Provider['icon'] =>
    providers.data?.providers.find((p) => p.id === providerId)?.icon ?? 'key'

  if (identities.isPending) {
    return (
      <>
        <PageHeader title={t('account:identities.title')} />
        <PageSkeleton />
      </>
    )
  }
  if (identities.isError) {
    return (
      <>
        <PageHeader title={t('account:identities.title')} />
        <ErrorNotice error={identities.error} onRetry={() => void identities.refetch()} />
      </>
    )
  }

  const { identities: list, linkable_providers: linkable } = identities.data
  const onlyOne = list.length <= 1
  const current = list.find((i) => i.is_current_session)
  const needsRecentLogin =
    link.error instanceof ApiError && link.error.code === 'link_requires_recent_login'

  function reauth() {
    if (!current) return
    hardNavigate(loginStartUrl(current.provider_id, { returnTo: '/account/identities' }))
  }

  return (
    <>
      <PageHeader title={t('account:identities.title')} subtitle={t('account:identities.intro')} />
      <Box sx={{ display: 'grid', gap: 2 }}>
        {returnedError !== null ? (
          <Alert severity="error" role="alert">
            {codeText(t, returnedError)}
          </Alert>
        ) : null}

        <Box component="ul" aria-label={t('account:identities.title')} sx={{ listStyle: 'none', m: 0, p: 0, display: 'grid', gap: 1.5 }}>
          {list.map((identity) => (
            <Card component="li" key={identity.id}>
              <CardContent sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }}>
                <ProviderIcon icon={iconFor(identity.provider_id)} />
                <Box sx={{ minWidth: 0, flex: 1, display: 'grid', gap: 0.5 }}>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                    <Typography sx={{ fontWeight: 600 }}>{identity.provider_name}</Typography>
                    {identity.is_current_session ? (
                      <Chip size="small" color="primary" label={t('account:identities.currentSession')} />
                    ) : null}
                  </Box>
                  <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>
                    {identity.display}
                  </Typography>
                  {identity.email ? (
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                      <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>
                        {identity.email}
                      </Typography>
                      <Chip
                        size="small"
                        variant="outlined"
                        color={identity.email_verified ? 'success' : 'default'}
                        label={
                          identity.email_verified
                            ? t('account:identities.verified')
                            : t('account:identities.unverified')
                        }
                      />
                    </Box>
                  ) : null}
                  <Typography variant="caption" color="text.secondary">
                    {t('account:identities.linked', { date: formatDateTime(identity.linked_at, lang) ?? t('common:time.unknown') })}
                    {' · '}
                    {identity.last_login_at
                      ? t('account:identities.lastLogin', {
                          date: formatDateTime(identity.last_login_at, lang) ?? t('common:time.unknown'),
                        })
                      : t('account:identities.neverLoggedIn')}
                  </Typography>
                </Box>
                <Button
                  color="error"
                  size="small"
                  disabled={onlyOne || remove.isPending}
                  onClick={() => setToUnlink(identity)}
                >
                  {t('account:identities.unlink')}
                </Button>
              </CardContent>
            </Card>
          ))}
        </Box>
        {onlyOne ? (
          <Typography variant="body2" color="text.secondary">
            {t('account:identities.unlinkLast')}
          </Typography>
        ) : null}

        <Card component="section" aria-labelledby="link-title">
          <CardContent sx={{ display: 'grid', gap: 1.5 }}>
            <Typography id="link-title" variant="h3" component="h2">
              {t('account:identities.linkTitle')}
            </Typography>
            {needsRecentLogin ? (
              <Alert
                severity="warning"
                role="alert"
                action={
                  current ? (
                    <Button color="inherit" size="small" onClick={reauth}>
                      {t('account:identities.reauth.cta')}
                    </Button>
                  ) : undefined
                }
              >
                <AlertTitle>{t('account:identities.reauth.title')}</AlertTitle>
                {t('account:identities.reauth.body')}
              </Alert>
            ) : link.isError ? (
              <ErrorNotice error={link.error} />
            ) : null}
            {linkable.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                {t('account:identities.noLinkable')}
              </Typography>
            ) : (
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {linkable.map((provider) => (
                  <Button
                    key={provider.id}
                    variant="outlined"
                    disabled={link.isPending}
                    startIcon={<ProviderIcon icon={provider.icon} />}
                    onClick={() => link.mutate(provider.id)}
                  >
                    {t('account:identities.linkWith', { name: provider.name })}
                  </Button>
                ))}
              </Box>
            )}
          </CardContent>
        </Card>
        <McpUrlCard />
      </Box>

      <ConfirmDialog
        open={toUnlink !== null}
        title={t('account:identities.unlinkConfirmTitle', { name: toUnlink?.provider_name ?? '' })}
        body={t('account:identities.unlinkConfirmBody')}
        confirmLabel={t('account:identities.unlink')}
        pending={remove.isPending}
        error={remove.error}
        onClose={() => {
          remove.reset()
          setToUnlink(null)
        }}
        onConfirm={() => {
          if (!toUnlink) return
          remove.mutate(toUnlink.id, {
            onSuccess: () => {
              setToUnlink(null)
              useToast.getState().show(t('account:identities.unlinked'))
            },
          })
        }}
      />
    </>
  )
}
