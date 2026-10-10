import Alert from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Chip from '@mui/material/Chip'
import Typography from '@mui/material/Typography'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router'
import { ApiError } from '@/api/errors'
import { clearCsrfToken } from '@/api/client'
import type { Identity } from '@/api/types'
import ConfirmDialog from '@/components/ConfirmDialog'
import ErrorNotice from '@/components/ErrorNotice'
import PageHeader from '@/components/PageHeader'
import ProviderIcon from '@/components/ProviderIcon'
import ReauthNotice from '@/components/ReauthNotice'
import ResponsiveTable, { type Column } from '@/components/ResponsiveTable'
import TimeText from '@/components/TimeText'
import { useIdentities, useProviders, useStartLink, useUnlinkIdentity } from '@/query/hooks'
import { useToast } from '@/stores/toast'
import { codeText } from '@/utils/errorText'
import { hardNavigate } from '@/utils/navigate'
import { safeProviderRedirect } from '@/utils/providerRedirect'
import { PageSkeleton } from './StateViews'

/**
 * /sign-in-methods: the ways this account can sign in (two or more providers). Linking is
 * explicit: the person is sent to the provider to prove they control the other account, then
 * comes back here with `?linked=1` or `?error=<code>` (a closed code, mapped to fixed text).
 * An identity that belongs to another user is refused by the server; nothing is merged.
 * Removing one ends every session of the account (connected apps stay connected).
 */
export default function SignInMethodsView() {
  const { t } = useTranslation()
  const client = useQueryClient()
  const [params] = useSearchParams()
  const identities = useIdentities()
  const providers = useProviders()
  const startLink = useStartLink()
  const unlink = useUnlinkIdentity()
  const [target, setTarget] = useState<Identity | null>(null)
  const [refused, setRefused] = useState(false)

  const names = new Map((providers.data?.providers ?? []).map((p) => [p.id, p]))
  const nameOf = (id: string) => names.get(id)?.name ?? id
  const iconOf = (id: string) => names.get(id)?.icon ?? 'key'
  const data = identities.data
  const fresh = data?.fresh === true
  const linked = params.get('linked') === '1'
  const errorParam = params.get('error')

  async function link(providerId: string) {
    setRefused(false)
    startLink.reset()
    try {
      const answer = await startLink.mutateAsync(providerId)
      const url = safeProviderRedirect(answer.redirect_to)
      if (url === null) {
        setRefused(true)
        return
      }
      hardNavigate(url)
    } catch {
      // The failure is on the mutation (shown below).
    }
  }

  async function confirmUnlink() {
    if (target === null) return
    try {
      const answer = await unlink.mutateAsync(target.id)
      setTarget(null)
      if (answer.signed_out) {
        // The method this session used is gone: the session ended with it.
        clearCsrfToken()
        client.clear()
        hardNavigate('/account/')
        return
      }
      useToast.getState().show(t('account:methods.unlinked'))
    } catch (error) {
      // Already gone (another tab, an owner): the list refreshes, and that is what was asked for.
      if (error instanceof ApiError && error.code === 'not_found') {
        setTarget(null)
        unlink.reset()
      }
    }
  }

  const columns: Column<Identity>[] = [
    {
      key: 'provider',
      header: t('account:methods.columns.provider'),
      primary: true,
      render: (i) => (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <ProviderIcon icon={iconOf(i.provider_id)} fontSize="small" />
          <span>{nameOf(i.provider_id)}</span>
          {i.current ? (
            <Chip size="small" variant="outlined" label={t('account:methods.current')} />
          ) : null}
        </Box>
      ),
    },
    {
      key: 'account',
      header: t('account:methods.columns.account'),
      render: (i) => (
        <Box sx={{ overflowWrap: 'anywhere' }}>
          {i.username || i.email || '–'}
          {i.email && i.email !== i.username ? (
            <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>
              {i.email}
            </Typography>
          ) : null}
          {i.email && i.email_verified ? (
            <Chip size="small" variant="outlined" label={t('account:methods.verified')} sx={{ ml: 0.5 }} />
          ) : null}
        </Box>
      ),
    },
    {
      key: 'linked',
      header: t('account:methods.columns.linked'),
      render: (i) => <TimeText iso={i.linked_at} />,
    },
    {
      key: 'lastSignIn',
      header: t('account:methods.columns.lastSignIn'),
      render: (i) => <TimeText iso={i.last_login_at} fallback={t('account:methods.never')} />,
    },
    {
      key: 'actions',
      header: t('account:methods.columns.actions'),
      actions: true,
      render: (i) => (
        <Button
          size="small"
          color="error"
          disabled={!i.can_unlink || !fresh}
          aria-label={t('account:methods.unlinkLabel', { name: nameOf(i.provider_id) })}
          onClick={() => {
            unlink.reset()
            setTarget(i)
          }}
        >
          {t('account:methods.unlink')}
        </Button>
      ),
    },
  ]

  return (
    <>
      <PageHeader title={t('account:methods.title')} subtitle={t('account:methods.intro')} />
      <Box sx={{ display: 'grid', gap: 2 }}>
        {linked ? (
          <Alert severity="success" role="status">
            {t('account:methods.linkedDone')}
          </Alert>
        ) : null}
        {errorParam !== null ? (
          <Alert severity="error" role="alert">
            <AlertTitle>{t('account:methods.linkFailed')}</AlertTitle>
            {codeText(t, errorParam)}
          </Alert>
        ) : null}

        {identities.isPending ? <PageSkeleton /> : null}
        {identities.isError ? (
          <ErrorNotice error={identities.error} onRetry={() => void identities.refetch()} />
        ) : null}

        {data && !fresh ? <ReauthNotice /> : null}

        {data ? (
          <ResponsiveTable
            label={t('account:methods.title')}
            columns={columns}
            rows={data.identities}
            rowKey={(i) => i.id}
          />
        ) : null}
        {data && data.identities.length === 1 ? (
          <Typography variant="body2" color="text.secondary">
            {t('account:methods.lastOne')}
          </Typography>
        ) : null}

        {data && data.linkable.length > 0 ? (
          <Card component="section" aria-labelledby="add-method-title">
            <CardContent sx={{ display: 'grid', gap: 1.5 }}>
              <Typography id="add-method-title" variant="h3" component="h2">
                {t('account:methods.addTitle')}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t('account:methods.addBody')}
              </Typography>
              {startLink.isError ? <ErrorNotice error={startLink.error} /> : null}
              {refused ? (
                <Alert severity="error" role="alert">
                  {t('errors:provider_unavailable')}
                </Alert>
              ) : null}
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {data.linkable.map((id) => (
                  <Button
                    key={id}
                    variant="outlined"
                    disabled={!fresh || startLink.isPending}
                    startIcon={<ProviderIcon icon={iconOf(id)} />}
                    onClick={() => void link(id)}
                  >
                    {t('account:methods.link', { name: nameOf(id) })}
                  </Button>
                ))}
              </Box>
            </CardContent>
          </Card>
        ) : null}

        <Typography variant="body2" color="text.secondary">
          {t('account:methods.effects')}
        </Typography>
      </Box>

      <ConfirmDialog
        open={target !== null}
        title={target ? t('account:methods.unlinkTitle', { name: nameOf(target.provider_id) }) : ''}
        body={
          target?.current
            ? `${t('account:methods.unlinkBody')} ${t('account:methods.unlinkCurrent')}`
            : t('account:methods.unlinkBody')
        }
        confirmLabel={t('account:methods.unlink')}
        pending={unlink.isPending}
        error={unlink.error}
        onClose={() => {
          unlink.reset()
          setTarget(null)
        }}
        onConfirm={() => void confirmUnlink()}
      />
    </>
  )
}
