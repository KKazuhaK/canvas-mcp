import Alert from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Typography from '@mui/material/Typography'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { Grant } from '@/api/types'
import ConfirmDialog from '@/components/ConfirmDialog'
import ErrorNotice from '@/components/ErrorNotice'
import McpUrlCard from '@/components/McpUrlCard'
import PageHeader from '@/components/PageHeader'
import { useGrants, useRevokeGrant } from '@/query/hooks'
import { useLanguage } from '@/stores/language'
import { useToast } from '@/stores/toast'
import { formatDateTime } from '@/utils/time'
import { PageSkeleton } from './StateViews'

/** /connected-apps: MCP grants (OAuth clients the person approved). */
export default function ConnectedAppsView() {
  const { t } = useTranslation()
  const lang = useLanguage((s) => s.lang)
  const grants = useGrants()
  const revoke = useRevokeGrant()
  const [target, setTarget] = useState<Grant | null>(null)

  const date = (iso: string | null) => formatDateTime(iso, lang) ?? t('common:time.unknown')

  return (
    <>
      <PageHeader title={t('account:grants.title')} subtitle={t('account:grants.intro')} />
      <Box sx={{ display: 'grid', gap: 2 }}>
        {grants.isPending ? <PageSkeleton /> : null}
        {grants.isError ? (
          <ErrorNotice error={grants.error} onRetry={() => void grants.refetch()} />
        ) : null}

        {grants.data && grants.data.grants.length === 0 ? (
          <Alert severity="info" role="note">
            <AlertTitle>{t('account:grants.emptyTitle')}</AlertTitle>
            {t('account:grants.emptyBody')}
          </Alert>
        ) : null}

        {grants.data && grants.data.grants.length > 0 ? (
          <Box component="ul" aria-label={t('account:grants.title')} sx={{ listStyle: 'none', m: 0, p: 0, display: 'grid', gap: 1.5 }}>
            {grants.data.grants.map((grant) => {
              const revoked = grant.revoked_at !== null
              return (
                <Card component="li" key={grant.id} sx={{ opacity: revoked ? 0.6 : 1 }}>
                  <CardContent sx={{ display: 'flex', gap: 2, alignItems: 'flex-start', justifyContent: 'space-between' }}>
                    <Box sx={{ minWidth: 0 }}>
                      <Typography sx={{ fontWeight: 600, overflowWrap: 'anywhere' }}>
                        {grant.client_name}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {t('account:grants.connected', { date: date(grant.created_at) })}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {grant.last_used_at
                          ? t('account:grants.lastUsed', { date: date(grant.last_used_at) })
                          : t('account:grants.neverUsed')}
                      </Typography>
                      {revoked ? (
                        <Typography variant="body2" color="text.secondary">
                          {t('account:grants.revokedOn', { date: date(grant.revoked_at) })}
                        </Typography>
                      ) : null}
                    </Box>
                    {!revoked ? (
                      <Button color="error" size="small" onClick={() => setTarget(grant)}>
                        {t('account:grants.revoke')}
                      </Button>
                    ) : null}
                  </CardContent>
                </Card>
              )
            })}
          </Box>
        ) : null}

        <McpUrlCard />
      </Box>

      <ConfirmDialog
        open={target !== null}
        title={t('account:grants.confirmTitle', { client: target?.client_name ?? '' })}
        body={t('account:grants.confirmBody', { client: target?.client_name ?? '' })}
        confirmLabel={t('account:grants.revoke')}
        pending={revoke.isPending}
        error={revoke.error}
        onClose={() => {
          revoke.reset()
          setTarget(null)
        }}
        onConfirm={() => {
          if (!target) return
          revoke.mutate(target.id, {
            onSuccess: () => {
              setTarget(null)
              useToast.getState().show(t('account:grants.done'))
            },
          })
        }}
      />
    </>
  )
}
