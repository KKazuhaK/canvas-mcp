import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Typography from '@mui/material/Typography'
import { Link as RouterLink } from 'react-router'
import { useTranslation } from 'react-i18next'
import { isUnauthenticated } from '@/api/errors'
import type { MeResponse } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'
import McpUrlCard from '@/components/McpUrlCard'
import PageHeader from '@/components/PageHeader'
import TokenSection from '@/components/token/TokenSection'
import AccountShell from '@/layouts/AccountShell'
import PublicLayout from '@/layouts/PublicLayout'
import { useMe } from '@/query/hooks'
import { FullPageLoading } from './StateViews'

function SignedOutHome() {
  const { t } = useTranslation()
  return (
    <PublicLayout>
      <Card component="section" aria-labelledby="signed-out-title">
        <CardContent sx={{ display: 'grid', gap: 2 }}>
          <Typography id="signed-out-title" variant="h1" component="h1">
            {t('auth:signedOut.title')}
          </Typography>
          <Typography>{t('auth:signedOut.body')}</Typography>
          <div>
            <Button component={RouterLink} to="/sign-in" variant="contained" size="large">
              {t('auth:signedOut.cta')}
            </Button>
          </div>
        </CardContent>
      </Card>
      <McpUrlCard />
    </PublicLayout>
  )
}

function AccountHome({ me }: { me: MeResponse }) {
  const { t } = useTranslation()
  return (
    <>
      <PageHeader
        title={t('account:home.title')}
        subtitle={t('account:home.signedInAs', {
          name: me.account.username || me.account.display_name,
        })}
      />
      <Box sx={{ display: 'grid', gap: 2 }}>
        {me.canvas ? <TokenSection canvas={me.canvas} /> : null}
        <McpUrlCard />
      </Box>
    </>
  )
}

/**
 * `/`: the signed-out landing page, or the account page, depending on GET /me.
 * A 401 here is the normal signed-out answer, not an error.
 */
export default function HomeView() {
  const me = useMe()
  if (me.isPending) return <FullPageLoading />
  if (isUnauthenticated(me.error)) return <SignedOutHome />
  if (me.isError) {
    return (
      <PublicLayout>
        <ErrorNotice error={me.error} onRetry={() => void me.refetch()} />
      </PublicLayout>
    )
  }
  return (
    <AccountShell me={me.data}>
      <AccountHome me={me.data} />
    </AccountShell>
  )
}
