import { Navigate, useLocation } from 'react-router'
import AccountShell from '@/layouts/AccountShell'
import PublicLayout from '@/layouts/PublicLayout'
import ErrorNotice from '@/components/ErrorNotice'
import { isUnauthenticated } from '@/api/errors'
import { useMe } from '@/query/hooks'
import { FullPageLoading } from '@/views/StateViews'
import { loginPathFor } from '@/utils/returnTo'

/**
 * Gate for every signed-in route. It reads the session from GET /me (React Query
 * cache), never from storage. The server remains the authority: every call is
 * re-checked there; this only decides what to draw.
 */
export default function RequireAuth() {
  const me = useMe()
  const location = useLocation()

  if (me.isPending) return <FullPageLoading />
  if (isUnauthenticated(me.error)) {
    return <Navigate to={loginPathFor(location.pathname + location.search)} replace />
  }
  if (me.isError) {
    return (
      <PublicLayout>
        <ErrorNotice error={me.error} onRetry={() => void me.refetch()} />
      </PublicLayout>
    )
  }
  return <AccountShell me={me.data} />
}
