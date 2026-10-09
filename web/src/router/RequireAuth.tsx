import { Navigate, useLocation } from 'react-router'
import AccountShell from '@/layouts/AccountShell'
import PublicLayout from '@/layouts/PublicLayout'
import ErrorNotice from '@/components/ErrorNotice'
import { isUnauthenticated } from '@/api/errors'
import { useMe } from '@/query/hooks'
import { FullPageLoading } from '@/views/StateViews'
import { loginPathFor } from '@/utils/returnTo'
import { SESSION_ENDED_STATE } from '@/utils/sessionEnded'

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
    // Data in the cache means the session was good a moment ago and has now ended; a
    // first visit by someone who never signed in gets no such message.
    return (
      <Navigate
        to={loginPathFor(location.pathname + location.search)}
        replace
        state={me.data ? SESSION_ENDED_STATE : undefined}
      />
    )
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
