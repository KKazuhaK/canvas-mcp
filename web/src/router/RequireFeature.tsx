import { Outlet } from 'react-router'
import type { Features } from '@/api/types'
import { useMe } from '@/query/hooks'
import { NotFoundNotice, PageSkeleton } from '@/views/StateViews'

/**
 * Routes for a feature the server does not serve are not there: the server says so
 * in GET /me `features`, and the screen answers like any unknown page. Must sit
 * inside RequireAuth.
 */
export default function RequireFeature({ feature }: { feature: keyof Features }) {
  const me = useMe()
  if (!me.data) return <PageSkeleton />
  if (!me.data.features[feature]) return <NotFoundNotice />
  return <Outlet />
}
