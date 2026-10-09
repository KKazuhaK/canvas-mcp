import { Outlet } from 'react-router'
import { useMe } from '@/query/hooks'
import { ForbiddenNotice, PageSkeleton } from '@/views/StateViews'

/**
 * Client-side gate for owner-only pages (UX only: the server re-authorises every
 * admin call, and asks for a recent sign-in). Must sit inside RequireAuth, so `me`
 * is already loaded.
 */
export default function RequireOwner() {
  const me = useMe()
  if (!me.data) return <PageSkeleton />
  if (!me.data.features.admin) return <ForbiddenNotice />
  return <Outlet />
}
