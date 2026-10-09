import { useEffect, type ReactNode } from 'react'
import type { MeResponse } from '@/api/types'
import { useDisplayZone } from '@/stores/displayZone'
import { useLanguage } from '@/stores/language'
import PendingView from '@/views/PendingView'
import AccountLayout from './AccountLayout'

/**
 * The signed-in frame plus the account-status gate. A pending account sees only
 * its status screen: no token form, no write tools, no nav. (A disabled account is
 * signed out by the server, so it never gets this far.) With no children it
 * renders the matched child route.
 */
export default function AccountShell({ me, children }: { me: MeResponse; children?: ReactNode }) {
  const remembered = me.ui_locale
  const applyRemembered = useLanguage((s) => s.applyRemembered)
  const setZone = useDisplayZone((s) => s.setZone)
  const displayZone = me.server.display_timezone

  // Times are shown in the zone the server uses for its own pages.
  useEffect(() => {
    setZone(displayZone)
  }, [displayZone, setZone])

  // The language the server remembers (shared with the server-rendered pages) applies
  // only when this browser has no choice of its own yet.
  useEffect(() => {
    if (remembered !== null) applyRemembered(remembered)
  }, [remembered, applyRemembered])

  if (me.account.status === 'pending') {
    return (
      <AccountLayout me={me}>
        <PendingView />
      </AccountLayout>
    )
  }
  return <AccountLayout me={me}>{children}</AccountLayout>
}
