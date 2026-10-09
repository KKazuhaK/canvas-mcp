import type { ReactNode } from 'react'
import type { MeResponse } from '@/api/types'
import DisabledView from '@/views/DisabledView'
import PendingView from '@/views/PendingView'
import AccountLayout from './AccountLayout'

/**
 * The signed-in frame plus the account-status gate. A pending or disabled
 * account sees only its status screen: no token form, no write tools, no nav.
 * With no children it renders the matched child route.
 */
export default function AccountShell({ me, children }: { me: MeResponse; children?: ReactNode }) {
  if (me.account.status === 'pending') {
    return (
      <AccountLayout me={me}>
        <PendingView />
      </AccountLayout>
    )
  }
  if (me.account.status === 'disabled') {
    return (
      <AccountLayout me={me}>
        <DisabledView />
      </AccountLayout>
    )
  }
  return <AccountLayout me={me}>{children}</AccountLayout>
}
