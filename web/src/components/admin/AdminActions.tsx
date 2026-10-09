import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { AdminAction, AdminAccount, AdminActionResponse } from '@/api/types'
import ConfirmDialog from '@/components/ConfirmDialog'
import ErrorNotice from '@/components/ErrorNotice'
import {
  useAdminAccessAction,
  useAdminMarkInvalid,
  useAdminRemoveEnrollment,
} from '@/query/hooks'
import { useToast } from '@/stores/toast'

/** Actions that change something people cannot easily take back are confirmed first. */
const NEEDS_CONFIRM: ReadonlySet<AdminAction> = new Set([
  'deny',
  'disable',
  'mark_invalid',
  'remove_enrollment',
])
const PRIMARY: ReadonlySet<AdminAction> = new Set(['approve', 'enable'])
const DESTRUCTIVE: ReadonlySet<AdminAction> = new Set(['deny', 'disable', 'remove_enrollment'])

/**
 * The row actions the server offers for one account (`account.actions`, computed
 * server-side), each with its confirmation where one is due. The UI offers exactly
 * the server's list and the server re-checks the owner in the store transaction.
 */
export default function AdminActions({ account }: { account: AdminAccount }) {
  const { t } = useTranslation()
  const access = useAdminAccessAction()
  const mark = useAdminMarkInvalid()
  const remove = useAdminRemoveEnrollment()
  const [confirm, setConfirm] = useState<AdminAction | null>(null)

  const busy = access.isPending || mark.isPending || remove.isPending
  const error = access.error ?? mark.error ?? remove.error
  const name = account.display_name

  function reset() {
    access.reset()
    mark.reset()
    remove.reset()
  }

  // mutateAsync, not mutate(.., { onSuccess }): the list refreshes as soon as the
  // action lands and this row may be gone (an approved account leaves the pending
  // list), and per-call callbacks are dropped once the component has unmounted.
  async function run(action: AdminAction) {
    try {
      let result: AdminActionResponse
      switch (action) {
        case 'approve':
        case 'deny':
        case 'disable':
        case 'enable':
          result = await access.mutateAsync({ id: account.id, action })
          break
        case 'mark_invalid':
          result = await mark.mutateAsync(account.id)
          break
        case 'remove_enrollment':
          result = await remove.mutateAsync(account.id)
          break
      }
      setConfirm(null)
      useToast
        .getState()
        .show(result.changed ? t(`admin:done.${action}`) : t('admin:unchanged'), result.changed ? 'success' : 'info')
    } catch {
      // The failure is on the mutation (shown below or in the dialog).
    }
  }

  function choose(action: AdminAction) {
    reset()
    if (NEEDS_CONFIRM.has(action)) setConfirm(action)
    else void run(action)
  }

  return (
    <Box sx={{ display: 'grid', gap: 1 }}>
      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
        {account.actions.map((action) => (
          <Button
            key={action}
            size="small"
            variant={PRIMARY.has(action) ? 'contained' : 'text'}
            color={DESTRUCTIVE.has(action) ? 'error' : 'primary'}
            disabled={busy}
            aria-label={`${t(`admin:actions.${action}`)}: ${name}`}
            onClick={() => choose(action)}
          >
            {t(`admin:actions.${action}`)}
          </Button>
        ))}
      </Box>
      {error && confirm === null ? <ErrorNotice error={error} /> : null}
      <ConfirmDialog
        open={confirm !== null}
        title={confirm ? t(`admin:confirm.${confirm}.title`, { name }) : ''}
        body={confirm ? t(`admin:confirm.${confirm}.body`) : ''}
        confirmLabel={confirm ? t(`admin:actions.${confirm}`) : ''}
        destructive={confirm !== null && DESTRUCTIVE.has(confirm)}
        pending={busy}
        error={error}
        onClose={() => {
          reset()
          setConfirm(null)
        }}
        onConfirm={() => {
          if (confirm !== null) void run(confirm)
        }}
      />
    </Box>
  )
}
