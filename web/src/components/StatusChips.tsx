import Chip from '@mui/material/Chip'
import { useTranslation } from 'react-i18next'
import type { AdminAccountStatus, CanvasTokenState } from '@/api/types'

const ACCOUNT_COLOR: Record<AdminAccountStatus, 'success' | 'warning' | 'default'> = {
  active: 'success',
  pending: 'warning',
  disabled: 'default',
  missing: 'default',
}

export function AccountStatusChip({ status }: { status: AdminAccountStatus }) {
  const { t } = useTranslation()
  return <Chip size="small" color={ACCOUNT_COLOR[status]} label={t(`common:status.${status}`)} />
}

const TOKEN_COLOR: Record<CanvasTokenState, 'success' | 'warning' | 'default'> = {
  active: 'success',
  invalid: 'warning',
  none: 'default',
}

/** The state of a stored Canvas token, as a small chip. */
export function TokenStateChip({ state }: { state: CanvasTokenState }) {
  const { t } = useTranslation()
  return (
    <Chip
      size="small"
      variant="outlined"
      color={TOKEN_COLOR[state]}
      label={t(`common:tokenState.${state}`)}
    />
  )
}
