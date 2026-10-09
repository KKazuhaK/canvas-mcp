import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import ErrorNotice from './ErrorNotice'

interface Props {
  open: boolean
  title: string
  body?: string
  /** Extra content (e.g. a select) shown under the body. */
  children?: ReactNode
  confirmLabel: string
  destructive?: boolean
  /** True while the request is in flight: both buttons are disabled (double-submit guard). */
  pending?: boolean
  error?: unknown
  confirmDisabled?: boolean
  onConfirm: () => void
  onClose: () => void
}

/** Every destructive action goes through this dialog. */
export default function ConfirmDialog({
  open,
  title,
  body,
  children,
  confirmLabel,
  destructive = true,
  pending = false,
  error,
  confirmDisabled = false,
  onConfirm,
  onClose,
}: Props) {
  const { t } = useTranslation()
  return (
    <Dialog
      open={open}
      onClose={pending ? undefined : onClose}
      aria-labelledby="confirm-dialog-title"
      fullWidth
      maxWidth="xs"
    >
      <DialogTitle id="confirm-dialog-title">{title}</DialogTitle>
      <DialogContent>
        {body ? <DialogContentText>{body}</DialogContentText> : null}
        {children}
        {error ? (
          <Box sx={{ mt: 1.5 }}>
            <ErrorNotice error={error} />
          </Box>
        ) : null}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={pending}>
          {t('common:actions.cancel')}
        </Button>
        <Button
          onClick={onConfirm}
          disabled={pending || confirmDisabled}
          color={destructive ? 'error' : 'primary'}
          variant="contained"
        >
          {confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  )
}
