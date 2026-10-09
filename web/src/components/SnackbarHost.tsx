import Alert from '@mui/material/Alert'
import Snackbar from '@mui/material/Snackbar'
import { useToast } from '@/stores/toast'

export default function SnackbarHost() {
  const id = useToast((s) => s.id)
  const message = useToast((s) => s.message)
  const severity = useToast((s) => s.severity)
  const hide = useToast((s) => s.hide)
  return (
    <Snackbar
      key={id}
      open={message !== null}
      autoHideDuration={5000}
      onClose={(_event, reason) => {
        if (reason !== 'clickaway') hide()
      }}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
    >
      <Alert onClose={hide} severity={severity} variant="filled" sx={{ width: '100%' }}>
        {message}
      </Alert>
    </Snackbar>
  )
}
