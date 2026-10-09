import Alert, { type AlertProps } from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Button from '@mui/material/Button'
import { useTranslation } from 'react-i18next'
import { isReauthRequired } from '@/api/errors'
import { errorText } from '@/utils/errorText'
import ReauthNotice from './ReauthNotice'

interface Props {
  error: unknown
  title?: string
  onRetry?: () => void
  severity?: AlertProps['severity']
}

/** A localized Alert for any failure. Text comes only from the closed code map. */
export default function ErrorNotice({ error, title, onRetry, severity = 'error' }: Props) {
  const { t } = useTranslation()
  if (isReauthRequired(error)) return <ReauthNotice />
  return (
    <Alert
      severity={severity}
      role="alert"
      action={
        onRetry ? (
          <Button color="inherit" size="small" onClick={onRetry}>
            {t('common:actions.retry')}
          </Button>
        ) : undefined
      }
    >
      {title ? <AlertTitle>{title}</AlertTitle> : null}
      {errorText(t, error)}
    </Alert>
  )
}
