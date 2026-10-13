import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'

export default function DraftStatus({ dirty, stale, reset }: { dirty: boolean; stale: boolean; reset: () => void }) {
  const { t } = useTranslation()
  if (!dirty) return null
  return <Alert severity={stale ? 'warning' : 'info'} role="status">
    <Typography variant="body2">{t(stale ? 'admin:workspace.staleDraft' : 'admin:workspace.unsaved')}</Typography>
    {stale && <Button size="small" onClick={reset}>{t('admin:workspace.discardDraft')}</Button>}
  </Alert>
}
