import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import type { AppClient } from '@/api/types'

/**
 * Who an app is, in the order of how far it can be trusted: a domain the app was fetched
 * from is shown first, with a "verified" badge, and the name it gives itself in muted
 * text; a self-registered app shows its name with a warning that anyone could pick it.
 * Text from the app is plain text here (React escapes it).
 */
export default function AppIdentity({ client, large = false }: { client: AppClient; large?: boolean }) {
  const { t } = useTranslation()
  const variant = large ? 'h2' : 'body1'
  if (client.verified) {
    return (
      <Box sx={{ display: 'grid', gap: 0.25, justifyItems: 'start', minWidth: 0 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <Typography variant={variant} component="p" sx={{ fontWeight: 600, overflowWrap: 'anywhere' }}>
            {client.label}
          </Typography>
          <Chip size="small" color="success" variant="outlined" label={t('account:apps.verified')} />
        </Box>
        {client.name && client.name !== client.label ? (
          <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>
            {t('account:apps.selfName', { name: client.name })}
          </Typography>
        ) : null}
      </Box>
    )
  }
  return (
    <Box sx={{ display: 'grid', gap: 0.25, justifyItems: 'start', minWidth: 0 }}>
      <Typography variant={variant} component="p" sx={{ fontWeight: 600, overflowWrap: 'anywhere' }}>
        {client.label || t('account:apps.unnamed')}
      </Typography>
      <Typography variant="caption" color="warning.main" sx={{ fontWeight: 500 }}>
        {t('account:apps.unverified')}
      </Typography>
    </Box>
  )
}
