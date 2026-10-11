import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Checkbox from '@mui/material/Checkbox'
import FormControlLabel from '@mui/material/FormControlLabel'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'

export default function CustodyNotice({ version, checked, onChange, disabled = false }: {
  version: number
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
}) {
  const { t, i18n } = useTranslation()
  const available = i18n.exists(`account:custody.v${version}`)
  return (
    <Box sx={{ display: 'grid', gap: 1 }}>
      <Alert severity="warning" icon={false} role="note">
        <Typography variant="body2">{available ? t(`account:custody.v${version}`) : t('account:custody.reload')}</Typography>
      </Alert>
      <FormControlLabel
        control={<Checkbox checked={checked} onChange={(_, value) => onChange(value)} disabled={disabled || !available} required />}
        label={t('account:custody.read')}
      />
    </Box>
  )
}
