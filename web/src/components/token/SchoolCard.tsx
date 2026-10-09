import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'

/**
 * EXTENSION POINT: school picker.
 *
 * School search and selection arrive from another branch. Until then this card
 * shows a disabled placeholder field and sends nothing to the API. The real
 * picker should replace the TextField, keep the card heading, and pass the
 * chosen school to the token PUT once the backend contract defines the field.
 */
export default function SchoolCard() {
  const { t } = useTranslation()
  return (
    <Card component="section" aria-labelledby="school-title">
      <CardContent sx={{ display: 'grid', gap: 1.5 }}>
        <Typography id="school-title" variant="h3" component="h2">
          {t('account:school.title')}
        </Typography>
        <TextField
          label={t('account:school.label')}
          value={t('account:school.value')}
          disabled
          size="small"
          fullWidth
          helperText={t('account:school.body')}
        />
      </CardContent>
    </Card>
  )
}
