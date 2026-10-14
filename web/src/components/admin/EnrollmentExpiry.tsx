import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import type { AdminEnrollment } from '@/api/types'
import { useLanguage } from '@/stores/language'
import { formatCalendarDate } from '@/utils/time'

export default function EnrollmentExpiry({ enrollment }: { enrollment: AdminEnrollment | null }) {
  const { t } = useTranslation()
  const language = useLanguage((state) => state.lang)
  if (!enrollment) return <Typography variant="body2">–</Typography>
  const known = enrollment.expiry_source === 'canvas'
  const value = known ? (enrollment.expires_on === null ? t('account:expiry.never') : formatCalendarDate(enrollment.expires_on, language) ?? t('account:expiry.sources.unknown')) : t('account:expiry.sources.unknown')
  return <Box sx={{ display: 'grid', gap: 0.5, justifyItems: 'start' }}>
    <Typography variant="body2">{value}</Typography>
    {known && (enrollment.expiry_notice === 'soon' || enrollment.expiry_notice === 'passed') && <Chip size="small" color="warning"
      label={t(enrollment.expiry_notice === 'passed' ? 'admin:enrollments.expired' : 'admin:enrollments.expiring')} />}
  </Box>
}
