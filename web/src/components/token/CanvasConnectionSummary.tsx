import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Typography from '@mui/material/Typography'
import { Link as RouterLink, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { CanvasTokenStatus } from '@/api/types'
import { TokenStateChip } from '@/components/StatusChips'
import TimeText from '@/components/TimeText'
import { useLanguage } from '@/stores/language'
import { formatCalendarDate } from '@/utils/time'
import { ExpiryBanner, InvalidBanner } from './TokenSection'

export default function CanvasConnectionSummary({ canvas }: { canvas: CanvasTokenStatus }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const language = useLanguage((state) => state.lang)
  const needsAction = canvas.state !== 'active' || !canvas.custody.current || canvas.expiry_notice !== 'none'
  return <Card component="section" aria-labelledby="connection-summary-title"><CardContent sx={{ display: 'grid', gap: 2 }}>
    <Box sx={{ display: 'flex', gap: 1, justifyContent: 'space-between', flexWrap: 'wrap' }}>
      <Typography id="connection-summary-title" variant="h2" component="h2">{t(canvas.state === 'none' ? 'account:enroll.title' : 'account:enrolled.title')}</Typography>
      <TokenStateChip state={canvas.state} />
    </Box>
    {canvas.state === 'none' ? <Typography>{t('account:overview.addToken')}</Typography> : <>
      {canvas.state === 'invalid' && <InvalidBanner canvas={canvas} />}
      <ExpiryBanner canvas={canvas} onReplace={() => navigate('/token?replace=1')} />
      <Box component="dl" sx={{ m: 0, display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'auto 1fr' }, gap: 1 }}>
        <Typography component="dt" color="text.secondary">{t('account:enrolled.school')}</Typography>
        <Typography component="dd" sx={{ m: 0, overflowWrap: 'anywhere' }}>{canvas.school?.name ?? '–'}{canvas.school?.offered === false ? ` ${t('account:enrolled.schoolNotOffered')}` : ''}</Typography>
        <Typography component="dt" color="text.secondary">{t('account:enrolled.expires')}</Typography>
        <Typography component="dd" sx={{ m: 0 }}>{canvas.expiry_source === 'canvas' ? (formatCalendarDate(canvas.expires_on, language) ?? t('account:expiry.never')) : t('account:expiry.sources.unknown')}</Typography>
        <Typography component="dt" color="text.secondary">{t('account:enrolled.lastVerified')}</Typography>
        <Typography component="dd" sx={{ m: 0 }}><TimeText iso={canvas.last_verified_at} /></Typography>
      </Box>
    </>}
    <Box><Button component={RouterLink} to="/token" variant={needsAction ? 'contained' : 'outlined'}>{t(canvas.state === 'none' ? 'account:overview.connect' : !canvas.custody.current ? 'account:overview.reviewNotice' : 'account:overview.manageToken')}</Button></Box>
  </CardContent></Card>
}
