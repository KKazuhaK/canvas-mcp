import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import Accordion from '@mui/material/Accordion'
import AccordionDetails from '@mui/material/AccordionDetails'
import AccordionSummary from '@mui/material/AccordionSummary'
import Alert from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Typography from '@mui/material/Typography'
import { useState, type ReactNode } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import type { CanvasTokenStatus } from '@/api/types'
import ConfirmDialog from '@/components/ConfirmDialog'
import ErrorNotice from '@/components/ErrorNotice'
import ExternalLink from '@/components/ExternalLink'
import TimeText from '@/components/TimeText'
import { useDeleteCanvasToken, useRecheckCanvasToken } from '@/query/hooks'
import { useLanguage } from '@/stores/language'
import { useToast } from '@/stores/toast'
import { formatCalendarDate, formatDateTime } from '@/utils/time'
import TokenForm from './TokenForm'

function EnrollCard() {
  const { t } = useTranslation()
  return (
    <Card component="section" aria-labelledby="enroll-title">
      <CardContent sx={{ display: 'grid', gap: 2 }}>
        <Typography id="enroll-title" variant="h2" component="h2">
          {t('account:enroll.title')}
        </Typography>
        <Box component="ol" sx={{ m: 0, pl: 3, display: 'grid', gap: 0.5 }}>
          {(['one', 'two', 'three'] as const).map((step) => (
            <li key={step}>
              <Trans
                i18nKey={`account:enroll.steps.${step}`}
                components={{ b: <strong />, c: <code /> }}
              />
            </li>
          ))}
        </Box>
        <TokenForm submitLabel={t('account:enroll.submit')} />
      </CardContent>
    </Card>
  )
}

function Detail({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <Typography component="dt" variant="body2" color="text.secondary">
        {label}
      </Typography>
      <Typography component="dd" variant="body2" sx={{ m: 0, overflowWrap: 'anywhere' }}>
        {children}
      </Typography>
    </>
  )
}

function EnrolledCard({ canvas }: { canvas: CanvasTokenStatus }) {
  const { t } = useTranslation()
  const lang = useLanguage((s) => s.lang)
  const recheck = useRecheckCanvasToken()
  const remove = useDeleteCanvasToken()
  const [confirmOpen, setConfirmOpen] = useState(false)
  const expires = formatCalendarDate(canvas.expires_on, lang)

  return (
    <Card component="section" aria-labelledby="enrolled-title">
      <CardContent sx={{ display: 'grid', gap: 2 }}>
        <Typography id="enrolled-title" variant="h2" component="h2">
          {t('account:enrolled.title')}
        </Typography>
        <Box
          component="dl"
          sx={{ m: 0, display: 'grid', gridTemplateColumns: 'minmax(7rem, auto) 1fr', gap: 1, columnGap: 2 }}
        >
          <Detail label={t('account:enrolled.canvasUser')}>
            {canvas.canvas_user_name ?? t('common:time.unknown')}
            {canvas.canvas_user_id !== null ? (
              <Typography component="span" variant="body2" color="text.secondary">
                {' '}
                ({t('account:enrolled.canvasUserId', { id: canvas.canvas_user_id })})
              </Typography>
            ) : null}
          </Detail>
          {canvas.school ? (
            <Detail label={t('account:enrolled.school')}>
              {canvas.school.name}
              {canvas.school.name !== canvas.school.host ? (
                <Typography component="span" variant="body2" color="text.secondary">
                  {' '}
                  ({canvas.school.host})
                </Typography>
              ) : null}
              {!canvas.school.offered ? (
                <Typography component="span" variant="body2" color="warning.main">
                  {' '}
                  {t('account:enrolled.schoolNotOffered')}
                </Typography>
              ) : null}
            </Detail>
          ) : null}
          {expires ? <Detail label={t('account:enrolled.expires')}>{expires}</Detail> : null}
          <Detail label={t('account:enrolled.lastUsed')}>
            <TimeText iso={canvas.last_used_at} />
          </Detail>
          <Detail label={t('account:enrolled.lastVerified')}>
            <TimeText iso={canvas.last_verified_at} />
          </Detail>
          <Detail label={t('account:enrolled.enrolled')}>
            <TimeText iso={canvas.enrolled_at} />
          </Detail>
          <Detail label={t('account:enrolled.updated')}>
            <TimeText iso={canvas.updated_at} />
          </Detail>
        </Box>
        {canvas.settings_url ? (
          <Typography variant="body2">
            <ExternalLink href={canvas.settings_url}>{t('account:enrolled.settingsLink')}</ExternalLink>
          </Typography>
        ) : null}
        {recheck.isError ? <ErrorNotice error={recheck.error} /> : null}
        {remove.isError && !confirmOpen ? <ErrorNotice error={remove.error} /> : null}
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          {canvas.recheck_allowed ? (
            <Button
              variant="outlined"
              disabled={recheck.isPending}
              onClick={() =>
                recheck.mutate(undefined, {
                  onSuccess: ({ result }) =>
                    useToast
                      .getState()
                      .show(t(result === 'restored' ? 'account:enrolled.restored' : 'account:enrolled.unchanged')),
                })
              }
            >
              {recheck.isPending ? t('account:enrolled.rechecking') : t('account:enrolled.recheck')}
            </Button>
          ) : null}
          <Button color="error" onClick={() => setConfirmOpen(true)}>
            {t('account:enrolled.delete.button')}
          </Button>
        </Box>
      </CardContent>
      <ConfirmDialog
        open={confirmOpen}
        title={t('account:enrolled.delete.confirmTitle')}
        body={t('account:enrolled.delete.confirmBody')}
        confirmLabel={t('account:enrolled.delete.button')}
        pending={remove.isPending}
        error={remove.error}
        onClose={() => {
          remove.reset()
          setConfirmOpen(false)
        }}
        onConfirm={() =>
          remove.mutate(undefined, {
            onSuccess: () => {
              setConfirmOpen(false)
              useToast.getState().show(t('account:enrolled.delete.done'))
            },
          })
        }
      />
    </Card>
  )
}

function ReplaceDisclosure({ defaultExpanded }: { defaultExpanded: boolean }) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(defaultExpanded)
  return (
    <Accordion
      expanded={expanded}
      onChange={(_e, next) => setExpanded(next)}
      disableGutters
      variant="outlined"
      sx={{ '&::before': { display: 'none' } }}
      // Unmounted while collapsed, so an empty token field is not sitting in the DOM.
      slotProps={{ transition: { unmountOnExit: true } }}
    >
      <AccordionSummary expandIcon={<ExpandMoreIcon />} aria-controls="replace-token-panel" id="replace-token-header">
        <Typography variant="h3" component="h2">
          {t('account:enrolled.replace.summary')}
        </Typography>
      </AccordionSummary>
      <AccordionDetails id="replace-token-panel">
        <TokenForm submitLabel={t('account:enrolled.replace.submit')} onSaved={() => setExpanded(false)} />
      </AccordionDetails>
    </Accordion>
  )
}

function InvalidBanner({ canvas }: { canvas: CanvasTokenStatus }) {
  const { t } = useTranslation()
  const lang = useLanguage((s) => s.lang)
  const since = formatDateTime(canvas.invalid_since, lang)
  const reason = canvas.invalid_reason ?? 'canvas_token_rejected'
  return (
    <Alert severity="warning" role="alert">
      <AlertTitle>{t(`account:invalid.${reason}.title`)}</AlertTitle>
      {t(`account:invalid.${reason}.body`)}
      {since ? ` ${t('account:invalid.since', { date: since })}` : ''}
    </Alert>
  )
}

function ExpiryBanner({ canvas }: { canvas: CanvasTokenStatus }) {
  const { t } = useTranslation()
  const lang = useLanguage((s) => s.lang)
  if (canvas.expiry_notice === 'none') return null
  const date = formatCalendarDate(canvas.expires_on, lang) ?? ''
  const passed = canvas.expiry_notice === 'passed'
  return (
    <Alert severity={passed ? 'warning' : 'info'} role="note">
      <AlertTitle>{passed ? t('account:expiry.passedTitle') : t('account:expiry.soonTitle')}</AlertTitle>
      {passed ? t('account:expiry.passedBody', { date }) : t('account:expiry.soonBody', { date })}
    </Alert>
  )
}

/** The Canvas token UI for every enrollment state. Shared by the home page and /token. */
export default function TokenSection({ canvas }: { canvas: CanvasTokenStatus }) {
  if (canvas.state === 'none') return <EnrollCard />

  return (
    <Box sx={{ display: 'grid', gap: 2 }}>
      {canvas.state === 'invalid' ? <InvalidBanner canvas={canvas} /> : null}
      <ExpiryBanner canvas={canvas} />
      <EnrolledCard canvas={canvas} />
      {/* Open by default when the stored token is unusable: the fix is the next step. */}
      <ReplaceDisclosure key={canvas.state} defaultExpanded={canvas.state === 'invalid'} />
    </Box>
  )
}
