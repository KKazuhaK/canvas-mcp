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
import TimeText from '@/components/TimeText'
import { useDeleteCanvasToken, useVerifyCanvasToken } from '@/query/hooks'
import { useLanguage } from '@/stores/language'
import { useToast } from '@/stores/toast'
import { formatDateTime } from '@/utils/time'
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
  const verify = useVerifyCanvasToken()
  const remove = useDeleteCanvasToken()
  const [confirmOpen, setConfirmOpen] = useState(false)

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
          <Detail label={t('account:enrolled.lastUsed')}>
            <TimeText iso={canvas.last_used_at} />
          </Detail>
          <Detail label={t('account:enrolled.enrolled')}>
            <TimeText iso={canvas.enrolled_at} />
          </Detail>
          <Detail label={t('account:enrolled.updated')}>
            <TimeText iso={canvas.updated_at} />
          </Detail>
          <Detail label={t('account:enrolled.lastChecked')}>
            <TimeText iso={canvas.last_checked_at} />
          </Detail>
        </Box>
        {verify.isError ? <ErrorNotice error={verify.error} /> : null}
        {remove.isError && !confirmOpen ? <ErrorNotice error={remove.error} /> : null}
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          <Button
            variant="outlined"
            disabled={verify.isPending}
            onClick={() =>
              verify.mutate(undefined, {
                onSuccess: () => useToast.getState().show(t('account:enrolled.rechecked')),
              })
            }
          >
            {verify.isPending ? t('account:enrolled.rechecking') : t('account:enrolled.recheck')}
          </Button>
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

/** The Canvas token UI for every enrollment state. Shared by the home page and /token. */
export default function TokenSection({ canvas }: { canvas: CanvasTokenStatus }) {
  const { t } = useTranslation()
  const lang = useLanguage((s) => s.lang)

  if (canvas.state === 'none') return <EnrollCard />

  const sinceText = formatDateTime(canvas.invalid_since, lang)
  return (
    <Box sx={{ display: 'grid', gap: 2 }}>
      {canvas.state === 'invalid' ? (
        <Alert severity="warning" role="alert">
          <AlertTitle>{t('account:invalid.title')}</AlertTitle>
          {sinceText
            ? t('account:invalid.body', { date: sinceText })
            : t('account:invalid.bodyNoDate')}
        </Alert>
      ) : null}
      {canvas.state === 'unknown' ? <Alert severity="info" role="note">{t('account:unknown.body')}</Alert> : null}
      <EnrolledCard canvas={canvas} />
      {/* Open by default when Canvas rejected the stored token: the fix is the next step. */}
      <ReplaceDisclosure key={canvas.state} defaultExpanded={canvas.state === 'invalid'} />
    </Box>
  )
}
