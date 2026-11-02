import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Typography from '@mui/material/Typography'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { ExtensionPairing } from '@/api/types'
import CopyField from '@/components/CopyField'
import ErrorNotice from '@/components/ErrorNotice'
import { useCreateExtensionPairing } from '@/query/hooks'

/** The state the extension put in the URL hash: base64url, 16 to 128 characters. Anything else is ignored. */
const STATE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/

export function extensionStateFromHash(hash: string): string | null {
  const value = new URLSearchParams(hash.replace(/^#/, '')).get('extension-auth')
  return value !== null && STATE_PATTERN.test(value) ? value : null
}

function countdown(ms: number): string {
  const total = Math.max(0, Math.ceil(ms / 1000))
  return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, '0')}`
}

/**
 * Pairing with the browser extension. With `state` (the extension opened this page), one code is
 * requested and handed to the extension through a hidden element it reads; without it, the person asks
 * for a code and types it into the extension. The code is single use, lives only in this component's
 * state, is never logged, and is dropped when it expires.
 */
export default function ExtensionPairingCard({ state }: { state: string | null }) {
  const { t } = useTranslation()
  const create = useCreateExtensionPairing()
  const [pairing, setPairing] = useState<ExtensionPairing | null>(null)
  const [expired, setExpired] = useState(false)
  const [now, setNow] = useState(() => Date.now())
  const requestedFor = useRef<string | null>(null)
  const { mutate, reset } = create

  function request() {
    setExpired(false)
    mutate(undefined, { onSuccess: (result) => setPairing(result) })
  }

  // The extension's own request: exactly one code per state, even if this effect runs twice.
  useEffect(() => {
    if (state === null || requestedFor.current === state) return
    requestedFor.current = state
    mutate(undefined, { onSuccess: (result) => setPairing(result) })
  }, [state, mutate])

  const expiresAt = pairing ? Date.parse(pairing.expiresAt) : null
  useEffect(() => {
    if (expiresAt === null) return
    const drop = () => {
      setPairing(null)
      setExpired(true)
      reset() // also drops the code from the mutation's own result
    }
    const left = expiresAt - Date.now()
    if (!Number.isFinite(left) || left <= 0) {
      drop()
      return
    }
    setNow(Date.now())
    const tick = setInterval(() => setNow(Date.now()), 1000)
    const stop = setTimeout(drop, left)
    return () => {
      clearInterval(tick)
      clearTimeout(stop)
    }
  }, [expiresAt, reset])

  return (
    <Card component="section" aria-labelledby="extension-pairing-title">
      <CardContent sx={{ display: 'grid', gap: 2 }}>
        <Typography id="extension-pairing-title" variant="h2" component="h2">
          {t('account:extension.pairing.title')}
        </Typography>
        {state !== null ? (
          <Typography color="text.secondary">{t('account:extension.pairing.fromExtension')}</Typography>
        ) : (
          <Typography color="text.secondary">{t('account:extension.pairing.manualHelp')}</Typography>
        )}
        {create.isError ? <ErrorNotice error={create.error} onRetry={request} /> : null}
        {pairing ? (
          <Box sx={{ display: 'grid', gap: 1 }}>
            {state !== null ? (
              <>
                <div id="canvas-extension-authorization" data-state={state} data-code={pairing.code} hidden />
                <Typography role="status" sx={{ fontWeight: 600 }}>
                  {t('account:extension.pairing.returnToExtension')}
                </Typography>
              </>
            ) : null}
            <CopyField
              value={pairing.code}
              label={t('account:extension.pairing.codeLabel')}
              copyLabel={t('account:extension.pairing.copyLabel')}
            />
            <Typography variant="body2" color="text.secondary">
              {t('account:extension.pairing.expiresIn', { time: countdown((expiresAt ?? 0) - now) })}
            </Typography>
          </Box>
        ) : null}
        {expired && !pairing ? (
          <Typography role="status" color="text.secondary">
            {t('account:extension.pairing.expired')}
          </Typography>
        ) : null}
        {!pairing && !(state !== null && !expired && !create.isError) ? (
          <Box>
            <Button variant="outlined" onClick={request} disabled={create.isPending}>
              {t(state !== null ? 'account:extension.pairing.again' : 'account:extension.pairing.show')}
            </Button>
          </Box>
        ) : null}
      </CardContent>
    </Card>
  )
}
