import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import TextField from '@mui/material/TextField'
import { useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { putCanvasToken } from '@/api/endpoints'
import { ApiError, toApiError } from '@/api/errors'
import ErrorNotice from '@/components/ErrorNotice'
import { refreshAfterTokenChange } from '@/query/hooks'
import { useToast } from '@/stores/toast'
import { TOKEN_MAX_LENGTH, TOKEN_MIN_LENGTH, checkTokenShape } from '@/utils/tokenInput'

/**
 * The Canvas token form. The token is write-only:
 *
 * - a password-type input (never echoed), autocomplete and spellcheck off;
 * - held in component state only, and sent once in the PUT body;
 * - NOT passed through useMutation (its `variables` would sit in the mutation
 *   cache), never part of a query key, never logged, never put in a URL;
 * - cleared from state as soon as the request settles, success or failure.
 */
export default function TokenForm({
  submitLabel,
  onSaved,
}: {
  submitLabel: string
  onSaved?: () => void
}) {
  const { t } = useTranslation()
  const client = useQueryClient()
  const [value, setValue] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<unknown>(null)

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    if (pending) return
    const checked = checkTokenShape(value)
    if (!checked.ok) {
      setValue('')
      setError(new ApiError(422, checked.code))
      return
    }
    setPending(true)
    setError(null)
    try {
      await putCanvasToken(checked.token)
      useToast.getState().show(t('account:enroll.saved'))
      await refreshAfterTokenChange(client)
      onSaved?.()
    } catch (e) {
      setError(toApiError(e))
    } finally {
      setValue('')
      setPending(false)
    }
  }

  return (
    <Box component="form" noValidate onSubmit={(e) => void onSubmit(e)} sx={{ display: 'grid', gap: 2 }}>
      <Alert severity="warning" icon={false} role="note">
        <strong>{t('account:enroll.warning')}</strong>
      </Alert>
      <TextField
        label={t('account:enroll.field')}
        name="canvas_token"
        type="password"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        required
        fullWidth
        disabled={pending}
        helperText={t('account:enroll.helper', { min: TOKEN_MIN_LENGTH, max: TOKEN_MAX_LENGTH })}
        slotProps={{
          htmlInput: {
            autoComplete: 'off',
            autoCapitalize: 'off',
            autoCorrect: 'off',
            spellCheck: false,
            minLength: TOKEN_MIN_LENGTH,
            maxLength: TOKEN_MAX_LENGTH,
          },
        }}
      />
      {error ? <ErrorNotice error={error} /> : null}
      <Box>
        <Button type="submit" variant="contained" disabled={pending || value.length === 0}>
          {pending ? t('account:enroll.submitting') : submitLabel}
        </Button>
      </Box>
    </Box>
  )
}
