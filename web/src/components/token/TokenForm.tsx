import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Skeleton from '@mui/material/Skeleton'
import TextField from '@mui/material/TextField'
import { useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { putCanvasToken } from '@/api/endpoints'
import { ApiError, toApiError } from '@/api/errors'
import type { CanvasTokenRequest } from '@/api/types'
import ConfirmDialog from '@/components/ConfirmDialog'
import ErrorNotice from '@/components/ErrorNotice'
import { refreshAfterTokenChange, useSchools } from '@/query/hooks'
import { useToast } from '@/stores/toast'
import { TOKEN_MAX_LENGTH, TOKEN_MIN_LENGTH, checkTokenShape } from '@/utils/tokenInput'
import SchoolPicker, { initialSelection, type SchoolSelection } from './SchoolPicker'

interface IdentityChange {
  enrolledName: string
  newName: string
  confirmation: string
}

function asText(value: string | number | undefined): string {
  return value === undefined ? '' : String(value)
}

/**
 * The Canvas token form. The token is write-only:
 *
 * - a password-type input (never echoed), autocomplete and spellcheck off;
 * - held in component state only, and sent once in the PUT body;
 * - NOT passed through useMutation (its `variables` would sit in the mutation
 *   cache), never part of a query key, never logged, never put in a URL;
 * - cleared from state as soon as the request settles, success or failure. The one
 *   exception is the "this token belongs to a different Canvas user" question: the
 *   server asks for a confirmation, and the same token is sent again together with
 *   it, so it stays in state until the person answers (then it is cleared too).
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
  const schools = useSchools()
  const [value, setValue] = useState('')
  const [expiresOn, setExpiresOn] = useState('')
  const [picked, setPicked] = useState<SchoolSelection | null | undefined>(undefined)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [change, setChange] = useState<IdentityChange | null>(null)

  const schoolData = schools.data
  const picker = schoolData?.mode === 'picker'
  const selection = picked !== undefined ? picked : schoolData ? initialSelection(schoolData) : null
  const needsSchool = picker && selection === null

  async function send(confirmation: string | null) {
    const checked = checkTokenShape(value)
    if (!checked.ok) {
      setValue('')
      setChange(null)
      setError(new ApiError(422, checked.code))
      return
    }
    const body: CanvasTokenRequest = { canvas_token: checked.token }
    if (picker && selection !== null) {
      body.school = selection.host
      if (selection.sig !== null) body.school_sig = selection.sig
    }
    if (expiresOn) body.expires_on = expiresOn
    if (confirmation !== null) body.confirm_identity_change = confirmation

    setPending(true)
    setError(null)
    let keepToken = false
    try {
      await putCanvasToken(body)
      setChange(null)
      setExpiresOn('')
      useToast.getState().show(t('account:enroll.saved'))
      await refreshAfterTokenChange(client)
      onSaved?.()
    } catch (e) {
      const failure = toApiError(e)
      if (failure.code === 'identity_change_required' && typeof failure.params.confirmation === 'string') {
        keepToken = true
        setChange({
          enrolledName: asText(failure.params.enrolled_user_name),
          newName: asText(failure.params.new_user_name),
          confirmation: failure.params.confirmation,
        })
      } else {
        setChange(null)
        setError(failure)
      }
    } finally {
      if (!keepToken) setValue('')
      setPending(false)
    }
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault()
    if (pending || needsSchool) return
    void send(null)
  }

  function cancelChange() {
    setChange(null)
    setValue('')
  }

  return (
    <Box component="form" noValidate onSubmit={onSubmit} sx={{ display: 'grid', gap: 2 }}>
      <Alert severity="warning" icon={false} role="note">
        <strong>{t('account:enroll.warning')}</strong>
      </Alert>

      {schools.isPending ? <Skeleton variant="rounded" height={40} /> : null}
      {schools.isError ? (
        <ErrorNotice error={schools.error} onRetry={() => void schools.refetch()} />
      ) : null}
      {schoolData ? (
        <SchoolPicker
          schools={schoolData}
          value={selection}
          onChange={setPicked}
          disabled={pending || change !== null}
        />
      ) : null}

      <TextField
        label={t('account:enroll.field')}
        name="canvas_token"
        type="password"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        required
        fullWidth
        disabled={pending || change !== null}
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
      <TextField
        label={t('account:enroll.expires')}
        name="expires_on"
        type="date"
        value={expiresOn}
        onChange={(e) => setExpiresOn(e.target.value)}
        disabled={pending || change !== null}
        helperText={t('account:enroll.expiresHelper')}
        slotProps={{ inputLabel: { shrink: true } }}
        sx={{ maxWidth: 260 }}
      />
      {error ? <ErrorNotice error={error} /> : null}
      <Box>
        <Button
          type="submit"
          variant="contained"
          disabled={pending || value.length === 0 || needsSchool || schools.isPending}
        >
          {pending ? t('account:enroll.submitting') : submitLabel}
        </Button>
        {needsSchool && value.length > 0 ? (
          <Alert severity="info" role="note" sx={{ mt: 1.5 }}>
            {t('errors:school_required')}
          </Alert>
        ) : null}
      </Box>

      <ConfirmDialog
        open={change !== null}
        title={t('account:enroll.identityChange.title')}
        body={t('account:enroll.identityChange.body', {
          enrolled: change?.enrolledName ?? '',
          next: change?.newName ?? '',
        })}
        confirmLabel={t('account:enroll.identityChange.confirm')}
        destructive={false}
        pending={pending}
        onClose={cancelChange}
        onConfirm={() => {
          if (change !== null) void send(change.confirmation)
        }}
      />
    </Box>
  )
}
