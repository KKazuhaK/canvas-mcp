import ContentCopyIcon from '@mui/icons-material/ContentCopy'
import CheckIcon from '@mui/icons-material/Check'
import IconButton from '@mui/material/IconButton'
import InputAdornment from '@mui/material/InputAdornment'
import TextField from '@mui/material/TextField'
import Tooltip from '@mui/material/Tooltip'
import { useEffect, useRef, useState, type FocusEvent } from 'react'
import { useTranslation } from 'react-i18next'

interface Props {
  value: string
  label: string
  copyLabel: string
}

/** Read-only value with a copy button. Clipboard failures are silent: the text stays selectable. */
export default function CopyField({ value, label, copyLabel }: Props) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  useEffect(() => () => clearTimeout(timer.current), [])

  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      clearTimeout(timer.current)
      timer.current = setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard blocked: the person can still select and copy the text.
    }
  }

  return (
    <TextField
      label={label}
      value={value}
      fullWidth
      size="small"
      slotProps={{
        htmlInput: { readOnly: true, onFocus: (e: FocusEvent<HTMLInputElement>) => e.currentTarget.select() },
        input: {
          endAdornment: (
            <InputAdornment position="end">
              <Tooltip title={copied ? t('common:actions.copied') : copyLabel}>
                <IconButton aria-label={copyLabel} edge="end" onClick={() => void copy()}>
                  {copied ? <CheckIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}
                </IconButton>
              </Tooltip>
            </InputAdornment>
          ),
        },
      }}
    />
  )
}
