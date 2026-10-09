import SearchIcon from '@mui/icons-material/Search'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import List from '@mui/material/List'
import ListItemButton from '@mui/material/ListItemButton'
import ListItemText from '@mui/material/ListItemText'
import MenuItem from '@mui/material/MenuItem'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useMutation } from '@tanstack/react-query'
import { useState, type KeyboardEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { searchSchools } from '@/api/endpoints'
import type { SchoolsResponse } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'

/** The school the person picked: a host, and the search proof when it came from a search. */
export interface SchoolSelection {
  host: string
  name: string
  /** Set only for a school found through the directory search. */
  sig: string | null
}

export const SEARCH_MIN_CHARS = 2
export const SEARCH_MAX_CHARS = 64

/** The selection a fresh form starts with: what the server says is the default. */
export function initialSelection(schools: SchoolsResponse): SchoolSelection | null {
  if (schools.mode !== 'picker' || schools.selected === null) return null
  const choice = schools.choices.find((c) => c.host === schools.selected)
  return { host: schools.selected, name: choice?.name ?? schools.selected, sig: null }
}

/**
 * Which Canvas site the token belongs to.
 *
 * - `picker`: the operator's featured schools (and the one you are enrolled at) in a
 *   list, plus, when the server allows it, a directory search. A search result
 *   carries a signature that the server checks, so only a school the server itself
 *   listed for this session can be enrolled.
 * - `sole` / `fixed`: the server has one school; it is shown, nothing is sent.
 */
export default function SchoolPicker({
  schools,
  value,
  onChange,
  disabled,
}: {
  schools: SchoolsResponse
  value: SchoolSelection | null
  onChange: (next: SchoolSelection | null) => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const search = useMutation({ mutationFn: (q: string) => searchSchools(q) })

  if (schools.mode !== 'picker') {
    if (!schools.sole) return null
    return (
      <Box>
        <Typography variant="body2" color="text.secondary">
          {t('account:school.label')}
        </Typography>
        <Typography sx={{ overflowWrap: 'anywhere' }}>
          {schools.sole.name}{' '}
          <Typography component="span" variant="body2" color="text.secondary">
            ({schools.sole.host})
          </Typography>
        </Typography>
      </Box>
    )
  }

  // A school found by search stays in the list so the select can show it.
  const options: SchoolSelection[] = schools.choices.map((c) => ({ host: c.host, name: c.name, sig: null }))
  if (value !== null && !options.some((o) => o.host === value.host)) options.push(value)

  const trimmed = query.trim()
  const queryOk = trimmed.length >= SEARCH_MIN_CHARS && trimmed.length <= SEARCH_MAX_CHARS

  function runSearch() {
    if (queryOk && !search.isPending) search.mutate(trimmed)
  }

  // Not a <form>: this sits inside the token form, and forms do not nest. Enter in
  // the box runs the search and must not submit the token.
  function onSearchKey(event: KeyboardEvent) {
    if (event.key === 'Enter') {
      event.preventDefault()
      runSearch()
    }
  }

  return (
    <Box sx={{ display: 'grid', gap: 1.5 }}>
      {options.length > 0 ? (
        <TextField
          select
          size="small"
          label={t('account:school.label')}
          value={value?.host ?? ''}
          disabled={disabled}
          fullWidth
          onChange={(e) => onChange(options.find((o) => o.host === e.target.value) ?? null)}
          helperText={t('account:school.pickHelper')}
        >
          {options.map((o) => (
            <MenuItem key={o.host} value={o.host}>
              {o.name} ({o.host})
            </MenuItem>
          ))}
        </TextField>
      ) : (
        <Typography variant="body2" color="text.secondary">
          {schools.search_enabled ? t('account:school.searchFirst') : t('account:school.noneOffered')}
        </Typography>
      )}

      {schools.search_enabled ? (
        <Box sx={{ display: 'grid', gap: 1 }}>
          <Box sx={{ display: 'flex', gap: 1, alignItems: 'flex-start' }}>
            <TextField
              size="small"
              type="search"
              label={t('account:school.searchLabel')}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={onSearchKey}
              disabled={disabled}
              fullWidth
              slotProps={{
                htmlInput: { maxLength: SEARCH_MAX_CHARS, autoComplete: 'off', spellCheck: false },
              }}
              helperText={t('account:school.searchHelper', {
                min: SEARCH_MIN_CHARS,
                max: SEARCH_MAX_CHARS,
              })}
            />
            <Button
              type="button"
              onClick={runSearch}
              variant="outlined"
              startIcon={<SearchIcon />}
              disabled={disabled || !queryOk || search.isPending}
              sx={{ flexShrink: 0, height: 40 }}
            >
              {search.isPending ? t('account:school.searching') : t('account:school.search')}
            </Button>
          </Box>
          {search.isError ? <ErrorNotice error={search.error} /> : null}
          {search.data && search.data.results.length === 0 ? (
            <Typography variant="body2" color="text.secondary" role="status">
              {t('account:school.noResults')}
            </Typography>
          ) : null}
          {search.data && search.data.results.length > 0 ? (
            <List dense aria-label={t('account:school.results')} sx={{ border: 1, borderColor: 'divider', borderRadius: 1 }}>
              {search.data.results.map((r) => (
                <ListItemButton
                  key={r.host}
                  selected={value?.host === r.host}
                  disabled={disabled}
                  onClick={() => onChange({ host: r.host, name: r.name, sig: r.sig })}
                >
                  <ListItemText primary={r.name} secondary={r.host} />
                </ListItemButton>
              ))}
            </List>
          ) : null}
        </Box>
      ) : null}
    </Box>
  )
}
