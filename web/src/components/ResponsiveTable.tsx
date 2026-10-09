import Box from '@mui/material/Box'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import Typography from '@mui/material/Typography'
import useMediaQuery from '@mui/material/useMediaQuery'
import { useTheme } from '@mui/material/styles'
import type { ReactNode } from 'react'

const visuallyHidden = {
  position: 'absolute',
  width: 1,
  height: 1,
  overflow: 'hidden',
  clip: 'rect(0 0 0 0)',
  whiteSpace: 'nowrap',
} as const

export interface Column<T> {
  key: string
  header: string
  render: (row: T) => ReactNode
  /** Shown as the card heading on small screens (first column by default). */
  primary?: boolean
  /** Rendered in the card footer / last table column, without a label. */
  actions?: boolean
}

/** A table from md up, stacked cards below, so nothing scrolls sideways at 360 px. */
export default function ResponsiveTable<T>({
  columns,
  rows,
  rowKey,
  label,
  rowSx,
}: {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T) => string
  label: string
  rowSx?: (row: T) => Record<string, unknown> | undefined
}) {
  const theme = useTheme()
  const desktop = useMediaQuery(theme.breakpoints.up('md'))

  if (desktop) {
    return (
      <TableContainer>
        <Table size="small" aria-label={label}>
          <TableHead>
            <TableRow>
              {columns.map((c) => (
                <TableCell key={c.key}>{c.actions ? <Box component="span" sx={visuallyHidden}>{c.header}</Box> : c.header}</TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((row) => (
              <TableRow key={rowKey(row)} sx={rowSx?.(row)}>
                {columns.map((c) => (
                  <TableCell key={c.key} sx={c.actions ? { whiteSpace: 'nowrap' } : undefined}>
                    {c.render(row)}
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    )
  }

  const primary = columns.find((c) => c.primary) ?? columns[0]
  const actions = columns.find((c) => c.actions)
  const body = columns.filter((c) => c !== primary && c !== actions)
  return (
    <Box component="ul" aria-label={label} sx={{ listStyle: 'none', m: 0, p: 0, display: 'grid', gap: 1.5 }}>
      {rows.map((row) => (
        <Card component="li" key={rowKey(row)} sx={rowSx?.(row)}>
          <CardContent sx={{ display: 'grid', gap: 1 }}>
            <Box sx={{ minWidth: 0, overflowWrap: 'anywhere' }}>{primary.render(row)}</Box>
            {body.map((c) => (
              <Box key={c.key} sx={{ display: 'grid', gap: 0.25 }}>
                <Typography variant="caption" color="text.secondary">
                  {c.header}
                </Typography>
                <Box sx={{ minWidth: 0, overflowWrap: 'anywhere' }}>{c.render(row)}</Box>
              </Box>
            ))}
            {actions ? <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>{actions.render(row)}</Box> : null}
          </CardContent>
        </Card>
      ))}
    </Box>
  )
}
