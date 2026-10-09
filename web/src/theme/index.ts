import { createTheme, type Theme } from '@mui/material/styles'
import type { ResolvedTheme } from '@/stores/theme'

// System font stack only: no webfonts, so `font-src 'self'` has nothing to load.
const FONT_STACK = [
  'system-ui',
  '-apple-system',
  '"Segoe UI"',
  '"Noto Sans SC"',
  '"PingFang SC"',
  '"Microsoft YaHei"',
  'Roboto',
  '"Helvetica Neue"',
  'Arial',
  'sans-serif',
].join(',')

export function buildTheme(mode: ResolvedTheme): Theme {
  const dark = mode === 'dark'
  return createTheme({
    palette: {
      mode,
      primary: { main: dark ? '#8ab4f8' : '#0b57d0' },
      background: dark
        ? { default: '#121316', paper: '#1c1d21' }
        : { default: '#f5f7fb', paper: '#ffffff' },
    },
    shape: { borderRadius: 12 },
    typography: {
      fontFamily: FONT_STACK,
      h1: { fontSize: '1.75rem', fontWeight: 600 },
      h2: { fontSize: '1.375rem', fontWeight: 600 },
      h3: { fontSize: '1.125rem', fontWeight: 600 },
      button: { textTransform: 'none', fontWeight: 600 },
    },
    components: {
      MuiButton: { defaultProps: { disableElevation: true } },
      MuiCard: { defaultProps: { variant: 'outlined' } },
      MuiPaper: { defaultProps: { elevation: 0 } },
    },
  })
}
