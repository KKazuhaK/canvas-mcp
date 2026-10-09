import CssBaseline from '@mui/material/CssBaseline'
import { ThemeProvider } from '@mui/material/styles'
import { QueryClientProvider, type QueryClient } from '@tanstack/react-query'
import { useEffect, useMemo } from 'react'
import { RouterProvider } from 'react-router'
import ErrorBoundary from '@/components/ErrorBoundary'
import SnackbarHost from '@/components/SnackbarHost'
import { useResolvedTheme, watchSystemTheme } from '@/stores/theme'
import { buildTheme } from '@/theme'

type AppRouter = Parameters<typeof RouterProvider>[0]['router']

export default function App({ client, router }: { client: QueryClient; router: AppRouter }) {
  const resolved = useResolvedTheme()
  const theme = useMemo(() => buildTheme(resolved), [resolved])

  useEffect(() => watchSystemTheme(), [])

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline enableColorScheme />
      <ErrorBoundary>
        <QueryClientProvider client={client}>
          <RouterProvider router={router} />
          <SnackbarHost />
        </QueryClientProvider>
      </ErrorBoundary>
    </ThemeProvider>
  )
}
