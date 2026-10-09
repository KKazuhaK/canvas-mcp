import { ThemeProvider } from '@mui/material/styles'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import type { ReactElement } from 'react'
import { RouterProvider } from 'react-router'
import { http } from '@/api/client'
import SnackbarHost from '@/components/SnackbarHost'
import { installMockServer, type MockScenario } from '@/dev/mockServer'
import { initI18n } from '@/i18n'
import { wireSession } from '@/query/session'
import { createTestRouter } from '@/router'
import { buildTheme } from '@/theme'
import { clearCsrfToken } from '@/api/client'
import i18next from 'i18next'
import { useLanguage } from '@/stores/language'
import { useToast } from '@/stores/toast'

/**
 * A QueryClient per test. Caches must never leak between tests, and the
 * production retry policy would turn a single-failure assertion into a
 * multi-second wait.
 */
export function makeTestQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 0, gcTime: Infinity },
      mutations: { retry: false },
    },
  })
}

export async function setupI18n(lang: 'en' | 'zh' = 'en'): Promise<void> {
  // Module-level stores outlive a test; start each one from a known state.
  useToast.setState({ message: null })
  useLanguage.setState({ lang })
  await initI18n(lang)
  if (i18next.language !== lang) await i18next.changeLanguage(lang)
}

export function renderWithQuery(ui: ReactElement) {
  const client = makeTestQueryClient()
  const result = render(
    <ThemeProvider theme={buildTheme('light')}>
      <QueryClientProvider client={client}>{ui}</QueryClientProvider>
    </ThemeProvider>,
  )
  return { client, result }
}

export interface RenderedApp {
  client: QueryClient
  router: ReturnType<typeof createTestRouter>
}

/**
 * The real route table over the real axios client, with the dev mock adapter
 * standing in for the server (no latency). The mock checks X-CSRF-Token itself,
 * so a missing header shows up as a csrf_invalid failure.
 */
export async function renderApp(
  path: string,
  scenario: MockScenario = 'enrolled',
  beforeRender?: () => void,
): Promise<RenderedApp> {
  await setupI18n('en')
  clearCsrfToken()
  installMockServer(http, { scenario, latency: [0, 0] })
  beforeRender?.()
  const client = makeTestQueryClient()
  const router = createTestRouter([path])
  wireSession(client, router)
  render(
    <ThemeProvider theme={buildTheme('light')}>
      <QueryClientProvider client={client}>
        <RouterProvider router={router} />
        <SnackbarHost />
      </QueryClientProvider>
    </ThemeProvider>,
  )
  return { client, router }
}
