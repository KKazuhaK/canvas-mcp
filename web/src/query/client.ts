import { QueryClient } from '@tanstack/react-query'
import { ApiError } from '@/api/errors'

/**
 * Retry a failed query at most once, and only when the failure looks transient:
 * the request never got an answer (network, timeout) or the server answered 5xx.
 * 501 and 503 are deliberate "not available" answers (e.g. token_store_unavailable)
 * and retrying them only delays the message.
 */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (failureCount >= 1) return false
  if (!(error instanceof ApiError)) return false
  if (error.isNetwork) return true
  return error.status >= 500 && error.status !== 501 && error.status !== 503
}

/**
 * One client per session. It is cleared on logout and on a 401
 * `not_authenticated`, so nothing from one account can be shown to the next.
 * Nothing is persisted: no persister, no storage.
 */
export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: shouldRetry,
        refetchOnWindowFocus: true,
        refetchOnReconnect: true,
        staleTime: 15_000,
      },
      mutations: { retry: false },
    },
  })
}
