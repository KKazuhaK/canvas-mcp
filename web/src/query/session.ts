import type { QueryClient } from '@tanstack/react-query'
import { clearCsrfToken, configureClient } from '@/api/client'
import { loginPathFor } from '@/utils/returnTo'
import { keys } from './keys'

/** The slice of a react-router data router that wireSession needs. */
export interface SessionRouter {
  state: { location: { pathname: string; search: string } }
  navigate: (to: string, opts?: { replace?: boolean }) => unknown
}

/**
 * Connect the HTTP client's two session hooks to a QueryClient and a navigator.
 *
 * - 401 not_authenticated on any call except the /me probe: the session is gone.
 *   Drop every cached byte of account data and go to /login. The current page is
 *   kept as `return_to` only if it passes the same-site validator.
 * - 403 csrf_invalid: refetch /me once so the next attempt carries a fresh token;
 *   the error itself still reaches the caller.
 */
export function wireSession(client: QueryClient, router: SessionRouter): void {
  configureClient({
    onUnauthorized: () => {
      clearCsrfToken()
      client.clear()
      const here = router.state.location
      void router.navigate(loginPathFor(here.pathname + here.search), { replace: true })
    },
    onCsrfInvalid: () => {
      void client.refetchQueries({ queryKey: keys.me })
    },
  })
}
