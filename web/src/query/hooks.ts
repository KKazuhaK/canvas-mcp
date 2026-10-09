import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from '@tanstack/react-query'
import {
  adminAccountAction,
  adminAudit,
  adminListAccounts,
  adminListEnrollments,
  adminRevokeEnrollment,
  deleteCanvasToken,
  deleteGrant,
  deleteIdentity,
  getConsent,
  getGrants,
  getIdentities,
  getLoginHistory,
  getMe,
  getProviders,
  getWriteTools,
  logout,
  postConsent,
  putWriteTools,
  startLinkUrl,
  verifyCanvasToken,
  type AdminAccountFilters,
  type AdminAuditFilters,
} from '@/api/endpoints'
import { clearCsrfToken } from '@/api/client'
import { ApiError } from '@/api/errors'
import type { AdminAccountActionBody, ConsentDecision } from '@/api/types'
import { hardNavigate } from '@/utils/navigate'
import { safeRedirectTarget } from '@/utils/returnTo'
import { keys } from './keys'

// ---- reads ---------------------------------------------------------------

export function useProviders() {
  return useQuery({ queryKey: keys.providers, queryFn: getProviders, staleTime: 60_000 })
}

/** The session probe. A 401 here means "signed out", not "something broke". */
export function useMe() {
  return useQuery({ queryKey: keys.me, queryFn: getMe })
}

export function useWriteTools() {
  return useQuery({ queryKey: keys.writeTools, queryFn: getWriteTools })
}

export function useIdentities() {
  return useQuery({ queryKey: keys.identities, queryFn: getIdentities })
}

export function useGrants() {
  return useQuery({ queryKey: keys.grants, queryFn: getGrants })
}

export function useLoginHistory() {
  return useQuery({ queryKey: keys.loginHistory, queryFn: getLoginHistory })
}

export function useConsent(txn: string | null) {
  return useQuery({
    queryKey: keys.consent(txn ?? ''),
    queryFn: () => getConsent(txn as string),
    enabled: txn !== null,
    // A consent transaction is single-use; never refetch it behind the person's back.
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    retry: false,
  })
}

// ---- Canvas token (the token itself is NOT handled by a mutation) -----------
//
// PUT /me/canvas-token is called directly from the form (see TokenForm). A
// useMutation would keep the token in `mutation.state.variables` inside the
// mutation cache until it is garbage-collected; a plain async handler keeps it
// only in component state and the one request body.

export function refreshAfterTokenChange(client: QueryClient): Promise<void> {
  return client.invalidateQueries({ queryKey: keys.me })
}

export function useDeleteCanvasToken() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: () => deleteCanvasToken(),
    onSuccess: () => refreshAfterTokenChange(client),
  })
}

export function useVerifyCanvasToken() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: () => verifyCanvasToken(),
    onSuccess: () => refreshAfterTokenChange(client),
    // A failed re-check may still have changed the stored state (invalid).
    onError: () => refreshAfterTokenChange(client),
  })
}

// ---- write tools -----------------------------------------------------------

export function useSaveWriteTools() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (enabled: string[]) => putWriteTools(enabled),
    onSuccess: (data) => {
      client.setQueryData(keys.writeTools, data)
      void client.invalidateQueries({ queryKey: keys.me })
    },
  })
}

// ---- identities ------------------------------------------------------------

export function useDeleteIdentity() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteIdentity(id),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.identities }),
  })
}

/** Ask for the IdP hand-off URL, then leave the SPA for it. */
export function useStartLink() {
  return useMutation({
    mutationFn: async (providerId: string) => {
      const { redirect_url } = await startLinkUrl(providerId)
      const target = safeRedirectTarget(redirect_url)
      if (target === null) throw new ApiError(0, 'internal_error')
      hardNavigate(target)
    },
  })
}

// ---- grants / sessions -----------------------------------------------------

export function useRevokeGrant() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteGrant(id),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.grants }),
  })
}

/** Ends the session, drops every cached byte of account data, then reloads at /login. */
export function useLogout() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (all: boolean) => logout(all),
    onSuccess: () => {
      clearCsrfToken()
      client.clear()
      hardNavigate('/account/login')
    },
  })
}

// ---- consent ---------------------------------------------------------------

export function useDecideConsent(txn: string) {
  return useMutation({
    mutationFn: async (decision: ConsentDecision) => {
      const { redirect_url } = await postConsent(txn, decision)
      // The destination comes from the server's JSON (built from the registered
      // redirect_uri), never from the client. We only refuse unsafe schemes.
      const target = safeRedirectTarget(redirect_url)
      if (target === null) throw new ApiError(0, 'internal_error')
      hardNavigate(target)
    },
  })
}

// ---- admin -----------------------------------------------------------------

export function useAdminAccounts(filters: AdminAccountFilters) {
  return useInfiniteQuery({
    queryKey: keys.adminAccounts(filters),
    queryFn: ({ pageParam }) => adminListAccounts(filters, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
}

export function useAdminAccountAction() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: AdminAccountActionBody }) =>
      adminAccountAction(id, body),
    onSuccess: () => client.invalidateQueries({ queryKey: ['admin', 'accounts'] }),
  })
}

export function useAdminEnrollments() {
  return useQuery({ queryKey: keys.adminEnrollments, queryFn: adminListEnrollments })
}

export function useRevokeEnrollment() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (accountId: string) => adminRevokeEnrollment(accountId),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.adminEnrollments }),
  })
}

export function useAdminAudit(filters: AdminAuditFilters) {
  return useInfiniteQuery({
    queryKey: keys.adminAudit(filters),
    queryFn: ({ pageParam }) => adminAudit(filters, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
}
