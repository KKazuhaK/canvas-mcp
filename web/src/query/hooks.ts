import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from '@tanstack/react-query'
import {
  adminAccessAction,
  adminAudit,
  adminGrants,
  adminListAccounts,
  adminListEnrollments,
  adminMarkInvalid,
  adminRemoveEnrollment,
  adminRevokeGrant,
  adminUnlinkIdentity,
  decideConsent,
  deleteCanvasToken,
  deleteWriteTools,
  getConsent,
  getGrants,
  getIdentities,
  getLoginHistory,
  getMe,
  getProviders,
  getSchools,
  getWriteTools,
  logout,
  putWriteTools,
  recheckCanvasToken,
  revokeGrant,
  startLink,
  unlinkIdentity,
  type AdminAccessAction,
} from '@/api/endpoints'
import { clearCsrfToken } from '@/api/client'
import type {
  AdminEnrollmentFilter,
  AdminStatusFilter,
  ConsentDecision,
  WriteToolsResponse,
} from '@/api/types'
import { hardNavigate } from '@/utils/navigate'
import { keys } from './keys'

// ---- reads ---------------------------------------------------------------

export function useProviders() {
  return useQuery({ queryKey: keys.providers, queryFn: getProviders, staleTime: 60_000 })
}

/** The session probe. A 401 here means "signed out", not "something broke". */
export function useMe() {
  return useQuery({ queryKey: keys.me, queryFn: getMe })
}

export function useSchools(enabled = true) {
  return useQuery({ queryKey: keys.schools, queryFn: getSchools, enabled })
}

export function useWriteTools(enabled = true) {
  return useQuery({ queryKey: keys.writeTools, queryFn: getWriteTools, enabled })
}

export function useLoginHistory() {
  return useInfiniteQuery({ queryKey: keys.loginHistory, queryFn: ({ pageParam }) => getLoginHistory(pageParam ? { cursor: pageParam } : {}), initialPageParam: null as string | null, getNextPageParam: (last) => last.next_cursor, select: (data) => ({ ...data, events: data.pages.flatMap(page => page.events) }) })
}

// ---- sign-in methods (two or more providers) -------------------------------------------

export function useIdentities(enabled = true) {
  return useQuery({ queryKey: keys.identities, queryFn: getIdentities, enabled })
}

/** The answer carries the provider's address; the screen checks it before navigating. */
export function useStartLink() {
  return useMutation({ mutationFn: (provider: string) => startLink(provider) })
}

/** An unlink ends every session of the account, so this one's own state is refetched too. */
export function useUnlinkIdentity() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => unlinkIdentity(id),
    // Also after a failure: the list may already have changed (another tab, an owner).
    onSettled: () =>
      Promise.all([
        client.invalidateQueries({ queryKey: keys.identities }),
        client.invalidateQueries({ queryKey: keys.me }),
        client.invalidateQueries({ queryKey: keys.loginHistory }),
      ]),
  })
}

// ---- Canvas token (the token itself is NOT handled by a mutation) -----------
//
// PUT /me/canvas-token is called directly from the form (see TokenForm). A
// useMutation would keep the token in `mutation.state.variables` inside the
// mutation cache until it is garbage-collected; a plain async handler keeps it
// only in component state and the one request body.

/** GET /me carries the token status, so refreshing it refreshes every card. */
export function refreshAfterTokenChange(client: QueryClient): Promise<void> {
  return Promise.all([
    client.invalidateQueries({ queryKey: keys.me }),
    client.invalidateQueries({ queryKey: keys.schools }),
  ]).then(() => undefined)
}

export function useDeleteCanvasToken() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: () => deleteCanvasToken(),
    onSuccess: () => refreshAfterTokenChange(client),
  })
}

export function useRecheckCanvasToken() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: () => recheckCanvasToken(),
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
      client.setQueryData<WriteToolsResponse>(keys.writeTools, data)
      void client.invalidateQueries({ queryKey: keys.me })
    },
  })
}

export function useTurnOffWriteTools() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: () => deleteWriteTools(),
    onSuccess: (data) => {
      client.setQueryData<WriteToolsResponse>(keys.writeTools, data)
      void client.invalidateQueries({ queryKey: keys.me })
    },
  })
}

// ---- session ---------------------------------------------------------------

/** Ends the session, drops every cached byte of account data, then reloads the landing page. */
export function useLogout() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: () => logout(),
    onSuccess: () => {
      clearCsrfToken()
      client.clear()
      // The signed-out landing page, not the IdP: a person who just signed out
      // must not be bounced straight back into a single-sign-on session.
      hardNavigate('/account/')
    },
  })
}

// ---- admin -----------------------------------------------------------------

export function useAdminAccounts(status: AdminStatusFilter | '') {
  return useInfiniteQuery({
    queryKey: keys.adminAccounts(status),
    queryFn: ({ pageParam }) => adminListAccounts(status || undefined, pageParam ? { cursor: pageParam } : {}),
    initialPageParam: null as string | null, getNextPageParam: (last) => last.next_cursor,
    select: (data) => ({ ...data, accounts: data.pages.flatMap(page => page.accounts), counts: data.pages[0].counts }),
  })
}

export function useAdminEnrollments(filter: AdminEnrollmentFilter) {
  return useInfiniteQuery({
    queryKey: keys.adminEnrollments(filter),
    queryFn: ({ pageParam }) => adminListEnrollments(filter, pageParam ? { cursor: pageParam } : {}),
    initialPageParam: null as string | null, getNextPageParam: (last) => last.next_cursor,
    select: (data) => ({ ...data, rows: data.pages.flatMap(page => page.rows), counts: data.pages[0].counts }),
  })
}

function refreshAdmin(client: QueryClient): Promise<void> {
  return Promise.all([
    client.invalidateQueries({ queryKey: keys.admin }),
    client.invalidateQueries({ queryKey: keys.me }),
  ]).then(() => undefined)
}

export function useAdminAccessAction() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, action }: { id: string; action: AdminAccessAction }) =>
      adminAccessAction(id, action),
    onSuccess: () => refreshAdmin(client),
  })
}

export function useAdminMarkInvalid() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => adminMarkInvalid(id),
    onSuccess: () => refreshAdmin(client),
  })
}

export function useAdminRemoveEnrollment() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => adminRemoveEnrollment(id),
    onSuccess: () => refreshAdmin(client),
  })
}

export function useAdminUnlinkIdentity() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => adminUnlinkIdentity(id),
    onSettled: () => refreshAdmin(client),
  })
}

export function useAdminAudit() {
  return useInfiniteQuery({
    queryKey: keys.adminAudit,
    queryFn: ({ pageParam }) => adminAudit(pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
}

// ---- apps: consent and connected apps (the server's own authorization server) ------------

/**
 * What an app asks for. The request id is a one-time secret of this browser, so it is read
 * from the URL by the screen and handed in, never stored in a query key. The answer does not
 * change while the person looks at it, and a failure is final (an expired or used request does
 * not come back), so there is no refetching or retrying.
 */
export function useConsent(txn: string, enabled: boolean) {
  return useQuery({
    queryKey: keys.consent,
    queryFn: () => getConsent(txn),
    enabled,
    retry: false,
    staleTime: Infinity,
    gcTime: 0,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
}

/** The one answer to a request; the response says where the browser goes next. */
export function useDecideConsent(txn: string) {
  return useMutation({ mutationFn: (decision: ConsentDecision) => decideConsent(txn, decision) })
}

export function useGrants(enabled = true) {
  return useInfiniteQuery({ queryKey: keys.grants, queryFn: ({ pageParam }) => getGrants(pageParam ? { cursor: pageParam } : {}), enabled, initialPageParam: null as string | null, getNextPageParam: (last) => last.next_cursor, select: (data) => ({ ...data, grants: data.pages.flatMap(page => page.grants) }) })
}

export function useRevokeGrant() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => revokeGrant(id),
    // Also after a failure: the list may already have changed (another tab, an owner).
    onSettled: () => client.invalidateQueries({ queryKey: keys.grants }),
  })
}

export function useAdminGrants(accountId: string, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: keys.adminGrants(accountId),
    queryFn: ({ pageParam }) => adminGrants(accountId, pageParam ? { cursor: pageParam } : {}),
    enabled, initialPageParam: null as string | null, getNextPageParam: (last) => last.next_cursor,
    select: (data) => ({ ...data, grants: data.pages.flatMap(page => page.grants) }),
  })
}

export function useAdminRevokeGrant(accountId: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => adminRevokeGrant(id),
    onSettled: () => client.invalidateQueries({ queryKey: keys.adminGrants(accountId) }),
  })
}
