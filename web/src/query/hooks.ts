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
  adminListAccounts,
  adminListEnrollments,
  adminMarkInvalid,
  adminRemoveEnrollment,
  deleteCanvasToken,
  deleteWriteTools,
  getLoginHistory,
  getMe,
  getProviders,
  getSchools,
  getWriteTools,
  logout,
  putWriteTools,
  recheckCanvasToken,
  type AdminAccessAction,
} from '@/api/endpoints'
import { clearCsrfToken } from '@/api/client'
import type { AdminEnrollmentFilter, AdminStatusFilter, WriteToolsResponse } from '@/api/types'
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
  return useQuery({ queryKey: keys.loginHistory, queryFn: getLoginHistory })
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
  return useQuery({
    queryKey: keys.adminAccounts(status),
    queryFn: () => adminListAccounts(status || undefined),
  })
}

export function useAdminEnrollments(filter: AdminEnrollmentFilter) {
  return useQuery({
    queryKey: keys.adminEnrollments(filter),
    queryFn: () => adminListEnrollments(filter),
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

export function useAdminAudit() {
  return useInfiniteQuery({
    queryKey: keys.adminAudit,
    queryFn: ({ pageParam }) => adminAudit(pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
}
