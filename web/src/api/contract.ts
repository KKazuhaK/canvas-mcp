import type {
  AdminAccountsResponse,
  AdminActionResponse,
  AdminAuditResponse,
  AdminEnrollmentFilter,
  AdminEnrollmentsResponse,
  AdminStatusFilter,
  CanvasTokenRequest,
  CanvasTokenStatus,
  ConsentDecision,
  ConsentDecisionResponse,
  ConsentResponse,
  GrantRevokeResponse,
  GrantsResponse,
  LoginHistoryResponse,
  MeResponse,
  ProvidersResponse,
  RecheckResponse,
  SchoolSearchResponse,
  SchoolsResponse,
  UiLocale,
  WriteToolsResponse,
  WriteToolsSavedResponse,
} from './types'

/**
 * The route table of /account/api: one entry per (method, path), with the query
 * string, the JSON body and the response it takes. Paths are relative to
 * API_BASE_URL and `{id}` is an account id.
 *
 * It is the single source for the HTTP calls (endpoints.ts), the dev mock
 * (dev/mockServer.ts) and the tests. tests/selfhost/test_account_api_contract.py
 * parses this file and fails when the set of routes differs from the server's, so a
 * route cannot be added on one side only. `void` means "204, no body".
 */
export interface Contract {
  'GET /providers': { response: ProvidersResponse }
  'GET /me': { response: MeResponse }
  'GET /me/canvas-token': { response: CanvasTokenStatus }
  'PUT /me/canvas-token': { body: CanvasTokenRequest; response: CanvasTokenStatus }
  'DELETE /me/canvas-token': { response: void }
  'POST /me/canvas-token/recheck': { response: RecheckResponse }
  'GET /me/schools': { response: SchoolsResponse }
  'GET /me/schools/search': { query: { q: string }; response: SchoolSearchResponse }
  'GET /me/write-tools': { response: WriteToolsResponse }
  'PUT /me/write-tools': { body: { enabled: string[] }; response: WriteToolsSavedResponse }
  'DELETE /me/write-tools': { response: WriteToolsSavedResponse }
  'GET /me/login-history': { response: LoginHistoryResponse }
  'PUT /me/ui-locale': { body: { locale: UiLocale }; response: void }
  'POST /session/logout': { response: void }
  'GET /admin/accounts': { query: { status?: AdminStatusFilter }; response: AdminAccountsResponse }
  'GET /admin/enrollments': {
    query: { filter?: AdminEnrollmentFilter }
    response: AdminEnrollmentsResponse
  }
  'POST /admin/accounts/{id}/approve': { response: AdminActionResponse }
  'POST /admin/accounts/{id}/deny': { response: AdminActionResponse }
  'POST /admin/accounts/{id}/disable': { response: AdminActionResponse }
  'POST /admin/accounts/{id}/enable': { response: AdminActionResponse }
  'POST /admin/enrollments/{id}/mark-invalid': { response: AdminActionResponse }
  'DELETE /admin/enrollments/{id}': { response: AdminActionResponse }
  'GET /admin/audit': { query: { before?: string }; response: AdminAuditResponse }
  // Only with the server's own authorization server (SELFHOST_AUTH_MODE=local): the
  // server answers not_found for these otherwise, and GET /me `features` says so.
  // `{id}` is a connection's id or an account id. The consent request id travels in the query
  // (read) and the body (decision), never in the path: proxies log paths, and blank queries.
  'GET /consent': { query: { txn: string }; response: ConsentResponse }
  'POST /consent': {
    body: { txn: string; decision: ConsentDecision }
    response: ConsentDecisionResponse
  }
  'GET /me/grants': { response: GrantsResponse }
  'DELETE /me/grants/{id}': { response: void }
  'GET /admin/accounts/{id}/grants': { response: GrantsResponse }
  'DELETE /admin/grants/{id}': { response: GrantRevokeResponse }
}

export type RouteKey = keyof Contract
export type ResponseOf<K extends RouteKey> = Contract[K]['response']
export type BodyOf<K extends RouteKey> = Contract[K] extends { body: infer B } ? B : never
export type QueryOf<K extends RouteKey> = Contract[K] extends { query: infer Q } ? Q : never
export type MethodOf<K extends RouteKey> = K extends `${infer M} ${string}` ? M : never

/** Split a route key into its HTTP method and path template. */
export function splitRoute(key: RouteKey): { method: string; path: string } {
  const space = key.indexOf(' ')
  return { method: key.slice(0, space), path: key.slice(space + 1) }
}
