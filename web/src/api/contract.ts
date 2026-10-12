import type {
  SiteAddressResponse,
  LoginProviderSave,
  LoginProviderSettings,
  SetupStatus,
  SetupRequest,
  PageQuery,
  AdminAccountsResponse,
  AdminSettingsResponse,
  FeaturedSchoolsRequest,
  SchoolCheckResponse,
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
  IdentitiesResponse,
  LinkStartResponse,
  LoginHistoryResponse,
  MeResponse,
  ProvidersResponse,
  RecheckResponse,
  SchoolSearchResponse,
  SchoolsResponse,
  UiLocale,
  UnlinkResponse,
  WriteToolsResponse,
  WriteToolsSavedResponse,
} from './types'

/**
 * The route table of /api/v1: one entry per (method, path), with the query
 * string, the JSON body and the response it takes. Paths are relative to
 * API_BASE_URL and `{id}` is an account id.
 *
 * It is the single source for the HTTP calls (endpoints.ts), the dev mock
 * (dev/mockServer.ts) and the tests. tests/selfhost/test_account_api_contract.py
 * parses this file and fails when the set of routes differs from the server's, so a
 * route cannot be added on one side only. `void` means "204, no body".
 */
export interface Contract {
  'POST /login/local': { body: { username: string; password: string; txn?: string; return_to?: string }; response: { redirect_to: string } }
  'PUT /me/password': { body: { current_password: string; new_password: string }; response: { redirect_to: string } }
  'PUT /admin/accounts/{id}/upn': { body: { upn: string; revision: number }; response: { revision: number; account_id: string } }
  'POST /me/local-password': { body: { password: string }; response: { redirect_to: string } }
  'POST /admin/local-accounts': { body: { revision: number; username: string; password: string; owner?: boolean }; response: { account_id: string; revision: number } }
  'GET /setup': { response: SetupStatus }
  'POST /setup': { body: SetupRequest; response: { redirect_to: string } }
  'GET /admin/login-providers': { response: LoginProviderSettings }
  'PUT /admin/login-providers/{id}': { body: LoginProviderSave; response: LoginProviderSettings }
  'GET /admin/settings': { response: AdminSettingsResponse }
  'PUT /admin/settings/site': { body: { revision: number; public_base_url: string; confirm: boolean }; response: SiteAddressResponse }
  'GET /admin/settings/login-policy': { response: { revision: number; policy: Record<string, boolean> } }
  'PUT /admin/settings/login-policy': { body: { revision: number; policy: Record<string, boolean> }; response: { revision: number; policy: Record<string, boolean> } }
  'GET /admin/accounts/{id}/login-policy': { response: { revision: number; policy: { allow_multiple: boolean | null; allowed_providers: string[] | null; sso_lock_provider: string | null; sso_lock_exempt: boolean } } }
  'PUT /admin/accounts/{id}/login-policy': { body: { revision: number; policy: { allow_multiple: boolean | null; allowed_providers: string[] | null } }; response: { revision: number; policy: { allow_multiple: boolean | null; allowed_providers: string[] | null; sso_lock_provider: string | null; sso_lock_exempt: boolean } } }
  'POST /admin/accounts/{id}/unlock-sso': { body: { revision: number }; response: { revision: number; policy: { allow_multiple: boolean | null; allowed_providers: string[] | null; sso_lock_provider: string | null; sso_lock_exempt: boolean } } }
  'PUT /admin/settings/sign-in-methods': { body: { revision: number; names: Record<string, string | null> }; response: AdminSettingsResponse }
  'PUT /admin/settings/schools': { body: FeaturedSchoolsRequest; response: AdminSettingsResponse }
  'POST /admin/settings/schools/check': { body: { host: string }; response: SchoolCheckResponse }
  'PUT /admin/settings/directory-search': { body: { revision: number; enabled: boolean }; response: AdminSettingsResponse }

  'GET /providers': { response: ProvidersResponse }
  'GET /me': { response: MeResponse }
  'GET /me/canvas-token': { response: CanvasTokenStatus }
  'PUT /me/canvas-token': { body: CanvasTokenRequest; response: CanvasTokenStatus }
  'DELETE /me/canvas-token': { response: void }
  'POST /me/canvas-token/recheck': { response: RecheckResponse }
  'POST /me/canvas-token/acknowledge': { body: { notice_version: number }; response: CanvasTokenStatus }
  'GET /me/schools': { response: SchoolsResponse }
  'GET /me/schools/search': { query: { q: string }; response: SchoolSearchResponse }
  'GET /me/write-tools': { response: WriteToolsResponse }
  'PUT /me/write-tools': { body: { enabled: string[] }; response: WriteToolsSavedResponse }
  'DELETE /me/write-tools': { response: WriteToolsSavedResponse }
  'GET /me/login-history': { query: PageQuery; response: LoginHistoryResponse }
  'PUT /me/ui-locale': { body: { locale: UiLocale }; response: void }
  'POST /session/logout': { response: void }
  'GET /admin/accounts': { query: PageQuery & { status?: AdminStatusFilter }; response: AdminAccountsResponse }
  'GET /admin/enrollments': {
    query: PageQuery & { filter?: AdminEnrollmentFilter }
    response: AdminEnrollmentsResponse
  }
  'POST /admin/accounts/{id}/approve': { response: AdminActionResponse }
  'POST /admin/accounts/{id}/deny': { response: AdminActionResponse }
  'POST /admin/accounts/{id}/disable': { response: AdminActionResponse }
  'POST /admin/accounts/{id}/enable': { response: AdminActionResponse }
  'POST /admin/enrollments/{id}/mark-invalid': { response: AdminActionResponse }
  'DELETE /admin/enrollments/{id}': { response: AdminActionResponse }
  'GET /admin/audit': { query: PageQuery & { account_id?: string }; response: AdminAuditResponse }
  // Only with two or more sign-in providers: the server answers not_found for these
  // otherwise, and GET /me `features.identities` says so. `{id}` is an identity's decimal id.
  'GET /me/identities': { response: IdentitiesResponse }
  'POST /me/identities/link': { body: { provider: string }; response: LinkStartResponse }
  'DELETE /me/identities/{id}': { response: UnlinkResponse }
  'DELETE /admin/identities/{id}': { response: AdminActionResponse }
  // Only with the server's own authorization server (SELFHOST_AUTH_MODE=local): the
  // server answers not_found for these otherwise, and GET /me `features` says so.
  // `{id}` is a connection's id or an account id. The consent request id travels in the query
  // (read) and the body (decision), never in the path: proxies log paths, and blank queries.
  'GET /consent': { query: { txn: string }; response: ConsentResponse }
  'POST /consent': {
    body: { txn: string; decision: ConsentDecision }
    response: ConsentDecisionResponse
  }
  'GET /me/grants': { query: PageQuery; response: GrantsResponse }
  'DELETE /me/grants/{id}': { response: void }
  'GET /admin/accounts/{id}/grants': { query: PageQuery; response: GrantsResponse }
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
