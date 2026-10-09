// DEV-ONLY mock of the /account/api contract.
//
// Loaded exclusively through `await import('./dev/mockServer')` in main.tsx,
// behind `import.meta.env.DEV && import.meta.env.VITE_MOCK === '1'`. In a
// production build that condition is the constant `false`, so this module and
// everything it imports are dropped; scripts/check-dist.mjs fails the build if
// any marker from this file or its fixtures appears in dist/.
//
// It swaps the axios adapter, so the real interceptors (CSRF header, error
// normalisation) still run. State is in memory and resets on reload. Pick a
// scenario with `?mock=<name>` on the first page load.

import {
  AxiosError,
  type AxiosInstance,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from 'axios'
import type {
  AdminAccount,
  AdminEnrollment,
  ApiErrorCode,
  AuditEntry,
  CanvasTokenStatus,
  ErrorParams,
  Grant,
  Identity,
  LoginEvent,
  MeResponse,
  Provider,
  ProvidersResponse,
  WriteTool,
} from '@/api/types'

export const MOCK_SCENARIOS = [
  'enrolled',
  'fresh',
  'signed-out',
  'pending',
  'disabled',
  'invalid',
  'token-invalid',
  'owner',
  'error-503',
  'rate-limited',
  'single-provider',
  'no-provider',
] as const
export type MockScenario = (typeof MOCK_SCENARIOS)[number]

const MOCK_CSRF = 'mock-csrf-token-not-a-secret'
const ago = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString()

const PROVIDERS: Provider[] = [
  { id: 'entra', kind: 'oidc', name: 'Microsoft', icon: 'microsoft' },
  { id: 'google', kind: 'oidc', name: 'Google', icon: 'google' },
  { id: 'github', kind: 'github_oauth2', name: 'GitHub', icon: 'github' },
]

function emptyCanvas(): CanvasTokenStatus {
  return {
    state: 'none',
    canvas_user_id: null,
    canvas_user_name: null,
    enrolled_at: null,
    updated_at: null,
    last_used_at: null,
    last_checked_at: null,
    invalid_since: null,
  }
}

function validCanvas(): CanvasTokenStatus {
  return {
    state: 'valid',
    canvas_user_id: 1234567,
    canvas_user_name: 'Ada Example',
    enrolled_at: ago(60 * 24 * 6),
    updated_at: ago(60 * 24 * 6),
    last_used_at: ago(20),
    last_checked_at: ago(20),
    invalid_since: null,
  }
}

const WRITE_TOOLS: WriteTool[] = [
  { name: 'create_planner_note', group: 'planner_calendar', risk: 'low', server_allowed: true, enabled: true },
  { name: 'update_planner_note', group: 'planner_calendar', risk: 'low', server_allowed: true, enabled: false },
  { name: 'delete_planner_note', group: 'planner_calendar', risk: 'medium', server_allowed: true, enabled: false },
  { name: 'mark_planner_item_complete', group: 'planner_calendar', risk: 'low', server_allowed: true, enabled: false },
  { name: 'create_personal_calendar_event', group: 'planner_calendar', risk: 'low', server_allowed: true, enabled: false },
  { name: 'delete_personal_calendar_event', group: 'planner_calendar', risk: 'medium', server_allowed: true, enabled: false },
  { name: 'submit_assignment', group: 'submissions', risk: 'high', server_allowed: true, enabled: false },
  { name: 'comment_on_my_submission', group: 'submissions', risk: 'medium', server_allowed: true, enabled: false },
  { name: 'mark_module_item_done', group: 'modules', risk: 'low', server_allowed: false, enabled: false },
  { name: 'send_message', group: 'messages', risk: 'high', server_allowed: true, enabled: true },
  { name: 'reply_to_conversation', group: 'messages', risk: 'high', server_allowed: true, enabled: false },
]

interface MockState {
  scenario: MockScenario
  signedIn: boolean
  me: MeResponse
  writeTools: WriteTool[]
  identities: Identity[]
  grants: Grant[]
  history: LoginEvent[]
  accounts: AdminAccount[]
  enrollments: AdminEnrollment[]
  audit: AuditEntry[]
}

function buildState(scenario: MockScenario): MockState {
  const owner = scenario === 'owner'
  const canvas =
    scenario === 'fresh' || scenario === 'error-503' || scenario === 'rate-limited' || scenario === 'pending' || scenario === 'disabled'
      ? emptyCanvas()
      : scenario === 'invalid' || scenario === 'token-invalid'
        ? { ...validCanvas(), state: 'invalid' as const, invalid_since: ago(60 * 30) }
        : validCanvas()
  const me: MeResponse = {
    account: {
      id: 'acct:00000000-0000-4000-8000-000000000001',
      display_name: 'Ada Example',
      email: 'ada@example.edu',
      role: owner ? 'owner' : 'user',
      status: scenario === 'pending' ? 'pending' : scenario === 'disabled' ? 'disabled' : 'active',
      created_at: ago(60 * 24 * 7),
    },
    csrf_token: MOCK_CSRF,
    session_issued_at: ago(3),
    canvas,
    write_tools_enabled_count: 0,
  }
  const writeTools = WRITE_TOOLS.map((tool) => ({ ...tool }))
  me.write_tools_enabled_count = writeTools.filter((t) => t.enabled).length

  return {
    scenario,
    signedIn: scenario !== 'signed-out',
    me,
    writeTools,
    identities: [
      {
        id: 'ident-1',
        provider_id: 'entra',
        provider_name: 'Microsoft',
        display: 'ada@example.edu',
        email: 'ada@example.edu',
        email_verified: true,
        linked_at: ago(60 * 24 * 7),
        last_login_at: ago(3),
        is_current_session: true,
      },
      {
        id: 'ident-2',
        provider_id: 'github',
        provider_name: 'GitHub',
        display: 'ada-example',
        email: null,
        email_verified: false,
        linked_at: ago(60 * 24 * 2),
        last_login_at: null,
        is_current_session: false,
      },
    ],
    grants: [
      {
        id: 'g_01',
        client_name: 'Claude',
        client_id: 'cl_demo',
        created_at: ago(60 * 24 * 5),
        last_used_at: ago(20),
        revoked_at: null,
      },
      {
        id: 'g_02',
        client_name: 'Example MCP Client',
        client_id: 'cl_demo2',
        created_at: ago(60 * 24 * 12),
        last_used_at: null,
        revoked_at: ago(60 * 24 * 3),
      },
    ],
    history: [
      { at: ago(3), provider_id: 'entra', outcome: 'success', reason: null, ip: '203.0.113.7', user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36' },
      { at: ago(60 * 20), provider_id: 'github', outcome: 'denied', reason: 'access_denied', ip: null, user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15' },
      { at: ago(60 * 48), provider_id: 'entra', outcome: 'error', reason: 'provider_error', ip: 'unknown', user_agent: null },
    ],
    accounts: [
      { id: me.account.id, display_name: 'Ada Example', email: 'ada@example.edu', role: owner ? 'owner' : 'user', status: 'active', providers: ['entra', 'github'], created_at: ago(60 * 24 * 7), last_login_at: ago(3), canvas_state: canvas.state, grants_count: 1 },
      { id: 'acct:00000000-0000-4000-8000-000000000002', display_name: 'Bob Example', email: null, role: 'user', status: 'pending', providers: ['github'], created_at: ago(60 * 24), last_login_at: null, canvas_state: 'none', grants_count: 0 },
      { id: 'acct:00000000-0000-4000-8000-000000000003', display_name: 'Cleo Example', email: 'cleo@example.edu', role: 'user', status: 'active', providers: ['google'], created_at: ago(60 * 24 * 4), last_login_at: ago(60 * 5), canvas_state: 'invalid', grants_count: 2 },
      { id: 'acct:00000000-0000-4000-8000-000000000004', display_name: 'Dev Example', email: 'dev@example.edu', role: 'user', status: 'disabled', providers: ['entra'], created_at: ago(60 * 24 * 9), last_login_at: ago(60 * 24 * 8), canvas_state: 'unknown', grants_count: 0 },
    ],
    enrollments: [
      { account_id: me.account.id, display_name: 'Ada Example', canvas_user_name: 'Ada Example', canvas_user_id: 1234567, state: 'valid', enrolled_at: ago(60 * 24 * 6), updated_at: ago(60 * 24 * 6), last_used_at: ago(20), invalid_since: null },
      { account_id: 'acct:00000000-0000-4000-8000-000000000003', display_name: 'Cleo Example', canvas_user_name: 'Cleo Example', canvas_user_id: 7654321, state: 'invalid', enrolled_at: ago(60 * 24 * 4), updated_at: ago(60 * 24 * 4), last_used_at: ago(60 * 30), invalid_since: ago(60 * 29) },
    ],
    audit: [
      { id: 'a1', at: ago(3), actor_account_id: me.account.id, actor_name: 'Ada Example', action: 'login', target_account_id: null, target_name: null, detail: { provider: 'entra' } },
      { id: 'a2', at: ago(60 * 3), actor_account_id: me.account.id, actor_name: 'Ada Example', action: 'approve', target_account_id: 'acct:00000000-0000-4000-8000-000000000003', target_name: 'Cleo Example', detail: null },
      { id: 'a3', at: ago(60 * 24), actor_account_id: null, actor_name: null, action: 'enrollment_revoke', target_account_id: 'acct:00000000-0000-4000-8000-000000000004', target_name: 'Dev Example', detail: { reason: 'expired' } },
      { id: 'a4', at: ago(60 * 25), actor_account_id: 'acct:00000000-0000-4000-8000-000000000003', actor_name: 'Cleo Example', action: 'write_tool_toggle', target_account_id: null, target_name: null, detail: { enabled: 2 } },
    ],
  }
}

// ---- plumbing ---------------------------------------------------------------

interface Reply {
  status: number
  data: unknown
}
const ok = (data: unknown, status = 200): Reply => ({ status, data })
const noContent = (): Reply => ({ status: 204, data: '' })
const fail = (status: number, code: ApiErrorCode, params?: ErrorParams): Reply => ({
  status,
  data: { error: { code, ...(params ? { params } : {}) } },
})

interface Ctx {
  match: RegExpMatchArray
  body: Record<string, unknown>
  query: URLSearchParams
}
type Handler = (ctx: Ctx, state: MockState) => Reply

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

function parseBody(data: unknown): Record<string, unknown> {
  if (typeof data === 'string' && data) {
    try {
      const parsed: unknown = JSON.parse(data)
      return typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : {}
    } catch {
      return {}
    }
  }
  return typeof data === 'object' && data !== null ? (data as Record<string, unknown>) : {}
}

function paged<T>(items: T[], cursor: string | null, size: number): { page: T[]; next: string | null } {
  const start = cursor ? Number.parseInt(cursor, 10) || 0 : 0
  const page = items.slice(start, start + size)
  const end = start + size
  return { page, next: end < items.length ? String(end) : null }
}

function syncAccountRow(state: MockState): void {
  const row = state.accounts.find((a) => a.id === state.me.account.id)
  if (row) row.canvas_state = state.me.canvas.state
}

const routes: { method: string; pattern: RegExp; admin?: boolean; handler: Handler }[] = [
  {
    method: 'GET',
    pattern: /^\/me$/,
    handler: (_c, s) => ok(s.me),
  },
  {
    method: 'GET',
    pattern: /^\/me\/canvas-token$/,
    handler: (_c, s) => ok(s.me.canvas),
  },
  {
    method: 'PUT',
    pattern: /^\/me\/canvas-token$/,
    handler: (c, s) => {
      if (s.scenario === 'error-503') return fail(503, 'token_store_unavailable')
      if (s.scenario === 'rate-limited') return fail(429, 'rate_limited', { retry_after_s: 30 })
      const token = typeof c.body.canvas_token === 'string' ? c.body.canvas_token.trim() : ''
      if (token.length < 20 || token.length > 512) return fail(422, 'token_invalid_format')
      if (token.includes('rejected')) return fail(422, 'token_rejected')
      if (token.includes('offline')) return fail(502, 'canvas_unavailable')
      const now = new Date().toISOString()
      s.me.canvas = {
        state: 'valid',
        canvas_user_id: 1234567,
        canvas_user_name: 'Ada Example',
        enrolled_at: s.me.canvas.enrolled_at ?? now,
        updated_at: now,
        last_used_at: s.me.canvas.last_used_at,
        last_checked_at: now,
        invalid_since: null,
      }
      syncAccountRow(s)
      return ok(s.me.canvas)
    },
  },
  {
    method: 'DELETE',
    pattern: /^\/me\/canvas-token$/,
    handler: (_c, s) => {
      if (s.scenario === 'error-503') return fail(503, 'token_store_unavailable')
      s.me.canvas = emptyCanvas()
      syncAccountRow(s)
      return noContent()
    },
  },
  {
    method: 'POST',
    pattern: /^\/me\/canvas-token\/verify$/,
    handler: (_c, s) => {
      if (s.scenario === 'rate-limited') return fail(429, 'rate_limited', { retry_after_s: 30 })
      if (s.me.canvas.state === 'none') return fail(404, 'not_found')
      s.me.canvas = { ...s.me.canvas, last_checked_at: new Date().toISOString() }
      return ok(s.me.canvas)
    },
  },
  {
    method: 'GET',
    pattern: /^\/me\/write-tools$/,
    handler: (_c, s) => ok({ server_enabled: true, tools: s.writeTools }),
  },
  {
    method: 'PUT',
    pattern: /^\/me\/write-tools$/,
    handler: (c, s) => {
      const enabled = Array.isArray(c.body.enabled) ? (c.body.enabled as unknown[]).map(String) : []
      const blocked = enabled.some((name) => !s.writeTools.find((t) => t.name === name)?.server_allowed)
      if (blocked) return fail(403, 'write_tool_not_allowed')
      for (const tool of s.writeTools) tool.enabled = enabled.includes(tool.name)
      s.me.write_tools_enabled_count = enabled.length
      return ok({ server_enabled: true, tools: s.writeTools })
    },
  },
  {
    method: 'GET',
    pattern: /^\/me\/identities$/,
    handler: (_c, s) => {
      const linked = new Set(s.identities.map((i) => i.provider_id))
      return ok({
        identities: s.identities,
        linkable_providers: PROVIDERS.filter((p) => !linked.has(p.id)),
      })
    },
  },
  {
    method: 'POST',
    pattern: /^\/me\/identities\/link\/([^/]+)$/,
    handler: (c) => ok({ redirect_url: `/account/api/login/${c.match[1]}/start` }),
  },
  {
    method: 'DELETE',
    pattern: /^\/me\/identities\/([^/]+)$/,
    handler: (c, s) => {
      if (s.identities.length <= 1) return fail(409, 'last_identity')
      const index = s.identities.findIndex((i) => i.id === c.match[1])
      if (index < 0) return fail(404, 'not_found')
      s.identities.splice(index, 1)
      return noContent()
    },
  },
  {
    method: 'GET',
    pattern: /^\/me\/grants$/,
    handler: (_c, s) => ok({ grants: s.grants }),
  },
  {
    method: 'DELETE',
    pattern: /^\/me\/grants\/([^/]+)$/,
    handler: (c, s) => {
      const grant = s.grants.find((g) => g.id === c.match[1])
      if (!grant) return fail(404, 'not_found')
      if (grant.revoked_at) return fail(409, 'grant_revoked')
      grant.revoked_at = new Date().toISOString()
      return noContent()
    },
  },
  {
    method: 'GET',
    pattern: /^\/me\/login-history$/,
    handler: (_c, s) => ok({ events: s.history }),
  },
  {
    method: 'POST',
    pattern: /^\/session\/logout$/,
    handler: (_c, s) => {
      s.signedIn = false
      return noContent()
    },
  },
  {
    method: 'GET',
    pattern: /^\/consent\/([^/]+)$/,
    handler: (c, s) => {
      if (c.match[1] === 'expired') return fail(410, 'consent_expired')
      if (c.match[1] !== 't_9f2') return fail(404, 'not_found')
      return ok({
        txn: 't_9f2',
        client_name: 'Claude',
        client_uri: 'https://claude.ai',
        redirect_host: 'claude.ai',
        scopes: ['canvas:read'],
        account_display_name: s.me.account.display_name,
        expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
      })
    },
  },
  {
    method: 'POST',
    pattern: /^\/consent\/([^/]+)$/,
    handler: (c) => {
      if (c.match[1] !== 't_9f2') return fail(404, 'not_found')
      // Same-origin on purpose: local development must not navigate off-site.
      return ok({ redirect_url: `/account/?consent=${c.body.decision === 'deny' ? 'denied' : 'allowed'}` })
    },
  },
  {
    method: 'GET',
    pattern: /^\/admin\/accounts$/,
    admin: true,
    handler: (c, s) => {
      const status = c.query.get('status')
      const q = (c.query.get('q') ?? '').toLowerCase()
      const filtered = s.accounts.filter(
        (a) =>
          (!status || a.status === status) &&
          (!q || a.display_name.toLowerCase().includes(q) || (a.email ?? '').toLowerCase().includes(q)),
      )
      const { page, next } = paged(filtered, c.query.get('cursor'), 3)
      return ok({ accounts: page, next_cursor: next })
    },
  },
  {
    method: 'POST',
    pattern: /^\/admin\/accounts\/([^/]+)\/action$/,
    admin: true,
    handler: (c, s) => {
      const account = s.accounts.find((a) => a.id === decodeURIComponent(c.match[1]))
      if (!account) return fail(404, 'not_found')
      switch (c.body.action) {
        case 'approve':
        case 'enable':
          account.status = 'active'
          break
        case 'disable':
          account.status = 'disabled'
          break
        case 'set_role':
          account.role = c.body.role === 'owner' ? 'owner' : 'user'
          break
        case 'revoke_grants':
          account.grants_count = 0
          break
        case 'unlink_identity':
          account.providers = account.providers.filter((p) => p !== c.body.identity_id)
          break
        default:
          return fail(422, 'validation_failed', { field: 'action' })
      }
      return ok(account)
    },
  },
  {
    method: 'GET',
    pattern: /^\/admin\/enrollments$/,
    admin: true,
    handler: (_c, s) => ok({ enrollments: s.enrollments }),
  },
  {
    method: 'DELETE',
    pattern: /^\/admin\/enrollments\/([^/]+)$/,
    admin: true,
    handler: (c, s) => {
      const id = decodeURIComponent(c.match[1])
      const index = s.enrollments.findIndex((e) => e.account_id === id)
      if (index < 0) return fail(404, 'not_found')
      s.enrollments.splice(index, 1)
      return noContent()
    },
  },
  {
    method: 'GET',
    pattern: /^\/admin\/audit$/,
    admin: true,
    handler: (c, s) => {
      const action = c.query.get('action')
      const actor = c.query.get('actor')
      const filtered = s.audit.filter(
        (e) => (!action || e.action === action) && (!actor || e.actor_account_id === actor),
      )
      const { page, next } = paged(filtered, c.query.get('cursor'), 3)
      return ok({ entries: page, next_cursor: next })
    },
  },
]

function handle(state: MockState, config: InternalAxiosRequestConfig): Reply {
  const method = (config.method ?? 'get').toUpperCase()
  const url = new URL(config.url ?? '/', 'http://mock.invalid')
  const query = new URLSearchParams(url.search)
  if (config.params && typeof config.params === 'object') {
    for (const [k, v] of Object.entries(config.params as Record<string, unknown>)) {
      if (v !== undefined && v !== null) query.set(k, String(v))
    }
  }
  const path = url.pathname

  if (method === 'GET' && path === '/providers') {
    const list =
      state.scenario === 'no-provider' ? [] : state.scenario === 'single-provider' ? PROVIDERS.slice(0, 1) : PROVIDERS
    const body: ProvidersResponse = {
      providers: list,
      login_mode: 'open',
      signups_paused: false,
      mcp_url: `${window.location.origin}/mcp`,
    }
    return ok(body)
  }

  if (!state.signedIn) return fail(401, 'not_authenticated')

  if (MUTATING.has(method) && config.headers.get('X-CSRF-Token') !== MOCK_CSRF) {
    return fail(403, 'csrf_invalid')
  }

  for (const route of routes) {
    if (route.method !== method) continue
    const match = path.match(route.pattern)
    if (!match) continue
    if (route.admin && state.me.account.role !== 'owner') return fail(403, 'forbidden')
    if (state.me.account.status !== 'active' && !/^\/(me|session)/.test(path)) return fail(403, 'forbidden')
    return route.handler({ match, body: parseBody(config.data), query }, state)
  }
  return fail(404, 'not_found')
}

export interface MockOptions {
  scenario?: MockScenario
  /** Simulated latency in ms ([min, max]); [0, 0] disables it (used by tests). */
  latency?: [number, number]
}

function readScenario(): MockScenario {
  const raw = new URLSearchParams(window.location.search).get('mock')
  return (MOCK_SCENARIOS as readonly string[]).includes(raw ?? '') ? (raw as MockScenario) : 'enrolled'
}

export function installMockServer(http: AxiosInstance, options: MockOptions = {}): MockState {
  const state = buildState(options.scenario ?? readScenario())
  const [minMs, maxMs] = options.latency ?? [150, 400]

  http.defaults.adapter = async (config: InternalAxiosRequestConfig): Promise<AxiosResponse> => {
    if (maxMs > 0) await sleep(minMs + Math.random() * (maxMs - minMs))
    const reply = handle(state, config)
    const response: AxiosResponse = {
      // A fresh copy per response: a real server never shares objects with the client.
      data: structuredClone(reply.data),
      status: reply.status,
      statusText: String(reply.status),
      headers: {},
      config,
      request: {},
    }
    if (reply.status >= 200 && reply.status < 300) return response
    throw new AxiosError(
      `Request failed with status code ${reply.status}`,
      reply.status >= 500 ? AxiosError.ERR_BAD_RESPONSE : AxiosError.ERR_BAD_REQUEST,
      config,
      response.request,
      response,
    )
  }
  return state
}
