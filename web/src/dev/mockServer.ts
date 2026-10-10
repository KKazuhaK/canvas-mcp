// DEV-ONLY mock of the /account/api contract.
//
// Loaded exclusively through `await import('./dev/mockServer')` in main.tsx,
// behind `import.meta.env.DEV && import.meta.env.VITE_MOCK === '1'`. In a
// production build that condition is the constant `false`, so this module and
// everything it imports are dropped; scripts/check-dist.mjs fails the build if
// any marker from this file or its fixtures appears in dist/.
//
// It is generated from the same types as the real client: every handler is
// registered under a key of the `Contract` table (api/contract.ts) and must return
// that route's response type, so the mock cannot drift from the wire shapes. It
// mirrors the server's pipeline too (session, pending gate, owner gate with the
// fresh-sign-in rule, CSRF header, closed error codes), so the screens exercise the
// same paths as against the real server. It swaps the axios adapter, so the real
// interceptors (CSRF header, error normalisation) still run. State is in memory
// and resets on reload. Pick a scenario with `?mock=<name>` on the first page load.

import {
  AxiosError,
  type AxiosInstance,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from 'axios'
import type { ResponseOf, RouteKey } from '@/api/contract'
import { splitRoute } from '@/api/contract'
import type {
  AdminAccount,
  AdminAction,
  AdminActionResponse,
  ApiErrorBody,
  ApiErrorCode,
  AuditEntry,
  CanvasTokenStatus,
  ConsentResponse,
  ErrorParams,
  Features,
  Grant,
  InvalidReason,
  LoginEvent,
  MeResponse,
  SchoolsResponse,
  UiLocale,
  WriteTool,
  WriteToolGroup,
  WriteToolGroupId,
  WriteToolsResponse,
} from '@/api/types'

export const MOCK_SCENARIOS = [
  'enrolled',
  'fresh',
  'signed-out',
  'pending',
  'invalid',
  'token-invalid',
  'revoked',
  'expiring',
  'picker',
  'identity-change',
  'owner',
  'stale-owner',
  'no-write-tools',
  'error-503',
  'rate-limited',
  // The server's own authorization server (SELFHOST_AUTH_MODE=local): consent and connected apps.
  'local',
  'local-owner',
  'local-pending',
] as const
export type MockScenario = (typeof MOCK_SCENARIOS)[number]

const MOCK_CSRF = 'mock-csrf-token-not-a-secret'
const SELF_ID = '00000000-0000-4000-8000-000000000001'
const acct = (n: number) => `00000000-0000-4000-8000-00000000000${n}`
const ago = (minutes: number) =>
  new Date(Date.now() - minutes * 60_000).toISOString().replace(/\.\d{3}Z$/, 'Z')
const inDays = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10)

/**
 * Request ids the consent screen can be opened with in the mock (`/consent?txn=<id>`).
 * Any other well-formed id answers authorization_invalid, like an expired or used one.
 */
const padTxn = (word: string) => word.padEnd(43, 'x')
export const MOCK_TXN = {
  verified: padTxn('mockverified'),
  unverified: padTxn('mockunverified'),
  loopback: padTxn('mockloopback'),
  unavailable: padTxn('mockunavailable'),
} as const

const SCHOOL = { host: 'canvas.example.edu', name: 'Example University', offered: true }
const SEARCHABLE = [
  { host: 'canvas.example.edu', name: 'Example University' },
  { host: 'learn.sample.edu', name: 'Sample College' },
  { host: 'canvas.demo.edu', name: 'Demo State University' },
]

// ---- fixtures ---------------------------------------------------------------

function emptyCanvas(): CanvasTokenStatus {
  return {
    state: 'none',
    canvas_user_id: null,
    canvas_user_name: null,
    school: null,
    invalid_reason: null,
    invalid_since: null,
    recheck_allowed: false,
    expires_on: null,
    expiry_notice: 'none',
    settings_url: null,
    enrolled_at: null,
    updated_at: null,
    last_used_at: null,
    last_verified_at: null,
  }
}

function activeCanvas(): CanvasTokenStatus {
  return {
    state: 'active',
    canvas_user_id: '1234567',
    canvas_user_name: 'Ada Example',
    school: SCHOOL,
    invalid_reason: null,
    invalid_since: null,
    recheck_allowed: false,
    expires_on: inDays(60),
    expiry_notice: 'none',
    settings_url: `https://${SCHOOL.host}/profile/settings`,
    enrolled_at: ago(60 * 24 * 6),
    updated_at: ago(60 * 24 * 6),
    last_used_at: ago(20),
    last_verified_at: ago(20),
  }
}

function invalidCanvas(reason: InvalidReason): CanvasTokenStatus {
  return {
    ...activeCanvas(),
    state: 'invalid',
    invalid_reason: reason,
    invalid_since: ago(60 * 30),
    recheck_allowed: reason !== 'revoked_by_admin',
  }
}

type ToolSeed = [name: string, group: WriteToolGroupId, offered: boolean, enabled: boolean, local?: boolean]
const TOOL_SEEDS: ToolSeed[] = [
  ['create_planner_note', 'planner', true, true],
  ['update_planner_note', 'planner', true, false],
  ['delete_planner_note', 'planner', true, false],
  ['mark_planner_item_complete', 'planner', true, false],
  ['create_personal_calendar_event', 'planner', true, false],
  ['delete_personal_calendar_event', 'planner', true, false],
  ['submit_assignment', 'submissions', true, false],
  ['comment_on_my_submission', 'submissions', true, false],
  ['mark_module_item_done', 'modules', false, false],
  ['send_message', 'inbox', true, true],
  ['reply_to_conversation', 'inbox', true, false],
  ['update_syllabus', 'other', true, false],
  ['download_course_file', 'other', true, false, true],
]
const GROUP_ORDER: WriteToolGroupId[] = ['planner', 'submissions', 'modules', 'inbox', 'other']

interface MockTool {
  name: string
  group: WriteToolGroupId
  offered: boolean
  enabled: boolean
  local: boolean
}

interface MockState {
  scenario: MockScenario
  signedIn: boolean
  fresh: boolean
  me: MeResponse
  canvas: CanvasTokenStatus
  tools: MockTool[]
  hasCatalog: boolean
  schools: SchoolsResponse
  history: LoginEvent[]
  accounts: AdminAccount[]
  audit: AuditEntry[]
  /** Live connected apps by account id (local scenarios). */
  grants: Map<string, Grant[]>
  /** Consent requests not decided yet. */
  txns: Set<string>
}

function accountRow(
  n: number,
  name: string,
  username: string,
  status: AdminAccount['status'],
  extra: Partial<AdminAccount> = {},
): AdminAccount {
  return {
    id: acct(n),
    key: `acct:${acct(n)}`,
    display_name: name,
    username,
    role: 'user',
    status,
    disabled_reason: null,
    disabled_at: null,
    created_at: ago(60 * 24 * (10 - n)),
    approved_at: status === 'pending' ? null : ago(60 * 24 * (9 - n)),
    last_login_at: status === 'pending' ? null : ago(60 * n),
    is_self: false,
    identity: { provider_id: 'entra', tenant_id: 'tenant-demo', subject: `subject-${n}` },
    enrollment: null,
    actions: [],
    ...extra,
  }
}

function enrollmentOf(
  name: string,
  id: string,
  invalid: InvalidReason | null,
): NonNullable<AdminAccount['enrollment']> {
  return {
    canvas_user_name: name,
    canvas_user_id: id,
    school: { ...SCHOOL, is_default: true },
    state: invalid ? 'invalid' : 'active',
    invalid_reason: invalid,
    invalid_since: invalid ? ago(60 * 29) : null,
    last_verified_at: ago(60),
    last_used_at: ago(60 * 3),
    created_at: ago(60 * 24 * 4),
    updated_at: ago(60 * 24 * 4),
  }
}

/** What the server offers for one row (the legacy `_admin_actions`, as the API computes it). */
function actionsFor(row: AdminAccount): AdminAction[] {
  if (row.status === 'pending') return ['approve', 'deny']
  const actions: AdminAction[] = []
  if (row.enrollment && row.enrollment.state !== 'invalid' && row.status === 'active') {
    actions.push('mark_invalid')
  }
  if (row.status === 'disabled') actions.push('enable')
  else if (row.status === 'missing') {
    // an enrollment without an account can only be removed
  } else if (!row.is_self) actions.push('disable')
  if (row.enrollment) actions.push('remove_enrollment')
  return actions
}

function auditEntry(
  id: number,
  action: string,
  actor: AuditEntry['actor'],
  target: AuditEntry['target'],
  detail: AuditEntry['detail'] = {},
  reason: string | null = null,
): AuditEntry {
  return { id, at: ago(id * 37), action, actor, target, reason, detail }
}

function grantOf(
  n: number,
  client: Grant['client'],
  redirectHost: string,
  lastUsedMinutes: number | null,
): Grant {
  return {
    id: `00000000-0000-4000-8000-0000000001${String(n).padStart(2, '0')}`,
    client,
    redirect_host: redirectHost,
    created_at: ago(60 * 24 * n),
    last_used_at: lastUsedMinutes === null ? null : ago(lastUsedMinutes),
    expires_at: ago(-60 * 24 * (30 - n)),
  }
}

function seedGrants(selfId: string): Map<string, Grant[]> {
  return new Map<string, Grant[]>([
    [
      selfId,
      [
        grantOf(1, { kind: 'cimd', label: 'claude.ai', name: 'Claude', host: 'claude.ai', verified: true }, 'claude.ai', 12),
        grantOf(2, { kind: 'cimd', label: 'claude.ai', name: 'Claude Code', host: 'claude.ai', verified: true }, '127.0.0.1', 60 * 5),
        grantOf(3, { kind: 'dcr', label: 'Sample Desktop Tool', name: 'Sample Desktop Tool', host: null, verified: false }, 'tool.example.test', null),
      ],
    ],
    [
      acct(3),
      [grantOf(4, { kind: 'dcr', label: 'Cleo Notes', name: 'Cleo Notes', host: null, verified: false }, 'notes.example.test', 90)],
    ],
  ])
}

function buildState(scenario: MockScenario): MockState {
  const local = scenario.startsWith('local')
  const owner = scenario === 'owner' || scenario === 'stale-owner' || scenario === 'local-owner'
  const pending = scenario === 'pending' || scenario === 'local-pending'
  const picker = scenario === 'picker'

  const canvas =
    scenario === 'fresh' || scenario === 'picker' || scenario === 'error-503' || scenario === 'rate-limited'
      ? emptyCanvas()
      : scenario === 'invalid' || scenario === 'token-invalid'
        ? invalidCanvas('canvas_token_rejected')
        : scenario === 'revoked'
          ? invalidCanvas('revoked_by_admin')
          : scenario === 'expiring'
            ? { ...activeCanvas(), expires_on: inDays(3), expiry_notice: 'soon' as const }
            : pending
              ? emptyCanvas()
              : activeCanvas()

  const features: Features = {
    school_picker: picker,
    school_search: picker,
    write_tools: !pending && scenario !== 'no-write-tools',
    admin: owner,
    identities: false,
    connected_apps: local && !pending,
    consent: local,
    logout_everywhere: false,
    role_management: false,
  }
  const tools: MockTool[] = TOOL_SEEDS.map(([name, group, offered, enabled, local]) => ({
    name,
    group,
    offered,
    enabled,
    local: local === true,
  }))
  const fresh = scenario !== 'stale-owner'
  const me: MeResponse = {
    account: {
      id: SELF_ID,
      key: `acct:${SELF_ID}`,
      display_name: 'Ada Example',
      username: 'ada@example.edu',
      provider_id: 'entra',
      role: owner ? 'owner' : 'user',
      status: pending ? 'pending' : 'active',
    },
    csrf_token: MOCK_CSRF,
    session: {
      issued_at: ago(3),
      expires_at: ago(-60 * 8),
      fresh_until: fresh ? ago(-7) : null,
      fresh,
      fresh_window_s: 600,
    },
    canvas: pending ? null : canvas,
    write_tools: null,
    features,
    ui_locale: null,
    server: { mcp_url: `${window.location.origin}/mcp`, display_timezone: 'America/Los_Angeles' },
  }

  const schools: SchoolsResponse = picker
    ? {
        mode: 'picker',
        choices: [
          { host: 'canvas.example.edu', name: 'Example University', source: 'featured' },
          { host: 'learn.sample.edu', name: 'Sample College', source: 'featured' },
        ],
        selected: 'canvas.example.edu',
        sole: null,
        search_enabled: true,
      }
    : {
        mode: 'fixed',
        choices: [],
        selected: null,
        sole: { host: SCHOOL.host, name: SCHOOL.name },
        search_enabled: false,
      }

  const selfRow = accountRow(1, 'Ada Example', 'ada@example.edu', 'active', {
    id: SELF_ID,
    key: `acct:${SELF_ID}`,
    role: owner ? 'owner' : 'user',
    is_self: true,
    enrollment: canvas.state === 'none' ? null : enrollmentOf('Ada Example', '1234567', null),
  })
  const accounts = [
    selfRow,
    accountRow(2, 'Bob Example', 'bob@example.edu', 'pending'),
    accountRow(3, 'Cleo Example', 'cleo@example.edu', 'active', {
      enrollment: enrollmentOf('Cleo Example', '7654321', 'canvas_token_rejected'),
    }),
    accountRow(4, 'Dev Example', 'dev@example.edu', 'disabled', {
      disabled_reason: 'admin_disabled',
      disabled_at: ago(60 * 24 * 2),
    }),
  ]
  for (const row of accounts) row.actions = actionsFor(row)

  const self = { kind: 'account' as const, key: selfRow.key, name: 'Ada Example' }
  const cleo = { key: `acct:${acct(3)}`, name: 'Cleo Example' }
  const audit = [
    auditEntry(7, 'account_created', { kind: 'system', key: null, name: null }, { key: `acct:${acct(2)}`, name: 'Bob Example' }, {}, 'pending_approval'),
    auditEntry(6, 'token_enrolled', { kind: 'account', key: cleo.key, name: cleo.name }, cleo, { school: SCHOOL.host }),
    auditEntry(5, 'account_approved', self, cleo),
    auditEntry(4, 'write_tools_changed', self, null, { enabled: ['create_planner_note', 'send_message'], count: 2 }),
    auditEntry(3, 'account_disabled', self, { key: `acct:${acct(4)}`, name: 'Dev Example' }, {}, 'admin_disabled'),
    auditEntry(2, 'role_changed', { kind: 'operator', key: null, name: null }, { key: selfRow.key, name: 'Ada Example' }, { role: 'owner' }),
    auditEntry(1, 'schema_migrated', { kind: 'system', key: null, name: null }, null, { version: 5 }),
  ]

  return {
    scenario,
    signedIn: scenario !== 'signed-out',
    fresh,
    me,
    canvas,
    tools,
    hasCatalog: scenario !== 'no-write-tools',
    schools,
    history: [
      { at: ago(3), provider_id: 'entra', outcome: 'success', reason: null },
      { at: ago(60 * 20), provider_id: 'entra', outcome: 'refused', reason: 'signups_paused' },
      { at: ago(60 * 24 * 6), provider_id: 'entra', outcome: 'pending', reason: 'account_created' },
    ],
    accounts,
    audit,
    grants: local ? seedGrants(SELF_ID) : new Map(),
    txns: new Set(local ? Object.values(MOCK_TXN) : []),
  }
}

// ---- views ---------------------------------------------------------------------

function toolView(tool: MockTool): WriteTool {
  return {
    name: tool.name,
    offered: tool.offered,
    enabled: tool.enabled,
    enabled_at: tool.enabled ? ago(60 * 24) : null,
    effect: tool.local ? 'local_write' : 'canvas_write',
  }
}

function writeToolsView(state: MockState): WriteToolsResponse {
  // The known groups are always listed; "other" only when it holds an offered tool.
  const groups: WriteToolGroup[] = GROUP_ORDER.map((id) => ({
    id,
    tools: state.tools
      .filter((tool) => tool.group === id && (id !== 'other' || tool.offered))
      .map(toolView),
  })).filter((group) => group.id !== 'other' || group.tools.length > 0)
  return {
    groups,
    kept_not_offered: [],
    offered_any: state.tools.some((tool) => tool.offered),
    editable: state.tools.some((tool) => tool.offered || tool.enabled),
  }
}

function meView(state: MockState): MeResponse {
  const pending = state.me.account.status === 'pending'
  const offered = state.tools.filter((tool) => tool.offered)
  return {
    ...state.me,
    canvas: pending ? null : state.canvas,
    write_tools:
      pending || !state.hasCatalog
        ? null
        : { offered: offered.length, enabled: offered.filter((tool) => tool.enabled).length },
  }
}

// ---- plumbing ---------------------------------------------------------------------

interface Ok<T> {
  status: number
  data: T
}
interface Fail {
  status: number
  data: ApiErrorBody
}
type Reply<T> = Ok<T> | Fail

const ok = <T>(data: T, status = 200): Ok<T> => ({ status, data })
const noContent = (): Ok<void> => ({ status: 204, data: '' as unknown as void })
const STATUS: Partial<Record<ApiErrorCode, number>> = {
  not_authenticated: 401,
  csrf_invalid: 403,
  origin_not_allowed: 403,
  reauth_required: 403,
  forbidden: 403,
  pending_approval: 403,
  access_disabled: 403,
  method_not_allowed: 405,
  unsupported_media_type: 415,
  payload_too_large: 413,
  malformed_request: 400,
  validation_failed: 422,
  not_found: 404,
  rate_limited: 429,
  token_store_unavailable: 503,
  internal_error: 500,
  token_invalid_format: 422,
  token_rejected: 422,
  token_unreadable: 422,
  canvas_unavailable: 503,
  identity_change_required: 409,
  recheck_not_allowed: 409,
  school_required: 422,
  school_invalid: 422,
  school_not_offered: 422,
  school_not_in_directory: 422,
  school_unresolvable: 422,
  school_address_blocked: 422,
  school_selection_unverified: 422,
  directory_unavailable: 503,
  write_tool_not_allowed: 422,
  write_tools_unavailable: 503,
  last_owner: 409,
  cannot_disable_self: 409,
  authorization_invalid: 400,
  client_unavailable: 409,
}
const fail = (code: ApiErrorCode, params?: ErrorParams): Fail => ({
  status: STATUS[code] ?? 500,
  data: { error: { code, ...(params ? { params } : {}) } },
})

interface Ctx {
  match: RegExpMatchArray
  /** The parsed JSON body (unvalidated, like the server's raw object). */
  body: Record<string, unknown>
  query: URLSearchParams
}
type Handler<K extends RouteKey> = (ctx: Ctx, state: MockState) => Reply<ResponseOf<K>>
type Access = 'public' | 'session' | 'active' | 'owner'

interface RouteDef {
  method: string
  pattern: RegExp
  access: Access
  csrf: boolean
  // The handler's context is typed per route at registration; the table holds them uniformly.
  handler: (ctx: Ctx, state: MockState) => Reply<unknown>
}

const routes: RouteDef[] = []

function route<K extends RouteKey>(key: K, access: Access, handler: Handler<K>): void {
  const { method, path } = splitRoute(key)
  routes.push({
    method,
    pattern: new RegExp(`^${path.replace('{id}', '([^/]+)')}$`),
    access,
    csrf: method !== 'GET' || key === 'GET /me/schools/search',
    handler: handler as unknown as RouteDef['handler'],
  })
}

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

function onlyFields(body: Record<string, unknown>, allowed: string[]): Fail | null {
  for (const field of Object.keys(body)) {
    if (!allowed.includes(field)) return fail('validation_failed', { field })
  }
  return null
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

function syncSelf(state: MockState): void {
  const row = state.accounts[0]
  row.enrollment =
    state.canvas.state === 'none'
      ? null
      : enrollmentOf(
          state.canvas.canvas_user_name ?? 'Ada Example',
          state.canvas.canvas_user_id ?? '1234567',
          state.canvas.state === 'invalid' ? state.canvas.invalid_reason : null,
        )
  row.actions = actionsFor(row)
}

// ---- routes -----------------------------------------------------------------------

route('GET /providers', 'public', (_c, s) =>
  ok({
    providers: [
      { id: 'entra', kind: 'oidc', name: 'Microsoft', icon: 'microsoft', start_url: '/account/login' },
    ],
    mcp_url: s.me.server.mcp_url,
  }),
)

route('GET /me', 'session', (_c, s) => ok(meView(s)))

route('GET /me/canvas-token', 'active', (_c, s) => ok(s.canvas))

route('PUT /me/canvas-token', 'active', (c, s) => {
  const bad = onlyFields(c.body, [
    'canvas_token',
    'school',
    'school_sig',
    'expires_on',
    'confirm_identity_change',
  ])
  if (bad) return bad
  if (s.scenario === 'rate-limited') return fail('rate_limited', { retry_after_s: 30 })
  const token = typeof c.body.canvas_token === 'string' ? c.body.canvas_token : ''
  if (!/^[A-Za-z0-9~._-]{20,512}$/.test(token)) return fail('token_invalid_format')

  const expires = c.body.expires_on
  if (typeof expires === 'string' && expires !== '') {
    // Like the server: a real date, today or later.
    if (!/^\d{4}-\d{2}-\d{2}$/.test(expires) || expires < new Date().toISOString().slice(0, 10)) {
      return fail('validation_failed', { field: 'expires_on' })
    }
  }

  let school = SCHOOL
  if (s.schools.mode === 'picker') {
    const host = typeof c.body.school === 'string' ? c.body.school : ''
    if (host === '') return fail('school_required')
    const featured = s.schools.choices.some((choice) => choice.host === host)
    if (!featured) {
      const found = SEARCHABLE.find((entry) => entry.host === host)
      if (!found) return fail('school_not_in_directory')
      if (c.body.school_sig !== `sig-${host}`) return fail('school_selection_unverified')
      school = { host: found.host, name: found.name, offered: true }
    } else {
      const choice = s.schools.choices.find((entry) => entry.host === host)
      school = { host, name: choice?.name ?? host, offered: true }
    }
  }

  if (token.includes('rejected')) return fail('token_rejected')
  if (token.includes('offline')) return fail('canvas_unavailable')
  if (s.scenario === 'error-503') return fail('token_store_unavailable')

  let name = 'Ada Example'
  let canvasId = '1234567'
  if (s.scenario === 'identity-change' && s.canvas.state !== 'none') {
    if (c.body.confirm_identity_change !== 'mock-confirmation') {
      return fail('identity_change_required', {
        enrolled_user_name: 'Ada Example',
        new_user_name: 'Zed Example',
        confirmation: 'mock-confirmation',
      })
    }
    name = 'Zed Example'
    canvasId = '7777777'
  }

  const now = ago(0)
  s.canvas = {
    state: 'active',
    canvas_user_id: canvasId,
    canvas_user_name: name,
    school,
    invalid_reason: null,
    invalid_since: null,
    recheck_allowed: false,
    expires_on: typeof expires === 'string' && expires !== '' ? expires : null,
    expiry_notice: 'none',
    settings_url: `https://${school.host}/profile/settings`,
    enrolled_at: s.canvas.enrolled_at ?? now,
    updated_at: now,
    last_used_at: s.canvas.last_used_at,
    last_verified_at: now,
  }
  syncSelf(s)
  return ok(s.canvas)
})

route('DELETE /me/canvas-token', 'active', (_c, s) => {
  if (s.scenario === 'error-503') return fail('token_store_unavailable')
  s.canvas = emptyCanvas()
  syncSelf(s)
  return noContent()
})

route('POST /me/canvas-token/recheck', 'active', (_c, s) => {
  if (s.scenario === 'rate-limited') return fail('rate_limited', { retry_after_s: 60 })
  if (s.canvas.state === 'none') return fail('not_found')
  if (s.canvas.invalid_reason === 'revoked_by_admin') return fail('recheck_not_allowed')
  if (s.canvas.state === 'invalid') {
    s.canvas = { ...s.canvas, state: 'active', invalid_reason: null, invalid_since: null, recheck_allowed: false, last_verified_at: ago(0) }
    syncSelf(s)
    return ok({ result: 'restored', canvas: s.canvas })
  }
  return ok({ result: 'unchanged', canvas: s.canvas })
})

route('GET /me/schools', 'active', (_c, s) => ok(s.schools))

route('GET /me/schools/search', 'active', (c, s) => {
  if (!s.schools.search_enabled) return fail('not_found')
  const q = (c.query.get('q') ?? '').trim()
  if (q.length < 2 || q.length > 64) return fail('validation_failed', { field: 'q', min: 2, max: 64 })
  if (q.toLowerCase().includes('offline')) return fail('directory_unavailable')
  const needle = q.toLowerCase()
  const results = SEARCHABLE.filter(
    (entry) => entry.name.toLowerCase().includes(needle) || entry.host.includes(needle),
  ).map((entry) => ({ host: entry.host, name: entry.name, sig: `sig-${entry.host}` }))
  return ok({ results })
})

route('GET /me/write-tools', 'active', (_c, s) =>
  s.hasCatalog ? ok(writeToolsView(s)) : fail('not_found'),
)

route('PUT /me/write-tools', 'active', (c, s) => {
  if (!s.hasCatalog) return fail('not_found')
  const bad = onlyFields(c.body, ['enabled'])
  if (bad) return bad
  const raw = c.body.enabled
  if (!Array.isArray(raw) || !raw.every((name) => typeof name === 'string')) {
    return fail('validation_failed', { field: 'enabled' })
  }
  const names = raw as string[]
  const known = new Set(s.tools.filter((tool) => tool.offered || tool.enabled).map((tool) => tool.name))
  const unknown = names.find((name) => !known.has(name))
  if (unknown !== undefined) return fail('write_tool_not_allowed', { tool: unknown })
  const wanted = (tool: MockTool) => (tool.offered ? names.includes(tool.name) : tool.enabled)
  const turnsOn = s.tools.some((tool) => !tool.enabled && wanted(tool))
  if (turnsOn && !s.fresh) return fail('reauth_required', { max_age_s: 600 })
  const changed = s.tools.some((tool) => tool.enabled !== wanted(tool))
  for (const tool of s.tools) tool.enabled = wanted(tool)
  return ok({ result: changed ? 'saved' : 'unchanged', ...writeToolsView(s) })
})

route('DELETE /me/write-tools', 'active', (_c, s) => {
  if (!s.hasCatalog) return fail('not_found')
  const changed = s.tools.some((tool) => tool.enabled)
  for (const tool of s.tools) tool.enabled = false
  return ok({ result: changed ? 'saved' : 'unchanged', ...writeToolsView(s) })
})

route('GET /me/login-history', 'session', (_c, s) => ok({ events: s.history }))

route('PUT /me/ui-locale', 'session', (c, s) => {
  const bad = onlyFields(c.body, ['locale'])
  if (bad) return bad
  const locale = c.body.locale
  if (locale !== 'en' && locale !== 'zh') return fail('validation_failed', { field: 'locale' })
  s.me.ui_locale = locale as UiLocale
  return noContent()
})

route('POST /session/logout', 'session', (_c, s) => {
  s.signedIn = false
  return noContent()
})

route('GET /admin/accounts', 'owner', (c, s) => {
  const status = c.query.get('status')
  if (status !== null && !['active', 'pending', 'disabled'].includes(status)) {
    return fail('validation_failed', { field: 'status' })
  }
  const shown = s.accounts
    .filter((a) => status === null || a.status === status)
    .sort((a, b) => (a.status === 'pending' ? 0 : 1) - (b.status === 'pending' ? 0 : 1))
  return ok({
    accounts: shown.map((a) => ({ ...a })),
    counts: {
      total: s.accounts.length,
      active: s.accounts.filter((a) => a.status === 'active').length,
      pending: s.accounts.filter((a) => a.status === 'pending').length,
      disabled: s.accounts.filter((a) => a.status === 'disabled').length,
      owners: s.accounts.filter((a) => a.status === 'active' && a.role === 'owner').length,
    },
  })
})

route('GET /admin/enrollments', 'owner', (c, s) => {
  const filter = c.query.get('filter') ?? 'all'
  if (filter !== 'all' && filter !== 'needs_reenroll') return fail('validation_failed', { field: 'filter' })
  const withToken = s.accounts.filter((a) => a.enrollment !== null)
  const needing = withToken.filter((a) => a.enrollment?.state === 'invalid')
  const rows =
    filter === 'needs_reenroll'
      ? needing
      : [...withToken, ...s.accounts.filter((a) => a.enrollment === null && a.status !== 'active')]
  rows.sort((a, b) => (a.status === 'pending' ? 0 : 1) - (b.status === 'pending' ? 0 : 1))
  return ok({
    rows: rows.map((a) => ({ ...a })),
    counts: {
      needing: needing.length,
      total_enrollments: withToken.length,
      disabled: s.accounts.filter((a) => a.status === 'disabled').length,
      pending: s.accounts.filter((a) => a.status === 'pending').length,
    },
  })
})

function findTarget(c: Ctx, s: MockState): AdminAccount | Fail {
  const id = decodeURIComponent(c.match[1])
  if (!UUID.test(id)) return fail('validation_failed', { field: 'id' })
  return s.accounts.find((a) => a.id === id) ?? fail('not_found')
}

function accessAction(action: 'approve' | 'deny' | 'disable' | 'enable') {
  return (c: Ctx, s: MockState): Reply<AdminActionResponse> => {
    const target = findTarget(c, s)
    if ('status' in target && 'data' in target) return target as Fail
    const row = target as AdminAccount
    let changed = false
    switch (action) {
      case 'approve':
        if (row.status === 'pending') {
          row.status = 'active'
          row.approved_at = ago(0)
          changed = true
        }
        break
      case 'deny':
        if (row.status === 'pending') {
          row.status = 'disabled'
          row.disabled_reason = 'approval_denied'
          row.disabled_at = ago(0)
          changed = true
        }
        break
      case 'disable':
        if (row.is_self) return fail('cannot_disable_self')
        if (row.status === 'active') {
          row.status = 'disabled'
          row.disabled_reason = 'admin_disabled'
          row.disabled_at = ago(0)
          changed = true
        }
        break
      case 'enable':
        if (row.status === 'disabled') {
          row.status = 'active'
          row.disabled_reason = null
          row.disabled_at = null
          changed = true
        }
        break
    }
    row.actions = actionsFor(row)
    return ok({ changed, account: { ...row } })
  }
}

route('POST /admin/accounts/{id}/approve', 'owner', accessAction('approve'))
route('POST /admin/accounts/{id}/deny', 'owner', accessAction('deny'))
route('POST /admin/accounts/{id}/disable', 'owner', accessAction('disable'))
route('POST /admin/accounts/{id}/enable', 'owner', accessAction('enable'))

route('POST /admin/enrollments/{id}/mark-invalid', 'owner', (c, s) => {
  const target = findTarget(c, s)
  if ('status' in target && 'data' in target) return target as Fail
  const row = target as AdminAccount
  if (row.enrollment === null) return fail('not_found')
  const changed = row.enrollment.state !== 'invalid'
  row.enrollment = {
    ...row.enrollment,
    state: 'invalid',
    invalid_reason: 'revoked_by_admin',
    invalid_since: ago(0),
  }
  row.actions = actionsFor(row)
  if (row.is_self) {
    s.canvas = invalidCanvas('revoked_by_admin')
  }
  return ok({ changed, account: { ...row } })
})

route('DELETE /admin/enrollments/{id}', 'owner', (c, s) => {
  const target = findTarget(c, s)
  if ('status' in target && 'data' in target) return target as Fail
  const row = target as AdminAccount
  const changed = row.enrollment !== null
  row.enrollment = null
  row.actions = actionsFor(row)
  if (row.is_self) s.canvas = emptyCanvas()
  return ok({ changed, account: { ...row } })
})

const AUDIT_PAGE = 3
route('GET /admin/audit', 'owner', (c, s) => {
  const raw = c.query.get('before')
  if (raw !== null && !/^\d{1,14}$/.test(raw)) return fail('validation_failed', { field: 'before' })
  const older = s.audit.filter((entry) => raw === null || entry.id < Number(raw))
  const page = older.slice(0, AUDIT_PAGE)
  return ok({
    entries: page,
    next_cursor: page.length >= AUDIT_PAGE ? String(page[page.length - 1].id) : null,
  })
})

// ---- apps (local scenarios only) ---------------------------------------------------------

const TXN_SHAPE = /^[A-Za-z0-9_-]{43}$/

function consentView(txn: string, state: MockState): ConsentResponse {
  const pending = state.me.account.status === 'pending'
  const client: ConsentResponse['client'] =
    txn === MOCK_TXN.unverified
      ? { kind: 'dcr', label: 'Sample Desktop Tool', name: 'Sample Desktop Tool', host: null, verified: false }
      : { kind: 'cimd', label: 'claude.ai', name: 'Claude', host: 'claude.ai', verified: true }
  const loopback = txn === MOCK_TXN.loopback
  return {
    client,
    redirect: loopback ? { host: '127.0.0.1', loopback: true } : { host: 'claude.ai', loopback: false },
    scopes: [{ name: 'Canvas.Access' }],
    account: { display_name: state.me.account.display_name, username: state.me.account.username },
    can_approve: !pending,
    expires_at: ago(-8),
  }
}

route('GET /consent/{id}', 'session', (c, s) => {
  if (!s.me.features.consent) return fail('not_found')
  const txn = decodeURIComponent(c.match[1])
  if (!TXN_SHAPE.test(txn) || !s.txns.has(txn)) return fail('authorization_invalid')
  if (txn === MOCK_TXN.unavailable) return fail('client_unavailable')
  return ok(consentView(txn, s))
})

route('POST /consent/{id}', 'session', (c, s) => {
  if (!s.me.features.consent) return fail('not_found')
  const bad = onlyFields(c.body, ['decision'])
  if (bad) return bad
  const decision = c.body.decision
  if (decision !== 'approve' && decision !== 'deny') return fail('validation_failed', { field: 'decision' })
  const txn = decodeURIComponent(c.match[1])
  if (!TXN_SHAPE.test(txn) || !s.txns.has(txn)) return fail('authorization_invalid')
  if (decision === 'approve' && s.me.account.status === 'pending') return fail('pending_approval')
  s.txns.delete(txn)
  if (txn === MOCK_TXN.unavailable) return fail('client_unavailable')
  const loopback = txn === MOCK_TXN.loopback
  const base = loopback ? 'http://127.0.0.1:39211/callback' : 'https://claude.ai/api/mcp/auth_callback'
  const query =
    decision === 'approve'
      ? 'code=mock-code&state=mock-state&iss=https%3A%2F%2Fmcp.example.test%2F'
      : 'error=access_denied&state=mock-state&iss=https%3A%2F%2Fmcp.example.test%2F'
  return ok({ redirect_to: `${base}?${query}` })
})

route('GET /me/grants', 'active', (_c, s) => {
  if (!s.me.features.connected_apps) return fail('not_found')
  return ok({ grants: s.grants.get(SELF_ID) ?? [] })
})

route('DELETE /me/grants/{id}', 'active', (c, s) => {
  if (!s.me.features.connected_apps) return fail('not_found')
  const id = decodeURIComponent(c.match[1])
  if (!UUID.test(id)) return fail('validation_failed', { field: 'id' })
  const mine = s.grants.get(SELF_ID) ?? []
  if (!mine.some((grant) => grant.id === id)) return fail('not_found')
  s.grants.set(SELF_ID, mine.filter((grant) => grant.id !== id))
  return noContent()
})

route('GET /admin/accounts/{id}/grants', 'owner', (c, s) => {
  if (!s.me.features.connected_apps) return fail('not_found')
  const id = decodeURIComponent(c.match[1])
  if (!UUID.test(id)) return fail('validation_failed', { field: 'id' })
  return ok({ grants: s.grants.get(id) ?? [] })
})

route('DELETE /admin/grants/{id}', 'owner', (c, s) => {
  if (!s.me.features.connected_apps) return fail('not_found')
  const id = decodeURIComponent(c.match[1])
  if (!UUID.test(id)) return fail('validation_failed', { field: 'id' })
  let changed = false
  for (const [account, list] of s.grants) {
    if (list.some((grant) => grant.id === id)) {
      s.grants.set(account, list.filter((grant) => grant.id !== id))
      changed = true
    }
  }
  return ok({ changed })
})

// ---- the adapter -------------------------------------------------------------------

function handle(state: MockState, config: InternalAxiosRequestConfig): Reply<unknown> {
  const method = (config.method ?? 'get').toUpperCase()
  const url = new URL(config.url ?? '/', 'http://mock.invalid')
  const query = new URLSearchParams(url.search)
  if (config.params && typeof config.params === 'object') {
    for (const [k, v] of Object.entries(config.params as Record<string, unknown>)) {
      if (v !== undefined && v !== null) query.set(k, String(v))
    }
  }
  const path = url.pathname

  const byPath = routes.filter((r) => r.pattern.test(path))
  if (byPath.length === 0) return fail('not_found')
  const found = byPath.find((r) => r.method === method)
  if (!found) return fail('method_not_allowed')

  if (found.access !== 'public') {
    if (!state.signedIn) return fail('not_authenticated')
    const pending = state.me.account.status === 'pending'
    if ((found.access === 'active' || found.access === 'owner') && pending) {
      return fail('pending_approval')
    }
    if (found.access === 'owner') {
      if (state.me.account.role !== 'owner') return fail('forbidden')
      if (!state.fresh) return fail('reauth_required', { max_age_s: 600 })
    }
    if (found.csrf && config.headers.get('X-CSRF-Token') !== MOCK_CSRF) return fail('csrf_invalid')
  }
  const match = path.match(found.pattern) as RegExpMatchArray
  return found.handler({ match, body: parseBody(config.data), query }, state)
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
