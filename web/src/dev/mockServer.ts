// DEV-ONLY mock of the /api/v1 contract.
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
  AdminSettingsResponse,
  MailSettingsResponse,
  NotificationPreferences,
  LoginProviderConfiguration,
  AdminAction,
  AdminActionResponse,
  AdminIdentity,
  ApiErrorBody,
  ApiErrorCode,
  AuditEntry,
  CanvasTokenStatus,
  ConsentResponse,
  ErrorParams,
  Features,
  Grant,
  Identity,
  InvalidReason,
  Provider,
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
  'setup',
  'enrolled',
  'featured',
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
  // Two or more sign-in providers: the chooser, Sign-in methods and the owner's per-account list.
  'multi',
  'custody_outdated',
  'multi-owner',
  'multi-stale',
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

const MULTI_PROVIDERS: Provider[] = [
  { id: 'entra', kind: 'oidc', name: 'Microsoft', icon: 'microsoft', start_url: '/auth/login/entra' },
  { id: 'google', kind: 'oidc', name: 'Google', icon: 'google', start_url: '/auth/login/google' },
  { id: 'github', kind: 'oauth2', name: 'GitHub', icon: 'github', start_url: '/auth/login/github' },
  { id: 'oidc:school', kind: 'oidc', name: 'School SSO', icon: 'key', start_url: '/auth/login/oidc/school' },
]
const IDENTITY_ID = /^[1-9][0-9]{0,17}$/

const SCHOOL = { host: 'canvas.example.edu', name: 'Example University', offered: true }
const SEARCHABLE = [
  { host: 'canvas.example.edu', name: 'Example University' },
  { host: 'learn.sample.edu', name: 'Sample College' },
  { host: 'canvas.demo.edu', name: 'Demo State University' },
]

// ---- fixtures ---------------------------------------------------------------

function emptyCanvas(): CanvasTokenStatus {
  return {
    custody: { notice_version: 1, acknowledged_version: null, acknowledged_at: null, current: false },
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
    custody: { notice_version: 1, acknowledged_version: 1, acknowledged_at: ago(60), current: true },
    state: 'active',
    canvas_user_id: '1234567',
    canvas_user_name: 'Ada Example',
    school: SCHOOL,
    invalid_reason: null,
    invalid_since: null,
    recheck_allowed: true,
    expires_on: inDays(60),
    expiry_source: 'canvas',
    expires_at: ago(-60 * 24 * 60),
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
  settings: AdminSettingsResponse
  mail: MailSettingsResponse
  notifications: NotificationPreferences
  setupInitialized: boolean
  providerConfigurations: LoginProviderConfiguration[]
  schools: SchoolsResponse
  history: LoginEvent[]
  accounts: AdminAccount[]
  audit: AuditEntry[]
  /** Live connected apps by account id (local scenarios). */
  grants: Map<string, Grant[]>
  /** Consent requests not decided yet. */
  txns: Set<string>
  /** Two or more sign-in providers are configured. */
  multi: boolean
  providers: Provider[]
  /** This account's linked sign-in methods (multi scenarios). */
  identities: Identity[]
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
    upn: username,
    upn_required: false,
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

/** The owner's view of an account's sign-in methods (ids are decimal strings, unique per mock). */
function adminIdentities(account: number, providerIds: string[]): AdminIdentity[] {
  return providerIds.map((providerId, index) => ({
    id: String(account * 10 + index + 1),
    provider_id: providerId,
    username: providerId === 'github' ? `account${account}` : `account${account}@example.edu`,
    subject: providerId === 'github' ? `${5800 + account}` : `subject-${account}-${providerId}`,
    issuer: providerId === 'oidc:school' ? 'https://idp.example.edu/realms/school' : 'https://issuer.example.test',
    linked_at: ago(60 * 24 * (9 - index)),
    last_login_at: ago(60 * (account + index)),
    can_unlink: providerIds.length > 1,
  }))
}

function enrollmentOf(
  name: string,
  id: string,
  invalid: InvalidReason | null,
): NonNullable<AdminAccount['enrollment']> {
  return {
    id: acct(Number(id)),
    is_primary: true,
    custody_notice_version: 1,
    custody_ack_at: ago(60),
    custody_current: true,
    canvas_user_name: name,
    canvas_user_id: id,
    school: { ...SCHOOL },
    state: invalid ? 'invalid' : 'active',
    invalid_reason: invalid,
    invalid_since: invalid ? ago(60 * 29) : null,
    last_verified_at: ago(60),
    last_used_at: ago(60 * 3),
    created_at: ago(60 * 24 * 4),
    updated_at: ago(60 * 24 * 4),
    expires_on: inDays(60),
    expires_at: ago(-60 * 24 * 60),
    expiry_source: 'canvas',
    expiry_notice: 'none',
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
  const owner =
    scenario === 'owner' ||
    scenario === 'stale-owner' ||
    scenario === 'local-owner' ||
    scenario === 'multi-owner' || scenario === 'featured'
  const pending = scenario === 'pending' || scenario === 'local-pending'
  const picker = !['featured', 'error-503', 'rate-limited'].includes(scenario)
  const multi = scenario.startsWith('multi')

  const canvas =
    scenario === 'featured' || scenario === 'fresh' || scenario === 'picker' || scenario === 'error-503' || scenario === 'rate-limited'
      ? emptyCanvas()
      : scenario === 'invalid' || scenario === 'token-invalid'
        ? invalidCanvas('canvas_token_rejected')
        : scenario === 'revoked'
          ? invalidCanvas('revoked_by_admin')
          : scenario === 'expiring'
            ? { ...activeCanvas(), expires_on: inDays(3), expires_at: ago(-60 * 24 * 3), expiry_notice: 'soon' as const }
            : pending
              ? emptyCanvas()
              : activeCanvas()

  if (scenario === 'custody_outdated') canvas.custody = { ...canvas.custody, acknowledged_version: 0, current: false }

  const features: Features = {
    school_picker: picker,
    school_search: picker,
    write_tools: !pending && scenario !== 'no-write-tools',
    admin: owner,
    identities: multi && !pending,


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
  const fresh = scenario !== 'stale-owner' && scenario !== 'multi-stale'
  const me: MeResponse = {
    custody_ack_required: false,
    account: {
      id: SELF_ID,
      key: `acct:${SELF_ID}`,
      display_name: 'Ada Example',
      username: 'ada@example.edu',
      upn: 'ada@example.edu',
      upn_required: false,
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

  const schools: SchoolsResponse = !picker
    ? { mode: 'sole', choices: [], selected: null, sole: { host: SCHOOL.host, name: SCHOOL.name }, search_enabled: false }
    : scenario === 'picker' ? { mode: 'picker', choices: [{ host: 'canvas.example.edu', name: 'Example University', source: 'featured' }, { host: 'learn.sample.edu', name: 'Sample College', source: 'featured' }], selected: null, sole: null, search_enabled: true } : { mode: 'picker', choices: canvas.school ? [{ host: canvas.school.host, name: canvas.school.name, source: 'enrolled' }] : [], selected: canvas.school?.host ?? null, sole: null, search_enabled: true }

  const selfRow = accountRow(1, 'Ada Example', 'ada@example.edu', 'active', {
    id: SELF_ID,
    key: `acct:${SELF_ID}`,
    role: owner ? 'owner' : 'user',
    is_self: true,
    enrollment: canvas.state === 'none' ? null : { ...enrollmentOf('Ada Example', '1234567', null), expires_on: canvas.expires_on, expires_at: canvas.expires_at ?? null, expiry_source: canvas.expiry_source ?? 'unknown', expiry_notice: canvas.expiry_notice },
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
  if (multi) {
    accounts[0].identities = adminIdentities(1, ['entra', 'github'])
    accounts[1].identities = adminIdentities(2, ['google'])
    accounts[2].identities = adminIdentities(3, ['entra'])
    accounts[3].identities = adminIdentities(4, ['oidc:school', 'entra'])
  }
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
    signedIn: scenario !== 'signed-out' && scenario !== 'setup',
    setupInitialized: scenario !== 'setup',
    providerConfigurations: [{ id: 'entra', protocol: 'entra', enabled: true, rank: 0, config: { tenant_id: '11111111-2222-3333-4444-555555555555', client_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' }, secret_present: true, callback_uri: 'https://canvas.example.test/auth/callback/entra' }],
    fresh,
    me,
    canvas,
    tools,
    hasCatalog: scenario !== 'no-write-tools',
    schools,
    notifications: { enabled: false, email: '', locale: 'en', mail_available: false, reminder_days: 7 },
    mail: { revision: 1, config: { enabled: false, host: '', port: 587, security: 'starttls', username: '', from_name: 'Canvas MCP', from_email: '', reminder_days: 7 }, secret_present: false },
    settings: {
      local_admin: { ready: false },
      site: { public_base_url: 'https://canvas.example.test', active_base_url: 'https://canvas.example.test', restart_required: false },
      revision: 1,
      sign_in_methods: (multi ? MULTI_PROVIDERS : [MULTI_PROVIDERS[0]]).map((p) => ({ id: p.id, protocol: p.id.startsWith('oidc:') ? 'oidc' : p.id, icon: p.icon, configured: true, default_name: p.name, display_name: null, effective_name: p.name })),
      schools: { directory_search: picker, featured: !picker ? [{ host: SCHOOL.host, display_name: SCHOOL.name, rank: 1, enrollments: 1, allow_private: false }] : [], warnings: [] },
      browser_session: { ttl_seconds: 604800 },
      retention: { auth_events_days: 90, audit_days: 0 },
    },
    history: [
      { id: 99, at: ago(3), provider_id: 'entra', outcome: 'success', reason: null },
      { id: 98, at: ago(60 * 20), provider_id: 'entra', outcome: 'refused', reason: 'signups_paused' },
      { id: 97, at: ago(60 * 24 * 6), provider_id: 'entra', outcome: 'pending', reason: 'account_created' },
    ],
    accounts,
    audit,
    grants: local ? seedGrants(SELF_ID) : new Map(),
    txns: new Set(Object.values(MOCK_TXN)),
    multi,
    providers: multi ? MULTI_PROVIDERS : [MULTI_PROVIDERS[0]],
    identities: [
      {
        id: '11',
        provider_id: 'entra',
        username: 'ada@example.edu',
        email: 'ada@example.edu',
        email_verified: true,
        linked_at: ago(60 * 24 * 9),
        last_login_at: ago(3),
        current: true,
        can_unlink: false,
      },
      {
        id: '12',
        provider_id: 'github',
        username: 'ada-example',
        email: 'ada@example.org',
        email_verified: false,
        linked_at: ago(60 * 24 * 2),
        last_login_at: null,
        current: false,
        can_unlink: false,
      },
    ],
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
    custody_ack_required: !pending && state.canvas.state !== 'none' && !state.canvas.custody.current,
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
  invalid_provider_configuration: 422,
  invalid_local_credentials: 422,
  local_username_taken: 409,
  local_login_failed: 401,
  provider_secret_required: 422,
  provider_identity_binding_changed: 409,
  too_many_providers: 422,
  installation_already_initialized: 409,
  installation_code_invalid: 403,
  provider_configuration_unavailable: 503,
  installation_authority_unavailable: 503,
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
  custody_ack_required: 422,
  custody_notice_outdated: 409,
  not_enrolled: 404,
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
  settings_conflict: 409,
  pilot_profile_restricted: 409,
  confirmation_required: 409,
  last_owner: 409,
  last_local_owner: 409,
  cannot_disable_self: 409,
  identity_in_use: 409,
  provider_already_linked: 409,
  last_identity: 409,
  link_session_ended: 409,
  provider_unavailable: 503,
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
    setup_required: !s.setupInitialized,
    providers: s.providers.map((p) => ({ ...p, start_url: s.multi ? p.start_url : '/auth/login', name: s.settings.sign_in_methods.find((m) => m.id === p.id)?.effective_name ?? p.name })),
    mcp_url: s.me.server.mcp_url,
  }),
)

route('GET /version', 'active', (_c, s) => s.me.features.admin
  ? ok({ version: 'dev', commit: 'none', built_at: 'unknown' })
  : fail('forbidden'))

route('POST /login/local', 'public', (c, s) => {
  if (c.body.username !== 'admin' || c.body.password !== 'a long private local password') return fail('local_login_failed')
  s.signedIn = true
  s.me.account.provider_id = 'local'
  return ok({ redirect_to: c.body.txn ? `/account/consent?txn=${c.body.txn}` : typeof c.body.return_to === 'string' ? c.body.return_to : '/account/' })
})
route('PUT /me/password', 'active', (_c, s) => { s.signedIn = false; return ok({ redirect_to: '/account/sign-in' }) })
route('POST /admin/local-accounts', 'owner', (c, s) => {
  if (c.body.revision !== s.settings.revision) return fail('settings_conflict')
  s.settings.revision += 1
  if (c.body.owner === true) s.settings.local_admin.ready = true
  return ok({ account_id: acct(9), revision: s.settings.revision })
})
route('GET /setup', 'public', (_c, s) => ok({ initialized: s.setupInitialized, revision: s.settings.revision, callback_uri: 'https://canvas.example.test/auth/callback/entra' }))
route('POST /setup', 'public', (c, s) => {
  if (s.setupInitialized) return fail('installation_already_initialized')
  if (c.body.code !== 'A'.repeat(43)) return fail('installation_code_invalid')
  if (c.body.revision !== s.settings.revision) return fail('settings_conflict')
  const local = c.body.local_account as { username?: string; password?: string } | undefined
  if (!local || typeof local.password !== 'string' || local.password.length < 15) return fail('invalid_local_credentials')
  if (c.body.provider_id && (typeof c.body.client_secret !== 'string' || c.body.client_secret.length < 16)) return fail('provider_secret_required')
  s.setupInitialized = true
  s.settings.revision += c.body.provider_id ? 2 : 1
  const external = s.providers.filter((provider) => provider.id === c.body.provider_id)
  s.providers = [{ id: 'local', kind: 'local', icon: 'key', name: 'Local account', start_url: '/account/sign-in' }, ...external]
  return ok({ redirect_to: '/account/sign-in' })
})
route('GET /admin/login-providers', 'owner', (_c, s) => ok({ revision: s.settings.revision, public_base_url: 'https://canvas.example.test', providers: s.providerConfigurations }))
route('PUT /admin/login-providers/{id}', 'owner', (c, s) => {
  if (c.body.revision !== s.settings.revision) return fail('settings_conflict')
  const id = decodeURIComponent(c.match[1])
  const old = s.providerConfigurations.find((provider) => provider.id === id)
  if (!old && id !== 'local' && (typeof c.body.client_secret !== 'string' || c.body.client_secret.length < 16)) return fail('provider_secret_required')
  if (typeof c.body.enabled !== 'boolean' || typeof c.body.rank !== 'number' || !c.body.config || typeof c.body.config !== 'object' || Array.isArray(c.body.config)) return fail('invalid_provider_configuration')
  const value: LoginProviderConfiguration = {
    id, protocol: id.startsWith('oidc:') ? 'oidc' : id as LoginProviderConfiguration['protocol'],
    enabled: c.body.enabled, rank: c.body.rank, config: c.body.config as LoginProviderConfiguration['config'],
    auto_link_email: typeof c.body.auto_link_email === 'boolean' ? c.body.auto_link_email : old?.auto_link_email ?? false,
    icon_data: c.body.icon_data === null ? null : typeof c.body.icon_data === 'string' ? c.body.icon_data : old?.icon_data ?? null,
    secret_present: id !== 'local', callback_uri: id === 'local' ? '' : `https://canvas.example.test/auth/callback/${id.replace(':', '/')}`,
  }
  s.providerConfigurations = [...s.providerConfigurations.filter((provider) => provider.id !== id), value]
  s.providers = s.providers.map((provider) => provider.id === id ? { ...provider, icon_data: value.icon_data } : provider)
  s.settings.revision += 1
  return ok({ revision: s.settings.revision, public_base_url: 'https://canvas.example.test', providers: s.providerConfigurations })
})

function settingsConflict(c: Ctx, s: MockState): Fail | null {
  return c.body.revision !== s.settings.revision ? fail('settings_conflict') : null
}
function refreshSchools(s: MockState) {
  const featured = s.settings.schools.featured
  const search = s.settings.schools.directory_search
  s.settings.schools.warnings = !search && !featured.length ? ['no_schools_offered'] : []
  const choices: SchoolsResponse['choices'] = featured.map((school) => ({ host: school.host, name: school.display_name || school.host, source: 'featured' }))
  const enrolled = s.canvas.school
  if (search && enrolled && !choices.some((school) => school.host === enrolled.host)) choices.push({ host: enrolled.host, name: enrolled.name, source: 'enrolled' })
  s.schools = { mode: search || featured.length > 1 ? 'picker' : featured.length ? 'sole' : 'none', choices, selected: enrolled && choices.some((school) => school.host === enrolled.host) ? enrolled.host : null, sole: !search && featured.length === 1 ? { host: featured[0].host, name: featured[0].display_name || featured[0].host } : null, search_enabled: search }
}
route('GET /admin/settings', 'owner', (_c, s) => ok(s.settings))
const loginPolicies = new WeakMap<MockState, Record<string, boolean>>()
type AccountPolicy = ResponseOf<'GET /admin/accounts/{id}/login-policy'>['policy']
const accountLoginPolicies = new WeakMap<MockState, Map<string, AccountPolicy>>()
function accountPolicy(s: MockState, id: string): AccountPolicy {
  return accountLoginPolicies.get(s)?.get(id) ?? { allow_multiple: null, allowed_providers: null, sso_lock_provider: null, sso_lock_exempt: false }
}
function putAccountPolicy(s: MockState, id: string, policy: AccountPolicy) {
  if (!accountLoginPolicies.has(s)) accountLoginPolicies.set(s, new Map())
  accountLoginPolicies.get(s)!.set(id, policy)
}
route('GET /admin/settings/login-policy', 'owner', (_c, s) => ok({ revision: s.settings.revision, policy: loginPolicies.get(s) ?? { allow_multiple: true, lock_first_sso: false, block_conflicting_registration: false } }))
route('PUT /admin/settings/login-policy', 'owner', (c, s) => {
  if (c.body.revision !== s.settings.revision) return fail('settings_conflict')
  const policy = c.body.policy as Record<string, boolean>
  if (!policy || Object.keys(policy).sort().join() !== 'allow_multiple,block_conflicting_registration,lock_first_sso' || Object.values(policy).some((value) => typeof value !== 'boolean')) return fail('validation_failed')
  loginPolicies.set(s, policy); s.settings.revision++
  return ok({ revision: s.settings.revision, policy })
})
route('GET /admin/accounts/{id}/login-policy', 'owner', (c, s) => ok({ revision: s.settings.revision, policy: accountPolicy(s, decodeURIComponent(c.match[1])) }))
route('PUT /admin/accounts/{id}/login-policy', 'owner', (c, s) => {
  if (c.body.revision !== s.settings.revision) return fail('settings_conflict')
  const id = decodeURIComponent(c.match[1])
  const policy = { ...accountPolicy(s, id), ...c.body.policy as { allow_multiple: boolean | null; allowed_providers: string[] | null } }
  putAccountPolicy(s, id, policy); s.settings.revision++
  return ok({ revision: s.settings.revision, policy })
})
route('POST /admin/accounts/{id}/unlock-sso', 'owner', (c, s) => {
  if (c.body.revision !== s.settings.revision) return fail('settings_conflict')
  const id = decodeURIComponent(c.match[1])
  const policy = { ...accountPolicy(s, id), allow_multiple: true, sso_lock_provider: null, sso_lock_exempt: true }
  putAccountPolicy(s, id, policy); s.settings.revision++
  return ok({ revision: s.settings.revision, policy })
})
route('PUT /admin/settings/site', 'owner', (c, s) => {
  if (c.body.revision !== s.settings.revision) return fail('settings_conflict')
  if (c.body.confirm !== true || typeof c.body.public_base_url !== 'string' || !/^https:\/\/[a-z0-9.-]+(?::[0-9]+)?\/?$/i.test(c.body.public_base_url)) return fail('validation_failed', { field: 'public_base_url' })
  const value = c.body.public_base_url.replace(/\/$/, '')
  s.settings.revision += 1
  s.settings.site = { public_base_url: value, active_base_url: s.settings.site.active_base_url, restart_required: value !== s.settings.site.active_base_url }
  return ok({ revision: s.settings.revision, site: s.settings.site })
})
route('PUT /admin/settings/sign-in-methods', 'owner', (c, s) => {
  const conflict = settingsConflict(c, s)
  if (conflict) return conflict
  const names = c.body.names as Record<string, string | null> | undefined
  if (!names || typeof names !== 'object' || Array.isArray(names) || Object.keys(names).some((id) => !s.settings.sign_in_methods.some((p) => p.id === id && p.configured))) return fail('validation_failed')
  const providers = s.settings.sign_in_methods.map((p) => {
    const name = Object.hasOwn(names, p.id) ? (names[p.id]?.trim() || null) : p.display_name
    return { ...p, display_name: name, effective_name: name ?? p.default_name }
  })
  if (new Set(providers.filter((p) => p.configured).map((p) => p.effective_name.toLowerCase())).size !== providers.filter((p) => p.configured).length) return fail('validation_failed')
  s.settings.sign_in_methods = providers
  s.settings.revision++
  return ok(s.settings)
})
route('GET /notifications', 'active', (_, s) => ok({ ...s.notifications, mail_available: s.mail.config.enabled, reminder_days: s.mail.config.reminder_days }))
route('PUT /notifications', 'active', (c, s) => {
  if (typeof c.body.enabled !== 'boolean' || typeof c.body.email !== 'string' || !['en', 'zh'].includes(c.body.locale as string) || (c.body.enabled && !/^[^\s@]+@[^\s@]+$/.test(c.body.email))) return fail('validation_failed')
  s.notifications = { ...s.notifications, enabled: c.body.enabled, email: c.body.email, locale: c.body.locale as 'en' | 'zh' }
  return ok({ ...s.notifications, mail_available: s.mail.config.enabled, reminder_days: s.mail.config.reminder_days })
})
route('POST /admin/settings/mail/test', 'owner', (_, s) => s.mail.config.enabled ? ok({ reachable: true }) : fail('mail_unavailable'))
route('GET /admin/settings/mail', 'owner', (_, s) => ok({ ...s.mail, revision: s.settings.revision }))
route('PUT /admin/settings/mail', 'owner', (c, s) => {
  const conflict = settingsConflict(c, s)
  if (conflict) return conflict
  const value = c.body.config as MailSettingsResponse['config'] | undefined
  if (!value || typeof value.from_name !== 'string' || value.from_name.length > 120 || /[\p{C}\p{Zl}\p{Zp}]/u.test(value.from_name)) return fail('validation_failed')
  if (!value || typeof value.enabled !== 'boolean' || !Number.isInteger(value.port) || value.port < 1 || value.port > 65535 || !['tls', 'starttls'].includes(value.security) || !Number.isInteger(value.reminder_days) || value.reminder_days < 1 || value.reminder_days > 90 || (value.enabled && (!value.host || !/^[^\s@]+@[^\s@]+$/.test(value.from_email)))) return fail('validation_failed')
  s.settings.revision++
  s.mail = { revision: s.settings.revision, config: { ...value, from_name: value.from_name.normalize('NFC').trim().replace(/\s+/gu, ' ') || 'Canvas MCP' }, secret_present: c.body.password === null ? s.mail.secret_present : Boolean(c.body.password) }
  return ok(s.mail)
})
route('PUT /admin/settings/browser-session', 'owner', (c, s) => {
  const conflict = settingsConflict(c, s)
  if (conflict) return conflict
  const ttl = c.body.ttl_seconds
  if (typeof ttl !== 'number' || !Number.isInteger(ttl) || ttl < 60 || ttl > 2592000) return fail('validation_failed')
  s.settings.browser_session.ttl_seconds = ttl
  s.settings.revision++
  return ok(s.settings)
})
route('PUT /admin/settings/directory-search', 'owner', (c, s) => {
  const conflict = settingsConflict(c, s)
  if (conflict) return conflict
  if (typeof c.body.enabled !== 'boolean') return fail('validation_failed')
  s.settings.schools.directory_search = c.body.enabled
  s.settings.revision++
  refreshSchools(s)
  return ok(s.settings)
})
route('POST /admin/settings/schools/check', 'owner', (c) => {
  const valid = typeof c.body.host === 'string' && /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(c.body.host) && !c.body.host.endsWith('.internal')
  return ok({ valid, ...(valid ? {} : { reason: 'school_invalid' as const }), suggested_name: null, in_directory: valid ? false : null })
})
route('PUT /admin/settings/schools', 'owner', (c, s) => {
  const conflict = settingsConflict(c, s)
  if (conflict) return conflict
  const featured = c.body.featured as { host: string; display_name: string }[] | undefined
  const confirmed = c.body.confirm_affected as string[] | undefined
  if (!Array.isArray(featured) || featured.length > 50 || !Array.isArray(confirmed)) return fail('validation_failed')
  const affected = Object.fromEntries(s.settings.schools.featured.filter((school) => !featured.some((next) => next.host === school.host) && school.enrollments > 0).map((school) => [school.host, school.enrollments]))
  if (!s.settings.schools.directory_search && Object.keys(affected).some((host) => !confirmed.includes(host))) return fail('confirmation_required', { affected })
  s.settings.schools.featured = featured.map((school, index) => ({ ...school, rank: index + 1, enrollments: s.canvas.school?.host === school.host ? 1 : 0, allow_private: false }))
  s.settings.revision++
  refreshSchools(s)
  return ok({ ...s.settings, affected_enrollments: affected })
})

route('GET /me', 'session', (_c, s) => ok(meView(s)))
route('PUT /admin/accounts/{id}/upn', 'owner', (c, s) => {
  if (c.body.revision !== s.settings.revision) return fail('settings_conflict')
  if (typeof c.body.upn !== 'string' || !/^[a-z0-9][a-z0-9.@_+-]{2,253}$/i.test(c.body.upn)) return fail('validation_failed', { field: 'upn' })
  s.settings.revision += 1
  const id = decodeURIComponent(c.match[1])
  const account = s.accounts.find((item) => item.id === id)
  if (account) account.upn = String(c.body.upn).trim().toLowerCase()
  return ok({ revision: s.settings.revision, account_id: id })
})
route('POST /me/local-password', 'active', (c) => {
  if (typeof c.body.password !== 'string' || c.body.password.length < 15) return fail('invalid_local_credentials')
  return ok({ redirect_to: '/account/sign-in' })
})

route('GET /me/canvas-token', 'active', (_c, s) => ok(s.canvas))

route('PUT /me/canvas-token', 'active', (c, s) => {
  const bad = onlyFields(c.body, [
    'canvas_token',
    'school',
    'school_sig',
    'confirm_identity_change',
    'custody',
  ])
  if (bad) return bad
  const ack = c.body.custody as { acknowledged?: unknown; notice_version?: unknown } | undefined
  if (!ack || ack.acknowledged !== true) return fail('custody_ack_required')
  if (ack.notice_version !== s.canvas.custody.notice_version) return fail('custody_notice_outdated', { notice_version: s.canvas.custody.notice_version })
  if (s.scenario === 'rate-limited') return fail('rate_limited', { retry_after_s: 30 })
  const token = typeof c.body.canvas_token === 'string' ? c.body.canvas_token : ''
  if (!/^[A-Za-z0-9~._-]{20,512}$/.test(token)) return fail('token_invalid_format')

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
    custody: { notice_version: s.canvas.custody.notice_version, acknowledged_version: s.canvas.custody.notice_version, acknowledged_at: now, current: true },
    state: 'active',
    canvas_user_id: canvasId,
    canvas_user_name: name,
    school,
    invalid_reason: null,
    invalid_since: null,
    recheck_allowed: true,
    expires_on: null,
    expiry_source: 'unknown',
    expires_at: null,
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

route('POST /me/canvas-token/acknowledge', 'active', (c, s) => {
  const bad = onlyFields(c.body, ['notice_version'])
  if (bad) return bad
  if (c.body.notice_version !== s.canvas.custody.notice_version) return fail('custody_notice_outdated', { notice_version: s.canvas.custody.notice_version })
  if (s.canvas.state === 'none') return fail('not_enrolled')
  s.canvas.custody = { ...s.canvas.custody, acknowledged_version: s.canvas.custody.notice_version, acknowledged_at: ago(0), current: true }
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
    s.canvas = { ...s.canvas, state: 'active', invalid_reason: null, invalid_since: null, recheck_allowed: true, last_verified_at: ago(0) }
    syncSelf(s)
    return ok({ result: 'restored', canvas: s.canvas })
  }
  s.canvas = { ...s.canvas, last_verified_at: ago(0) }
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

function pageRows<T>(c: Ctx, rows: T[], scope: string, key: (row: T) => string | number) {
  const limit = Number(c.query.get('limit') ?? 50)
  let before: string | number | null = null
  const cursor = c.query.get('cursor')
  if (cursor) {
    const decoded = JSON.parse(atob(cursor.replace(/-/g, '+').replace(/_/g, '/')))
    if (decoded[0] !== 1 || decoded[1] !== scope) throw new Error('invalid cursor')
    before = decoded[2]
  }
  const ordered = [...rows].sort((a, b) => key(a) < key(b) ? 1 : key(a) > key(b) ? -1 : 0)
  const selected = ordered.filter(row => before === null || key(row) < before).slice(0, limit + 1)
  const items = selected.slice(0, limit)
  const next_cursor = selected.length > limit
    ? btoa(JSON.stringify([1, scope, key(items[items.length - 1])])).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    : null
  return { items, next_cursor }
}

route('GET /me/login-history', 'session', (c, s) => { const page = pageRows(c, s.history, 'auth-events/' + s.me.account.id, e => e.id); return ok({ events: page.items, next_cursor: page.next_cursor }) })

// ---- sign-in methods (multi scenarios only; not_found otherwise, like the server) -------------

function identitiesView(s: MockState) {
  const linked = new Set(s.identities.map((i) => i.provider_id))
  return {
    identities: s.identities.map((i) => ({ ...i, can_unlink: s.identities.length > 1 })),
    linkable: s.providers.filter((p) => !linked.has(p.id)).map((p) => p.id),
    fresh: s.fresh,
    fresh_window_s: 600,
  }
}

route('GET /me/identities', 'active', (_c, s) => (s.multi ? ok(identitiesView(s)) : fail('not_found')))

route('POST /me/identities/link', 'active', (c, s) => {
  if (!s.multi) return fail('not_found')
  const bad = onlyFields(c.body, ['provider'])
  if (bad) return bad
  const provider = c.body.provider
  if (typeof provider !== 'string' || !s.providers.some((p) => p.id === provider)) {
    return fail('validation_failed', { field: 'provider' })
  }
  if (!s.fresh) return fail('reauth_required', { max_age_s: 600 })
  if (s.identities.some((i) => i.provider_id === provider)) return fail('provider_already_linked')
  return ok({ redirect_to: `https://idp.example.invalid/authorize?provider=${encodeURIComponent(provider)}` })
})

route('DELETE /me/identities/{id}', 'active', (c, s) => {
  if (!s.multi) return fail('not_found')
  const id = decodeURIComponent(c.match[1])
  if (!IDENTITY_ID.test(id)) return fail('validation_failed', { field: 'id' })
  const found = s.identities.find((i) => i.id === id)
  if (!found) return fail('not_found')
  if (!s.fresh) return fail('reauth_required', { max_age_s: 600 })
  if (s.identities.length <= 1) return fail('last_identity')
  s.identities = s.identities.filter((i) => i.id !== id)
  return ok({ signed_out: found.current })
})

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
  const page = pageRows(c, shown, "accounts/" + (status ?? "None"), a => a.id)
  return ok({
    accounts: page.items,
    next_cursor: page.next_cursor,
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
      : withToken
  rows.sort((a, b) => (a.status === 'pending' ? 0 : 1) - (b.status === 'pending' ? 0 : 1))
  const page = pageRows(c, rows, "enrollments/" + (filter === "needs_reenroll" ? "True" : "False"), a => a.enrollment?.id ?? a.id)
  return ok({
    rows: page.items,
    next_cursor: page.next_cursor,
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

route('DELETE /admin/identities/{id}', 'owner', (c, s) => {
  if (!s.multi) return fail('not_found')
  const id = decodeURIComponent(c.match[1])
  if (!IDENTITY_ID.test(id)) return fail('validation_failed', { field: 'id' })
  const row = s.accounts.find((a) => a.identities?.some((i) => i.id === id))
  if (!row || !row.identities) return fail('not_found')
  if (row.identities.length <= 1) return fail('last_identity')
  row.identities = row.identities.filter((i) => i.id !== id)
  for (const i of row.identities) i.can_unlink = row.identities.length > 1
  return ok({ changed: true, account: { ...row } })
})

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

route('GET /admin/audit', 'owner', (c, s) => {
  const page = pageRows(c, s.audit, 'audit/None', e => e.id)
  return ok({ entries: page.items, next_cursor: page.next_cursor })
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

route('GET /consent', 'session', (c, s) => {
  const txn = c.query.get('txn') ?? ''
  if (!TXN_SHAPE.test(txn) || !s.txns.has(txn)) return fail('authorization_invalid')
  if (txn === MOCK_TXN.unavailable) return fail('client_unavailable')
  return ok(consentView(txn, s))
})

route('POST /consent', 'session', (c, s) => {
  const bad = onlyFields(c.body, ['txn', 'decision'])
  if (bad) return bad
  const decision = c.body.decision
  if (decision !== 'approve' && decision !== 'deny') return fail('validation_failed', { field: 'decision' })
  const txn = typeof c.body.txn === 'string' ? c.body.txn : ''
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

route('GET /me/grants', 'active', (c, s) => {
  const page = pageRows(c, s.grants.get(SELF_ID) ?? [], 'grants/' + SELF_ID + '/False', g => g.id)
  return ok({ grants: page.items, next_cursor: page.next_cursor })
})

route('DELETE /me/grants/{id}', 'active', (c, s) => {
  const id = decodeURIComponent(c.match[1])
  if (!UUID.test(id)) return fail('validation_failed', { field: 'id' })
  const mine = s.grants.get(SELF_ID) ?? []
  if (!mine.some((grant) => grant.id === id)) return fail('not_found')
  s.grants.set(SELF_ID, mine.filter((grant) => grant.id !== id))
  return noContent()
})

route('GET /admin/accounts/{id}/grants', 'owner', (c, s) => {
  const id = decodeURIComponent(c.match[1])
  if (!UUID.test(id)) return fail('validation_failed', { field: 'id' })
  const page = pageRows(c, s.grants.get(id) ?? [], 'grants/' + id + '/False', g => g.id)
  return ok({ grants: page.items, next_cursor: page.next_cursor })
})

route('DELETE /admin/grants/{id}', 'owner', (c, s) => {
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
