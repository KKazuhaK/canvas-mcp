import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios'
import { http } from '@/api/client'
import type { ApiErrorCode, CanvasTokenStatus, MeResponse } from '@/api/types'

// Small, obviously fake data for client-level tests. No real names, no tokens.

export function canvasFixture(overrides: Partial<CanvasTokenStatus> = {}): CanvasTokenStatus {
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
    ...overrides,
  }
}

export function meFixture(
  overrides: Partial<MeResponse['account']> = {},
  rest: Partial<Omit<MeResponse, 'account'>> = {},
): MeResponse {
  return {
    account: {
      id: '00000000-0000-4000-8000-0000000000aa',
      key: 'acct:00000000-0000-4000-8000-0000000000aa',
      display_name: 'Test User',
      username: 'test.user@example.test',
      provider_id: 'entra',
      role: 'user',
      status: 'active',
      ...overrides,
    },
    csrf_token: 'test-csrf-token',
    session: {
      issued_at: '2026-01-01T00:00:00Z',
      expires_at: '2026-01-02T00:00:00Z',
      fresh_until: null,
      fresh: false,
      fresh_window_s: 600,
    },
    canvas: canvasFixture(),
    write_tools: { offered: 0, enabled: 0 },
    features: {
      school_picker: false,
      school_search: false,
      write_tools: true,
      admin: false,
      identities: false,
      connected_apps: false,
      consent: false,
      logout_everywhere: false,
      role_management: false,
    },
    ui_locale: null,
    server: { mcp_url: 'https://x.test/mcp', display_timezone: 'UTC' },
    ...rest,
  }
}

export interface RecordedRequest {
  method: string
  url: string
  headers: Record<string, string>
  data: unknown
  params?: unknown
}

type Reply = { status: number; data?: unknown }

/** Replace the adapter with a scripted one; returns the list of requests it saw. */
export function scriptAdapter(
  reply: (request: RecordedRequest) => Reply | Promise<Reply>,
): RecordedRequest[] {
  const seen: RecordedRequest[] = []
  http.defaults.adapter = async (config: InternalAxiosRequestConfig): Promise<AxiosResponse> => {
    const request: RecordedRequest = {
      method: (config.method ?? 'get').toUpperCase(),
      url: config.url ?? '',
      headers: Object.fromEntries(
        Object.entries(config.headers.toJSON()).map(([k, v]) => [k.toLowerCase(), String(v)]),
      ),
      data: config.data,
      params: config.params,
    }
    seen.push(request)
    const { status, data } = await reply(request)
    const response: AxiosResponse = { data: data ?? '', status, statusText: '', headers: {}, config, request: {} }
    if (status >= 200 && status < 300) return response
    throw new AxiosError('failed', 'ERR_BAD_REQUEST', config, {}, response)
  }
  return seen
}

export const errorBody = (code: ApiErrorCode | string, params?: Record<string, unknown>) => ({
  error: { code, ...(params ? { params } : {}) },
})

/** Wrap whatever adapter is installed (e.g. the dev mock) and record each request. */
export function recordRequests(): RecordedRequest[] {
  const inner = http.defaults.adapter as (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>
  const seen: RecordedRequest[] = []
  http.defaults.adapter = (config: InternalAxiosRequestConfig) => {
    seen.push({
      method: (config.method ?? 'get').toUpperCase(),
      url: config.url ?? '',
      headers: Object.fromEntries(
        Object.entries(config.headers.toJSON()).map(([k, v]) => [k.toLowerCase(), String(v)]),
      ),
      data: config.data,
      params: config.params,
    })
    return inner(config)
  }
  return seen
}
