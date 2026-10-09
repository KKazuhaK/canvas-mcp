import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios'
import { http } from '@/api/client'
import type { ApiErrorCode, MeResponse } from '@/api/types'

// Small, obviously fake data for client-level tests. No real names, no tokens.

export function meFixture(overrides: Partial<MeResponse['account']> = {}): MeResponse {
  return {
    account: {
      id: 'acct:00000000-0000-4000-8000-0000000000aa',
      display_name: 'Test User',
      email: 'test.user@example.test',
      role: 'user',
      status: 'active',
      created_at: '2026-01-01T00:00:00Z',
      ...overrides,
    },
    csrf_token: 'test-csrf-token',
    session_issued_at: '2026-01-01T00:00:00Z',
    canvas: {
      state: 'none',
      canvas_user_id: null,
      canvas_user_name: null,
      enrolled_at: null,
      updated_at: null,
      last_used_at: null,
      last_checked_at: null,
      invalid_since: null,
    },
    write_tools_enabled_count: 0,
  }
}

export interface RecordedRequest {
  method: string
  url: string
  headers: Record<string, string>
  data: unknown
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
    })
    return inner(config)
  }
  return seen
}
