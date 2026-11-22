import { useCallback, useEffect, useRef, useState } from 'react'

/** Must match the extension's bridge (browser-extension/src/lib/defaults.ts). */
export const BRIDGE_CHANNEL = 'canvas-companion'
/** How long to wait for the extension to answer before saying it is not installed. */
export const DETECT_MS = 1500
const CONNECT_TIMEOUT_MS = 20_000
/** A full sync reads dozens of Canvas resources. */
const SYNC_TIMEOUT_MS = 120_000
/** Opening the page syncs by itself when the portal's copy is older than this. */
export const AUTO_SYNC_AFTER_MS = 60 * 60_000

export interface Companion {
  status: 'detecting' | 'absent' | 'present'
  /** Whether this browser's extension is paired with this portal. */
  connected: boolean
  /** When this browser last synced successfully (ISO 8601), as the extension reports it. */
  lastSyncAt: string | null
  /** Why this browser's last sync failed, if it did. */
  lastError: string | null
}

export interface SyncResult {
  ok: boolean
  error?: string
  /** Resources the portal accepted in this run. */
  updated: number
}

export interface ConnectResult {
  ok: boolean
  error?: string
  /** Paired, but the person still has to allow the extension to read their Canvas site. */
  needsCanvasAccess?: boolean
}

type Message = { channel?: unknown; from?: unknown; type?: unknown; [key: string]: unknown }

function fromExtension(event: MessageEvent): Message | null {
  if (event.source !== window || event.origin !== window.location.origin) return null
  const data = event.data as Message | null
  return data && data.channel === BRIDGE_CHANNEL && data.from === 'extension' ? data : null
}

function post(message: Record<string, unknown>) {
  window.postMessage({ channel: BRIDGE_CHANNEL, from: 'page', ...message }, window.location.origin)
}

/**
 * The Canvas MCP Sync extension, if it runs on this page. Its bridge answers only on the portal it
 * was built for, in the top frame, and only to messages from this same page.
 */
export function useCompanion(): {
  companion: Companion
  connect: (code: string, canvasOrigin: string | null) => Promise<ConnectResult>
  sync: (force: boolean) => Promise<SyncResult>
} {
  const [companion, setCompanion] = useState<Companion>({ status: 'detecting', connected: false, lastSyncAt: null, lastError: null })
  const waiting = useRef<((result: ConnectResult) => void) | null>(null)
  const syncing = useRef<((result: SyncResult) => void) | null>(null)

  useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      const data = fromExtension(event)
      if (!data) return
      if (data.type === 'ready') {
        setCompanion({
          status: 'present',
          connected: data.connected === true,
          lastSyncAt: typeof data.lastSyncAt === 'string' ? data.lastSyncAt : null,
          lastError: typeof data.lastError === 'string' ? data.lastError : null,
        })
      } else if (data.type === 'synced' && syncing.current) {
        syncing.current({
          ok: data.ok === true,
          error: typeof data.error === 'string' && data.error ? data.error : undefined,
          updated: typeof data.updated === 'number' ? data.updated : 0,
        })
      }
      else if (data.type === 'result' && waiting.current) {
        waiting.current({
          ok: data.ok === true,
          error: typeof data.error === 'string' && data.error ? data.error : undefined,
          needsCanvasAccess: data.needsCanvasAccess === true,
        })
      }
    }
    window.addEventListener('message', onMessage)
    post({ type: 'hello' })
    const timer = setTimeout(() => setCompanion((c) => (c.status === 'detecting' ? { ...c, status: 'absent' } : c)), DETECT_MS)
    return () => {
      window.removeEventListener('message', onMessage)
      clearTimeout(timer)
    }
  }, [])

  const connect = useCallback(
    (code: string, canvasOrigin: string | null) =>
      new Promise<ConnectResult>((resolve) => {
        const timer = setTimeout(() => finish({ ok: false }), CONNECT_TIMEOUT_MS)
        function finish(result: ConnectResult) {
          clearTimeout(timer)
          waiting.current = null
          resolve(result)
        }
        waiting.current = finish
        post({ type: 'connect', code, canvasOrigin })
      }),
    [],
  )

  const sync = useCallback(
    (force: boolean) =>
      new Promise<SyncResult>((resolve) => {
        const timer = setTimeout(() => finish({ ok: false, updated: 0 }), SYNC_TIMEOUT_MS)
        function finish(result: SyncResult) {
          clearTimeout(timer)
          syncing.current = null
          resolve(result)
        }
        syncing.current = finish
        post({ type: 'sync', force })
      }),
    [],
  )

  return { companion, connect, sync }
}
