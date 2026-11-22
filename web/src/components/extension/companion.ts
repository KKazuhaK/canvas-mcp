import { useCallback, useEffect, useRef, useState } from 'react'

/** Must match the extension's bridge (browser-extension/src/lib/defaults.ts). */
export const BRIDGE_CHANNEL = 'canvas-companion'
/** How long to wait for the extension to answer before saying it is not installed. */
export const DETECT_MS = 1500
const CONNECT_TIMEOUT_MS = 20_000

export interface Companion {
  status: 'detecting' | 'absent' | 'present'
  /** Whether this browser's extension is paired with this portal. */
  connected: boolean
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
export function useCompanion(): { companion: Companion; connect: (code: string, canvasOrigin: string | null) => Promise<ConnectResult> } {
  const [companion, setCompanion] = useState<Companion>({ status: 'detecting', connected: false })
  const waiting = useRef<((result: ConnectResult) => void) | null>(null)

  useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      const data = fromExtension(event)
      if (!data) return
      if (data.type === 'ready') setCompanion({ status: 'present', connected: data.connected === true })
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

  return { companion, connect }
}
