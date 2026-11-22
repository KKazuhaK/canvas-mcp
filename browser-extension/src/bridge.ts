// Declared only for the default portal. It lets the portal's browser-extension page see that the
// extension is installed and hand it a one-time pairing code (and the person's Canvas address) after
// the person clicks "Connect this browser". It reads nothing else on the page and never sees cookies
// or the upload token.
import { BRIDGE_CHANNEL } from './lib/defaults.ts';

declare const browser: typeof chrome | undefined;
(() => {
  const api: typeof chrome = typeof browser !== 'undefined' ? browser : chrome;
  const root = document.documentElement;
  if (root.dataset.canvasCompanionBridge) return;
  root.dataset.canvasCompanionBridge = 'active';
  const post = (message: Record<string, unknown>) =>
    window.postMessage({ channel: BRIDGE_CHANNEL, from: 'extension', ...message }, location.origin);
  const version = api.runtime.getManifest().version;
  let claiming = false;
  let syncing = false;
  const announce = async () => {
    let status: { connected?: boolean; canvasOrigin?: string; lastSyncAt?: string | null; lastError?: string | null } | undefined;
    try {
      status = (await api.runtime.sendMessage({ type: 'canvas.bridge.status' })) as typeof status;
    } catch {
      /* the service worker wakes on the next message */
    }
    post({
      type: 'ready',
      version,
      connected: !!status?.connected,
      canvasOrigin: status?.canvasOrigin ?? null,
      lastSyncAt: status?.lastSyncAt ?? null,
      lastError: status?.lastError ?? null,
    });
  };
  window.addEventListener('message', (event) => {
    if (event.source !== window || event.origin !== location.origin) return;
    const data = event.data;
    if (!data || data.channel !== BRIDGE_CHANNEL || data.from !== 'page') return;
    if (data.type === 'hello') {
      void announce();
      return;
    }
    if (data.type === 'sync') {
      if (syncing) return;
      syncing = true;
      api.runtime
        .sendMessage({ type: 'canvas.bridge.sync', force: data.force === true })
        .then(
          (r: { ok?: boolean; error?: string; counts?: { accepted?: number } } | undefined) =>
            post({ type: 'synced', ok: !!r?.ok, error: r?.ok ? '' : (r?.error ?? 'Sync failed.'), updated: r?.counts?.accepted ?? 0 }),
          () => post({ type: 'synced', ok: false, error: 'Could not reach the extension. Reload this page and try again.', updated: 0 }),
        )
        .finally(() => {
          syncing = false;
          void announce();
        });
      return;
    }
    if (data.type !== 'connect' || typeof data.code !== 'string' || claiming) return;
    claiming = true;
    const canvasOrigin = typeof data.canvasOrigin === 'string' ? data.canvasOrigin : undefined;
    api.runtime
      .sendMessage({ type: 'canvas.bridge.claim', code: data.code, canvasOrigin })
      .then(
        (r: { ok?: boolean; error?: string; needsCanvasAccess?: boolean } | undefined) =>
          post({ type: 'result', ok: !!r?.ok, error: r?.ok ? '' : (r?.error ?? 'Pairing failed.'), needsCanvasAccess: !!r?.needsCanvasAccess }),
        () => post({ type: 'result', ok: false, error: 'Could not reach the extension. Reload this page and try again.' }),
      )
      .finally(() => {
        claiming = false;
        void announce();
      });
  });
  void announce();
})();
