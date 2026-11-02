import { runFetches, type FetchResult } from './canvas-fetch.ts';
import type { FetchJob } from './allowlist.ts';
import { UserError } from './errors.ts';
import { hostPattern, parseOrigin, sameOrigin } from './origin.ts';
import { updateFetched } from './fetched.ts';
import { claimCode, mayInject, newPairing, pairingUrl, validateClaim } from './pairing.ts';
import { isPopupSender, type SenderLike } from './senders.ts';
import {
  CODE_RE,
  clearAll,
  isConnected,
  markDisconnected,
  readState,
  saveConnection,
  type LastResult,
  type Stored,
} from './state.ts';
import { runSync, type Outcome } from './sync.ts';

export const ALARM_NAME = 'canvas-sync';
export const ALARM_MINUTES = 60;
export const MIN_SYNC_GAP_MS = 10 * 60_000;
const MIN_ATTEMPT_GAP_MS = 60_000;
const TAB_DEBOUNCE_MS = 1500;

export interface ControllerEnv {
  fetch: typeof fetch;
  now(): number;
  randomBytes(n: number): Uint8Array;
}

type Trigger = 'tab' | 'alarm' | 'manual';

// `api` is the extension API (chrome or browser). It is typed loosely so tests
// can pass a partial mock.
export function createController(api: typeof chrome, env: ControllerEnv) {
  const storage = api.storage.local as unknown as import('./state.ts').StorageArea;
  const popupUrl = () => api.runtime.getURL('popup.html');
  let claiming = false;
  let running: Promise<Outcome> | undefined;
  let tabTimer: ReturnType<typeof setTimeout> | undefined;

  async function ensureAlarm() {
    if (!api.alarms) return;
    const s = await readState(storage);
    if (isConnected(s)) {
      if (!(await api.alarms.get(ALARM_NAME))) await api.alarms.create(ALARM_NAME, { delayInMinutes: ALARM_MINUTES, periodInMinutes: ALARM_MINUTES });
    } else {
      await api.alarms.clear(ALARM_NAME);
    }
  }

  async function hasPermission(origin: string): Promise<boolean> {
    try {
      return await api.permissions.contains({ origins: [hostPattern(origin)] });
    } catch {
      return false;
    }
  }

  async function claimAndStore(portalOrigin: string, code: string) {
    const token = await claimCode(env.fetch, portalOrigin, code);
    await saveConnection(storage, portalOrigin, token);
    await ensureAlarm();
  }

  async function injectLink(tabId: number, url: string | undefined) {
    const { pairing } = await readState(storage);
    if (!mayInject(pairing, tabId, url, env.now())) return;
    await api.scripting.executeScript({ target: { tabId }, files: ['link.js'] });
  }

  async function startPairing(rawOrigin: unknown) {
    const portalOrigin = parseOrigin(rawOrigin, 'portal address');
    if (!(await hasPermission(portalOrigin))) {
      throw new UserError('no_permission', 'Allow the extension to access the portal address first.');
    }
    let cap: { browserSync?: unknown } | null = null;
    try {
      const res = await env.fetch(`${portalOrigin}/api/v1/extension/capabilities`, {
        credentials: 'omit',
        redirect: 'error',
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) cap = (await res.json()) as { browserSync?: unknown };
    } catch {
      throw new UserError('portal_unreachable', 'Could not reach the portal. Check the address and your connection.');
    }
    if (!cap || cap.browserSync !== 1) {
      throw new UserError('unsupported', 'This portal does not support browser sync yet.');
    }
    const pairing = newPairing(portalOrigin, env.now(), env.randomBytes);
    await storage.set({ pairing });
    const tab = await api.tabs.create({ url: pairingUrl(pairing) });
    if (tab.id === undefined) throw new UserError('tab', 'Could not open the pairing page.');
    pairing.tabId = tab.id;
    await storage.set({ pairing });
    // A cached page may finish loading before onUpdated can see the tab id.
    const current = await api.tabs.get(tab.id);
    if (current.status === 'complete') await injectLink(tab.id, current.url);
    return { ok: true };
  }

  async function handleClaim(message: { state?: unknown; code?: unknown }, sender: SenderLike) {
    const { pairing } = await readState(storage);
    if (claiming) throw new UserError('busy', 'Pairing is already in progress.');
    const code = validateClaim(pairing, sender, api.runtime.id, message, env.now());
    claiming = true;
    try {
      await claimAndStore(pairing!.portalOrigin, code);
      await storage.set({ pairing: { ...pairing!, status: 'connected', message: 'Connected.' } });
      return { ok: true };
    } catch (e) {
      await storage.set({
        pairing: { ...pairing!, status: 'error', message: e instanceof UserError ? e.message : 'Pairing failed.' },
      });
      throw e;
    } finally {
      claiming = false;
    }
  }

  async function disconnect() {
    const s = await readState(storage);
    let remote = true;
    if (isConnected(s)) {
      try {
        const res = await env.fetch(`${s.portalOrigin}/api/v1/extension/binding`, {
          method: 'DELETE',
          credentials: 'omit',
          redirect: 'error',
          headers: { Authorization: `Bearer ${s.uploadToken}` },
          signal: AbortSignal.timeout(15000),
        });
        await res.body?.cancel();
        remote = res.ok || res.status === 401;
      } catch {
        remote = false;
      }
    }
    await clearAll(storage);
    await api.alarms?.clear(ALARM_NAME);
    return {
      ok: true,
      remoteRevoked: remote,
      message: remote ? 'Disconnected.' : 'Disconnected on this browser. The portal could not be reached; remove the connection from your account page too.',
    };
  }

  async function findCanvasTab(canvasOrigin: string): Promise<number | undefined> {
    const tabs = await api.tabs.query({ url: `${hostPattern(canvasOrigin)}` });
    const usable = tabs.filter((t) => t.id !== undefined && sameOrigin(t.url, canvasOrigin));
    return (usable.find((t) => t.status === 'complete') ?? usable[0])?.id;
  }

  async function readCanvasViaTab(tabId: number, origin: string, jobs: FetchJob[], maxPages: number): Promise<FetchResult[]> {
    const [injected] = await api.scripting.executeScript({
      target: { tabId },
      func: runFetches,
      args: [origin, jobs, maxPages],
    });
    const result = injected?.result as FetchResult[] | undefined;
    if (!Array.isArray(result)) throw new Error('no result');
    return result;
  }

  async function record(trigger: Trigger, outcome: Outcome, previous: Record<string, string> | undefined) {
    const at = new Date(env.now()).toISOString();
    const last: LastResult = { at, trigger, ok: outcome.ok, code: outcome.code, message: outcome.message, counts: outcome.counts, skipReasons: (outcome.skipReasons ?? []).slice(0, 10) };
    const patch: Record<string, unknown> = { lastResult: last, lastAttemptAt: at };
    if (outcome.ok) patch.lastSyncAt = at;
    if (outcome.fetchedKeys?.length || outcome.planKeys) {
      let base = previous;
      if (outcome.courseSetChanged && base) {
        const drop = new Set(outcome.perCourseKeys ?? []);
        base = Object.fromEntries(Object.entries(base).filter(([k]) => !drop.has(k)));
      }
      patch.lastFetchedAt = updateFetched(base, outcome.fetchedKeys ?? [], outcome.planKeys, at);
    }
    if (outcome.ok && outcome.courseIds) patch.lastCourseIds = outcome.courseIds;
    if (outcome.retryAfterMs) patch.backoffUntil = env.now() + outcome.retryAfterMs;
    await storage.set(patch);
    if (outcome.reconnect) await markDisconnected(storage);
  }

  function runSyncOnce(trigger: Trigger): Promise<Outcome> {
    if (running) return running;
    running = (async (): Promise<Outcome> => {
      const empty = { planned: 0, fetched: 0, canvasErrors: 0, skipped: 0, accepted: 0, rejected: 0 };
      const s = await readState(storage);
      const fail = (code: string, message: string): Outcome => ({ ok: false, code, message, counts: empty });
      if (!isConnected(s)) return fail('not_connected', s.needsReconnect ? 'Reconnect to your portal from the popup.' : 'Connect to your portal first.');
      if (!s.canvasOrigin) return fail('no_canvas', 'Choose your Canvas site in the popup first.');
      if (!(await hasPermission(s.canvasOrigin))) return fail('no_permission', 'Allow the extension to access your Canvas site from the popup.');
      if (s.backoffUntil && s.backoffUntil > env.now()) {
        return fail('rate_limited', 'The extension is waiting before trying again (see the last result above).');
      }
      const tabId = await findCanvasTab(s.canvasOrigin);
      const deps = {
        fetch: env.fetch,
        now: () => new Date(env.now()),
        readCanvas: async (origin: string, jobs: FetchJob[], maxPages: number) =>
          tabId !== undefined ? readCanvasViaTab(tabId, origin, jobs, maxPages) : runFetches(origin, jobs, maxPages),
      };
      const outcome = await runSync(
        {
          portalOrigin: s.portalOrigin!,
          uploadToken: s.uploadToken!,
          canvasOrigin: s.canvasOrigin,
          probeFirst: trigger === 'alarm' && tabId === undefined,
          // Only "Sync now" refreshes cold resources that are not due.
          force: trigger === 'manual',
          lastFetched: s.lastFetchedAt ?? {},
          ...(s.lastCourseIds ? { lastCourseIds: s.lastCourseIds } : {}),
        },
        deps,
      );
      // A signed-out alarm run changes nothing and waits for the next page visit.
      if (outcome.waiting) return outcome;
      // Without a Canvas tab, a manual run that finds Canvas signed out says so.
      await record(trigger, outcome, s.lastFetchedAt);
      return outcome;
    })().finally(() => {
      running = undefined;
    });
    return running;
  }

  async function handleMessage(message: any, sender: SenderLike) {
    const type = message?.type;
    if (type === 'canvas.pair.claim') return handleClaim(message, sender);
    if (typeof type !== 'string' || !isPopupSender(sender, api.runtime.id, popupUrl())) {
      throw new UserError('refused', 'Request refused.');
    }
    switch (type) {
      case 'canvas.pair.start':
        return startPairing(message.portalOrigin);
      case 'canvas.pair.manual': {
        const portalOrigin = parseOrigin(message.portalOrigin, 'portal address');
        const code = typeof message.code === 'string' ? message.code.trim() : '';
        if (!CODE_RE.test(code)) throw new UserError('invalid_code', 'Enter the pairing code shown on your portal page.');
        if (claiming) throw new UserError('busy', 'Pairing is already in progress.');
        claiming = true;
        try {
          await claimAndStore(portalOrigin, code);
        } finally {
          claiming = false;
        }
        return { ok: true };
      }
      case 'canvas.canvas.set': {
        const canvasOrigin = parseOrigin(message.canvasOrigin, 'Canvas address');
        if (!(await hasPermission(canvasOrigin))) throw new UserError('no_permission', 'Allow the extension to access this Canvas site first.');
        const s = await readState(storage);
        await storage.set({ canvasOrigin });
        // A different school starts from a clean sync history.
        if (s.canvasOrigin && s.canvasOrigin !== canvasOrigin) await storage.remove(['lastSyncAt', 'lastAttemptAt', 'lastResult', 'lastFetchedAt', 'lastCourseIds']);
        return { ok: true };
      }
      case 'canvas.sync.now': {
        const outcome = await runSyncOnce('manual');
        return { ok: outcome.ok, error: outcome.ok ? undefined : outcome.message, outcome };
      }
      case 'canvas.disconnect':
        return disconnect();
      default:
        throw new UserError('unknown', 'Unknown request.');
    }
  }

  async function onTabUpdated(tabId: number, change: { status?: string }, tab: { url?: string }) {
    if (change.status !== 'complete' || !tab.url) return;
    await injectLink(tabId, tab.url).catch(() => {});
    const s = await readState(storage);
    if (!isConnected(s) || !s.canvasOrigin || !sameOrigin(tab.url, s.canvasOrigin)) return;
    const now = env.now();
    if (s.lastSyncAt && now - Date.parse(s.lastSyncAt) < MIN_SYNC_GAP_MS) return;
    if (s.lastAttemptAt && now - Date.parse(s.lastAttemptAt) < MIN_ATTEMPT_GAP_MS) return;
    if (s.backoffUntil && s.backoffUntil > now) return;
    if (tabTimer) clearTimeout(tabTimer);
    tabTimer = setTimeout(() => {
      tabTimer = undefined;
      void runSyncOnce('tab').catch(() => {});
    }, TAB_DEBOUNCE_MS);
  }

  async function onAlarm(alarm: { name: string }) {
    if (alarm.name !== ALARM_NAME) return;
    await runSyncOnce('alarm');
  }

  return { handleMessage, onTabUpdated, onAlarm, ensureAlarm, runSyncOnce, disconnect };
}

export type { Stored };
