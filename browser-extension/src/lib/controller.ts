import { runFetches, type FetchResult } from './canvas-fetch.ts';
import type { FetchJob } from './allowlist.ts';
import { INTENT_TTL_MS } from './defaults.ts';
import { IGNORED_SNOOZE_MS, reminderDue } from './reminder.ts';
import { UserError } from './errors.ts';
import { hostPattern, parseOrigin, sameOrigin } from './origin.ts';
import { updateFetched } from './fetched.ts';
import { PAIRING_PATH, claimCode, mayInject, newPairing, pairingUrl, validateClaim } from './pairing.ts';
import { isPopupSender, type SenderLike } from './senders.ts';
import {
  CODE_RE,
  clearAll,
  isConnected,
  markDisconnected,
  readState,
  saveConnection,
  type Intent,
  type LastResult,
  type Stored,
} from './state.ts';
import { runSync, type Outcome } from './sync.ts';

export const ALARM_NAME = 'canvas-sync';
export const ALARM_MINUTES = 30;
/** The first periodic sync runs this soon after the alarm is created (pairing, install). */
export const FIRST_ALARM_MINUTES = 1;
/** One sync shortly after the browser starts. */
export const STARTUP_ALARM = 'canvas-startup-sync';
export const MIN_SYNC_GAP_MS = 10 * 60_000;
const MIN_ATTEMPT_GAP_MS = 60_000;
const TAB_DEBOUNCE_MS = 1500;
export const COLD_BUDGET = 30;

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
      if (!(await api.alarms.get(ALARM_NAME))) await api.alarms.create(ALARM_NAME, { delayInMinutes: FIRST_ALARM_MINUTES, periodInMinutes: ALARM_MINUTES });
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
    await storage.remove('notice');
    await registerBridge(portalOrigin).catch(() => {});
    await ensureAlarm();
    await syncSoon();
  }

  // The first sync after connecting (or choosing the Canvas site) runs now instead of waiting
  // for the next Canvas page visit or the hourly alarm.
  async function syncSoon() {
    const s = await readState(storage);
    if (!isConnected(s) || !s.canvasOrigin || !(await hasPermission(s.canvasOrigin))) return;
    void runSyncOnce('tab').catch(() => {});
  }

  async function setCanvas(canvasOrigin: string) {
    if (!(await hasPermission(canvasOrigin))) throw new UserError('no_permission', 'Allow the extension to access this Canvas site first.');
    const s = await readState(storage);
    await storage.set({ canvasOrigin });
    await storage.remove(['suggestedCanvasOrigin', 'notice']);
    // A different school starts from a clean sync history.
    if (s.canvasOrigin && s.canvasOrigin !== canvasOrigin) await storage.remove(['lastSyncAt', 'lastAttemptAt', 'lastResult', 'lastFetchedAt', 'lastCourseIds']);
    await syncSoon();
  }

  const BRIDGE_ID = 'canvas-portal-bridge';
  /**
   * The page bridge runs only on the portal the person chose: the one they paired, or the one they
   * asked to connect from the popup. No portal is built in; the script is registered at runtime for
   * that one origin, after the person allowed access to it.
   */
  async function registerBridge(origin: string | null) {
    if (origin) await storage.set({ bridgeOrigin: origin });
    else await storage.remove('bridgeOrigin');
    const scripting = api.scripting as typeof api.scripting | undefined;
    if (!scripting?.registerContentScripts) return;
    try {
      await scripting.unregisterContentScripts({ ids: [BRIDGE_ID] });
    } catch {
      /* not registered yet */
    }
    if (origin) {
      await scripting.registerContentScripts([
        { id: BRIDGE_ID, matches: [`${hostPattern(origin).replace(/\*$/, '')}account/*`], js: ['bridge.js'], runAt: 'document_idle', persistAcrossSessions: true },
      ]);
    }
  }

  // Registered scripts do not survive every update: put the bridge back for the saved portal.
  async function restoreBridge() {
    const { bridgeOrigin } = await readState(storage);
    if (bridgeOrigin && (await hasPermission(bridgeOrigin))) await registerBridge(bridgeOrigin);
  }

  // The chosen portal's page, in a top-level tab of this browser: its origin, or null.
  async function bridgeSenderOrigin(sender: SenderLike): Promise<string | null> {
    if (sender.id !== api.runtime.id || sender.tab?.id === undefined) return null;
    if (sender.frameId !== undefined && sender.frameId !== 0) return null;
    const { bridgeOrigin } = await readState(storage);
    return bridgeOrigin && sameOrigin(sender.url, bridgeOrigin) ? bridgeOrigin : null;
  }

  // Pairing handed over by the portal page. Canvas access cannot be asked for from a web page, so
  // when the suggested Canvas site is not allowed yet the popup opens in a tab to ask with one click.
  async function bridgeClaim(portalOrigin: string, message: { code?: unknown; canvasOrigin?: unknown }) {
    const code = typeof message.code === 'string' ? message.code.trim() : '';
    if (!CODE_RE.test(code)) throw new UserError('invalid_code', 'The page sent an invalid pairing code. Reload it and try again.');
    if (claiming) throw new UserError('busy', 'Pairing is already in progress.');
    let suggested: string | undefined;
    try {
      suggested = message.canvasOrigin == null ? undefined : parseOrigin(message.canvasOrigin, 'Canvas address');
    } catch {
      suggested = undefined;
    }
    claiming = true;
    try {
      await claimAndStore(portalOrigin, code);
    } finally {
      claiming = false;
    }
    const s = await readState(storage);
    const canvas = s.canvasOrigin ?? suggested;
    if (canvas && (await hasPermission(canvas))) {
      if (canvas !== s.canvasOrigin) await setCanvas(canvas);
      return { ok: true };
    }
    if (suggested) await storage.set({ suggestedCanvasOrigin: suggested });
    await api.tabs.create({ url: `${popupUrl()}?setup=canvas` });
    return { ok: true, needsCanvasAccess: true };
  }

  let resuming: Promise<{ ok: boolean; error?: string }> | undefined;
  /**
   * Finishes what the popup started before the browser asked for site access. Chrome closes the
   * popup while that prompt is open, so the popup saves its request first and this finishes it once
   * access is granted: from the popup if it survived, or from permissions.onAdded.
   */
  function resumeIntent() {
    if (resuming) return resuming;
    resuming = (async () => {
      const { pendingIntent: intent } = (await storage.get('pendingIntent')) as { pendingIntent?: Intent };
      if (!intent) return { ok: true };
      await storage.remove(['pendingIntent', 'notice']);
      try {
        if (typeof intent.at !== 'number' || env.now() - intent.at > INTENT_TTL_MS) {
          throw new UserError('expired', 'That request expired. Try again from the popup.');
        }
        if (intent.type === 'canvas.set') {
          await setCanvas(parseOrigin(intent.canvasOrigin, 'Canvas address'));
          return { ok: true };
        }
        const portalOrigin = parseOrigin(intent.portalOrigin, 'portal address');
        if (intent.type === 'pair.start') return await startPairing(portalOrigin);
        if (intent.type === 'page') {
          // The person is on this portal's pairing page: let it talk to the extension and finish there.
          if (!(await hasPermission(portalOrigin))) throw new UserError('no_permission', 'Allow the extension to access the portal address first.');
          await registerBridge(portalOrigin);
          if (typeof intent.tabId === 'number') await api.scripting.executeScript({ target: { tabId: intent.tabId }, files: ['bridge.js'] });
          return { ok: true };
        }
        if (intent.type === 'pair.manual') {
          await manualPair(portalOrigin, intent.code);
          return { ok: true };
        }
        throw new UserError('unknown', 'Unknown request.');
      } catch (e) {
        const message = e instanceof UserError ? e.message : 'Something went wrong. Please try again.';
        await storage.set({ notice: message });
        return { ok: false, error: message };
      }
    })().finally(() => {
      resuming = undefined;
    });
    return resuming;
  }

  async function manualPair(portalOrigin: string, rawCode: unknown) {
    const code = typeof rawCode === 'string' ? rawCode.trim() : '';
    if (!CODE_RE.test(code)) throw new UserError('invalid_code', 'Enter the pairing code shown on your portal page.');
    if (!(await hasPermission(portalOrigin))) throw new UserError('no_permission', 'Allow the extension to access the portal address first.');
    if (claiming) throw new UserError('busy', 'Pairing is already in progress.');
    claiming = true;
    try {
      await claimAndStore(portalOrigin, code);
    } finally {
      claiming = false;
    }
  }

  async function bridgeSync(portalOrigin: string, message: { force?: unknown }) {
    const s = await readState(storage);
    if (!isConnected(s) || s.portalOrigin !== portalOrigin) throw new UserError('not_connected', 'Connect this browser first.');
    // A click on the page refreshes everything, like Sync now in the popup; opening the page only
    // syncs what is due, like a Canvas page visit.
    const outcome = await runSyncOnce(message.force === true ? 'manual' : 'tab');
    return { ok: outcome.ok, error: outcome.ok ? undefined : outcome.message, counts: outcome.counts };
  }

  async function onInstalled(_details: { reason?: string } | undefined) {
    await ensureAlarm();
    await restoreBridge();
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
    await registerBridge(null).catch(() => {});
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
    const last: LastResult = { at, trigger, ok: outcome.ok, code: outcome.code, message: outcome.message, counts: outcome.counts, skipReasons: (outcome.skipReasons ?? []).slice(0, 10), ...(outcome.timing ? { timing: outcome.timing } : {}) };
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
    if (outcome.ok) {
      // The data is fresh again: any open reminder has done its job.
      await storage.remove('snoozeUntil');
      await closeReminders().catch(() => {});
    }
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
          // Page visits and the alarm refresh at most 30 cold requests; the first sync after
          // pairing (no lastSyncAt) is unbudgeted.
          ...(trigger !== 'manual' && s.lastSyncAt ? { budget: COLD_BUDGET } : {}),
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
    if (type === 'canvas.bridge.status' || type === 'canvas.bridge.claim' || type === 'canvas.bridge.sync') {
      const origin = await bridgeSenderOrigin(sender);
      if (!origin) throw new UserError('refused', 'Request refused.');
      if (type === 'canvas.bridge.claim') return bridgeClaim(origin, message);
      if (type === 'canvas.bridge.sync') return bridgeSync(origin, message);
      const s = await readState(storage);
      return {
        ok: true,
        connected: isConnected(s) && s.portalOrigin === origin,
        // Not connected here yet means the person chose this portal in the popup: the page pairs by itself.
        pending: !(isConnected(s) && s.portalOrigin === origin),
        canvasOrigin: s.canvasOrigin ?? null,
        lastSyncAt: s.lastSyncAt ?? null,
        lastError: s.lastResult && !s.lastResult.ok ? s.lastResult.message : null,
      };
    }
    if (typeof type !== 'string' || !isPopupSender(sender, api.runtime.id, popupUrl())) {
      throw new UserError('refused', 'Request refused.');
    }
    switch (type) {
      case 'canvas.pair.start':
        return startPairing(message.portalOrigin);
      case 'canvas.pair.manual':
        await manualPair(parseOrigin(message.portalOrigin, 'portal address'), message.code);
        return { ok: true };
      case 'canvas.canvas.set':
        await setCanvas(parseOrigin(message.canvasOrigin, 'Canvas address'));
        return { ok: true };
      case 'canvas.intent.resume':
        return resumeIntent();
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
    if (alarm.name === STARTUP_ALARM) {
      // A recent sync (from the previous session) is fresh enough.
      const s = await readState(storage);
      if (!s.lastSyncAt || env.now() - Date.parse(s.lastSyncAt) >= MIN_SYNC_GAP_MS) await runSyncOnce('alarm');
      await maybeRemind();
      return;
    }
    if (alarm.name !== ALARM_NAME) return;
    await runSyncOnce('alarm');
    await maybeRemind();
  }

  const reminderUrl = () => api.runtime.getURL('reminder.html');
  const isReminder = (t: { url?: string }) => t.url?.split(/[?#]/)[0] === reminderUrl();
  async function closeReminders() {
    if (!api.tabs.remove) return;
    const ids = (await api.tabs.query({ url: reminderUrl() })).filter(isReminder).flatMap((t) => (t.id === undefined ? [] : [t.id]));
    if (ids.length) await api.tabs.remove(ids);
  }
  /**
   * A background sync needs Canvas signed in. When it keeps failing and the data gets older than the
   * person's chosen age, open the extension's reminder page (never Canvas itself).
   */
  async function maybeRemind() {
    const s = await readState(storage);
    if (!isConnected(s) || !s.canvasOrigin) return;
    const now = env.now();
    if (!reminderDue(s, now)) return;
    if ((await api.tabs.query({ url: reminderUrl() })).some(isReminder)) return;
    // Ignoring the page snoozes it, so it comes back later instead of on every check.
    await storage.set({ snoozeUntil: now + IGNORED_SNOOZE_MS });
    await api.tabs.create({ url: reminderUrl() });
  }

  async function onStartup() {
    await ensureAlarm();
    await restoreBridge().catch(() => {});
    if (api.alarms && isConnected(await readState(storage))) await api.alarms.create(STARTUP_ALARM, { delayInMinutes: FIRST_ALARM_MINUTES });
  }

  return { handleMessage, onTabUpdated, onAlarm, onStartup, maybeRemind, ensureAlarm, runSyncOnce, disconnect, resumeIntent, onInstalled };
}

export type { Stored };
