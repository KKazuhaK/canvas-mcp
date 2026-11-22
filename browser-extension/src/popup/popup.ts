import { DEFAULT_PORTAL } from '../lib/defaults.ts';
import { hostPattern, looksLikeCanvas, parseOrigin } from '../lib/origin.ts';
import { PAIRING_PATH } from '../lib/pairing.ts';
import { describeStatus } from '../lib/status.ts';
import { readState, type Stored, type StorageArea } from '../lib/state.ts';
import { remindHours } from '../lib/reminder.ts';

declare const browser: typeof chrome | undefined;
const api: typeof chrome = typeof browser !== 'undefined' ? browser : chrome;
const storage = api.storage.local as unknown as StorageArea;
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

let busy = false;
let canvasPrefilled = false;
// Opened in a tab by the extension after the portal page paired it: ask for Canvas access here.
const canvasSetup = new URLSearchParams(location.search).get('setup') === 'canvas';

function say(kind: 'error' | 'message', text: string) {
  $('error').hidden = true;
  $('message').hidden = true;
  const el = $(kind);
  el.textContent = text;
  el.hidden = !text;
}

async function render() {
  const s: Stored = await readState(storage);
  const view = describeStatus(s, Date.now());
  $('headline').textContent = view.headline;
  const rows = $('rows');
  rows.replaceChildren();
  for (const [k, v] of view.rows) {
    const dt = document.createElement('dt');
    dt.textContent = k;
    const dd = document.createElement('dd');
    dd.textContent = v;
    rows.append(dt, dd);
  }
  const skips = $('skips');
  skips.replaceChildren(
    ...view.skipReasons.map((t) => {
      const li = document.createElement('li');
      li.textContent = t;
      return li;
    }),
  );
  if (view.error) {
    $('error').textContent = view.error;
    $('error').hidden = false;
  }
  // Connected: the connect section stays out of the way; Disconnect is the way to switch portals.
  $('connect').hidden = view.connected;
  if (s.portalOrigin && s.portalOrigin !== DEFAULT_PORTAL && !$<HTMLInputElement>('portal').value) {
    $<HTMLInputElement>('portal').value = s.portalOrigin;
    $<HTMLDetailsElement>('manual-connect').open = true;
  }
  $('canvas').hidden = !view.connected && !s.canvasOrigin;
  const canvasInput = $<HTMLInputElement>('canvas-origin');
  const canvasButton = $<HTMLButtonElement>('canvas-btn');
  const suggested = !s.canvasOrigin ? s.suggestedCanvasOrigin : undefined;
  if (s.canvasOrigin) canvasInput.value = s.canvasOrigin;
  else if (suggested && !canvasInput.value) canvasInput.value = suggested;
  else if (!canvasPrefilled) {
    canvasPrefilled = true;
    void prefillFromActiveTab(canvasInput);
  }
  $('canvas-hint').hidden = !suggested;
  if (suggested) $('canvas-hint').textContent = `Your portal says your Canvas site is ${new URL(suggested).host}. Allow access to it and syncing starts.`;
  canvasButton.textContent = suggested ? 'Allow access and start syncing' : 'Save Canvas site';
  canvasButton.className = suggested || (view.connected && !s.canvasOrigin) ? '' : 'secondary';
  if (canvasSetup && suggested && !busy) canvasButton.focus();
  ($('sync-btn') as HTMLButtonElement).disabled = busy || !view.connected || !s.canvasOrigin;
  ($('disconnect-btn') as HTMLButtonElement).disabled = busy || (!view.connected && !s.needsReconnect && !s.canvasOrigin);
}

// activeTab lets the popup read the URL of the tab it was opened from.
async function prefillFromActiveTab(input: HTMLInputElement) {
  try {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && !input.value && looksLikeCanvas(tab.url, DEFAULT_PORTAL)) input.value = parseOrigin(new URL(tab.url).origin);
  } catch {
    /* not a usable page */
  }
}

async function send(message: Record<string, unknown>): Promise<{ ok?: boolean; error?: string; message?: string }> {
  const res = (await api.runtime.sendMessage(message)) as { ok?: boolean; error?: string; message?: string } | undefined;
  return res ?? { ok: false, error: 'The extension did not answer. Try again.' };
}

async function guarded(button: HTMLButtonElement, work: () => Promise<void>) {
  if (busy) return;
  busy = true;
  button.setAttribute('aria-busy', 'true');
  say('message', '');
  try {
    await work();
  } catch (e) {
    say('error', e instanceof Error ? e.message : 'Something went wrong.');
  } finally {
    busy = false;
    button.removeAttribute('aria-busy');
    await render();
  }
}

// Permission requests must start from the click, before any other await.
async function allow(origin: string): Promise<void> {
  const granted = await api.permissions.request({ origins: [hostPattern(origin)] });
  if (!granted) throw new Error('Access was not allowed, so the extension cannot continue.');
}

/**
 * Asks for access to a site and then finishes the request. The request is saved first: Chrome closes
 * this popup while its access prompt is open, and the background then finishes it (permissions.onAdded).
 */
async function withAccess(origin: string, intent: Record<string, unknown>) {
  void storage.set({ pendingIntent: { ...intent, at: Date.now() } });
  try {
    await allow(origin);
  } catch (e) {
    await storage.remove('pendingIntent');
    throw e;
  }
  const res = await send({ type: 'canvas.intent.resume' });
  if (!res.ok) throw new Error(res.error);
}

$('open-portal').addEventListener('click', (ev) =>
  guarded(ev.currentTarget as HTMLButtonElement, async () => {
    if (!DEFAULT_PORTAL) {
      $<HTMLDetailsElement>('manual-connect').open = true;
      throw new Error('Enter your portal address below.');
    }
    await api.tabs.create({ url: `${DEFAULT_PORTAL}${PAIRING_PATH}` });
    window.close();
  }),
);

$('connect-btn').addEventListener('click', (ev) =>
  guarded(ev.currentTarget as HTMLButtonElement, async () => {
    const portalOrigin = parseOrigin($<HTMLInputElement>('portal').value, 'portal address');
    await withAccess(portalOrigin, { type: 'pair.start', portalOrigin });
    say('message', 'Pairing page opened. Sign in there and approve the connection.');
  }),
);

$('pair-btn').addEventListener('click', (ev) =>
  guarded(ev.currentTarget as HTMLButtonElement, async () => {
    const portalOrigin = parseOrigin($<HTMLInputElement>('portal').value.trim() || DEFAULT_PORTAL, 'portal address');
    const code = $<HTMLInputElement>('code').value.trim();
    await withAccess(portalOrigin, { type: 'pair.manual', portalOrigin, code });
    $<HTMLInputElement>('code').value = '';
    say('message', 'Connected.');
  }),
);

$('canvas-btn').addEventListener('click', (ev) =>
  guarded(ev.currentTarget as HTMLButtonElement, async () => {
    const canvasOrigin = parseOrigin($<HTMLInputElement>('canvas-origin').value, 'Canvas address');
    await withAccess(canvasOrigin, { type: 'canvas.set', canvasOrigin });
    say('message', 'Canvas site saved. The first sync has started.');
  }),
);

$('sync-btn').addEventListener('click', (ev) =>
  guarded(ev.currentTarget as HTMLButtonElement, async () => {
    say('message', 'Syncing...');
    const res = await send({ type: 'canvas.sync.now' });
    if (!res.ok) throw new Error(res.error);
    say('message', 'Sync finished.');
  }),
);

$('disconnect-btn').addEventListener('click', (ev) =>
  guarded(ev.currentTarget as HTMLButtonElement, async () => {
    const res = await send({ type: 'canvas.disconnect' });
    if (!res.ok) throw new Error(res.error);
    say('message', res.message ?? 'Disconnected.');
  }),
);

// The reminder age: set here or on the reminder page; a new choice clears any snooze.
async function showReminderChoice() {
  const chosen = String(remindHours((await readState(storage)).remindAfterHours));
  for (const option of Array.from($<HTMLSelectElement>('remind-after').options)) option.selected = option.value === chosen;
}
$<HTMLSelectElement>('remind-after').addEventListener('change', async () => {
  const hours = remindHours(Number($<HTMLSelectElement>('remind-after').value));
  await storage.set({ remindAfterHours: hours });
  await storage.remove('snoozeUntil');
  say('message', hours ? 'Reminder saved.' : 'Reminders are off.');
});
void showReminderChoice();

api.storage.onChanged.addListener(() => void render());
void render();
