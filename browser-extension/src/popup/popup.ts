import { hostPattern, parseOrigin } from '../lib/origin.ts';
import { describeStatus } from '../lib/status.ts';
import { readState, type Stored, type StorageArea } from '../lib/state.ts';

declare const browser: typeof chrome | undefined;
const api: typeof chrome = typeof browser !== 'undefined' ? browser : chrome;
const storage = api.storage.local as unknown as StorageArea;
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

let busy = false;
let canvasPrefilled = false;

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
  $('connect-btn').textContent = view.connected ? 'Connect again' : 'Connect';
  if (s.portalOrigin && !$<HTMLInputElement>('portal').value) $<HTMLInputElement>('portal').value = s.portalOrigin;
  const canvasInput = $<HTMLInputElement>('canvas-origin');
  if (s.canvasOrigin) canvasInput.value = s.canvasOrigin;
  else if (!canvasPrefilled) {
    canvasPrefilled = true;
    void prefillFromActiveTab(canvasInput);
  }
  ($('sync-btn') as HTMLButtonElement).disabled = busy || !view.connected || !s.canvasOrigin;
  ($('disconnect-btn') as HTMLButtonElement).disabled = busy || (!view.connected && !s.needsReconnect && !s.canvasOrigin);
}

// activeTab lets the popup read the URL of the tab it was opened from.
async function prefillFromActiveTab(input: HTMLInputElement) {
  try {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && !input.value) input.value = parseOrigin(new URL(tab.url).origin);
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

$('connect-btn').addEventListener('click', (ev) =>
  guarded(ev.currentTarget as HTMLButtonElement, async () => {
    const origin = parseOrigin($<HTMLInputElement>('portal').value, 'portal address');
    await allow(origin);
    const res = await send({ type: 'canvas.pair.start', portalOrigin: origin });
    if (!res.ok) throw new Error(res.error);
    say('message', 'Pairing page opened. Sign in there and approve the connection.');
  }),
);

$('pair-btn').addEventListener('click', (ev) =>
  guarded(ev.currentTarget as HTMLButtonElement, async () => {
    const origin = parseOrigin($<HTMLInputElement>('portal').value, 'portal address');
    await allow(origin);
    const res = await send({ type: 'canvas.pair.manual', portalOrigin: origin, code: $<HTMLInputElement>('code').value });
    if (!res.ok) throw new Error(res.error);
    $<HTMLInputElement>('code').value = '';
    say('message', 'Connected.');
  }),
);

$('canvas-btn').addEventListener('click', (ev) =>
  guarded(ev.currentTarget as HTMLButtonElement, async () => {
    const origin = parseOrigin($<HTMLInputElement>('canvas-origin').value, 'Canvas address');
    await allow(origin);
    const res = await send({ type: 'canvas.canvas.set', canvasOrigin: origin });
    if (!res.ok) throw new Error(res.error);
    say('message', 'Canvas site saved.');
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

api.storage.onChanged.addListener(() => void render());
void render();
