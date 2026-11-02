import { createController } from './lib/controller.ts';
import { UserError } from './lib/errors.ts';

declare const browser: typeof chrome | undefined;
const api: typeof chrome = typeof browser !== 'undefined' ? browser : chrome;

if (typeof api.storage.local.setAccessLevel === 'function') {
  void api.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }).catch(() => {});
}

const controller = createController(api, {
  fetch: (input, init) => fetch(input, init),
  now: () => Date.now(),
  randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)),
});

// Listeners are registered synchronously so a restarted service worker receives the event that woke it.
api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== 'string' || !message.type.startsWith('canvas.')) return false;
  controller.handleMessage(message, sender).then(sendResponse, (e) => {
    sendResponse({ ok: false, error: e instanceof UserError ? e.message : 'Something went wrong. Please try again.' });
  });
  return true;
});
api.tabs.onUpdated.addListener((tabId, change, tab) => {
  void controller.onTabUpdated(tabId, change, tab).catch(() => {});
});
api.alarms?.onAlarm.addListener((alarm) => {
  void controller.onAlarm(alarm).catch(() => {});
});
api.runtime.onInstalled?.addListener(() => void controller.ensureAlarm().catch(() => {}));
api.runtime.onStartup?.addListener(() => void controller.ensureAlarm().catch(() => {}));
