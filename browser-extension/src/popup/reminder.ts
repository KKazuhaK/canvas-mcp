import { HOUR_MS, remindHours } from '../lib/reminder.ts';
import { readState, type StorageArea } from '../lib/state.ts';
import { relativeTime } from '../lib/status.ts';

declare const browser: typeof chrome | undefined;
const api: typeof chrome = typeof browser !== 'undefined' ? browser : chrome;
const storage = api.storage.local as unknown as StorageArea;
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const say = (text: string) => {
  $('message').textContent = text;
};

async function load() {
  const s = await readState(storage);
  $('age').textContent = s.lastSyncAt
    ? `Your Canvas data was last updated ${relativeTime(s.lastSyncAt, Date.now())}.`
    : 'Your Canvas data has not been synced yet.';
  const chosen = String(remindHours(s.remindAfterHours));
  for (const option of Array.from($<HTMLSelectElement>('remind-after').options)) option.selected = option.value === chosen;
}

$('open-canvas').addEventListener('click', async () => {
  const s = await readState(storage);
  // Without a Canvas site yet, the popup's settings page is where to choose one.
  await api.tabs.create({ url: s.canvasOrigin ?? api.runtime.getURL('popup.html') });
  window.close();
});

for (const button of Array.from(document.querySelectorAll<HTMLButtonElement>('[data-snooze]'))) {
  button.addEventListener('click', async () => {
    await storage.set({ snoozeUntil: Date.now() + Number(button.dataset.snooze) * HOUR_MS });
    say(`OK. You'll be reminded ${button.dataset.label}.`);
    setTimeout(() => window.close(), 900);
  });
}

$<HTMLSelectElement>('remind-after').addEventListener('change', async () => {
  const hours = remindHours(Number($<HTMLSelectElement>('remind-after').value));
  await storage.set({ remindAfterHours: hours });
  say(hours ? 'Saved.' : 'Reminders are off. You can turn them on again in the extension popup.');
});

void load();
