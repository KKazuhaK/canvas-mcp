// When to open the "update your Canvas data" reminder. The extension never opens Canvas by itself.

/** How old the data may get before a reminder, in hours; 0 turns reminders off. */
export const REMIND_CHOICES = [24, 72, 168, 0] as const;
export const DEFAULT_REMIND_HOURS = 24;
/** An ignored reminder comes back after this long, not on every check. */
export const IGNORED_SNOOZE_MS = 12 * 3600_000;
export const HOUR_MS = 3600_000;

export function remindHours(value: unknown): number {
  return typeof value === 'number' && (REMIND_CHOICES as readonly number[]).includes(value) ? value : DEFAULT_REMIND_HOURS;
}

/**
 * A reminder is due when reminders are on, no snooze is running, and the data (or, before the first
 * sync, the connection) is older than the chosen age.
 */
export function reminderDue(
  s: { lastSyncAt?: string | undefined; connectedAt?: string | undefined; remindAfterHours?: unknown; snoozeUntil?: unknown },
  now: number,
): boolean {
  const hours = remindHours(s.remindAfterHours);
  if (!hours) return false;
  if (typeof s.snoozeUntil === 'number' && s.snoozeUntil > now) return false;
  const since = Date.parse(s.lastSyncAt ?? s.connectedAt ?? '');
  return Number.isFinite(since) && now - since >= hours * HOUR_MS;
}
