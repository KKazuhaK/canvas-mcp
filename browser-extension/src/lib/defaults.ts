declare const __CANVAS_DEFAULT_PORTAL__: string | undefined;

/**
 * The portal this extension connects to with one click, set at build time from the manifest's page
 * bridge (scripts/build.mjs). Empty in an unconfigured build: then every portal goes through the popup.
 */
export const DEFAULT_PORTAL: string = typeof __CANVAS_DEFAULT_PORTAL__ === 'string' ? __CANVAS_DEFAULT_PORTAL__ : '';
/** Page <-> extension messages on the portal use this channel name. */
export const BRIDGE_CHANNEL = 'canvas-companion';
/** A request saved before a permission prompt is finished only within this window. */
export const INTENT_TTL_MS = 5 * 60_000;
