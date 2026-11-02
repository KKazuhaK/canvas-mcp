// Injected only into the pairing tab opened by this extension. It reads the
// one-time pairing code from the page and hands it to the background script.
// It does not read cookies, account details or anything else on the page.
declare const browser: typeof chrome | undefined;
(() => {
  const api: typeof chrome = typeof browser !== 'undefined' ? browser : chrome;
  const state = /^#extension-auth=([a-f0-9]{64})$/.exec(location.hash)?.[1];
  const root = document.documentElement;
  if (!state || root.dataset.canvasLinkObserver) return;
  root.dataset.canvasLinkObserver = 'active';
  let sending = false;
  const read = async () => {
    const el = document.getElementById('canvas-extension-authorization');
    if (!el || sending || el.dataset.result) return;
    const code = el.dataset.code;
    if (el.dataset.state !== state || !code) return;
    sending = true;
    try {
      const result = (await api.runtime.sendMessage({ type: 'canvas.pair.claim', state, code })) as { ok?: boolean; error?: string } | undefined;
      el.removeAttribute('data-code');
      el.dataset.result = result?.ok ? 'connected' : 'error';
      el.dataset.message = result?.error ?? '';
    } catch {
      el.removeAttribute('data-code');
      el.dataset.result = 'error';
      el.dataset.message = 'Could not reach the extension. Start again from its popup.';
    }
  };
  const observer = new MutationObserver(() => void read());
  observer.observe(root, { subtree: true, childList: true, attributes: true, attributeFilter: ['data-state', 'data-code'] });
  void read();
  setTimeout(() => observer.disconnect(), 10 * 60_000);
})();
